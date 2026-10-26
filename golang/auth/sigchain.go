package auth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// defaultCapabilities is what an ADD_DEVICE event grants when it lists none
// (matches DeviceCapability in the Python implementation).
var defaultCapabilities = []string{
	"sign_messages", "sign_files", "sign_identity", "encrypt", "authenticate", "manage_claims",
}

// MalformedError marks a structurally invalid sigchain (as opposed to one that
// is well-formed but fails verification).
type MalformedError struct{ msg string }

func (e *MalformedError) Error() string { return e.msg }

func malformed(format string, args ...any) error {
	return &MalformedError{msg: fmt.Sprintf(format, args...)}
}

// IsMalformed reports whether err is a MalformedError.
func IsMalformed(err error) bool {
	var m *MalformedError
	return errors.As(err, &m)
}

// Device is an active device key in a sigchain.
type Device struct {
	Pubkey       string
	Label        string
	Capabilities []string
	AddedAt      int64
	Expires      *int64
}

// HasCapability reports whether the device holds capability c.
func (d Device) HasCapability(c string) bool {
	return hasString(d.Capabilities, c)
}

func hasString(list []string, want string) bool {
	for _, have := range list {
		if have == want {
			return true
		}
	}
	return false
}

// Sigchain is a verified, append-only chain of identity events.
type Sigchain struct {
	events []map[string]any
	hashes []string
	master string
}

// ParseSigchain parses and verifies a decoded JSON array of events (use
// DecodeJSON so numbers are json.Number). The chain is verified from genesis:
// signatures, prev links and signer authorization.
//
// Event hashes are computed over the event exactly as received, which equals
// the Python implementation's hash for events it serialized itself.
func ParseSigchain(raw []any) (*Sigchain, error) {
	if len(raw) == 0 {
		return nil, malformed("empty sigchain")
	}

	sc := &Sigchain{}
	prevHash := ""

	// State needed to authorize claim events: devices added so far, devices
	// revoked, and claims seen (claim_id -> revoked).
	type deviceState struct {
		caps    []string
		expires int64 // 0 = never
	}
	devices := map[string]deviceState{}
	revoked := map[string]bool{}
	claims := map[string]bool{}
	claimTypes := map[string]string{}

	for i, item := range raw {
		ev, ok := item.(map[string]any)
		if !ok {
			return nil, malformed("event %d: not an object", i)
		}
		typ, ok := stringField(ev, "type")
		if !ok {
			return nil, malformed("event %d: missing type", i)
		}
		signedBy, ok := stringField(ev, "signed_by")
		if !ok {
			return nil, malformed("event %d: missing signed_by", i)
		}
		sig, ok := stringField(ev, "signature")
		if !ok {
			return nil, malformed("event %d: missing signature", i)
		}
		if alg, present := ev["alg"]; present && alg != "ed25519" {
			return nil, malformed("event %d: unsupported alg", i)
		}
		if alg, present := ev["hash_alg"]; present && alg != "sha256" {
			return nil, malformed("event %d: unsupported hash_alg", i)
		}

		signable := make(map[string]any, len(ev))
		for k, v := range ev {
			if k != "signature" {
				signable[k] = v
			}
		}
		msg, err := Canonical(signable)
		if err != nil {
			return nil, malformed("event %d: %v", i, err)
		}
		if !verifyHex(signedBy, msg, sig) {
			return nil, fmt.Errorf("event %d: signature invalid", i)
		}

		hash, err := eventHash(ev)
		if err != nil {
			return nil, malformed("event %d: %v", i, err)
		}

		if i == 0 {
			if typ != "genesis" {
				return nil, fmt.Errorf("first event must be genesis")
			}
			pub, ok := stringField(ev, "pubkey")
			if !ok {
				return nil, malformed("genesis: missing pubkey")
			}
			if pub != signedBy {
				return nil, fmt.Errorf("genesis must be self-signed")
			}
			if prev := ev["prev"]; prev != nil {
				return nil, fmt.Errorf("genesis must not have prev")
			}
			sc.master = pub
		} else {
			if prev, _ := ev["prev"].(string); prev != prevHash {
				return nil, fmt.Errorf("event %d: prev hash mismatch", i)
			}
			switch typ {
			case "add_device", "revoke_device", "set_recovery", "resolve_fork", "set_distribution":
				if signedBy != sc.master {
					return nil, fmt.Errorf("event %d: must be signed by master key", i)
				}
				switch typ {
				case "add_device":
					if pub, ok := stringField(ev, "device_pubkey"); ok {
						expires, _ := intField(ev, "expires")
						devices[pub] = deviceState{caps: capabilitiesOf(ev), expires: expires}
					}
				case "revoke_device":
					if pub, ok := stringField(ev, "device_pubkey"); ok {
						revoked[pub] = true
					}
				}
			case "add_claim", "revoke_claim", "set_claim_order":
				// Master, or a currently valid device holding manage_claims.
				if signedBy != sc.master {
					d, known := devices[signedBy]
					ts, _ := intField(ev, "timestamp")
					allowed := known && !revoked[signedBy] &&
						hasString(d.caps, "manage_claims") &&
						!(d.expires != 0 && d.expires < ts)
					if !allowed {
						return nil, fmt.Errorf("event %d: signer may not manage claims", i)
					}
				}
				if typ == "set_claim_order" {
					// The holder's preferred claims of one type, first = default.
					claimType, ok := stringField(ev, "claim_type")
					order, isList := ev["order"].([]any)
					if !ok || !isList || len(order) < 1 || len(order) > 32 {
						return nil, malformed("event %d: a claim order lists between 1 and 32 claims", i)
					}
					seen := map[string]bool{}
					for _, item := range order {
						id, isString := item.(string)
						if !isString || seen[id] {
							return nil, fmt.Errorf("event %d: a claim is listed twice", i)
						}
						seen[id] = true
						isRevoked, exists := claims[id]
						if !exists {
							return nil, fmt.Errorf("event %d: orders an unknown claim", i)
						}
						if isRevoked {
							return nil, fmt.Errorf("event %d: orders a revoked claim", i)
						}
						if claimTypes[id] != claimType {
							return nil, fmt.Errorf("event %d: orders a claim of another type", i)
						}
					}
					break
				}
				claimID, ok := stringField(ev, "claim_id")
				if !ok {
					return nil, malformed("event %d: missing claim_id", i)
				}
				if typ == "add_claim" {
					if _, dup := claims[claimID]; dup {
						return nil, fmt.Errorf("event %d: duplicate claim_id", i)
					}
					claims[claimID] = false
					claimTypes[claimID], _ = stringField(ev, "claim_type")
				} else {
					isRevoked, exists := claims[claimID]
					if !exists {
						return nil, fmt.Errorf("event %d: revokes an unknown claim", i)
					}
					if isRevoked {
						return nil, fmt.Errorf("event %d: claim already revoked", i)
					}
					claims[claimID] = true
				}
			case "rotate_master":
				if signedBy != sc.master {
					return nil, fmt.Errorf("event %d: rotation must be signed by old master", i)
				}
				np, ok := stringField(ev, "new_pubkey")
				if !ok {
					return nil, malformed("event %d: missing new_pubkey", i)
				}
				sc.master = np
			case "social_recovery":
				// The Python implementation accepts these without checking the
				// trustee threshold (TODO there). Do not trust an unverified
				// master change here.
				return nil, fmt.Errorf("event %d: social_recovery is not supported", i)
			case "genesis":
				return nil, malformed("event %d: unexpected genesis", i)
			default:
				return nil, malformed("event %d: unknown event type %q", i, typ)
			}
		}

		sc.events = append(sc.events, ev)
		sc.hashes = append(sc.hashes, hash)
		prevHash = hash
	}
	return sc, nil
}

// IdentityHash is the hash of the genesis event.
func (s *Sigchain) IdentityHash() string { return s.hashes[0] }

// HeadHash is the hash of the newest event.
func (s *Sigchain) HeadHash() string { return s.hashes[len(s.hashes)-1] }

// Len is the number of events.
func (s *Sigchain) Len() int { return len(s.events) }

// Hashes returns all event hashes in order.
func (s *Sigchain) Hashes() []string { return append([]string(nil), s.hashes...) }

// HasEvent reports whether an event with this hash is in the chain.
func (s *Sigchain) HasEvent(hash string) bool {
	for _, h := range s.hashes {
		if h == hash {
			return true
		}
	}
	return false
}

// MasterKey is the current master public key (hex).
func (s *Sigchain) MasterKey() string { return s.master }

// ActiveDevices returns the device keys that are added, not revoked and not
// expired at time now (unix seconds). Like the Python implementation, the
// genesis key is listed as a "Primary" device without the authenticate
// capability.
func (s *Sigchain) ActiveDevices(now int64) []Device {
	devices := map[string]Device{}
	var order []string
	revoked := map[string]bool{}

	put := func(d Device) {
		if _, exists := devices[d.Pubkey]; !exists {
			order = append(order, d.Pubkey)
		}
		devices[d.Pubkey] = d
	}

	for _, ev := range s.events {
		typ, _ := stringField(ev, "type")
		ts, _ := intField(ev, "timestamp")
		switch typ {
		case "genesis":
			pub, _ := stringField(ev, "pubkey")
			put(Device{
				Pubkey:       pub,
				Label:        "Primary",
				Capabilities: []string{"sign", "encrypt"},
				AddedAt:      ts,
			})
		case "add_device":
			pub, ok := stringField(ev, "device_pubkey")
			if !ok {
				continue
			}
			var expires *int64
			if e, ok := intField(ev, "expires"); ok && e != 0 {
				expires = &e
				if e < now {
					continue
				}
			}
			label, _ := stringField(ev, "label")
			put(Device{
				Pubkey:       pub,
				Label:        label,
				Capabilities: capabilitiesOf(ev),
				AddedAt:      ts,
				Expires:      expires,
			})
		case "revoke_device":
			if pub, ok := stringField(ev, "device_pubkey"); ok {
				revoked[pub] = true
			}
		}
	}

	var active []Device
	for _, pub := range order {
		d := devices[pub]
		if revoked[pub] {
			continue
		}
		if d.Expires != nil && *d.Expires < now {
			continue
		}
		active = append(active, d)
	}
	return active
}

func capabilitiesOf(ev map[string]any) []string {
	raw, present := ev["capabilities"]
	if !present {
		return append([]string(nil), defaultCapabilities...)
	}
	list, ok := raw.([]any)
	if !ok {
		return nil // null or malformed: grant nothing
	}
	caps := make([]string, 0, len(list))
	for _, c := range list {
		if s, ok := c.(string); ok {
			caps = append(caps, s)
		}
	}
	return caps
}

func eventHash(ev map[string]any) (string, error) {
	canonical, err := Canonical(ev)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// verifyHex checks an Ed25519 signature given hex-encoded key and signature.
func verifyHex(pubHex string, msg []byte, sigHex string) bool {
	pub, err := hex.DecodeString(pubHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

func stringField(m map[string]any, key string) (string, bool) {
	s, ok := m[key].(string)
	return s, ok
}

// intField reads an integer field decoded as json.Number.
func intField(m map[string]any, key string) (int64, bool) {
	n, ok := m[key].(json.Number)
	if !ok {
		return 0, false
	}
	v, err := n.Int64()
	if err != nil {
		return 0, false
	}
	return v, true
}
