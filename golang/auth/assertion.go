package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// AuthDomain is prepended to every signed assertion (domain separation), so an
// assertion signature can never be valid as an event, message, file or trust
// signature.
var AuthDomain = []byte("nodetide-auth-v1\x00")

const (
	AssertionType = "AUTH_ASSERTION"
	RequestType   = "AUTH_REQUEST"

	DefaultRequestLifetime = 300 // seconds
	MaxRequestLifetime     = 600
	MaxAssertionLifetime   = 600 // exp - iat
	ClockSkew              = 60

	MaxPendingChallenges = 10000

	capAuthenticate = "authenticate"
)

// nowUnix is replaceable in tests.
var nowUnix = func() int64 { return time.Now().Unix() }

// SigningInput returns the bytes signed for an assertion: AuthDomain followed
// by the canonical JSON of the assertion without its "sig" field.
func SigningInput(assertion map[string]any) ([]byte, error) {
	body := make(map[string]any, len(assertion))
	for k, v := range assertion {
		if k != "sig" {
			body[k] = v
		}
	}
	canonical, err := Canonical(body)
	if err != nil {
		return nil, err
	}
	return append(append([]byte(nil), AuthDomain...), canonical...), nil
}

// VerifyError is a failed assertion check. Code is machine readable:
// invalid_assertion, wrong_audience, expired, invalid_sigchain,
// unknown_chain_head, device_not_authorized, bad_signature.
type VerifyError struct {
	Code    string
	Message string
}

func (e *VerifyError) Error() string { return e.Code + ": " + e.Message }

func fail(code, message string) *VerifyError {
	return &VerifyError{Code: code, Message: message}
}

// Result is a successfully verified assertion.
type Result struct {
	Identity string
	Device   string
	// Claims are self-asserted by the signer; they are signed but not verified.
	Claims map[string]any
}

// VerifyAssertion verifies an AuthAssertion against a (verified) sigchain.
// Nonce single-use is the caller's responsibility (see Store).
func VerifyAssertion(assertion map[string]any, sc *Sigchain, expectedAud string, now int64) (*Result, *VerifyError) {
	if assertion == nil {
		return nil, fail("invalid_assertion", "Assertion must be an object")
	}
	if t, _ := assertion["type"].(string); t != AssertionType {
		return nil, fail("invalid_assertion", "Not an AUTH_ASSERTION")
	}

	var str = map[string]string{}
	for _, name := range []string{"identity", "device", "aud", "nonce", "chain_head", "sig"} {
		s, ok := assertion[name].(string)
		if !ok || s == "" {
			return nil, fail("invalid_assertion", "Missing or invalid field: "+name)
		}
		str[name] = s
	}
	iat, ok := intField(assertion, "iat")
	if !ok {
		return nil, fail("invalid_assertion", "Missing or invalid field: iat")
	}
	exp, ok := intField(assertion, "exp")
	if !ok {
		return nil, fail("invalid_assertion", "Missing or invalid field: exp")
	}
	var claims map[string]any
	if raw, present := assertion["claims"]; present {
		claims, ok = raw.(map[string]any)
		if !ok {
			return nil, fail("invalid_assertion", "claims must be an object")
		}
	}

	// 1. Audience and time window
	if str["aud"] != expectedAud {
		return nil, fail("wrong_audience", "Assertion audience does not match")
	}
	if exp <= iat || exp-iat > MaxAssertionLifetime {
		return nil, fail("invalid_assertion", "Invalid assertion lifetime")
	}
	if iat > now+ClockSkew {
		return nil, fail("expired", "Assertion issued in the future")
	}
	if now > exp+ClockSkew {
		return nil, fail("expired", "Assertion expired")
	}

	// 2. Sigchain belongs to the claimed identity (ParseSigchain verified it)
	if sc.IdentityHash() != str["identity"] {
		return nil, fail("invalid_assertion", "Sigchain does not match identity")
	}

	// 3. chain_head must be in the chain we hold, else our copy is stale
	if !sc.HasEvent(str["chain_head"]) {
		return nil, fail("unknown_chain_head", "Signer knows a sigchain event we do not; fetch a newer sigchain")
	}

	// 4. Device is active, is not the master key, and holds authenticate
	deviceHex := str["device"]
	if deviceHex == sc.MasterKey() {
		return nil, fail("device_not_authorized", "Master key may not sign assertions")
	}
	var device *Device
	for _, d := range sc.ActiveDevices(now) {
		if d.Pubkey == deviceHex {
			d := d
			device = &d
			break
		}
	}
	if device == nil {
		return nil, fail("device_not_authorized", "Device is not active")
	}
	if !device.HasCapability(capAuthenticate) {
		return nil, fail("device_not_authorized", "Device lacks authenticate capability")
	}
	if device.AddedAt > iat+ClockSkew {
		return nil, fail("device_not_authorized", "Device was added after assertion")
	}

	// 5. Signature
	msg, err := SigningInput(assertion)
	if err != nil || !verifyHex(deviceHex, msg, str["sig"]) {
		return nil, fail("bad_signature", "Signature verification failed")
	}

	return &Result{Identity: str["identity"], Device: deviceHex, Claims: claims}, nil
}

// Request is an AuthRequest (the RP's challenge).
type Request struct {
	Type      string   `json:"type"`
	Aud       string   `json:"aud"`
	Nonce     string   `json:"nonce"`
	IssuedAt  int64    `json:"issued_at"`
	ExpiresAt int64    `json:"expires_at"`
	Callback  string   `json:"callback,omitempty"`
	Claims    []string `json:"claims,omitempty"`
}

// ErrStoreFull is returned when too many challenges are outstanding.
var ErrStoreFull = errors.New("too many outstanding challenges")

// Store tracks issued challenges until they are used or expire.
type Store struct {
	mu   sync.Mutex
	reqs map[string]Request
	max  int
}

// NewStore creates a challenge store holding at most max outstanding requests.
func NewStore(max int) *Store {
	return &Store{reqs: map[string]Request{}, max: max}
}

// New issues a challenge. lifetime is clamped to [1, MaxRequestLifetime].
func (s *Store) New(aud, callback string, claims []string, lifetime int64) (Request, error) {
	if lifetime < 1 {
		lifetime = 1
	}
	if lifetime > MaxRequestLifetime {
		lifetime = MaxRequestLifetime
	}
	buf := make([]byte, 24) // 192 bits
	if _, err := rand.Read(buf); err != nil {
		return Request{}, err
	}
	now := nowUnix()
	req := Request{
		Type:      RequestType,
		Aud:       aud,
		Nonce:     base64.RawURLEncoding.EncodeToString(buf),
		IssuedAt:  now,
		ExpiresAt: now + lifetime,
		Callback:  callback,
		Claims:    claims,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.reqs) >= s.max {
		s.cleanupLocked(now)
		if len(s.reqs) >= s.max {
			return Request{}, ErrStoreFull
		}
	}
	s.reqs[req.Nonce] = req
	return req, nil
}

// Peek returns an outstanding, unexpired request without consuming it.
func (s *Store) Peek(nonce string) (Request, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.reqs[nonce]
	if !ok {
		return Request{}, false
	}
	if nowUnix() > req.ExpiresAt {
		delete(s.reqs, nonce)
		return Request{}, false
	}
	return req, true
}

// Consume marks a nonce as used. It returns false if it was not outstanding.
func (s *Store) Consume(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.reqs[nonce]; !ok {
		return false
	}
	delete(s.reqs, nonce)
	return true
}

// Cleanup removes expired challenges and returns how many were removed.
func (s *Store) Cleanup() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cleanupLocked(nowUnix())
}

func (s *Store) cleanupLocked(now int64) int {
	removed := 0
	for nonce, req := range s.reqs {
		if now > req.ExpiresAt {
			delete(s.reqs, nonce)
			removed++
		}
	}
	return removed
}

// Len is the number of outstanding challenges.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.reqs)
}
