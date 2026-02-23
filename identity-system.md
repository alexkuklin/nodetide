# Distributed Identity System

## Overview

A transport-agnostic identity system designed for delay-tolerant messaging across multiple delivery mechanisms (TCP/DNS, TCP/mDNS, Bluetooth, mesh radio, sneakernet).

## Core Principles

- **Identity = hash(sigchain)** - Stable identifier derived from append-only event log
- **Master/sub-key hierarchy** - Separate identity continuity from operational keys
- **Append-only sigchain** - Embedded in protocol, no history rewriting
- **Social recovery** - Threshold of trusted contacts can recover compromised identity

## Key Hierarchy

```
Master Key (identity)
├── signs → Device Key A (phone)
├── signs → Device Key B (laptop)
├── signs → Device Key C (agent/bot)
└── signs → Key Rotation Record → New Master Key
                                   ├── signs → Device Key D
                                   └── ...
```

## Sigchain Structure

The sigchain is an append-only log of signed events:

```
┌─────────────────────────────────────────────────────────┐
│ Event 0: GENESIS                                        │
│   pubkey: <master_pubkey_0>                             │
│   sig: <self-signed>                                    │
├─────────────────────────────────────────────────────────┤
│ Event 1: SET_RECOVERY (optional, can be added anytime)  │
│   recovery_threshold: 3                                 │
│   recovery_trustees: [alice, bob, carol, dave, eve]     │
│   prev: hash(event_0)                                   │
│   sig: <signed by master_0>                             │
├─────────────────────────────────────────────────────────┤
│ Event 2: ADD_DEVICE                                     │
│   device_pubkey: <phone_key>                            │
│   label: "phone"                                        │
│   expires: 2026-06-01 (optional)                        │
│   prev: hash(event_1)                                   │
│   sig: <signed by master_0>                             │
├─────────────────────────────────────────────────────────┤
│ Event 3: REVOKE_DEVICE                                  │
│   device_pubkey: <phone_key>                            │
│   reason: "lost"                                        │
│   prev: hash(event_2)                                   │
│   sig: <signed by master_0>                             │
├─────────────────────────────────────────────────────────┤
│ Event 4: ROTATE_MASTER                                  │
│   new_pubkey: <master_pubkey_1>                         │
│   prev: hash(event_3)                                   │
│   sig: <signed by master_0>                             │
├─────────────────────────────────────────────────────────┤
│ Event 5: SOCIAL_RECOVERY                                │
│   new_pubkey: <master_pubkey_2>                         │
│   prev: hash(event_4)                                   │
│   recovery_sigs: [                                      │
│     {trustee: alice, sig: ...},                         │
│     {trustee: bob, sig: ...},                           │
│     {trustee: dave, sig: ...}                           │
│   ]                                                     │
└─────────────────────────────────────────────────────────┘

Identity = hash(event_0) = "7f3a8b..." (stable forever)
```

## Event Types

| Event | Signed by | Purpose |
|-------|-----------|---------|
| `GENESIS` | self | Create identity (minimal, no trustees required) |
| `SET_RECOVERY` | master | Add/update recovery trustees (optional, anytime) |
| `ADD_DEVICE` | master | Authorize sub-key |
| `REVOKE_DEVICE` | master | Explicit revocation |
| `ROTATE_MASTER` | old master | Normal key rotation |
| `SOCIAL_RECOVERY` | threshold of trustees | Emergency recovery |

## Revocation

Two mechanisms:

1. **Explicit revocation** - `REVOKE_DEVICE` event signed by master key
2. **Expiration** - Optional `expires` timestamp on device keys

## Verification Rules

1. Walk chain from genesis
2. Track current valid master key
3. Track active device keys (added, not revoked, not expired)
4. Accept messages signed by any currently-valid key

## Design Decisions

### Trustee Format

Trustees are identified by their **identity hash only**:

```
recovery_trustees: [
  "7f3a8b...",  // alice's identity hash
  "9c2d1e...",  // bob's identity hash
  ...
]
```

At verification time, resolve each trustee's sigchain to find their valid signing keys. No circular dependency since `SET_RECOVERY` comes after genesis. References remain stable even if trustees rotate their own keys.

### Recovery Payload

Trustees sign a **structured recovery request**, not just the new pubkey:

```
RecoveryRequest = {
  type: "RECOVERY_REQUEST",
  identity: <hash of genesis being recovered>,
  prev: <hash of last known valid event>,
  new_pubkey: <new master key>,
  timestamp: <unix timestamp>
}
```

This prevents:
- **Replay attacks** - `prev` ties signature to specific chain state
- **Ambiguity** - explicitly names which identity is being recovered
- **Stale signatures** - timestamp allows expiration policy (e.g., reject signatures older than 30 days)

### Conflict Resolution

**Detect forks, flag as conflicted, require explicit resolution.**

In a DTN environment, "first-seen" is unreliable since there's no global ordering.

| Step | Action |
|------|--------|
| **Detect** | Two events with same `prev` = fork |
| **Flag** | Mark identity as "CONFLICTED" - treat messages with suspicion |
| **Display** | For consistency, lower event hash shown as "primary" (display only) |
| **Resolve** | Explicit resolution required (see below) |

Resolution mechanisms:
1. `RESOLVE_FORK` event signed by current master key, choosing a branch
2. Social recovery establishes new canonical branch
3. Revocation on one branch that invalidates the other (e.g., revoking key that signed competing branch)

### Sigchain Distribution

**Full chain by default, delta sync when state is known.**

| Scenario | Approach |
|----------|----------|
| First encounter | Send full chain |
| Subsequent sync | "I have through event N, send N+1 onward" |
| Verification | Always verify from genesis |

Rationale:
- Chains are typically short (tens of events for personal identity)
- Full chain is self-contained, works offline, no coordination needed
- Delta sync is optimization, not requirement
- Compression recommended for multi-hop transports (chains compress well)

## Encoding & Algorithms

**Algorithm agility**: Crypto algorithms and hash functions are not hardcoded. Each event specifies its algorithm, allowing future migration.

```
Event = {
  version: 1,
  alg: "ed25519",
  hash_alg: "sha256",
  ...
}
```

**Event encoding**: JSON for human readability. Can be transcoded to compact binary (CBOR, etc.) for transport if needed.

## Key Capabilities

Device keys can have limited permissions:

```
ADD_DEVICE = {
  device_pubkey: <key>,
  capabilities: ["sign_messages", "sign_files"],  // optional, default: all
  expires: <timestamp>
}
```

Possible capabilities:
- `sign_messages` - can sign chat/messages
- `sign_files` - can sign file attestations
- `sign_identity` - can vouch for other identities (usually master only)
- `encrypt` - can receive encrypted content

## Timestamps

Timestamps are self-reported by default. Optionally, events can include external timestamp witness signatures:

```
timestamp: 1735689600,
timestamp_witness: {
  service: "timestamping.example.org",
  sig: <signature over event hash + timestamp>
}
```

## Discovery

Initial sigchain discovery is transport-agnostic:
- DNS TXT records
- Well-known URL (`.well-known/identity.json`)
- QR code exchange
- Out-of-band sharing (email, chat, paper)

## Revocation Priority

Revocation events are **top priority** in sync protocols. Nodes should propagate revocations before other event types.

Rate limiting should be applied to prevent flooding attacks - a node should not accept excessive revocation events from a single source in a short time window.

## Trustee Liveness

Two mechanisms to handle unresponsive trustees:

**1. Proactive Rotation**
- Replace trustees via `SET_RECOVERY` while you have master key access
- Best practice: rotate trustees periodically

**2. Backup Trustee Tiers**

```
SET_RECOVERY = {
  primary_trustees: [A, B, C, D, E],
  primary_threshold: 3,
  backup_trustees: [F, G, H],
  backup_threshold: 2,
  backup_activates_after: 90 days  // of primary non-response
}
```

If primary trustees fail to respond within timeout, backup tier becomes eligible.

**Minimum trustees**: Configurable, recommend minimum of 3 for primary tier.

## Identity Types

### Pseudonymous

Identities with no real-world binding are allowed. The trust model handles this naturally - others simply won't have `IdentityAssertion` records linking the hash to a real name.

### Ephemeral

Short-lived identities explicitly marked:

```
GENESIS = {
  pubkey: <key>,
  ephemeral: true,
  ownership_proof: <signature linking to a persistent identity>  // optional
}
```

Ephemeral identities can optionally prove ownership by a persistent identity (useful for burner accounts that may need later attribution).

### Organizational

Org identities are marked and managed internally by personal identities:

```
GENESIS = {
  pubkey: <key>,
  identity_type: "organization",
  name: "Acme Corp"
}

ADD_ADMIN = {
  admin_identity: <personal identity hash>,
  role: "admin" | "member",
  capabilities: ["add_device", "sign_messages"],
  prev: <hash>,
  sig: <signed by current admin>
}
```

Org actions require signatures from authorized personal identities.

## Trust Model

Scope: Identity verification and trust delegation only. Content trust is out of scope for this system.

### Identity Assertions

Claims about who an identity belongs to:

```
IdentityAssertion = {
  subject: <identity hash>,
  claimed_name: "John Doe",
  verification: "IN_PERSON" | "VIDEO" | "VOUCHED" | "SOCIAL_PROOF" | "CLAIMED",
  confidence: -1.0 to 1.0,
  timestamp: <unix>,
  note: "Met at DEF CON 2025, verified fingerprint"
}
```

| Confidence | Meaning |
|------------|---------|
| +1.0 | Certain this identity is the claimed person |
| +0.5 | Reasonably confident |
| 0.0 | No information |
| -0.5 | Doubtful this is the claimed person |
| -1.0 | Certain this is NOT the claimed person (impersonation) |

Verification levels:

| Level | Method |
|-------|--------|
| `IN_PERSON` | Physical key exchange |
| `VIDEO` | Live video verification |
| `VOUCHED` | Verified by someone you trust |
| `SOCIAL_PROOF` | Public proofs (signed statement on known account/website) |
| `CLAIMED` | Unverified self-assertion |

### Trust Delegation

How much you trust someone else's identity assertions:

```
TrustDelegation = {
  subject: <identity hash>,
  weight: 0.0 to 1.0,
  depth_limit: <int, optional>,
  timestamp: <unix>
}
```

Weight of 0.0 = ignore their assertions. Weight of 1.0 = fully trust their judgment.

### Transitive Trust Calculation

```
Path trust = my_delegation(A) × A's_delegation(B) × ... × final_confidence
Multiple paths = max(path1, path2, ...)
Depth limit = configurable per-delegation (optional)
```

Example:
- I trust Alice at 0.6, Alice trusts Bob at 0.9 → path trust = 0.54
- I trust Carol at 0.8, Carol trusts Bob at 0.7 → path trust = 0.56
- Result: max(0.54, 0.56) = 0.56

### Contested Identity

When positive and negative assertions conflict:

| Via Alice | Via Bob | Result |
|-----------|---------|--------|
| +0.8 "is John" | — | +0.8 |
| — | -0.9 "is NOT John" | -0.9 |
| +0.8 "is John" | -0.7 "is NOT John" | **CONTESTED** |

Contested identities surface both assertions rather than computing a combined score. User must resolve manually.

## Transport Layer

Hybrid approach: compatible with Bundle Protocol (RFC 9171) where useful, extended/simplified as needed.

Reference implementations: [dtn7-go](https://github.com/dtn7/dtn7-go), [ION-DTN](https://sourceforge.net/projects/ion-dtn/)

### Addressing

Identity-first with optional routing hints:

```
Destination: 7f3a8b... (identity hash)
Hints: [node://abc123, node://def456]  // optional
```

Identity is the address. Hints help routing but aren't authoritative.

### Bundle Format

Single bundle type with in-band type field:

```
Bundle = {
  version: 1,
  type: "revocation" | "sigchain" | "message" | "content_announce" | "ack",
  sender: <identity hash>,
  recipient: <identity hash or "*" for broadcast>,
  ttl: <seconds>,
  created: <timestamp>,
  hints: [<node>, ...],
  payload: <type-specific content>,
  sig: <signed by sender>
}
```

Relays read `type` for priority handling (revocations first).

### Convergence Layer Adapters

Pluggable transport modules. Each CLA handles discovery, connection, and data transfer for its medium.

#### Internet/WAN

**TCP Direct**
| Aspect | Details |
|--------|---------|
| Discovery | DNS SRV/TXT, well-known URLs, static config |
| Connection | Standard TCP/IP |
| Bandwidth | High |
| Latency | Low |
| Use | Primary transport when online |

**WebSocket**
| Aspect | Details |
|--------|---------|
| Discovery | Same as TCP |
| Connection | HTTP upgrade to WS |
| Bandwidth | High |
| Use | Browser clients, firewall traversal |

**QUIC/HTTP3**
| Aspect | Details |
|--------|---------|
| Discovery | Same as TCP |
| Connection | UDP-based, built-in encryption |
| Bandwidth | High |
| Use | Mobile (handles network changes), modern infrastructure |

#### Local Network

**mDNS/DNS-SD**
| Aspect | Details |
|--------|---------|
| Discovery | Multicast DNS broadcast |
| Connection | TCP on local IP |
| Range | LAN only |
| Use | Home/office, same WiFi |

**WiFi Direct**
| Aspect | Details |
|--------|---------|
| Discovery | WiFi Direct service discovery |
| Connection | Peer-to-peer WiFi (no router) |
| Range | ~200m |
| Use | Direct device-to-device |

#### Short Range

**Bluetooth Classic**
| Aspect | Details |
|--------|---------|
| Discovery | Bluetooth inquiry |
| Range | ~10-100m |
| Bandwidth | ~2 Mbps |
| Use | Device pairing, small transfers |

**BLE (Bluetooth Low Energy)**
| Aspect | Details |
|--------|---------|
| Discovery | BLE advertisement with service UUID |
| Range | ~10-50m |
| Bandwidth | ~125 Kbps |
| Power | Very low |
| Use | Background sync, beacons, mobile |

**NFC**
| Aspect | Details |
|--------|---------|
| Discovery | Tap |
| Range | ~4cm |
| Bandwidth | ~400 Kbps |
| Use | Initial pairing, key exchange, small payloads |

#### Mesh/Radio

**LoRa (raw)**
| Aspect | Details |
|--------|---------|
| Discovery | Periodic beacon |
| Range | 2-15km (line of sight) |
| Bandwidth | 0.3-50 Kbps |
| Power | Low |
| Use | Rural, disaster scenarios |

**Meshtastic**
| Aspect | Details |
|--------|---------|
| Discovery | Mesh node announcement |
| Range | Multi-hop extends coverage |
| Bandwidth | Low |
| Features | Built-in mesh routing, encrypted |
| Use | Off-grid communication |

**Ham Radio (Packet)**
| Aspect | Details |
|--------|---------|
| Discovery | Manual/frequency scanning |
| Range | Varies (HF can go global) |
| Bandwidth | Very low |
| Requirements | License required |
| Use | Emergency, remote areas |

**WiFi Mesh (802.11s)**
| Aspect | Details |
|--------|---------|
| Discovery | Mesh beacons |
| Range | Extended via hops |
| Bandwidth | High |
| Use | Community networks, events |

#### High Latency

**Sneakernet**
| Aspect | Details |
|--------|---------|
| Discovery | Manual |
| Medium | USB drive, SD card, hard drive |
| Bandwidth | Very high (TB per trip) |
| Latency | Hours/days |
| Use | Bulk transfer, air-gapped systems |

**Satellite (Store-forward)**
| Aspect | Details |
|--------|---------|
| Discovery | Service-specific |
| Coverage | Global (Iridium, Starlink, etc.) |
| Latency | Variable |
| Use | Remote areas, maritime |

**SMS/MMS**
| Aspect | Details |
|--------|---------|
| Discovery | Phone number mapping |
| Coverage | Ubiquitous |
| Bandwidth | Very low |
| Use | Notifications, small payloads, bootstrap |

#### Exotic/Experimental

**QR Codes**
| Aspect | Details |
|--------|---------|
| Capacity | ~3KB |
| Use | Identity exchange, small payloads, offline bootstrap |

**Audio/Ultrasonic**
| Aspect | Details |
|--------|---------|
| Range | Room-scale |
| Bandwidth | Very low |
| Use | Pairing, presence detection |

**Steganographic**
| Aspect | Details |
|--------|---------|
| Medium | Images/posts on existing platforms |
| Bandwidth | Very low |
| Use | Censorship resistance |

### Relay Model

**Open relay**: Anyone can offer to relay for any identity. No authorization required.

```
RelayAnnounce = {
  node: <node identity>,
  type: "public" | "identity-specific",
  serves: ["*"] or [<identity>, ...],
  retention: 7 days,
  sig: <signed by node>
}
```

**Relay self-protection**: Relays enforce their own policies:

```
RelayPolicy = {
  rate_limit: 100 messages/hour per sender,
  max_message_size: 64KB,
  retention: 7 days,
  priority_rules: ["revocation > sigchain > messages"],
  blocked_senders: [<identity>, ...]
}
```

**Unreliable relay warnings**: Part of trust model:

```
RelayWarning = {
  relay_node: <node identity>,
  issue: "drops_messages" | "logs_metadata" | "selective_delivery" | "spam",
  confidence: 0.0-1.0,
  evidence: "...",
  timestamp: <unix>,
  sig: <signed by reporter>
}
```

### Large Content

Pull model for content exceeding size threshold (~64KB default):

```
ContentAnnounce = {
  content_hash: <hash>,
  size: 15000000,
  mime_type: "application/zip",
  chunks: [<hash1>, <hash2>, ...],
  available_from: [<node>, ...],
  expires: <timestamp>,
  sig: <signed by sender>
}
```

Relays and recipients fetch on demand based on interest and bandwidth.

### TTL and Retention

- Sender requests TTL in bundle
- Relay may shorten (limited storage)
- Relay may keep longer (not enforceable)
- TTL is hint, not guarantee
- Sensitive content must rely on encryption, not TTL

### Routing

**Sender decides strategy**: Protocol doesn't mandate routing approach.

Options available to sender:
- Direct delivery (if path known)
- Single relay
- Multiple relays (spray)
- Broadcast

### Delivery Confirmation

Relay pickup ≠ delivered. Delivery requires acknowledgment from recipient:

```
DeliveryAck = {
  message_id: <hash>,
  recipient: <identity>,
  received_at: <timestamp>,
  sig: <signed by recipient device>
}
```

Ack is itself a bundle that travels back through the network.

### Transport Security

None at transport layer:
- End-to-end encryption at message layer (when needed)
- Signatures for authenticity
- Transport is public infrastructure

## Messaging Layer

Privacy comes from encryption, not path. All messages travel over public transport.

| Type | Encryption | Distribution |
|------|------------|--------------|
| Private | Encrypted to recipient | Any path |
| Group | Encrypted to group members | Any path |
| Public | Signed only | Broadcast/open |

### Private Messages

Encrypted to recipient's current device key(s) from their sigchain:

```
PrivateMessage = {
  type: "private",
  recipient: <identity hash>,
  encrypted_to: [<device_key_1>, ...],
  ciphertext: <encrypted payload>,
  reply_to: <message hash>,  // optional
  request_receipt: "none" | "delivery" | "read",  // optional
  request_transit_report: true,  // optional
  ephemeral_key: <key>,  // optional, for forward secrecy
  sig: <signed by sender>
}
```

Multi-device: encrypt to all recipient's active device keys.

### Group Messages

Sender chooses encryption mode based on needs:

```
GroupMessage = {
  type: "group",
  group_id: <hash>,
  encryption_mode: "per_member" | "shared_key" | "sender_key",
  ciphertext: <encrypted payload>,
  reply_to: <message hash>,  // optional
  sig: <signed by sender>
}
```

| Mode | Description | Best for |
|------|-------------|----------|
| `per_member` | Encrypt symmetric key to each member | Small groups, one-off messages |
| `shared_key` | Group shares symmetric key, rotated on membership change | Stable groups, high traffic |
| `sender_key` | Each member has own sender key for group | Large groups, forward secrecy |

Recipients must support all modes.

### Group Management

Groups have their own append-only event log (mini-sigchain):

```
GroupDefinition = {
  group_id: <hash of this event>,
  name: "Project X",
  created_by: <identity>,
  membership_policy: "admin_only" | "member_invite" | "open",
  encryption_mode: "per_member" | "shared_key" | "sender_key",
  sig: <signed by creator>
}

GroupEvent = {
  type: "add_member" | "remove_member" | "rotate_key" | "change_admin",
  group_id: <hash>,
  subject: <identity>,
  prev: <hash>,
  sig: <signed by admin>
}
```

### Public Messages

Signed but not encrypted. Anyone can read:

```
PublicMessage = {
  type: "public",
  sender: <identity hash>,
  recipient: "*",
  content: <payload>,
  reply_to: <message hash>,  // optional
  sig: <signed by sender>
}
```

### Forward Secrecy

Optional. Sender includes ephemeral key for forward secrecy when needed:

| Mode | Use case |
|------|----------|
| Static keys | Default, simple, works with DTN delays |
| Ephemeral keys | Opt-in when forward secrecy matters |

Ephemeral key exchange requires overhead, may not complete in high-latency scenarios.

### Receipts

Optional, sender-requested, recipient may ignore:

```
DeliveryAck = {
  message_id: <hash>,
  recipient: <identity>,
  received_at: <timestamp>,
  sig: <signed by recipient>
}

ReadReceipt = {
  message_id: <hash>,
  recipient: <identity>,
  read_at: <timestamp>,
  sig: <signed by recipient>
}
```

### Transit Reports

For debugging delivery issues. Optional, may be ignored:

```
TransitReport = {
  message_id: <hash>,
  hops: [
    {node: <identity>, received: <timestamp>, forwarded: <timestamp>},
    ...
  ],
  sig: <signed by reporter>
}
```

### Threading

Simple parent reference. Clients reconstruct threads locally:

```
reply_to: <message hash>  // optional
```

## Content Layer

MIME-style content containers. Leverage existing standards and tooling.

### Content Structure

```
Content = {
  content_type: "text/plain",  // any MIME type
  content_encoding: "utf-8" | "base64",
  content_disposition: "inline" | "attachment",
  filename: "document.pdf",  // optional
  body: <content>
}
```

Any MIME type allowed. Clients decide what to render/handle.

### Multipart Content

```
MultipartContent = {
  content_type: "multipart/mixed" | "multipart/alternative" | "multipart/related",
  parts: [
    {content_type: "text/plain", body: "..."},
    {content_type: "text/html", body: "..."},
    {content_type: "application/pdf", filename: "doc.pdf", body: <base64>}
  ]
}
```

| Multipart type | Use |
|----------------|-----|
| `mixed` | Message with attachments |
| `alternative` | Same content, different formats (plain + HTML) |
| `related` | HTML with inline images |

### Content Addressing

All content is hash-addressable:

```
content_hash = hash(canonical(content))
```

Used for:
- Deduplication
- Integrity verification
- References (reply_to, edits, large content)

### Large Content (Chunked)

Content exceeding size threshold is split into manifest + chunks:

```
ContentManifest = {
  content_hash: <hash of full content>,
  content_type: "application/zip",
  total_size: 50000000,
  chunk_size: 65536,
  chunks: [
    {index: 0, hash: <hash>, size: 65536},
    {index: 1, hash: <hash>, size: 65536},
    ...
  ],
  sig: <signed by sender>
}

ContentChunk = {
  manifest_hash: <hash of manifest>,
  index: 0,
  data: <bytes>
}
```

**Verification:**
1. Receive manifest, verify sender signature
2. Fetch chunks independently (any order, any source)
3. Verify each chunk hash against manifest
4. Reassemble

**Benefits:**
- Partial/resumable fetch
- Multi-source fetch (different relays)
- Single signature covers all chunks
- Configurable chunk size

| Size | Strategy |
|------|----------|
| < threshold | Inline in message |
| ≥ threshold | Manifest + chunks |

Threshold configurable per node (default ~64KB).

### Edits and Versions

Content is immutable. Edits create new content referencing original:

```
Content = {
  ...
  edit_of: <original content hash>,
  version: 2,
  ...
}
```

Clients display latest version, may show edit history.

### Deletion Requests

Polite request, not enforceable:

```
DeleteRequest = {
  content_hash: <hash>,
  reason: "...",
  sig: <signed by author>
}
```

Relays and recipients may honor or ignore. Content may persist.

### Content Trust

Separate concern from identity trust. To be designed separately.

Potential dimensions:
- Authenticity (who created it)
- Quality/accuracy
- Safety (malicious content)

## Related Systems

| System | Approach |
|--------|----------|
| **PGP** | Master key + signing/encryption subkeys |
| **Signal** | Identity key + device prekeys |
| **Keybase** | Per-device keys, sigchain for rotation |
| **KERI** | Key Event Receipt Infrastructure - append-only log of key events |
| **DID methods** | Various, some support key rotation via signed updates |
| **Scuttlebutt** | Identity = pubkey hash, append-only feed |
