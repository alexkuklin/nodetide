# Changelog

Progress notes kept between sessions. Newest first. Each entry says what changed, why, and what is
still open, so a new session can pick up without re-deriving context.

## 2026-10-25 (latest) - signing testkit

### Added
- **`testkit/`** (scope deliberately limited to signing): `./testkit/run setup | selftest | token |
  claim | sign | anchors | verify | report | clean`. Isolated state in `.testkit/` via the new
  `NODETIDE_HOME` variable (the CLI's data directory), so `~/.nodetide` is never touched. `report` prints
  only technical facts (no names, ID numbers or hashes) and is the thing to paste when asking for help.
  The kit is itself tested (`python/tests/test_testkit.py`).
- `nodetide eid anchors ATTESTATION --out DIR` (`eidas/anchors.py`): follows the certificate's
  AIA links to collect the issuer chain, checks each certificate signed the one below, shows
  SHA-256 fingerprints and saves them as trust anchors only after interactive confirmation. Refuses
  private/loopback addresses unless `--allow-private`.

### Fixed
- Claim IDs could begin with `-`, so `nodetide claim ...` / `eid ...` parsed them as options. New
  claim IDs always start with a letter or digit.

### Scope note
- A broader testkit (demo node, simulated user app, simulated OIDC client, Go/UI runners) was started and
  removed at the owner's request: "only signing". If wanted later, the useful missing piece is a
  simulated user app, since no real client can yet approve OIDC sign-ins or verify an email claim.

## 2026-10-25 (later) - eID token tooling, name mapping, verified claims in OIDC

### Added
- **OIDC bridge releases verified claims** (`core/relying_party.py`, `oidc/provider.py`): scopes
  `profile`/`email`/`phone` map to `legal_name`/`email`/`phone` claims; the user's app sends
  `presentations` with its assertion; the bridge applies `ClaimRule`s (issuers, proof types,
  assurance, age, no recovery since) and returns standard claims plus an OpenID Connect for Identity
  Assurance `verified_claims` block. `display.claims_requested` in the challenge tells the app what
  is acceptable. Self-asserted genesis names are now labelled `name_verified: false`.
  Config: `NODETIDE_OIDC_TRUSTED_ISSUERS`, `NODETIDE_OIDC_NAME_MATCH`.
- **eID signing with PIN, rewritten against the real card** (`eidas/pkcs11.py`, `cli/claims.py`):
  slots and certificates are read without any PIN (`nodetide eid tokens`); the signing slot is chosen
  explicitly; the PIN is typed at a hidden prompt, tried once, never stored; locked / final-try /
  count-low states are checked first; keys that demand the PIN for every signature
  (`CKA_ALWAYS_AUTHENTICATE`) are handled with a context-specific login.
- **Certificate name mapping** (`eidas/certs.py`): givenName/surname plus the common name minus the
  surname (middle names, patronymics), and match strengths `exact` < `transliterated` <
  `approximate` (Alexey/Aleksey, Cyrillic vs Latin). `POST /api/claims/verify` takes `name_match`.

### Findings about the real token (no personal data)
- B-Trust (BORICA) card, Gemalto IDPrime MD, RSA 3072, SafeNet client libraries in `/usr/local/lib`
  (`libIDPrimePKCS11.dylib` is the default module). Certificate: qualified, QSCD, key usage
  content commitment, issued by "B-Trust Operational Qualified CA", subject has givenName, surname,
  serialNumber (national ID, never copied), CN with patronymic, and an email address.
- Two slots with separate PINs: slot 0 (authentication; certificate and public key visible, private
  key hidden before login) and slot 16 "(Digital Signature)". The qualified signing key is expected
  behind slot 16's PIN. Wrong PINs cost retries: nothing in the tool retries.
- The certificate carries an email address; verifying an `email` claim from it is possible later but
  qualified CAs do not necessarily prove mailbox control.

### Not yet done
- **Real signing has not been run**: needs the user's PIN. Expected: `eid tokens`, create a
  `legal_name` claim, `eid sign CLAIM_ID --slot 16`, `eid chain`, `eid verify --anchors DIR`
  with the B-Trust CA certificates from the provider.

## 2026-10-25 - Claims, attestations, OIDC bridge, explorer, native SSO

### Added
- **Native SSO** (`core/auth.py`, `api/auth/native.py`, `golang/auth/`): challenge/response login
  with `AuthRequest`/`AuthAssertion`, `authenticate` device capability, audience- and
  nonce-bound, domain-separated signatures. Python endpoints `/api/auth/{challenge,verify,login}`;
  the Go node has `challenge` and `verify` (sigchain must be supplied; no identity store yet).
  Python and Go agree byte-for-byte on canonical JSON and sigchain hashing (checked by a
  cross-language run, including claim events).
- **OIDC bridge** (`oidc/`): any Nodetide identity can sign in to standard OIDC apps
  (code flow + PKCE, RS256 id_token, `sub` = identity hash). Unknown or stale identities are queued
  in a persistent fetcher (`oidc/fetcher.py`, SSRF-guarded) and the user sees "failed for now".
  Enable with `NODETIDE_OIDC_ISSUER`; see README.
- **Explorer** (`explorer/`, `web/explorer/`): read-only API (`/api/explorer/*`) and a
  dependency-free UI at `/explorer` (`?node=` browses another node). Search index tables are kept
  up to date by `Storage.save_sigchain`; existing DBs are backfilled on open. `NODETIDE_EXPLORER=0`
  disables it.
- **Claims and attestations** replace `IdentityAssertion` (see spec section "Claims and
  Attestations"):
  - Sigchain events `ADD_CLAIM` / `REVOKE_CLAIM` (master or device with `manage_claims`), strict
    rules in `Sigchain.verify` and mirrored in Go (`golang/auth/sigchain.go`).
  - `core/claims.py`: salted commitments, value normalization, `ClaimDocument`, `Attestation`,
    `AttestationRevocation`, verification. Pinned commitment test vectors.
  - API `api/claims.py`: claims listing, signed publish/unpublish of claim documents,
    attestations, revocations, stateless `POST /api/claims/verify`.
  - **Email verification** (`verifiers/`): node-owned issuer identity (device key with
    `sign_identity`), SMTP / dev-log / memory mail senders, rate limits, single-use codes.
  - **eIDAS qualified e-signature proofs** (`eidas/`): CAdES-BES build/parse, QCStatements,
    certificate path validation (two-phase so strangers' certificates cannot make the node fetch
    URLs), Bulgarian name transliteration, PKCS#11 signer. Proof attestations are never stored or
    published because the embedded certificate carries personal identifiers.
  - CLI: `nodetide claim add|list|revoke|export`, `nodetide eid statement|attach|sign|tokens|chain|verify`.
- Trust delegations gained a claim-type `scope`; `GET /api/trust/calculate/{hash}?claim_type=`
  now computes path trust to an attestation issuer.

### Removed
- `IdentityAssertion`, `trust_assertions` table (dropped on open), `/api/trust/assertions`,
  `nodetide trust assert`, the web client's assertion UI. No migration: nothing was in use.

### Fixed
- `/api/auth/token` (legacy) called `Sigchain.from_events`, which does not exist.

### Verification at time of writing
- Python: full suite passes (`PYTHONPATH=src:. pytest tests`).
- Go: `gofmt`, `go vet`, `go test ./auth/` pass; cross-language run against the live Go server passes.
- Explorer UI exercised in jsdom against a seeded live node (no browser errors).
- **Not tested on real hardware or real credentials:** the PKCS#11 signer (only against a fake
  token), real Bulgarian eID certificates and trust anchors, real SMTP delivery.

### Open / next
- Try the real eID token: `nodetide eid tokens` then `eid sign`, or `eid statement` + the provider's
  signing app + `eid attach`; then `eid chain` / `eid verify` with the provider's CA certificates.
  Tokens whose key needs the PIN for every signature (`CKA_ALWAYS_AUTHENTICATE`) are not handled yet.
- No client UI yet (web, Android) for claims, signing assertions, or answering OIDC sign-ins; the
  OIDC bridge and email verifier are only exercised through the API and tests.
- OIDC bridge does not yet put verified claims (`name`, `email`) into id_tokens.
- Relying-party policy evaluation (`evaluate claim` in the spec) is described but only the pieces
  (`verify_attestation`, `/api/claims/verify`, trust path calculation) exist.
- The Go node has no identity store, sessions, OIDC bridge or explorer API.
- Python's `Sigchain.verify` accepts `social_recovery` without checking the trustee threshold (old
  TODO); Go rejects such chains.
- Sessions, challenges, OIDC attempts and pending email codes are in memory: run a single instance.
- Trusted-list handling for eIDAS is manual (operator supplies CA certificates); no CAdES-T
  timestamp checking, so proof attestations are kept short-lived.
- `golang/` has no `go.sum`; the Dockerfile resolves modules at build time.

### Working notes for the next session
- Tests: create a venv with the project dependencies plus `pytest pytest-asyncio`, then
  `cd python && PYTHONPATH=src:. pytest tests`. Go: `cd golang && go test ./auth/`.
- Tests that need PKI use the synthetic CA in `python/tests/pki.py`; never commit real certificates
  or signature files (they contain national ID numbers).
- Editing tools in this environment decoded `\uXXXX` escape sequences written in files; build such
  strings from a placeholder instead (see the canonical-JSON golden tests).
