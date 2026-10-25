# Nodetide

A distributed identity and messaging system with multiple language implementations.

## Overview

Nodetide is a decentralized identity system built on cryptographic sigchains. It provides:

- **Self-sovereign identity**: Users control their own cryptographic keys
- **Sigchain-based verification**: All identity operations are cryptographically linked
- **Multi-device support**: Add/revoke devices with full audit trail
- **Social recovery**: Recover access through trusted contacts
- **Claims and attestations**: Holders make claims (email, phone, legal name); issuers attest them; relying parties decide whom to trust
- **DTN Transport**: Pluggable convergence layer adapters for delay-tolerant networks

## Architecture

The project supports multiple backend implementations sharing a common web client:

```
Nodetide/
├── python/              # Python implementation (aiohttp)
│   ├── src/Nodetide/  # Source code
│   ├── tests/           # Test suite
│   ├── Dockerfile
│   └── pyproject.toml
├── golang/              # Go implementation (chi router)
│   ├── main.go
│   ├── Dockerfile
│   └── go.mod
├── web/                 # Shared web client (Alpine.js)
│   ├── index.html
│   ├── js/
│   └── css/
├── .github/workflows/   # CI/CD pipelines
├── identity-system.md   # Protocol specification
└── README.md
```

### Language Implementations

| Implementation | Status | Port | Subdomain |
|---------------|--------|------|-----------|
| Python | Complete | 4560 | python.dblog.kuklin.eu |
| Go | Stub/Template | 4561 | golang.dblog.kuklin.eu |

Each implementation:
- Serves the same web client from `/web`
- Exposes identical REST API at `/api/*`
- Uses port 4557 internally (mapped to unique host ports)
- Stores data in `/data` volume

## Quick Start

### Running Locally

**Python:**
```bash
cd python
pip install -e .
python -m Nodetide.cli.main api start --port 4557
```

**Go:**
```bash
cd golang
go run .
```

**Docker (Python):**
```bash
docker build -f python/Dockerfile -t Nodetide:python .
docker run -p 4557:4557 -v Nodetide-data:/data Nodetide:python
```

**Docker (Go):**
```bash
docker build -f golang/Dockerfile -t Nodetide:golang .
docker run -p 4557:4557 -v Nodetide-data:/data Nodetide:golang
```

### Accessing the Web UI

Open http://localhost:4557 in your browser.

## CLI Commands (Python)

```bash
# Identity management
Nodetide identity create [--name NAME]
Nodetide identity list
Nodetide identity show [IDENTITY_HASH]
Nodetide identity add-device --label "Phone"
Nodetide identity set-recovery --trustees A,B,C --threshold 2

# Trust assertions
Nodetide trust delegate IDENTITY --weight 0.8 [--scope legal_name,email]
Nodetide trust show IDENTITY

# Messaging
Nodetide message send RECIPIENT --text "Hello"
Nodetide message list

# API server
Nodetide api start [--host HOST] [--port PORT] [--web-root PATH]
```

## API Reference

All implementations expose the same REST API:

### Identity Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/identities` | Create identity with genesis event |
| GET | `/api/identities` | List known identities |
| GET | `/api/identities/{hash}` | Get identity details |
| GET | `/api/identities/{hash}/sigchain` | Get full sigchain |
| POST | `/api/identities/{hash}/events` | Submit signed event |
| GET | `/api/identities/{hash}/devices` | List active devices |

### Sessions

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/session` | Create authenticated session |
| GET | `/api/session` | Check session status |
| DELETE | `/api/session` | Invalidate session |

### Native SSO

Challenge/response login for third-party services. See "Authentication (SSO)" in [identity-system.md](identity-system.md).

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/challenge` | Issue an `AUTH_REQUEST` (nonce bound to an audience) |
| POST | `/api/auth/verify` | Verify an `AUTH_ASSERTION`; body `{assertion, sigchain?}` |
| POST | `/api/auth/login` | Verify an assertion for this node and open a session (Python only) |

- `NODETIDE_AUTH_AUDIENCE` sets this node's own origin: the default `aud` for challenges and the only audience `login` accepts.
- Only device keys holding the `authenticate` capability can sign assertions; the master key cannot.
- The Go node has no identity store yet, so `sigchain` is required on `verify` there and `login` is not available.
- `/api/session` and `/api/auth/token` predate this flow (no audience, no nonce) and are kept for existing clients.

### Claims and attestations

An identity can make **claims** about itself (`email`, `phone`, `legal_name`); third parties issue **attestations** that they verified a claim; whoever relies on a claim decides whom to trust. Only a salted commitment goes on the sigchain, so claim values never become public unless the holder publishes them. Full design: "Claims and Attestations" in [identity-system.md](identity-system.md).

```bash
nodetide claim add --type legal_name --given Maria --family Ivanova   # value stays in ~/.nodetide/claims/
nodetide claim list
nodetide claim revoke CLAIM_ID
```

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/identities/{hash}/claims` | Claims on the chain, attestations, published values (if any) |
| POST | `/api/claims/documents` | Publish or unpublish a claim's value (signed by the holder) |
| POST | `/api/attestations` | Store an issuer-signed attestation |
| GET | `/api/attestations?subject=&claim_id=&issuer=` | Query attestations |
| POST | `/api/attestations/revocations` | Issuer withdraws an attestation |
| POST | `/api/claims/verify` | Stateless check of any attestation, optionally against a disclosed value |

**Email verification** (assurance `low`) is a separate, independent service, never part of a node: `python -m nodetide.verifiers.service --port 4558` with `NODETIDE_VERIFIER_URL` (its public origin), `NODETIDE_VERIFIER_HOME` (state: its own database and issuer keys), `NODETIDE_SMTP_HOST` (+ `_PORT`, `_USER`, `_PASSWORD`, `_SECURITY=starttls|ssl|none`), `NODETIDE_EMAIL_FROM`, optionally `NODETIDE_ISSUER_NAME`; `NODETIDE_EMAIL_DEV_LOG=1` logs codes instead of sending mail (development). It creates its own issuer identity (`GET /api/verify/issuer`, which includes the issuer's sigchain) and `NODETIDE_VERIFIER_PUBLISH_ISSUER=FILE` writes the identity hash for the operator to pin. Flow: `POST /api/auth/challenge`, sign an assertion whose claims are `{"purpose": "claim_verification", "claim_id": ...}`, `POST /api/verify/email/start` with the claim document and the holder's sigchain, then `POST /api/verify/email/confirm` with the code the person types from the email. Nobody trusts the service by default: a bridge accepts its attestations only when its identity hash is in `NODETIDE_OIDC_EMAIL_ISSUERS`.

**eID / qualified e-signature** (assurance up to `high`): the holder signs a statement with an electronic signature made with a qualified certificate; relying parties check it against CA certificates they trust (`NODETIDE_EIDAS_ANCHORS=<directory of PEM/DER CA certificates>`, `NODETIDE_EIDAS_REVOCATION=hard-fail|soft-fail|off`).

```bash
# with the signing application your eID provider gives you:
nodetide eid statement CLAIM_ID                 # writes statement-<id>.txt, sign it as detached CAdES (.p7s)
nodetide eid attach CLAIM_ID statement-<id>.txt statement-<id>.txt.p7s

# or straight from a PKCS#11 token (pip install 'nodetide[eid]'); the PIN is only ever typed at the prompt:
nodetide eid tokens
nodetide eid sign CLAIM_ID

nodetide eid chain attestation-<id>.json        # which CAs signed it
nodetide eid verify attestation-<id>.json --anchors DIR --document claim.json
```

An attestation made this way **contains your certificate, with personal identifiers**. Nodes refuse to store or publish it; give it only to the party you want to prove the claim to.

### Explorer

A read-only, block-explorer-style view of the public information a node knows: identities and their sigchains (keys, devices, recovery trustees, every event), public messages with signature checks, trust delegations, and relay subscriptions.

- **UI:** `/explorer` on any node that serves the web client. Search by name or by the start of an identity, event or message hash.
- **Another node:** `/explorer/?node=https://relay.example.org` browses that node's API instead (it allows cross-origin reads). Use this for relays, whose image ships no web files.
- **API:** `GET /api/explorer/{stats,identities,identities/{hash},events,events/{hash},messages,messages/{hash},trust/delegations,search,network}`; lists take `limit` (max 100) and `offset`.
- **Never shown:** private keys, sessions, recovery requests in progress, challenges, and any message that is not public.
- **Messages from other nodes are not verified when stored,** so the explorer checks each public message's signature against the sender's current keys when you open it.
- **Switch it off** with `NODETIDE_EXPLORER=0`. Existing databases are indexed automatically on first start.
- The Go node serves the UI but has no explorer API yet, so the page says so.

### OIDC Bridge (Python)

Lets any Nodetide identity sign in to standard OIDC applications (Keycloak-style authorization-code flow with PKCE, RS256 `id_token`). Disabled unless `NODETIDE_OIDC_ISSUER` is set.

| Variable | Purpose |
|----------|---------|
| `NODETIDE_OIDC_ISSUER` | Public https origin of this node, e.g. `https://dblog.kuklin.eu` (enables the bridge) |
| `NODETIDE_OIDC_CLIENTS_FILE` | JSON list of registered applications (see below) |
| `NODETIDE_OIDC_KEY_FILE` | RSA signing key; defaults to `oidc_signing_key.pem` beside the database and is created on first start |
| `NODETIDE_SEED_NODES` | Comma-separated node URLs asked for identities this node doesn't know |
| `NODETIDE_FETCH_ALLOW_PRIVATE` | `1` to let the fetcher reach private/loopback addresses (LAN or development only) |
| `NODETIDE_OIDC_TRUSTED_ISSUERS` | Comma-separated identity hashes trusted to attest `email`, `phone` and `legal_name`. Nothing is trusted unless named, including anything running beside the node |
| `NODETIDE_OIDC_EMAIL_ISSUERS` | Comma-separated identity hashes trusted to attest `email` only, e.g. an independent verification service |
| `NODETIDE_OIDC_NAME_MATCH` | `exact`, `transliterated` (default) or `approximate`: how loosely a legal name may differ from an eID certificate |

Clients file (omit `client_secret_sha256` for public clients, which must use PKCE; PKCE is accepted for all):

```json
[{"client_id": "grafana", "name": "Grafana",
  "redirect_uris": ["https://grafana.example.com/login/generic_oauth"],
  "client_secret_sha256": "<sha256 hex of the secret>"}]
```

Point the application at `https://<issuer>/.well-known/openid-configuration`. Endpoints: `/oidc/authorize`, `/oidc/token`, `/oidc/userinfo`, `/oidc/jwks.json`. The `sub` claim is the identity hash.

**Verified claims.** Applications get more than an identity hash when they ask for it by scope: `profile` returns the verified legal name (`name`, `given_name`, `family_name`, `name_verified`, plus an OpenID Connect for Identity Assurance `verified_claims` block naming the trust framework, e.g. `eidas`), `email` returns `email` and `email_verified`, `phone` returns `phone_number`. Nothing is released that the scope did not ask for, and only claims backed by an attestation this bridge accepts: its own email verifier, an eIDAS qualified-signature proof (if `NODETIDE_EIDAS_ANCHORS` is set; legal names need `high` assurance), or an issuer in `NODETIDE_OIDC_TRUSTED_ISSUERS`. The user's app chooses what to reveal: the challenge lists what is acceptable (`display.claims_requested`) and the app sends `presentations` (claim document + attestation) with its assertion; the response says what was released or rejected, never the values. Without a verified name, `profile` falls back to the identity's own display name with `name_verified: false`.

Identities the node doesn't know yet are fetched in the background and the user sees a "failed for now, try again later" message; see "Authentication (SSO)" in [identity-system.md](identity-system.md). Run a single instance: attempts, codes and tokens are held in memory.

### Recovery

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/identities/{hash}/recovery/initiate` | Start recovery process |
| POST | `/api/identities/{hash}/recovery/{id}/sign` | Submit trustee signature |
| GET | `/api/identities/{hash}/recovery/{id}` | Check recovery status |
| GET | `/api/identities/{hash}/recovery/pending` | List pending recoveries |

### Trust Network

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/trust/delegations` | Create trust delegation |
| GET | `/api/trust/delegations?from={hash}` | Query delegations |
| GET | `/api/trust/calculate/{hash}?claim_type=` | Trust in an attestation issuer via delegation paths |

### Utilities

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/verify` | Verify a sigchain |
| GET | `/api/lookup/{hash}` | Lookup identity |
| GET | `/health` | Health check endpoint |

## Deployment

### Infrastructure Overview

The production deployment uses:

- **Hetzner Cloud**: CAX11 VPS (ARM64, 2 vCPU, 4GB RAM, Debian 12)
- **AWS ECR**: Docker image registry
- **GitHub Actions**: CI/CD pipelines
- **Nginx**: Reverse proxy with SSL termination
- **Zero-SSL**: Wildcard certificate via Hetzner DNS validation

```
┌─────────────────────────────────────────────────────────────┐
│                    Hetzner VPS                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    Nginx                             │   │
│  │  *.dblog.kuklin.eu:443 (SSL) → localhost:$port      │   │
│  └─────────────────────────────────────────────────────┘   │
│           │                           │                     │
│           ▼                           ▼                     │
│  ┌─────────────────┐         ┌─────────────────┐           │
│  │ Nodetide-python│         │ Nodetide-golang│           │
│  │    :4560        │         │    :4561        │           │
│  └─────────────────┘         └─────────────────┘           │
└─────────────────────────────────────────────────────────────┘
```

### DNS Configuration

| Record | Type | Value |
|--------|------|-------|
| `dblog.kuklin.eu` | A/AAAA | VPS IP |
| `*.dblog.kuklin.eu` | A/AAAA | VPS IP |

Subdomains route to implementations:
- `dblog.kuklin.eu` → Python (default)
- `python.dblog.kuklin.eu` → Python
- `golang.dblog.kuklin.eu` → Go

### CI/CD Pipeline

On push to `main`:

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Checkout   │────▶│  Build Matrix│────▶│    Deploy    │
│              │     │  - python    │     │  - python    │
│              │     │  - golang    │     │  - golang    │
└──────────────┘     └──────────────┘     └──────────────┘
                            │
                            ▼
                     ┌──────────────┐
                     │   Push ECR   │
                     │ :variant-latest│
                     │ :variant-sha │
                     └──────────────┘
```

1. **Build Job** (parallel matrix):
   - Builds `python/Dockerfile` → `Nodetide:python-latest`
   - Builds `golang/Dockerfile` → `Nodetide:golang-latest`
   - Pushes to AWS ECR with tags: `{variant}-latest`, `{variant}-{sha}`
   - Multi-arch: `linux/amd64`, `linux/arm64`

2. **Deploy Job** (after build):
   - SSHes to VPS as `deploy-Nodetide` user
   - Runs `/usr/local/bin/deploy-Nodetide-wrapper.sh {variant}`
   - Pulls new image from ECR and restarts container

### Manual Deployment

```bash
# Deploy specific variant
ssh deploy-Nodetide@dblog.kuklin.eu \
    "sudo /usr/local/bin/deploy-Nodetide-wrapper.sh python"

# Deploy all variants
for v in python golang; do
    ssh deploy-Nodetide@dblog.kuklin.eu \
        "sudo /usr/local/bin/deploy-Nodetide-wrapper.sh $v"
done
```

### Infrastructure Management

Infrastructure is managed via Terraform in [Nodetide-infra](https://github.com/alexkuklin/Nodetide-infra):

```bash
# Plan changes
cd Nodetide-infra/terraform
terraform plan

# Apply changes
terraform apply
```

Or trigger via GitHub Actions → "Terraform Apply" workflow (manual dispatch).

**Key Resources:**
- `hcloud_server.Nodetide` - VPS instance
- `hcloud_zone_record.*` - DNS records (A, AAAA, wildcard)
- `aws_ecr_repository.Nodetide` - Container registry
- `aws_iam_role.github_actions` - OIDC role for CI/CD

## Adding a New Implementation

To add a new language implementation (e.g., Rust):

### 1. Create Directory Structure

```bash
mkdir -p rust/src
```

### 2. Implement the Server

The server must:
- Listen on port 4557 (configurable via `PORT` env var)
- Serve static files from embedded `/web` directory
- Implement REST API endpoints at `/api/*`
- Store data in `/data` directory

### 3. Create Dockerfile

```dockerfile
# rust/Dockerfile
FROM rust:1.75 AS builder
WORKDIR /build
COPY rust/ ./
COPY web/ ./web/
RUN cargo build --release

FROM debian:bookworm-slim
RUN useradd -m Nodetide
COPY --from=builder /build/target/release/Nodetide /app/
WORKDIR /app
USER Nodetide
EXPOSE 4557
CMD ["./Nodetide"]
```

### 4. Update Workflow Matrix

Edit `.github/workflows/docker-build.yml`:

```yaml
matrix:
  variant:
    - name: python
      dockerfile: python/Dockerfile
    - name: golang
      dockerfile: golang/Dockerfile
    - name: rust                    # Add new variant
      dockerfile: rust/Dockerfile
```

### 5. Update VPS Configuration

In `Nodetide-infra/terraform/hetzner_vps.tf`:

**Port mapping:**
```bash
declare -A PORTS=(
    ["python"]="4560"
    ["golang"]="4561"
    ["rust"]="4562"              # Add new port
)
```

**Nginx routing:**
```nginx
map $host $backend_port {
    default                         4560;
    "python.dblog.kuklin.eu"        4560;
    "golang.dblog.kuklin.eu"        4561;
    "rust.dblog.kuklin.eu"          4562;    # Add new route
    "dblog.kuklin.eu"               4560;
}
```

### 6. Apply Infrastructure

```bash
cd Nodetide-infra/terraform
terraform apply
```

The new implementation will be accessible at `rust.dblog.kuklin.eu`.

## Development

### Python Development

```bash
cd python
pip install -e ".[dev]"

# Run tests
pytest tests/

# Run with auto-reload
python -m Nodetide.cli.main api start --port 4557
```

**Code Structure:**
- `core/crypto.py` - Ed25519/X25519 key operations
- `core/identity.py` - Sigchain and event types
- `core/storage.py` - SQLite persistence
- `core/trust.py` - Trust graph calculations
- `api/routes.py` - REST API handlers
- `api/auth.py` - Session management
- `cli/main.py` - CLI entry point

### Go Development

```bash
cd golang
go mod download

# Run tests
go test ./...

# Run server
go run .
```

### Web Client Development

The web client uses Alpine.js and is served statically:

```bash
# Serve with Python backend
cd python
python -m Nodetide.cli.main api start --web-root ../web

# Or with any static server
cd web
python -m http.server 8080
```

## Security Considerations

- **Key Management**: Private keys never leave the client
- **Sigchain Integrity**: All operations cryptographically linked
- **Signature Verification**: All events verified before acceptance
- **Social Recovery**: Threshold scheme prevents single point of failure
- **Trust Decay**: Delegated trust scores decrease with depth
- **No Backdoors**: No master keys or recovery mechanisms controlled by operators

## Protocol Specification

See [identity-system.md](identity-system.md) for the complete protocol specification including:

- Event types and formats
- Signature schemes
- Sigchain verification rules
- Trust calculation algorithms
- Recovery protocols

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement changes with tests
4. Ensure CI passes
5. Submit a pull request

For protocol changes, update `identity-system.md` first and discuss in an issue.
