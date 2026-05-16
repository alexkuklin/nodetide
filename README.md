# Nodetide

A distributed identity and messaging system with multiple language implementations.

## Overview

Nodetide is a decentralized identity system built on cryptographic sigchains. It provides:

- **Self-sovereign identity**: Users control their own cryptographic keys
- **Sigchain-based verification**: All identity operations are cryptographically linked
- **Multi-device support**: Add/revoke devices with full audit trail
- **Social recovery**: Recover access through trusted contacts
- **Trust network**: Web-of-trust style identity assertions
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
Nodetide trust assert IDENTITY --name "Bob" --confidence 0.9
Nodetide trust delegate IDENTITY --weight 0.8
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
| POST | `/api/trust/assertions` | Create identity assertion |
| GET | `/api/trust/assertions?subject={hash}` | Query assertions |
| POST | `/api/trust/delegations` | Create trust delegation |
| GET | `/api/trust/delegations?from={hash}` | Query delegations |
| GET | `/api/trust/calculate/{hash}` | Calculate transitive trust |

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
