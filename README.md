# Distriblog

Distributed identity and messaging system for delay-tolerant networks.

## Features

- **Sigchain-based Identity**: Append-only log of signed events for identity management
- **Master/Device Key Hierarchy**: Ed25519 signing with X25519 encryption
- **Social Recovery**: Threshold-based key recovery via trusted contacts
- **Trust Model**: Identity assertions and transitive trust delegation
- **DTN Transport**: Pluggable convergence layer adapters (TCP/mDNS, Bluetooth, LoRa, etc.)
- **Web Client**: Browser-based interface with WebAuthn/passkey support

## Installation

```bash
pip install distriblog
```

## Quick Start

```bash
# Create an identity
distriblog identity create --name "Alice"

# Start the API server
distriblog api start --public --web-root ./web

# Or use Docker
docker-compose up -d
```

## CLI Commands

```bash
# Identity management
distriblog identity create [--name NAME]
distriblog identity list
distriblog identity show [IDENTITY_HASH]
distriblog identity add-device --label "Phone"
distriblog identity set-recovery --trustees A,B,C --threshold 2

# Trust assertions
distriblog trust assert IDENTITY --name "Bob" --confidence 0.9
distriblog trust delegate IDENTITY --weight 0.8
distriblog trust show IDENTITY

# Messaging
distriblog message send RECIPIENT --text "Hello"
distriblog message list

# API server
distriblog api start [--host HOST] [--port PORT] [--web-root PATH]
```

## Docker

```bash
# Build and run
docker-compose up -d

# Check health
curl http://localhost:4557/health
```

## Architecture

```
distriblog/
├── core/           # Crypto, identity, storage, trust
├── transport/      # Bundle format, CLAs, relay
├── messaging/      # Private/group messages, encryption
├── content/        # MIME handling, chunking
├── api/            # REST API server
├── cli/            # Command-line interface
└── daemon/         # Background relay service
```

## License

MIT
