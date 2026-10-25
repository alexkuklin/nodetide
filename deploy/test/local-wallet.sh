#!/bin/sh
# Run the test wallet on THIS machine against a remote node. The wallet's keys stay here; it only
# makes outbound HTTPS calls to the node, so nothing on the server changes.
#
#   ./local-wallet.sh https://nt-node.example.org [--tunnel user@server] [--port 4572]
#
# --tunnel opens ssh -L 4573 to the server's test mailbox, which the wallet reads to finish email
# verification. State (keys, attestations) lives in .local-wallet/ (git-ignored); the HTTP password
# is generated once and printed. Open http://localhost:4572 (user: wallet).
set -eu
cd "$(dirname "$0")"
ROOT=$(cd ../.. && pwd)

NODE="${1:-}"; [ -n "$NODE" ] || { sed -n '2,9p' "$0"; exit 2; }
shift
TUNNEL=""; PORT=4572
while [ $# -gt 0 ]; do
    case "$1" in
        --tunnel) TUNNEL="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        *) echo "unknown option $1" >&2; exit 2 ;;
    esac
done

STATE=.local-wallet
mkdir -p "$STATE/data"; chmod 700 "$STATE"
if [ ! -d "$STATE/venv" ]; then
    python3 -m venv "$STATE/venv"
    "$STATE/venv/bin/pip" install -q "$ROOT/python"
fi
if [ ! -f "$STATE/password" ]; then
    python3 -c 'import secrets;print(secrets.token_urlsafe(18))' > "$STATE/password"
    chmod 600 "$STATE/password"
fi

if [ -n "$TUNNEL" ]; then
    ssh -N -L 127.0.0.1:4573:127.0.0.1:4573 "$TUNNEL" &
    trap 'kill $! 2>/dev/null' EXIT INT TERM
fi

echo "wallet:   http://localhost:$PORT   (user: wallet, password: $(cat "$STATE/password"))"
echo "node:     $NODE"
[ -n "$TUNNEL" ] && echo "mailbox:  http://localhost:4573 (tunnel to $TUNNEL)"
NODE_URL="$NODE" WALLET_URL="http://localhost:$PORT" MAILPIT_URL="http://127.0.0.1:4573" \
WALLET_PASSWORD="$(cat "$STATE/password")" DATA_DIR="$PWD/$STATE/data" HOST=127.0.0.1 PORT="$PORT" \
    "$STATE/venv/bin/python" wallet/app.py
