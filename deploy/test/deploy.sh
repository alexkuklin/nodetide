#!/bin/sh
# Copy the stack to a server and (re)start it there.
#
#   ./deploy.sh user@server                     # installs into ~/nodetide-test on the server
#   ./deploy.sh user@server --dir /opt/nodetide-test
#   ./deploy.sh user@server --dry-run           # show what would be copied, change nothing
#   ./deploy.sh user@server --down              # stop the stack there (data volumes are kept)
#
# Needs on the server: Docker with the compose plugin, and ssh access for that user. The build happens
# on the server, from the copied sources, so no registry is involved. Prepare .env with:
#   ./init.sh --domain example.org [--edge]
set -eu
cd "$(dirname "$0")"
ROOT=$(cd ../.. && pwd)

TARGET="${1:-}"; [ -n "$TARGET" ] || { sed -n '2,10p' "$0"; exit 2; }
shift
DIR="nodetide-test"; DRY=0; DOWN=0
while [ $# -gt 0 ]; do
    case "$1" in
        --dir) DIR="$2"; shift 2 ;;
        --dry-run) DRY=1; shift ;;
        --down) DOWN=1; shift ;;
        *) echo "unknown option $1" >&2; exit 2 ;;
    esac
done

[ -f .env ] || { echo "no .env: run ./init.sh --domain example.org first" >&2; exit 1; }
grep -q '^ALLOW_INSECURE=0' .env || echo "warning: .env is a LOCAL setup (plain http); a public server needs ./init.sh --domain ..." >&2
grep -q '^ANCHORS_DIR=./.smoke' .env && { echo ".env still trusts the synthetic smoke-test CA; remove ANCHORS_DIR and EIDAS_REVOCATION=off first" >&2; exit 1; }

if [ "$DOWN" = 1 ]; then
    exec ssh "$TARGET" "cd '$DIR/deploy/test' && docker compose down"
fi

RSYNC="rsync -az --delete --human-readable"
[ "$DRY" = 1 ] && RSYNC="$RSYNC --dry-run --itemize-changes"

echo "copying to $TARGET:$DIR ..."
ssh "$TARGET" "mkdir -p '$DIR/deploy/test' '$DIR/python' '$DIR/web' && chmod 700 '$DIR/deploy/test'"
$RSYNC "$ROOT/python/src" "$ROOT/python/pyproject.toml" "$TARGET:$DIR/python/"
$RSYNC "$ROOT/web/" "$TARGET:$DIR/web/"
$RSYNC "$ROOT/README.md" "$TARGET:$DIR/"
# the stack itself; the smoke-test material never goes to a server, secrets travel only over ssh
$RSYNC --exclude '.smoke' --exclude '__pycache__' ./ "$TARGET:$DIR/deploy/test/"

[ "$DRY" = 1 ] && { echo "(dry run: nothing changed on the server)"; exit 0; }

COMMIT=$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)
echo "building and starting on the server (commit $COMMIT) ..."
ssh "$TARGET" "cd '$DIR/deploy/test' && GIT_COMMIT=$COMMIT docker compose up -d --build --remove-orphans && docker compose ps"

. ./.env
echo
echo "node:    $NODE_URL   (explorer: $NODE_URL/explorer/)"
echo "rp:      $RP_URL"
echo "grafana: $GRAFANA_URL   (\"Sign in with Nodetide\"; local admin password is GRAFANA_ADMIN_PASSWORD in .env)"
echo "verifier: $VERIFIER_URL   (independent email verification service; codes are mailed, see README for the mailbox)"
echo "wallet:  $WALLET_URL   (user 'wallet'; password is WALLET_PASSWORD in .env)"
echo "mailbox: ssh -L 4573:127.0.0.1:4573 $TARGET   then open http://localhost:4573   (the verifier's mail, unless SMTP_HOST is set)"
echo "check:   ./smoke.py run   (after ./smoke.py prepare for the eID path; remove that setup again afterwards)"
