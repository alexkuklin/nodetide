#!/bin/sh
# Starts the verification service. The eID notary is switched on only when trust anchors are present:
# the service refuses to start the notary with an empty anchors directory.
set -eu

if [ -d /anchors ] && [ -n "$(ls -A /anchors 2>/dev/null | grep -v '^\.gitkeep$' || true)" ]; then
    export NODETIDE_EIDAS_ANCHORS=/anchors
    echo "eID notary: ON ($(ls /anchors | grep -c -v '^\.gitkeep$') trust anchor files, revocation=${NODETIDE_EIDAS_REVOCATION:-hard-fail})"
else
    echo "eID notary: OFF (put CA certificates in deploy/test/anchors/ to enable)"
fi

exec python -m nodetide.verifiers.service --host 0.0.0.0 --port 4558
