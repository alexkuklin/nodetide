#!/bin/sh
# Starts the node. eID proof verification is switched on only when trust anchors are present:
# the verifier refuses to start with an empty anchors directory.
set -eu

if [ -d /anchors ] && [ -n "$(ls -A /anchors 2>/dev/null | grep -v '^\.gitkeep$' || true)" ]; then
    export NODETIDE_EIDAS_ANCHORS=/anchors
    echo "eID proof verification: ON ($(ls /anchors | grep -c -v '^\.gitkeep$') trust anchor files, revocation=${NODETIDE_EIDAS_REVOCATION:-hard-fail})"
else
    echo "eID proof verification: OFF (put CA certificates in deploy/test/anchors/ to enable)"
fi

exec python -m nodetide.cli.main api start --host 0.0.0.0 --port 4557
