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

# Pin the independent verification service's issuer identity (public hash, written by the verifier container).
# That one identity attests email and phone; the node trusts it for those two claim types and nothing else.
if [ -z "${NODETIDE_OIDC_EMAIL_ISSUERS:-}" ] && [ -s /issuer/email-issuer ]; then
    ISSUER=$(tr -d '[:space:]' < /issuer/email-issuer)
    export NODETIDE_OIDC_EMAIL_ISSUERS="$ISSUER"
    export NODETIDE_OIDC_PHONE_ISSUERS="${NODETIDE_OIDC_PHONE_ISSUERS:-$ISSUER}"
    echo "email and phone attestations trusted from issuer $ISSUER"
else
    echo "email attestations trusted from: ${NODETIDE_OIDC_EMAIL_ISSUERS:-nobody}; phone: ${NODETIDE_OIDC_PHONE_ISSUERS:-nobody}"
fi

exec python -m nodetide.cli.main api start --host 0.0.0.0 --port 4557
