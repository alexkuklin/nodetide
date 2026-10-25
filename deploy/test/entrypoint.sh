#!/bin/sh
# Starts the node. The node verifies nobody and never sees a certificate: eID attestations come from the
# verification service acting as a notary, and the node only believes the issuer it is told to.
set -eu

# Pin the independent verification service's issuer identity (public hash, written by the verifier container).
# That one identity attests email, phone and (as eID notary) legal name, birth date and age; the node trusts it for those and nothing else.
if [ -z "${NODETIDE_OIDC_EMAIL_ISSUERS:-}" ] && [ -s /issuer/email-issuer ]; then
    ISSUER=$(tr -d '[:space:]' < /issuer/email-issuer)
    export NODETIDE_OIDC_EMAIL_ISSUERS="$ISSUER"
    export NODETIDE_OIDC_PHONE_ISSUERS="${NODETIDE_OIDC_PHONE_ISSUERS:-$ISSUER}"
    export NODETIDE_OIDC_NOTARY_ISSUERS="${NODETIDE_OIDC_NOTARY_ISSUERS:-$ISSUER}"
    echo "email, phone and eID-derived attestations trusted from issuer $ISSUER"
else
    echo "email attestations trusted from: ${NODETIDE_OIDC_EMAIL_ISSUERS:-nobody}; phone: ${NODETIDE_OIDC_PHONE_ISSUERS:-nobody}"
fi

exec python -m nodetide.cli.main api start --host 0.0.0.0 --port 4557
