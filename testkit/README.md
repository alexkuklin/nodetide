# Signing testkit

Try the eID claim-signing flow end to end, safely. It works with your own card, and the
offline self-test needs none.

What it guarantees:

- **Isolated.** It uses its own Nodetide data directory in `.testkit/` (git-ignored) via
  `NODETIDE_HOME`. Your real `~/.nodetide` is never read or written.
- **No PIN handling.** The PIN is typed only at the prompt of `nodetide eid sign`. The kit
  never sees, stores or logs it. A wrong PIN is never retried.
- **Nothing personal in what you share.** `report` prints only technical facts about the
  certificate and the verification outcome: no names, no ID numbers, no identity hashes.
  Never share `.testkit/out/` (it holds your certificate) or paste an attestation file.

## Steps

```sh
./testkit/run setup        # once: virtualenv with nodetide, pytest and PyKCS11
./testkit/run selftest     # signing code against a synthetic CA and a fake card; no card needed
./testkit/run token        # slots, PIN state and certificates of the inserted card (no PIN)
./testkit/run claim --given GIVEN --family FAMILY    # names exactly as on your certificate
./testkit/run sign         # shows the statement, then asks which slot and for the PIN
./testkit/run anchors      # fetches the CA chain; compare fingerprints, then confirm
./testkit/run verify       # verifies like a relying party (needs network for revocation)
./testkit/run report       # the shareable summary
./testkit/run clean        # remove the test identity and attestation (--all: virtualenv too)
```

### Notes on the card

- Cards such as the B-Trust / Gemalto IDPrime have **several slots, each with its own PIN**.
  `token` shows them. The qualified signature normally needs the *digital signature* PIN
  (the slot labelled "(Dig..."), not the authentication PIN.
- `sign` shows the exact statement and which slot it will log in to, and asks for confirmation
  before the PIN prompt. If the slot reports one attempt left, it says so and asks again.
- Qualified keys usually want the PIN again for the signature itself, so expect two prompts.
- If `sign` says the key is not on the chosen slot, try the other slot. Each wrong PIN costs
  an attempt, so stop and look at `token` rather than guessing.

### Trust anchors

`verify` needs the CA certificates behind your signature. `anchors` follows the
certificate's own download links and shows each fingerprint; **compare them with the ones
your eID provider publishes** before confirming, because a downloaded certificate is only
as trustworthy as that check.

If the download fails, put the provider's CA certificates (PEM or DER) into
`.testkit/anchors/` yourself.

### If something fails

| Symptom | Likely cause |
|---|---|
| `No PKCS#11 module found` | Pass `--module /path/to/library` (SafeNet: `/usr/local/lib/libIDPrimePKCS11.dylib`) |
| `name does not match` | `claim` was given a different spelling than the certificate; `report --leniency approximate` shows if it is only a spelling variant |
| `untrusted_certificate` | The anchors do not cover this chain; run `anchors` again or add the provider's root |
| revocation `FAIL` but chain OK | The provider's OCSP/CRL could not be reached or did not answer; retry with `--revocation soft-fail` to separate the two |

The kit's own behaviour is tested by `python/tests/test_testkit.py`, which `selftest` runs too.
