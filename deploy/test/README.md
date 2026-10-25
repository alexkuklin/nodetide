# Nodetide test stack

A docker-compose deployment for testing the whole thing on a server, with a real, independent
OIDC client in front of it. Nothing here is production: the wallet holds a development identity
in plain JSON and the mailbox is a catch-all.

```
browser ──► rp (oauth2-proxy) ──► "Signed in" page (shows the claims it received)
   │            │ standard OIDC: discovery, PKCE, client secret, RS256 id_token
   │            ▼
   ├──────► node (Nodetide: OIDC bridge, email verifier, eID proof verifier, explorer)
   │            │ verification codes by SMTP
   │            ▼
   │         mailpit (catches the emails; nothing is ever delivered)
   └──────► wallet (stands in for the Nodetide app: identity, claims, signs-in on your behalf)
```

| Service | What it is | Public name | Local port |
|---|---|---|---|
| `node` | the Python node from this repo | `nt-node.<domain>` | 4570 |
| `rp` | oauth2-proxy + a page that prints the received claims | `nt-rp.<domain>` | 4571 |
| `wallet` | test wallet (HTTP basic auth, user `wallet`) | `nt-wallet.<domain>` | 4572 |
| `mailpit` | test mailbox UI (private: SSH tunnel) | - | 4573 |
| `edge` | optional Caddy with automatic HTTPS | all three | 80 / 443 |

Everything binds to `127.0.0.1`. The browser and the containers use the very same public URLs
(the containers reach them through `host-gateway`), so what works here is what a real client sees.

## Try it on your machine first

```sh
cd deploy/test
./init.sh --local                 # .env + config/, URLs under *.localtest.me:8080 (plain http)
docker compose up -d --build      # the edge profile is on in local mode
python3 smoke.py run              # needs the repo's Python env (nodetide, aiohttp)
```

Then open `http://nt-rp.localtest.me:8080`: you are sent to the Nodetide sign-in page. Open the wallet at
`http://nt-wallet.localtest.me:8080` (password: `WALLET_PASSWORD` in `.env`), paste the sign-in address,
choose which claims to reveal, approve, and the first tab shows what the application received.

`smoke.py prepare` makes a synthetic "eID" CA so the legal-name path runs without a card. It edits `.env`;
undo that (remove `ANCHORS_DIR` and `EIDAS_REVOCATION` lines) before real use. `deploy.sh` refuses to ship it.

## Deploy to a server

The server needs Docker with the compose plugin, three DNS names pointing at it, and either free ports
80/443 (use `--edge`) or an existing reverse proxy (see `nginx.conf.example`; the stack only listens locally).

```sh
./init.sh --domain example.org --edge      # drop --edge if nginx or similar already serves 80/443
./deploy.sh user@server                    # copies the sources, builds and starts on the server
./deploy.sh user@server --dry-run          # show what would be copied
./deploy.sh user@server --down             # stop (volumes are kept)
```

It builds on the server from the copied sources, so no registry or CI is involved. The mailbox is private:
`ssh -L 4573:127.0.0.1:4573 user@server` and open `http://localhost:4573`.

## Testing with your real eID card

The card stays on your machine; the server only ever sees signatures and certificates.

1. In the wallet, add a **legal name** claim (the names as on your certificate) and press **Create statement
   to sign**; download `statement-….txt`. You have 10 minutes to sign it.
2. On your machine: `./testkit/run sign-file ~/Downloads/statement-….txt` (asks for the digital-signature PIN;
   see `testkit/README.md` for the slots and PIN safety). It writes `statement-….txt.p7s`.
3. The server must trust your CA. Fetch it, check the fingerprints against the provider's published ones,
   and put it where the stack reads anchors:
   `./testkit/run anchors statement-….txt.p7s --out deploy/test/anchors` and
   `./deploy.sh user@server` (the node picks the anchors up on restart).
4. Upload the `.p7s` in the wallet. The node's verdict is shown next to the attestation. Revocation is checked
   online (`EIDAS_REVOCATION=hard-fail` in `.env`; use `soft-fail` while debugging a provider's OCSP).
5. Open the application at `nt-rp.<domain>` and approve the sign-in in the wallet with the legal name shared.
   The page lists `name_verified: true` and a `verified_claims` block naming the `eidas` trust framework.

The certificate inside the signature holds your national ID number. It travels to the server inside the wallet's
attestation and to nowhere else, and the node never stores it (proof attestations are not persisted); but the
wallet's volume does keep the attestation file, so `docker compose down -v` when you are done.

## Files

| | |
|---|---|
| `docker-compose.yml`, `Dockerfile`, `entrypoint.sh` | the stack and its self-contained image |
| `init.sh` | writes `.env` (random secrets) and `config/clients.json` |
| `deploy.sh` | copy + build + start on a server over ssh |
| `smoke.py` | end-to-end check, plays a browser through the standard OIDC client |
| `wallet/`, `echo/` | the test wallet and the page that prints received claims |
| `Caddyfile`, `nginx.conf.example` | TLS / routing for the three names |
| `anchors/` | CA certificates (PEM/DER) the node trusts for eID proofs; empty = proofs switched off |

## Security notes

- `.env`, `config/`, `anchors/` and `.smoke/` are git-ignored and excluded from the Docker build context.
- The wallet's keys are development keys; its password is the only thing between the internet and that identity.
- `NODETIDE_OIDC_ALLOW_INSECURE` (plain http) exists only for the local profile and is `0` for a domain.

## Server on Hetzner

`terraform/` creates the server (checking real availability) and `.github/workflows/test-stack.yml` applies it manually; see `terraform/README.md` for the required secrets.
