"""The sign-in page can offer "open in wallet" links for web wallets (stack wallet, one on the user's machine)."""

import pytest

from nodetide.oidc.config import ConfigError, OIDCConfig
from nodetide.oidc.pages import render_login_page

ISSUER = "https://node.example.org"


def page(wallets):
    return render_login_page("App", "abc", ISSUER, "nonce", wallets)


def test_no_wallet_links_by_default():
    html = page(())
    assert "Open Nodetide app" in html and "/signin?link=" not in html


def test_links_carry_the_challenge_address_and_name_the_wallet():
    html = page(["http://localhost:4572", "https://wallet.example.org"])
    challenge = "https%3A%2F%2Fnode.example.org%2Foidc%2Flogin%2Fabc%2Fchallenge"
    assert f'href="http://localhost:4572/signin?link={challenge}"' in html
    assert f'href="https://wallet.example.org/signin?link={challenge}"' in html
    assert "Open in wallet at localhost:4572" in html


def test_wallet_links_open_in_a_new_tab_so_this_page_keeps_polling():
    html = page(["http://localhost:4572"])
    link = html[html.index('<a class="btn" target="_blank"'):].split(">")[0]
    assert 'rel="noopener noreferrer"' in link and "/signin?link=" in html


def test_the_fragment_secret_is_never_put_in_a_wallet_link():
    assert "#" not in "".join(p for p in page(["http://localhost:4572"]).split('href="')[2:3]).split('"')[0]


def test_config_reads_and_normalises_wallet_urls(monkeypatch):
    monkeypatch.setenv("NODETIDE_OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("NODETIDE_OIDC_WALLET_URLS", " http://localhost:4572/ , https://w.example.org ")
    cfg = OIDCConfig.from_env()
    assert cfg.wallet_urls == ["http://localhost:4572", "https://w.example.org"]


@pytest.mark.parametrize("bad", ["javascript:alert(1)", "ftp://x", "https://w.example.org/?a=b", "https://w.example.org/#x", "notaurl"])
def test_config_rejects_unsafe_wallet_urls(bad):
    with pytest.raises(ConfigError):
        OIDCConfig(issuer=ISSUER, clients={}, wallet_urls=[bad])
