"""SSRF protection for fetching sigchains from untrusted URLs.

The fetcher contacts addresses supplied by anonymous users (hints in a sign-in
request). Without a guard that is a path to the node's loopback services, LAN
and cloud metadata endpoints.

Defences:
  * only http/https URLs without credentials
  * literal IP hosts must be globally routable
  * hostnames are resolved through GuardedResolver, which drops non-public
    addresses, so DNS rebinding cannot swap in a private address at connect time
  * redirects are never followed, responses are size-capped, timeouts are short
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
from typing import Any
from urllib.parse import quote, urlsplit

import aiohttp
from aiohttp.abc import AbstractResolver

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
FETCH_TIMEOUT = 15


def is_public_ip(addr: str) -> bool:
    """True if `addr` is a globally routable unicast address."""
    try:
        ip = ipaddress.ip_address(addr.split("%")[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def validate_source_url(url: str, allow_private: bool = False) -> str | None:
    """Return a normalized base URL (scheme://host[:port]) or None if unacceptable."""
    if not isinstance(url, str) or len(url) > 512:
        return None
    try:
        parts = urlsplit(url.strip())
        port = parts.port  # raises ValueError on a bad port
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    if parts.username or parts.password:
        return None
    host = parts.hostname
    if not allow_private:
        try:
            ipaddress.ip_address(host)
            literal = True
        except ValueError:
            literal = False
        # aiohttp does not call the resolver for literal IPs, so check here.
        if literal and not is_public_ip(host):
            return None
        if host.lower() in ("localhost",) or host.lower().endswith(".localhost"):
            return None
    netloc = f"[{host}]" if ":" in host else host
    if port:
        netloc = f"{netloc}:{port}"
    return f"{parts.scheme}://{netloc}"


class GuardedResolver(AbstractResolver):
    """Resolver that only returns public addresses."""

    async def resolve(
        self, host: str, port: int = 0, family: int = socket.AF_INET
    ) -> list[dict[str, Any]]:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(
            host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )
        results: list[dict[str, Any]] = []
        for fam, _, _, _, sockaddr in infos:
            ip = sockaddr[0]
            if is_public_ip(ip):
                results.append({
                    "hostname": host,
                    "host": ip,
                    "port": port,
                    "family": fam,
                    "proto": 0,
                    "flags": socket.AI_NUMERICHOST,
                })
        if not results:
            raise OSError(f"{host} does not resolve to a public address")
        return results

    async def close(self) -> None:
        return None


async def http_fetch_sigchain(
    base_url: str,
    identity_hash: str,
    allow_private: bool = False,
) -> list[dict[str, Any]] | None:
    """GET {base_url}/api/identities/{hash}/sigchain and return its events.

    Returns None if the node does not have the identity. Raises on network
    errors. The caller must verify the returned chain.
    """
    base = validate_source_url(base_url, allow_private)
    if base is None:
        raise ValueError("source URL not allowed")

    url = f"{base}/api/identities/{quote(identity_hash, safe='')}/sigchain"
    connector = aiohttp.TCPConnector(
        resolver=None if allow_private else GuardedResolver(),
        limit=4,
    )
    timeout = aiohttp.ClientTimeout(total=FETCH_TIMEOUT)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        async with session.get(url, allow_redirects=False) as resp:
            if resp.status != 200:
                return None
            body = b""
            async for chunk in resp.content.iter_chunked(65536):
                body += chunk
                if len(body) > MAX_RESPONSE_BYTES:
                    return None

    data = json.loads(body)
    events = data.get("events") if isinstance(data, dict) else None
    if not isinstance(events, list) or not all(isinstance(e, dict) for e in events):
        return None
    return events
