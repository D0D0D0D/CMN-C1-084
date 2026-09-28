"""AgentCore Platform v1.0 — CMN-C1-084 default HTTP transport.

The transport is the only place that performs real network I/O. It is injected
into WebFetchService so that all SSRF *decision* logic stays testable offline.
This default uses the stdlib only (no runtime deps).

DNS-rebinding / TOCTOU defense (F-1):
  WebFetchService resolves the host ONCE, validates every resolved IP against the
  forbidden-class denylist, and hands the *pinned* safe IP to this transport. This
  transport then connects to that pinned IP directly — it does NOT let the stdlib
  re-resolve the host name at connect time. The original host name is still used
  for the HTTP ``Host`` header and (for TLS) for SNI + certificate verification.
  This is the standard "connect to a verified IP, verify the cert against the
  hostname" pattern and fully closes the resolve-then-connect rebinding window.

It does NOT auto-follow redirects (WebFetchService re-validates each hop itself).
"""

from __future__ import annotations

import http.client
import ssl
from typing import Any
from urllib.parse import urlsplit

_TIMEOUT_S = 10
_MAX_BYTES = 2_000_000  # 2 MB cap
_USER_AGENT = "cmn-c1-084-governance-qa"


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection that dials a pre-validated (pinned) IP.

    ``host`` keeps the original host name (used for the ``Host`` header), while
    the TCP connection is opened to ``pinned_ip``. This prevents any second DNS
    resolution between WebFetchService's IP validation and the actual connect.
    """

    def __init__(self, host: str, pinned_ip: str, **kw: Any) -> None:
        super().__init__(host, **kw)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:  # noqa: D401
        # Open the socket to the pinned IP, NOT to a freshly resolved host name.
        self.sock = self._create_connection(
            (self._pinned_ip, self.port), self.timeout, self.source_address
        )
        if self._tunnel_host:
            self._tunnel()


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that dials a pinned IP but verifies the cert by host name.

    The TCP socket is opened to ``pinned_ip``; TLS is wrapped with
    ``server_hostname=host`` so SNI and certificate validation still use the
    original host name (a public cert for the host, not for the IP).
    """

    def __init__(self, host: str, pinned_ip: str, *, context: ssl.SSLContext, **kw: Any) -> None:
        super().__init__(host, context=context, **kw)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:  # noqa: D401
        sock = self._create_connection(
            (self._pinned_ip, self.port), self.timeout, self.source_address
        )
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
        # server_hostname = original host name → correct SNI + cert verification,
        # even though the socket is connected to the pinned IP.
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _build_connection(
    url: str, pinned_ip: str
) -> http.client.HTTPConnection:
    parts = urlsplit(url)
    host = parts.hostname or ""
    scheme = (parts.scheme or "").lower()
    if scheme == "https":
        port = parts.port or 443
        ctx = ssl.create_default_context()
        return _PinnedHTTPSConnection(
            host, pinned_ip, context=ctx, port=port, timeout=_TIMEOUT_S
        )
    if scheme == "http":
        port = parts.port or 80
        return _PinnedHTTPConnection(host, pinned_ip, port=port, timeout=_TIMEOUT_S)
    raise ValueError(f"unsupported scheme for transport: {scheme!r}")


def default_http_fetch(url: str, pinned_ip: str) -> dict[str, Any]:
    """Fetch `url` (single hop, no auto-redirect) over the pinned IP.

    The connection is opened to ``pinned_ip`` (the address WebFetchService
    already verified is not private/loopback/metadata); the host name is used
    only for the ``Host`` header and TLS SNI/cert verification. Redirects are
    NOT followed here — 3xx ``Location`` is surfaced to WebFetchService, which
    re-validates the next hop (host allowlist + IP class).

    Returns {"status", "content_type", "body", "location"}.
    """
    parts = urlsplit(url)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"

    conn = _build_connection(url, pinned_ip)
    try:
        conn.request(
            "GET",
            path,
            headers={"User-Agent": _USER_AGENT, "Host": parts.hostname or ""},
        )
        resp = conn.getresponse()
        body = resp.read(_MAX_BYTES).decode("utf-8", errors="replace")
        return {
            "status": resp.status,
            "content_type": resp.getheader("Content-Type", "") or "",
            "body": body,
            "location": resp.getheader("Location", "") or "",
        }
    finally:
        conn.close()
