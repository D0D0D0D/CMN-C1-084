"""AgentCore Platform v1.0 — CMN-C1-084 WebFetchService (SSRF-defended).

This is the security core of the template. It fetches governance reference
pages ONLY from an operator-curated allowlist, with a defense-in-depth SSRF
denylist. See docs/02_design.md §セキュリティ設計.

Design notes:
  * The network transport is an injected callable (`fetcher`) so the SSRF
    *decision logic* can be unit-tested without any real network access.
  * The DNS resolver is also injected (`resolver`) so rebinding / private-IP
    resolution can be tested deterministically.
  * Every URL is validated BEFORE connecting; on redirects each hop is
    re-validated (host allowlist + resolved-IP class). The resolved IP is
    pinned and handed to the transport so the connection cannot be re-resolved
    to a different address (TOCTOU / DNS-rebinding defense).
  * HTML/PDF extraction is text-only with external entities disabled (XXE) and
    NO automatic secondary requests (images / iframes / RDFa / PDF actions).
"""

from __future__ import annotations

import ipaddress
import socket
import time
from datetime import datetime, timezone
from typing import Any, Callable, Optional
from urllib.parse import urlparse

from framework.errors import SecurityViolationError


class SourceUnreachableError(Exception):
    """An allowlisted host could not be reached (DNS/transport), not an attack.

    Kept outside SecurityViolationError on purpose: fetch_many() propagates
    security violations (they must abort) but collects unreachable sources so
    main can RETRY or fall back to the no_sources_available answer. Treating a
    temporarily unresolvable allowlisted host as a violation took the whole
    agent down instead of degrading, which is the opposite of the documented
    behaviour ("if no source could be fetched after retries, return a safe
    'no current information' answer").
    """


class SSRFViolationError(SecurityViolationError):
    """SSRF/allowlist violation in the web-fetch layer.

    Subclasses the framework's SecurityViolationError (so callers catching the
    base type still handle it) but takes a single human-readable message — the
    base class's (node_name, required, actual) shape is for the S-1 trust gate,
    not for URL/allowlist/IP denials.
    """

    def __init__(self, message: str) -> None:
        # Bypass the base 3-arg __init__; set its attributes for compatibility.
        Exception.__init__(self, message)
        self.node_name = "WebFetchService"
        self.required = "allowlisted-safe-url"
        self.actual = message


# ── Cloud metadata hosts (any scheme/path) — always denied ────────────────────
_METADATA_HOSTS = frozenset(
    {
        "metadata.google.internal",          # GCE / GKE
        "metadata.goog",
        "169.254.169.254",                   # AWS IMDS / GCP / Azure / OpenStack
        "fd00:ec2::254",                     # AWS IMDSv6
    }
)
_METADATA_IPS = frozenset({"169.254.169.254", "fd00:ec2::254"})

_ALLOWED_SCHEMES = frozenset({"http", "https"})
_MAX_REDIRECTS = 5


def _now_iso() -> str:
    """ISO-8601 UTC timestamp (string — State is msgpack-safe)."""
    return datetime.now(timezone.utc).isoformat()


def normalize_host(host: str | None) -> str:
    """Canonical host form for allowlist comparison (shared by S-3 / fetch).

    Lower-cases, strips a single trailing dot (FQDN root, e.g. ``FSA.GO.JP.`` →
    ``fsa.go.jp``), and strips surrounding whitespace. ``urlparse`` already drops
    any ``:port`` from ``.hostname``. Using one function in both WebFetchService
    and PostProcessNode prevents a normalization mismatch from opening a bypass
    (F-3 / case + trailing-dot allowlist evasion).
    """
    if not host:
        return ""
    h = host.strip().lower()
    if h.endswith(".") and h != ".":
        h = h[:-1]
    return h


def host_of(url: str | None) -> str:
    """Extract and normalize the host of a URL (empty string if none)."""
    if not url:
        return ""
    return normalize_host(urlparse(url).hostname)


def _default_resolver(host: str) -> list[str]:
    """Resolve host to a list of IP strings (A + AAAA). Raises on failure."""
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return sorted({info[4][0] for info in infos})


def _canonical_ip(ip_str: str) -> ipaddress._BaseAddress | None:
    """Parse an IP literal, tolerating non-decimal IPv4 (octal/hex/integer).

    `ipaddress.ip_address` rejects `0177.0.0.1`, `0x7f.0.0.1`, and the 32-bit
    integer form `2130706433` — all of which the libc resolver WOULD expand to a
    real (often private/loopback) address. To keep `is_forbidden_ip` correct as a
    standalone defense-in-depth primitive, normalize those forms here before
    classification. Returns None if it is not an IP literal at all (a real
    hostname, which is handled by the resolve step, not this function).
    """
    try:
        return ipaddress.ip_address(ip_str)
    except ValueError:
        pass
    s = ip_str.strip()
    # 32-bit integer form: 2130706433 == 127.0.0.1
    if s.isdigit():
        try:
            val = int(s)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except ValueError:
            return None
    # Dotted form with octal (0NNN) / hex (0xNN) octets: 0177.0.0.1 / 0x7f.0.0.1
    parts = s.split(".")
    if 1 <= len(parts) <= 4:
        octets: list[int] = []
        for p in parts:
            if p == "":
                return None
            try:
                if p.lower().startswith("0x"):
                    octets.append(int(p, 16))
                elif p.startswith("0") and len(p) > 1:
                    octets.append(int(p, 8))
                else:
                    octets.append(int(p, 10))
            except ValueError:
                return None
        if all(0 <= o <= 255 for o in octets) and len(octets) == 4:
            try:
                return ipaddress.IPv4Address(".".join(str(o) for o in octets))
            except ValueError:
                return None
    return None


def is_forbidden_ip(ip_str: str) -> bool:
    """True if `ip_str` is a private / loopback / link-local / metadata address.

    Covers IPv4 and IPv6, including IPv4-mapped IPv6 (e.g. ::ffff:169.254.169.254),
    ULA (fc00::/7), link-local (fe80::/10, 169.254.0.0/16), loopback, and
    non-decimal IPv4 literal forms (octal / hex / 32-bit integer) that the OS
    resolver would otherwise expand to a forbidden address.
    """
    if ip_str in _METADATA_IPS:
        return True
    ip = _canonical_ip(ip_str)
    if ip is None:
        # Not a parseable IP literal in any recognized form — fail closed.
        return True

    # Unwrap IPv4-mapped / 6to4 IPv6 so a mapped metadata/private v4 is caught.
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        elif ip.sixtofour is not None:
            ip = ip.sixtofour

    if str(ip) in _METADATA_IPS:
        return True

    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


class WebFetchService:
    """Allowlist + SSRF-denylist live web fetcher with short-TTL cache.

    :param allowlist: hostnames permitted to fetch from (exact host match).
    :param fetcher: callable(url, ip) -> {"status", "content_type", "body"}.
                    Injected transport; receives the pinned resolved IP so it
                    must connect to that address (no re-resolution).
    :param resolver: callable(host) -> list[str] of resolved IPs (injectable).
    :param cache_ttl_seconds: short cache TTL (default 600s = 10 min).
    :param per_host_min_interval: minimum seconds between requests to one host.
    """

    def __init__(
        self,
        allowlist: list[str],
        fetcher: Callable[[str, str], dict[str, Any]],
        resolver: Optional[Callable[[str], list[str]]] = None,
        cache_ttl_seconds: int = 600,
        per_host_min_interval: float = 0.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._allowlist = frozenset(normalize_host(h) for h in (allowlist or []) if h)
        self._fetcher = fetcher
        self._resolver = resolver or _default_resolver
        self._cache_ttl = cache_ttl_seconds
        self._per_host_min_interval = per_host_min_interval
        self._clock = clock
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._last_request: dict[str, float] = {}

    # ── URL / host / IP validation ────────────────────────────────────────
    def _validate_url(self, url: str) -> tuple[str, str]:
        """Validate scheme + host allowlist. Returns (scheme, host) or raises."""
        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        if scheme not in _ALLOWED_SCHEMES:
            raise SSRFViolationError(
                f"SSRF: scheme '{scheme or '<none>'}' not allowed (only http/https): {url}"
            )
        host = normalize_host(parsed.hostname)
        if not host:
            raise SSRFViolationError(f"SSRF: URL has no host: {url}")
        if host in _METADATA_HOSTS:
            raise SSRFViolationError(f"SSRF: metadata host blocked: {host}")
        if host not in self._allowlist:
            raise SSRFViolationError(
                f"SSRF: host '{host}' is not in source_allowlist"
            )
        return scheme, host

    def _resolve_and_pin(self, host: str) -> str:
        """Resolve host and return a single safe IP, or raise on any forbidden IP."""
        try:
            ips = self._resolver(host)
        except SecurityViolationError:
            # A resolver that itself reports a violation keeps that meaning:
            # the broad except below must not demote it to "unreachable".
            raise
        except Exception as exc:  # noqa: BLE001 — still fail closed: never fetch
            # Fail closed (this host is not fetched) without claiming an attack:
            # the host is allowlisted, we simply could not resolve it now.
            raise SourceUnreachableError(f"DNS resolution failed for {host}: {exc}") from exc
        if not ips:
            raise SourceUnreachableError(f"no addresses resolved for {host}")
        # Reject if ANY resolved address is forbidden (a rebinding attacker may
        # return both a public and a private record).
        parsed_ips: list[tuple[str, ipaddress._BaseAddress]] = []
        for ip in ips:
            if is_forbidden_ip(ip):
                raise SSRFViolationError(
                    f"SSRF: host '{host}' resolved to forbidden address {ip}"
                )
            # is_forbidden_ip fails closed for unparseable values, so a safe
            # result is guaranteed to have a canonical address here.
            parsed_ip = _canonical_ip(ip)
            if parsed_ip is None:
                raise SSRFViolationError(
                    f"SSRF: host '{host}' resolved to unparseable address {ip}"
                )
            parsed_ips.append((ip, parsed_ip))

        # Prefer IPv4 for IPv4-only egress environments. Within each address
        # family, use numeric order so injected resolvers are deterministic too.
        return min(parsed_ips, key=lambda item: (item[1].version, int(item[1])))[0]

    def _rate_limit(self, host: str) -> None:
        if self._per_host_min_interval <= 0:
            return
        last = self._last_request.get(host)
        now = self._clock()
        if last is not None and (now - last) < self._per_host_min_interval:
            raise SSRFViolationError(f"rate limit exceeded for host {host}")
        self._last_request[host] = now

    # ── Fetch ─────────────────────────────────────────────────────────────
    def fetch(self, url: str) -> dict[str, Any]:
        """Fetch a single allowlisted URL, following+re-validating redirects.

        Returns {"url", "fetched_at", "excerpt"}. Raises SecurityViolationError
        on any allowlist / SSRF violation (including on redirect hops).
        """
        cached = self._cache.get(url)
        if cached is not None:
            ts, value = cached
            if (self._clock() - ts) < self._cache_ttl:
                return value

        current_url = url
        for _hop in range(_MAX_REDIRECTS + 1):
            scheme, host = self._validate_url(current_url)
            pinned_ip = self._resolve_and_pin(host)
            self._rate_limit(host)

            resp = self._fetcher(current_url, pinned_ip)
            status = resp.get("status", 200)

            # Follow redirects, re-validating EACH hop (host allowlist + IP class).
            if status in (301, 302, 303, 307, 308) and resp.get("location"):
                current_url = resp["location"]
                continue

            excerpt = self._extract_text(
                resp.get("content_type", ""), resp.get("body", "")
            )
            result = {
                "url": url,                      # canonical request URL
                "final_url": current_url,
                "fetched_at": _now_iso(),
                "excerpt": excerpt,
            }
            self._cache[url] = (self._clock(), result)
            return result

        raise SSRFViolationError(f"SSRF: too many redirects fetching {url}")

    def fetch_many(self, urls: list[str]) -> tuple[list[dict[str, Any]], list[str]]:
        """Fetch several URLs. Returns (successful_contexts, transient_errors).

        Allowlist / SSRF violations propagate (they are not transient). Transient
        transport errors (timeouts) are collected so main can decide RETRY vs
        the no_sources_available fallback.
        """
        contexts: list[dict[str, Any]] = []
        transient: list[str] = []
        for u in urls:
            try:
                contexts.append(self.fetch(u))
            except SecurityViolationError:
                raise
            except Exception as exc:  # noqa: BLE001 — transient transport failure
                transient.append(f"{u}: {exc}")
        return contexts, transient

    # ── Text extraction (no secondary fetch, XXE disabled) ────────────────
    @staticmethod
    def _extract_text(content_type: str, body: str) -> str:
        """Extract body text only.

        HTML/PDF parsing here is deliberately minimal and side-effect-free:
        it NEVER issues secondary requests (no image/iframe/RDFa/PDF-action
        fetch) and disables external entity expansion (XXE). For HTML we strip
        tags with a non-resolving parser; PDF/text bodies are passed through.
        """
        ct = (content_type or "").lower()
        if "html" in ct or body.lstrip().startswith("<"):
            return _strip_html(body)
        # text/plain, application/pdf (pre-extracted text), markdown, etc.
        return body.strip()


# ── Minimal, non-resolving HTML stripper (no external entities, no I/O) ────────
def _strip_html(html: str) -> str:
    """Strip tags and script/style content without resolving any external refs."""
    from html.parser import HTMLParser

    class _TextOnly(HTMLParser):
        def __init__(self) -> None:
            super().__init__(convert_charrefs=True)
            self._chunks: list[str] = []
            self._skip = 0

        def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            if tag in ("script", "style"):
                self._skip += 1
            # Note: we intentionally ignore src/href/data attributes — no
            # secondary resource is ever fetched from parsed content.

        def handle_endtag(self, tag: str) -> None:
            if tag in ("script", "style") and self._skip:
                self._skip -= 1

        def handle_data(self, data: str) -> None:
            if self._skip == 0 and data.strip():
                self._chunks.append(data.strip())

    parser = _TextOnly()
    parser.feed(html)
    return " ".join(parser._chunks).strip()
