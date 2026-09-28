# CMN-C1-084 — Unit Tests: WebFetchService SSRF defenses (security core)
#
# All tests inject a stub fetcher + resolver — NO real network access. The SSRF
# *decision logic* (allowlist, IP class, DNS rebinding, redirect re-validation,
# scheme, metadata) is what is verified here.

import pytest

from framework.errors import SecurityViolationError
from src.services.web_fetch_service import (
    WebFetchService,
    is_forbidden_ip,
    normalize_host,
)


PUBLIC_IP = "93.184.216.34"


def _ok_fetch(url, ip):
    return {"status": 200, "content_type": "text/html", "body": "<p>hello</p>", "location": ""}


def _service(allowlist, fetcher=_ok_fetch, resolver=None):
    return WebFetchService(
        allowlist=allowlist,
        fetcher=fetcher,
        resolver=resolver or (lambda host: [PUBLIC_IP]),
        per_host_min_interval=0.0,
    )


class TestAllowlist:
    def test_allowlisted_host_fetches(self):
        svc = _service(["www.fsa.go.jp"])
        out = svc.fetch("https://www.fsa.go.jp/policy")
        assert out["url"] == "https://www.fsa.go.jp/policy"
        assert "hello" in out["excerpt"]
        assert out["fetched_at"]  # ISO-8601 string

    def test_host_not_on_allowlist_is_blocked(self):
        svc = _service(["www.fsa.go.jp"])
        with pytest.raises(SecurityViolationError, match="not in source_allowlist"):
            svc.fetch("https://evil.example.com/x")


class TestScheme:
    @pytest.mark.parametrize("url", [
        "file:///etc/passwd",
        "gopher://www.fsa.go.jp/x",
        "ftp://www.fsa.go.jp/x",
    ])
    def test_non_http_schemes_blocked(self, url):
        svc = _service(["www.fsa.go.jp"])
        with pytest.raises(SecurityViolationError, match="scheme"):
            svc.fetch(url)


class TestMetadataAndPrivateIP:
    def test_metadata_host_blocked(self):
        svc = _service(["169.254.169.254", "metadata.google.internal"])
        with pytest.raises(SecurityViolationError, match="metadata host"):
            svc.fetch("http://169.254.169.254/latest/meta-data/")

    def test_gce_metadata_host_blocked(self):
        svc = _service(["metadata.google.internal"])
        with pytest.raises(SecurityViolationError, match="metadata host"):
            svc.fetch("http://metadata.google.internal/computeMetadata/v1/")

    def test_allowlisted_host_resolving_to_private_ip_blocked(self):
        # Host is allowlisted, but DNS resolves to a private address → blocked.
        svc = _service(["www.fsa.go.jp"], resolver=lambda h: ["10.0.0.5"])
        with pytest.raises(SecurityViolationError, match="forbidden address"):
            svc.fetch("https://www.fsa.go.jp/policy")

    def test_resolving_to_loopback_blocked(self):
        svc = _service(["www.fsa.go.jp"], resolver=lambda h: ["127.0.0.1"])
        with pytest.raises(SecurityViolationError, match="forbidden address"):
            svc.fetch("https://www.fsa.go.jp/policy")

    def test_resolving_to_metadata_ip_blocked(self):
        svc = _service(["www.fsa.go.jp"], resolver=lambda h: ["169.254.169.254"])
        with pytest.raises(SecurityViolationError, match="forbidden address"):
            svc.fetch("https://www.fsa.go.jp/policy")


class TestDnsRebinding:
    def test_rebinding_mixed_records_rejected(self):
        # Attacker returns BOTH a public and a private address; any forbidden → block.
        svc = _service(["www.fsa.go.jp"], resolver=lambda h: [PUBLIC_IP, "192.168.1.10"])
        with pytest.raises(SecurityViolationError, match="forbidden address"):
            svc.fetch("https://www.fsa.go.jp/policy")


class TestIPv6:
    @pytest.mark.parametrize("ip", [
        "::1",                          # loopback
        "fc00::1",                      # ULA fc00::/7
        "fe80::1",                      # link-local
        "::ffff:169.254.169.254",       # IPv4-mapped metadata
        "::ffff:10.0.0.1",              # IPv4-mapped private
    ])
    def test_forbidden_ipv6_classes(self, ip):
        assert is_forbidden_ip(ip) is True

    def test_public_ipv6_allowed_class(self):
        assert is_forbidden_ip("2606:2800:220:1:248:1893:25c8:1946") is False

    def test_allowlisted_host_resolving_to_ipv6_loopback_blocked(self):
        svc = _service(["www.fsa.go.jp"], resolver=lambda h: ["::1"])
        with pytest.raises(SecurityViolationError, match="forbidden address"):
            svc.fetch("https://www.fsa.go.jp/policy")


class TestRedirectRevalidation:
    def test_redirect_to_off_allowlist_host_blocked(self):
        def redirecting_fetch(url, ip):
            if "fsa.go.jp" in url:
                return {"status": 302, "location": "https://evil.example.com/x", "body": "", "content_type": ""}
            return _ok_fetch(url, ip)
        svc = _service(["www.fsa.go.jp"], fetcher=redirecting_fetch)
        with pytest.raises(SecurityViolationError, match="not in source_allowlist"):
            svc.fetch("https://www.fsa.go.jp/policy")

    def test_redirect_to_internal_metadata_blocked(self):
        def redirecting_fetch(url, ip):
            if "fsa.go.jp" in url:
                return {"status": 302, "location": "http://169.254.169.254/", "body": "", "content_type": ""}
            return _ok_fetch(url, ip)
        svc = _service(["www.fsa.go.jp", "169.254.169.254"], fetcher=redirecting_fetch)
        with pytest.raises(SecurityViolationError, match="metadata host"):
            svc.fetch("https://www.fsa.go.jp/policy")

    def test_redirect_to_allowlisted_host_followed(self):
        def redirecting_fetch(url, ip):
            if url.endswith("/old"):
                return {"status": 301, "location": "https://www.fsa.go.jp/new", "body": "", "content_type": ""}
            return {"status": 200, "content_type": "text/html", "body": "<p>final</p>", "location": ""}
        svc = _service(["www.fsa.go.jp"], fetcher=redirecting_fetch)
        out = svc.fetch("https://www.fsa.go.jp/old")
        assert "final" in out["excerpt"]
        assert out["final_url"].endswith("/new")

    def test_redirect_loop_capped(self):
        def looping_fetch(url, ip):
            return {"status": 302, "location": "https://www.fsa.go.jp/loop", "body": "", "content_type": ""}
        svc = _service(["www.fsa.go.jp"], fetcher=looping_fetch)
        with pytest.raises(SecurityViolationError, match="too many redirects"):
            svc.fetch("https://www.fsa.go.jp/loop")


class TestParserSecondaryFetch:
    def test_html_extraction_does_not_fetch_subresources(self):
        # The HTML carries an <img>/<iframe>/<script> with remote src; extraction
        # must return ONLY text and must NOT call the fetcher again.
        calls = []

        def counting_fetch(url, ip):
            calls.append(url)
            body = (
                "<html><body>"
                "<img src='http://169.254.169.254/steal'>"
                "<iframe src='http://10.0.0.1/'></iframe>"
                "<script>fetch('http://evil/')</script>"
                "Governance text only."
                "</body></html>"
            )
            return {"status": 200, "content_type": "text/html", "body": body, "location": ""}

        svc = _service(["www.fsa.go.jp"], fetcher=counting_fetch)
        out = svc.fetch("https://www.fsa.go.jp/p")
        assert calls == ["https://www.fsa.go.jp/p"]  # exactly one fetch, no secondary
        assert "Governance text only." in out["excerpt"]
        assert "169.254" not in out["excerpt"]       # script/img content excluded
        assert "evil" not in out["excerpt"]


class TestCacheAndRateLimit:
    def test_cache_hit_avoids_second_fetch(self):
        calls = []

        def counting_fetch(url, ip):
            calls.append(url)
            return _ok_fetch(url, ip)

        svc = WebFetchService(
            allowlist=["www.fsa.go.jp"], fetcher=counting_fetch,
            resolver=lambda h: [PUBLIC_IP], cache_ttl_seconds=600,
        )
        svc.fetch("https://www.fsa.go.jp/p")
        svc.fetch("https://www.fsa.go.jp/p")
        assert len(calls) == 1  # second served from cache

    def test_rate_limit_enforced(self):
        t = {"now": 0.0}
        svc = WebFetchService(
            allowlist=["www.fsa.go.jp"], fetcher=_ok_fetch,
            resolver=lambda h: [PUBLIC_IP], per_host_min_interval=5.0,
            cache_ttl_seconds=0, clock=lambda: t["now"],
        )
        svc.fetch("https://www.fsa.go.jp/a")
        with pytest.raises(SecurityViolationError, match="rate limit"):
            svc.fetch("https://www.fsa.go.jp/b")


class TestFetchMany:
    def test_security_violation_propagates(self):
        svc = _service(["www.fsa.go.jp"])
        with pytest.raises(SecurityViolationError):
            svc.fetch_many(["https://evil.example.com/x"])

    def test_transient_error_collected_not_raised(self):
        def failing_fetch(url, ip):
            raise TimeoutError("connect timeout")
        svc = _service(["www.fsa.go.jp"], fetcher=failing_fetch)
        contexts, transient = svc.fetch_many(["https://www.fsa.go.jp/a"])
        assert contexts == []
        assert len(transient) == 1


# ── F-1: the pinned IP must actually be what the transport connects to ────────
class TestIPPinningContract:
    def test_ipv4_is_preferred_when_resolver_returns_ipv6_first(self):
        seen = {}

        def recording_fetch(url, ip):
            seen["ip"] = ip
            return _ok_fetch(url, ip)

        svc = WebFetchService(
            allowlist=["www.fsa.go.jp"], fetcher=recording_fetch,
            resolver=lambda h: ["2606:4700::6812:107c", "104.18.16.124"],
            per_host_min_interval=0.0,
        )
        svc.fetch("https://www.fsa.go.jp/p")
        assert seen["ip"] == "104.18.16.124"

    def test_ipv6_is_pinned_when_no_ipv4_is_resolved(self):
        seen = {}

        def recording_fetch(url, ip):
            seen["ip"] = ip
            return _ok_fetch(url, ip)

        svc = WebFetchService(
            allowlist=["www.fsa.go.jp"], fetcher=recording_fetch,
            resolver=lambda h: ["2606:4700::6812:107c"],
            per_host_min_interval=0.0,
        )
        svc.fetch("https://www.fsa.go.jp/p")
        assert seen["ip"] == "2606:4700::6812:107c"

    @pytest.mark.parametrize(
        "resolved_ips",
        [
            ["104.18.16.124", "::1"],
            ["2606:4700::6812:107c", "10.0.0.5"],
        ],
    )
    def test_mixed_ip_families_with_any_forbidden_address_are_rejected(self, resolved_ips):
        svc = _service(["www.fsa.go.jp"], resolver=lambda h: resolved_ips)
        with pytest.raises(SecurityViolationError, match="forbidden address"):
            svc.fetch("https://www.fsa.go.jp/p")

    def test_pinned_ip_is_passed_to_transport(self):
        # The IP handed to the fetcher must be the resolved/validated IP, not a
        # host name (so the transport connects to it, not a re-resolution).
        seen = {}

        def recording_fetch(url, ip):
            seen["ip"] = ip
            return _ok_fetch(url, ip)

        svc = WebFetchService(
            allowlist=["www.fsa.go.jp"], fetcher=recording_fetch,
            resolver=lambda h: [PUBLIC_IP], per_host_min_interval=0.0,
        )
        svc.fetch("https://www.fsa.go.jp/p")
        assert seen["ip"] == PUBLIC_IP  # pinned IP reaches the transport

    def test_rebind_second_resolution_forbidden_never_reaches_transport(self):
        # Rebinding resolver: 1st call safe IP, 2nd call metadata IP. The service
        # resolves ONCE per hop and pins; if a hostile record appears in the
        # resolved set it is rejected. Here the FIRST resolution already contains
        # both records → blocked before the transport is ever called.
        calls = {"resolve": 0, "fetch": 0}

        def rebinding_resolver(host):
            calls["resolve"] += 1
            # Attacker returns a public + a metadata address together.
            return [PUBLIC_IP, "169.254.169.254"]

        def counting_fetch(url, ip):
            calls["fetch"] += 1
            return _ok_fetch(url, ip)

        svc = WebFetchService(
            allowlist=["www.fsa.go.jp"], fetcher=counting_fetch,
            resolver=rebinding_resolver, per_host_min_interval=0.0,
        )
        with pytest.raises(SecurityViolationError, match="forbidden address"):
            svc.fetch("https://www.fsa.go.jp/p")
        assert calls["fetch"] == 0  # transport never reached with a bad IP

    def test_default_transport_http_connects_to_pinned_ip(self):
        # Drive the REAL default-transport HTTP connection but stub the socket
        # layer: the TCP connect target MUST be the pinned IP (no re-resolution),
        # while the Host header keeps the original host name.
        import src.services.http_transport as T

        captured = {}

        class _FakeSock:
            def close(self): pass

        def fake_create_connection(address, timeout=None, source_address=None):
            captured["connect_addr"] = address
            return _FakeSock()

        conn = T._build_connection("http://www.fsa.go.jp/p", "203.0.113.9")
        conn._create_connection = fake_create_connection  # type: ignore[assignment]
        conn.connect()

        assert captured["connect_addr"][0] == "203.0.113.9"  # pinned IP
        assert captured["connect_addr"][1] == 80              # http default port

    def test_default_transport_https_wraps_with_original_hostname(self):
        # For TLS the socket connects to the pinned IP, but server_hostname (SNI +
        # cert verification) MUST be the original host name, not the IP.
        import src.services.http_transport as T

        captured = {}

        class _FakeSock:
            def close(self): pass

        def fake_create_connection(address, timeout=None, source_address=None):
            captured["connect_addr"] = address
            return _FakeSock()

        class _FakeCtx:
            def wrap_socket(self, sock, server_hostname=None):
                captured["server_hostname"] = server_hostname
                return sock

        conn = T._build_connection("https://www.fsa.go.jp/p", "203.0.113.9")
        conn._create_connection = fake_create_connection  # type: ignore[assignment]
        conn._context = _FakeCtx()  # type: ignore[assignment]
        conn.connect()

        assert captured["connect_addr"][0] == "203.0.113.9"        # pinned IP
        assert captured["connect_addr"][1] == 443                  # https port
        assert captured["server_hostname"] == "www.fsa.go.jp"      # cert verified by host


# ── F-3 / bypass: host casing + trailing dot must not evade the allowlist ─────
class TestHostNormalizationBypass:
    def test_uppercase_host_still_blocked_when_off_allowlist(self):
        svc = _service(["www.fsa.go.jp"])
        with pytest.raises(SecurityViolationError, match="not in source_allowlist"):
            svc.fetch("https://EVIL.EXAMPLE.COM/x")

    def test_uppercase_allowlisted_host_normalizes(self):
        svc = _service(["WWW.FSA.GO.JP"])
        out = svc.fetch("https://www.fsa.go.jp/policy")
        assert "hello" in out["excerpt"]

    def test_trailing_dot_host_matches_allowlist(self):
        # FQDN-root trailing dot must normalize to the same allowlist host.
        svc = _service(["www.fsa.go.jp"])
        out = svc.fetch("https://www.fsa.go.jp./policy")
        assert "hello" in out["excerpt"]

    def test_trailing_dot_does_not_bypass_metadata_block(self):
        svc = _service(["169.254.169.254"])
        with pytest.raises(SecurityViolationError):
            svc.fetch("http://169.254.169.254./latest/")

    def test_normalize_host_helper(self):
        assert normalize_host("FSA.GO.JP.") == "fsa.go.jp"
        assert normalize_host("  Www.Example.COM  ") == "www.example.com"
        assert normalize_host(None) == ""


# ── bypass: non-decimal IPv4 literal forms (octal / hex / integer) ────────────
class TestNumericIPForms:
    @pytest.mark.parametrize("ip", [
        "0177.0.0.1",   # octal 127.0.0.1
        "0x7f.0.0.1",   # hex 127.0.0.1
        "2130706433",   # 32-bit integer 127.0.0.1
        "3232235521",   # 192.168.0.1
        "0xA9FEA9FE",   # 169.254.169.254 hex-integer (fail-closed)
    ])
    def test_numeric_ip_forms_are_forbidden(self, ip):
        assert is_forbidden_ip(ip) is True

    def test_resolver_returning_numeric_loopback_is_blocked(self):
        # If a resolver yields a non-decimal IPv4 literal that decodes to a
        # forbidden address, the service must still reject it.
        svc = _service(["www.fsa.go.jp"], resolver=lambda h: ["2130706433"])
        with pytest.raises(SecurityViolationError, match="forbidden address"):
            svc.fetch("https://www.fsa.go.jp/policy")


# ── bypass: redirect Location pointing at a private / metadata IP literal ─────
class TestRedirectToPrivateIP:
    def test_redirect_location_private_ip_blocked(self):
        def redirecting_fetch(url, ip):
            if "fsa.go.jp" in url:
                return {"status": 302, "location": "http://10.0.0.5/admin",
                        "body": "", "content_type": ""}
            return _ok_fetch(url, ip)
        # 10.0.0.5 is not on the allowlist → blocked at host check on the hop.
        svc = _service(["www.fsa.go.jp"], fetcher=redirecting_fetch)
        with pytest.raises(SecurityViolationError, match="not in source_allowlist"):
            svc.fetch("https://www.fsa.go.jp/policy")

    def test_redirect_location_metadata_integer_ip_blocked(self):
        # Redirect to 169.254.169.254 expressed as a 32-bit integer literal.
        def redirecting_fetch(url, ip):
            if "fsa.go.jp" in url:
                return {"status": 302, "location": "http://2852039166/latest/",
                        "body": "", "content_type": ""}
            return _ok_fetch(url, ip)
        # Even if the numeric host were allowlisted, resolution → forbidden class.
        svc = _service(["www.fsa.go.jp", "2852039166"],
                       fetcher=redirecting_fetch,
                       resolver=lambda h: ["169.254.169.254"] if h == "2852039166" else [PUBLIC_IP])
        with pytest.raises(SecurityViolationError):
            svc.fetch("https://www.fsa.go.jp/policy")


class TestUnresolvableHostDegradesRatherThanAborting:
    """An allowlisted host that will not resolve is unreachable, not an attack.

    Regression: a resolver failure raised SSRFViolationError, which fetch_many()
    deliberately propagates, so one temporarily unresolvable source aborted the
    whole invocation. docs/02 says the opposite -- when no source can be
    fetched the agent answers with the no_sources_available marker. Found on
    AGENTIC STAR, where config/config.yaml still carries a placeholder internal wiki
    host: every request failed with "SSRF: DNS resolution failed".
    """

    @staticmethod
    def _raising_resolver(_host):
        raise OSError("[Errno -2] Name or service not known")

    def test_resolver_failure_is_not_a_security_violation(self):
        from framework.errors import SecurityViolationError

        from src.services.web_fetch_service import SourceUnreachableError

        svc = _service(["www.fsa.go.jp"], resolver=self._raising_resolver)
        with pytest.raises(SourceUnreachableError) as caught:
            svc.fetch("https://www.fsa.go.jp/a")
        assert not isinstance(caught.value, SecurityViolationError)

    def test_empty_resolution_is_not_a_security_violation(self):
        from framework.errors import SecurityViolationError

        from src.services.web_fetch_service import SourceUnreachableError

        svc = _service(["www.fsa.go.jp"], resolver=lambda _h: [])
        with pytest.raises(SourceUnreachableError) as caught:
            svc.fetch("https://www.fsa.go.jp/a")
        assert not isinstance(caught.value, SecurityViolationError)

    def test_fetch_many_collects_it_as_transient_instead_of_aborting(self):
        svc = _service(["www.fsa.go.jp"], resolver=self._raising_resolver)
        contexts, transient = svc.fetch_many(["https://www.fsa.go.jp/a"])
        assert contexts == []
        assert len(transient) == 1 and "DNS resolution failed" in transient[0]

    def test_one_unresolvable_source_does_not_lose_the_reachable_ones(self):
        """The real shape of the AGENTIC STAR failure: 2 good sources, 1 placeholder."""

        def resolver(host):
            if host == "governance.internal.example.com":
                raise OSError("[Errno -2] Name or service not known")
            return [PUBLIC_IP]

        svc = _service(["www.fsa.go.jp", "governance.internal.example.com"], resolver=resolver)
        contexts, transient = svc.fetch_many(
            ["https://www.fsa.go.jp/a", "https://governance.internal.example.com/wiki"]
        )
        assert len(contexts) == 1
        assert len(transient) == 1

    def test_a_forbidden_address_is_still_a_security_violation(self):
        """The relaxation must not weaken the actual SSRF guard."""

        from src.services.web_fetch_service import SSRFViolationError

        svc = _service(["www.fsa.go.jp"], resolver=lambda _h: ["169.254.169.254"])
        with pytest.raises(SSRFViolationError):
            svc.fetch("https://www.fsa.go.jp/a")


def test_a_resolver_that_reports_a_violation_is_not_demoted_to_unreachable():
    """The broad except around the resolver must not swallow a real verdict."""

    from framework.errors import SecurityViolationError

    from src.services.web_fetch_service import SSRFViolationError

    def resolver(_host):
        raise SSRFViolationError("SSRF: resolver refused this host")

    svc = _service(["www.fsa.go.jp"], resolver=resolver)
    with pytest.raises(SecurityViolationError):
        svc.fetch("https://www.fsa.go.jp/a")
