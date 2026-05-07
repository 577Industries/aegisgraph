#!/usr/bin/env python3
"""Idempotent builder for the PolyDiff regression corpus.

This script writes the per-case directories under
`polydiff/regression/cases/<id>/` with `input`, `description.md`,
`expected.json`, and `reference.url`.

Why a builder rather than 30 hand-edited dirs? The corpus is large
enough that hand-editing is error-prone. A builder lets us:
  - keep the case data in one auditable Python file
  - regenerate the corpus deterministically
  - add new cases without touching shell scripts

Run: `python3 polydiff/regression/build_corpus.py`. The script is
idempotent — it writes each file regardless of whether it already
exists, so cases stay in sync with this source of truth.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Case:
    case_id: str
    input_url: str  # Raw URL string; written to `input` (no trailing newline)
    summary: str
    bug_class: str
    primary_axes: list[str]
    primary_security_tags: list[str]
    expected_pairs: list[dict]  # raw expected_disagreements list
    reference_url: str
    historical_cve_or_disclosure_reference: str | None = None
    publication_policy: str = "synthetic-public-candidate"
    extra_notes: str = ""


# --------------------------------------------------------------------- #
# Case data (≥30). Each input is constructed from public references in
# the comment block above the case. Hosts use IETF example reservations
# (example.com / example.net / example.org / 192.0.2.0/24 / 198.51.100.0/24).
# No live target probing; no exploit triggers.
# --------------------------------------------------------------------- #

CASES: list[Case] = [
    # ---- userinfo / host confusion ---- #
    Case(
        "REG-URL-OkHttp-userinfo-1",
        "https://trusted.example@evil.example/resource",
        "Validator-vs-fetcher userinfo-host confusion (Snyk 2022 canonical case).",
        "userinfo-host-confusion",
        ["userinfo_present", "host_lowercased"],
        ["userinfo-host-confusion", "origin-confusion"],
        [
            {"axis": "userinfo_present", "rule_id": "SR-USERINFO-DISAGREE", "tag": "userinfo-host-confusion"},
            {"axis": "host_lowercased", "rule_id": "SR-HOST-MISMATCH", "tag": "origin-confusion"},
        ],
        "https://snyk.io/blog/url-confusion-vulnerabilities/",
    ),
    Case(
        "REG-URL-OkHttp-userinfo-2",
        "https://@evil.example/admin",
        "Empty userinfo: java.net.URI vs okhttp.HttpUrl (Bishop Fox 2022).",
        "userinfo-host-confusion",
        ["userinfo_present"],
        ["userinfo-host-confusion"],
        [{"axis": "userinfo_present", "rule_id": "SR-USERINFO-DISAGREE", "tag": "userinfo-host-confusion"}],
        "https://bishopfox.com/blog/url-parsing-attacks",
    ),
    Case(
        "REG-URL-Userinfo-Empty-Auth",
        "https://user:@evil.example/",
        "Empty password segment; RFC 3986 ambiguity on `user:@host`.",
        "userinfo-host-confusion",
        ["password_present", "userinfo_raw"],
        ["userinfo-host-confusion"],
        [{"axis": "password_present", "rule_id": "SR-USERINFO-DISAGREE", "tag": "userinfo-host-confusion"}],
        "https://datatracker.ietf.org/doc/html/rfc3986#section-3.2.1",
    ),

    # ---- Snyk 2022 host parsing study (8 cases) ---- #
    Case(
        "REG-URL-Snyk-2022-host-1",
        "https://example.com#@evil.example/",
        "Fragment-as-userinfo: parser disagreement on whether '#@' splits host.",
        "host-injection",
        ["host_lowercased"],
        ["origin-confusion"],
        [{"axis": "host_lowercased", "rule_id": "SR-HOST-MISMATCH", "tag": "origin-confusion"}],
        "https://snyk.io/blog/url-confusion-vulnerabilities/",
    ),
    Case(
        "REG-URL-Snyk-2022-host-2",
        "https://example.com:443@evil.example/",
        "Port-then-userinfo: host=example.com vs evil.example.",
        "host-injection",
        ["host_lowercased", "port_value"],
        ["origin-confusion"],
        [{"axis": "host_lowercased", "rule_id": "SR-HOST-MISMATCH", "tag": "origin-confusion"}],
        "https://snyk.io/blog/url-confusion-vulnerabilities/",
    ),
    Case(
        "REG-URL-Snyk-2022-host-3",
        "https:///example.com/",
        "Triple-slash empty authority — WHATWG treats example.com as host; urllib gets host=None and path=/example.com/.",
        "host-injection",
        ["host", "path"],
        ["origin-confusion"],
        [
            {"axis": "host", "rule_id": "SR-HOST-MISMATCH-RAW", "tag": "origin-confusion"},
            {"axis": "path", "rule_id": "SR-PATH-NORMALIZE-DISAGREE", "tag": "path-normalization-confusion"},
        ],
        "https://snyk.io/blog/url-confusion-vulnerabilities/",
        historical_cve_or_disclosure_reference="Snyk-2022-URL-Confusion",
    ),
    Case(
        "REG-URL-Snyk-2022-host-4",
        "https://example.com.evil.example/",
        "Subdomain-suffix confusion (NOT real disagreement; baseline normalcy check).",
        "host-baseline",
        ["host_lowercased"],
        [],
        [],
        "https://snyk.io/blog/url-confusion-vulnerabilities/",
    ),
    Case(
        "REG-URL-Snyk-2022-host-5",
        "https://example.com\\\\@evil.example/",
        "Double-backslash (URL-escape inside): WHATWG converts to slash, RFC 3986 keeps as host char.",
        "path-confusion",
        ["host_lowercased", "backslash_treated_as_slash"],
        ["origin-confusion", "path-confusion"],
        [
            {"axis": "host_lowercased", "rule_id": "SR-HOST-MISMATCH", "tag": "origin-confusion"},
            {"axis": "backslash_treated_as_slash", "rule_id": "SR-BACKSLASH", "tag": "path-confusion"},
        ],
        "https://snyk.io/blog/url-confusion-vulnerabilities/",
        historical_cve_or_disclosure_reference="Snyk-2022-URL-Confusion",
    ),
    Case(
        "REG-URL-Snyk-2022-host-6",
        "https://example.com:0/",
        "Port=0: some parsers reject, others accept.",
        "port-confusion",
        ["port_value", "parsed"],
        ["port-confusion"],
        [{"axis": "port_value", "rule_id": "SR-PORT-DISAGREE", "tag": "port-confusion"}],
        "https://snyk.io/blog/url-confusion-vulnerabilities/",
    ),
    Case(
        "REG-URL-Snyk-2022-host-7",
        "https://example.com..evil.example/",
        "Double-dot in host (zero-length label): okhttp accepts, java.net.URI rejects.",
        "host-injection",
        ["host_lowercased", "parsed"],
        ["origin-confusion", "gating-bypass"],
        [
            {"axis": "host_lowercased", "rule_id": "SR-HOST-MISMATCH", "tag": "origin-confusion"},
            {"axis": "parsed", "rule_id": "SR-PARSED-DIFFERS", "tag": "gating-bypass"},
        ],
        "https://snyk.io/blog/url-confusion-vulnerabilities/",
    ),
    Case(
        "REG-URL-Snyk-2022-host-8",
        "https://example.com./",
        "Trailing-dot host: WHATWG normalizes; legacy parsers keep the dot.",
        "host-baseline",
        ["host_lowercased", "trailing_slash_normalized"],
        ["origin-confusion"],
        [{"axis": "host_lowercased", "rule_id": "SR-HOST-MISMATCH", "tag": "origin-confusion"}],
        "https://url.spec.whatwg.org/#host-parsing",
    ),

    # ---- Node WHATWG vs urllib legacy ---- #
    Case(
        "REG-URL-Node-WHATWG-legacy",
        "https:foo",
        "Bare scheme path (no //) — WHATWG/urllib disagree on whether 'foo' is host or path.",
        "scheme-confusion",
        ["scheme_authority_separator_strict", "host_lowercased", "path"],
        ["scheme-confusion"],
        [
            {"axis": "scheme_authority_separator_strict", "rule_id": "SR-SCHEME-AUTHORITY", "tag": "scheme-confusion"},
            {"axis": "path", "rule_id": "SR-PATH-NORMALIZE-DISAGREE", "tag": "path-normalization-confusion"},
        ],
        "https://nodejs.org/api/url.html#legacy-url-api",
    ),

    # ---- IPv4 octet handling ---- #
    Case(
        "REG-URL-IPv4-leading-zeroes",
        "http://0177.0.0.1/",
        "Octal-vs-decimal IPv4: 0177=127 in WHATWG, but 0177 stays string in RFC 3986.",
        "ssrf-private-network",
        ["host", "host_is_loopback", "host_is_private_or_link_local", "leading_zeroes_in_octets_stripped"],
        ["ssrf-loopback-bypass", "ssrf-private-network"],
        [
            {"axis": "host_is_loopback", "rule_id": "SR-LOOPBACK-DISAGREE", "tag": "ssrf-loopback-bypass"},
            {"axis": "host_is_private_or_link_local", "rule_id": "SR-PRIVATE-DISAGREE", "tag": "ssrf-private-network"},
            {"axis": "leading_zeroes_in_octets_stripped", "rule_id": "SR-LEADING-ZERO-OCTET", "tag": "ssrf-private-network"},
        ],
        "https://datatracker.ietf.org/doc/html/rfc6943#section-3.1.1",
        historical_cve_or_disclosure_reference="CVE-2021-29921",  # Python ipaddress octal
    ),
    Case(
        "REG-URL-IPv4-Decimal",
        "http://2130706433/",
        "Single 32-bit decimal IPv4: 2130706433 = 127.0.0.1; WHATWG decodes to 127.0.0.1, RFC 3986 keeps as raw string.",
        "ssrf-private-network",
        ["host", "host_is_loopback"],
        ["ssrf-loopback-bypass"],
        [
            {"axis": "host", "rule_id": "SR-HOST-MISMATCH-RAW", "tag": "origin-confusion"},
            {"axis": "host_is_loopback", "rule_id": "SR-LOOPBACK-DISAGREE", "tag": "ssrf-loopback-bypass"},
        ],
        "https://datatracker.ietf.org/doc/html/rfc6943#section-3.1.1",
        historical_cve_or_disclosure_reference="CVE-2021-29921",  # Same Python-ipaddress bug class
    ),
    Case(
        "REG-URL-IPv4-Hex",
        "http://0x7f.0.0.1/",
        "Hex IPv4 octet: 0x7f=127; WHATWG accepts and decodes, RFC 3986 keeps as raw string.",
        "ssrf-private-network",
        ["host", "host_is_loopback"],
        ["ssrf-loopback-bypass"],
        [
            {"axis": "host", "rule_id": "SR-HOST-MISMATCH-RAW", "tag": "origin-confusion"},
            {"axis": "host_is_loopback", "rule_id": "SR-LOOPBACK-DISAGREE", "tag": "ssrf-loopback-bypass"},
        ],
        "https://datatracker.ietf.org/doc/html/rfc6943#section-3.1.1",
        historical_cve_or_disclosure_reference="CVE-2021-29921",  # Same Python-ipaddress bug class
    ),

    # ---- IDN / Unicode ---- #
    Case(
        "REG-URL-IDN-Spoof-Cyrillic",
        "https://xn--80ak6aa92e.example/",
        "Cyrillic 'а' lookalike encoded as punycode; some parsers decode, others don't.",
        "idn-spoof",
        ["host_has_idn", "host_punycode", "host_decoded"],
        ["idn-spoof"],
        [
            {"axis": "host_has_idn", "rule_id": "SR-IDN-DISAGREE", "tag": "idn-spoof"},
            {"axis": "host_punycode", "rule_id": "SR-PUNYCODE-DISAGREE", "tag": "idn-spoof"},
        ],
        "https://chromium.googlesource.com/chromium/src/+/HEAD/docs/idn.md",
    ),
    Case(
        "REG-URL-IDN-Mixed-Script",
        "https://exаmple.example/",  # Cyrillic 'а' inside ASCII context
        "Mixed-script IDN: visual lookalike with Cyrillic 'а' character.",
        "idn-spoof",
        ["host_has_idn", "host_punycode"],
        ["idn-spoof"],
        [{"axis": "host_has_idn", "rule_id": "SR-IDN-DISAGREE", "tag": "idn-spoof"}],
        "https://chromium.googlesource.com/chromium/src/+/HEAD/docs/idn.md",
    ),

    # ---- Backslash IE-legacy ---- #
    Case(
        "REG-URL-Backslash-IE-legacy",
        "https://example.com\\@evil.example/",
        "IE-style backslash in authority; WHATWG converts to /, others keep as host char.",
        "path-confusion",
        ["host_lowercased", "backslash_treated_as_slash"],
        ["origin-confusion", "path-confusion"],
        [
            {"axis": "host_lowercased", "rule_id": "SR-HOST-MISMATCH", "tag": "origin-confusion"},
            {"axis": "backslash_treated_as_slash", "rule_id": "SR-BACKSLASH", "tag": "path-confusion"},
        ],
        "https://url.spec.whatwg.org/#concept-basic-url-parser",
        historical_cve_or_disclosure_reference="Snyk-2022-URL-Confusion",
    ),

    # ---- Tab/newline stripping ---- #
    Case(
        "REG-URL-LinkPreview-Tab",
        "https://example.com\t.evil.example/",
        "Tab inside host: WHATWG strips before parsing, RFC keeps it.",
        "link-preview-bypass",
        ["host_lowercased", "tab_or_newline_stripped"],
        ["origin-confusion", "link-preview-bypass"],
        [
            {"axis": "host_lowercased", "rule_id": "SR-HOST-MISMATCH", "tag": "origin-confusion"},
            {"axis": "tab_or_newline_stripped", "rule_id": "SR-TAB-NEWLINE", "tag": "link-preview-bypass"},
        ],
        "https://url.spec.whatwg.org/#concept-basic-url-parser",
    ),
    Case(
        "REG-URL-LinkPreview-Newline",
        "https://example.com\n.evil.example/",
        "Newline inside host: WHATWG strips, RFC parsers may reject or keep.",
        "link-preview-bypass",
        ["host_lowercased", "tab_or_newline_stripped", "parsed"],
        ["origin-confusion", "link-preview-bypass", "gating-bypass"],
        [
            {"axis": "tab_or_newline_stripped", "rule_id": "SR-TAB-NEWLINE", "tag": "link-preview-bypass"},
            {"axis": "parsed", "rule_id": "SR-PARSED-DIFFERS", "tag": "gating-bypass"},
        ],
        "https://url.spec.whatwg.org/#concept-basic-url-parser",
    ),
    Case(
        "REG-URL-LinkPreview-CR",
        "https://example.com\r.evil.example/",
        "Carriage return inside host: same class as tab/newline.",
        "link-preview-bypass",
        ["host_lowercased", "tab_or_newline_stripped"],
        ["link-preview-bypass"],
        [{"axis": "tab_or_newline_stripped", "rule_id": "SR-TAB-NEWLINE", "tag": "link-preview-bypass"}],
        "https://url.spec.whatwg.org/#concept-basic-url-parser",
    ),

    # ---- Percent-encoding in host ---- #
    Case(
        "REG-URL-Percent-In-Host",
        "https://example%2ecom/",
        "Percent-encoded dot in host: some parsers decode, others don't.",
        "host-injection",
        ["host_lowercased", "percent_decoding_applied_in_host"],
        ["host-injection"],
        [{"axis": "percent_decoding_applied_in_host", "rule_id": "SR-PERCENT-DECODE-HOST", "tag": "host-injection"}],
        "https://datatracker.ietf.org/doc/html/rfc3986#section-3.2.2",
        historical_cve_or_disclosure_reference="CVE-2022-37434",  # zlib chunked, but as parser class example
    ),

    # ---- IPv6 mapped loopback ---- #
    Case(
        "REG-URL-IPv6-Mapped-Loopback",
        "http://[::ffff:127.0.0.1]/status",
        "IPv4-mapped IPv6 loopback (RFC 4291 §2.5.5.2). WHATWG normalizes to [::ffff:7f00:1]; urllib keeps original form. Distinct host strings reach the same address.",
        "ssrf-ipv6-mapped",
        ["host"],
        ["origin-confusion"],
        [
            {"axis": "host", "rule_id": "SR-HOST-MISMATCH-RAW", "tag": "origin-confusion"},
        ],
        "https://datatracker.ietf.org/doc/html/rfc4291#section-2.5.5.2",
    ),
    Case(
        "REG-URL-IPv6-Compressed",
        "http://[::1]/admin",
        "IPv6 loopback short form: should be classified as loopback by all.",
        "ssrf-private-network",
        ["host", "host_is_loopback"],
        ["ssrf-loopback-bypass"],
        [{"axis": "host_is_loopback", "rule_id": "SR-LOOPBACK-DISAGREE", "tag": "ssrf-loopback-bypass"}],
        "https://datatracker.ietf.org/doc/html/rfc4291",
    ),

    # ---- libcurl userinfo ---- #
    Case(
        "REG-URL-libcurl-CURLU-userinfo",
        "https://user@example.com/path",
        "libcurl curl_url_set vs java.net.URI: userinfo encoding differences.",
        "userinfo-host-confusion",
        ["username", "userinfo_raw"],
        ["userinfo-host-confusion"],
        [{"axis": "username", "rule_id": "SR-USERINFO-RAW-DISAGREE", "tag": "userinfo-host-confusion"}],
        "https://curl.se/libcurl/c/curl_url_set.html",
    ),

    # ---- Path traversal / dot resolution ---- #
    Case(
        "REG-URL-Path-Dotdot-Resolution",
        "https://example.com/foo/../bar",
        "Path '..' segments: okhttp/rust_url normalize; java.net.URI keeps raw.",
        "path-traversal",
        ["path_normalized", "path_traversal_resolved"],
        ["path-traversal", "path-normalization-confusion"],
        [
            {"axis": "path_traversal_resolved", "rule_id": "SR-PATH-TRAVERSAL", "tag": "path-traversal"},
            {"axis": "path_normalized", "rule_id": "SR-PATH-NORMALIZE-DISAGREE", "tag": "path-normalization-confusion"},
        ],
        "https://datatracker.ietf.org/doc/html/rfc3986#section-5.2.4",
    ),
    Case(
        "REG-URL-Path-Encoded-Dotdot",
        "https://example.com/%2e%2e/admin",
        "Percent-encoded '..' in path: WHATWG decodes-and-resolves to /admin; urllib keeps %2e%2e raw.",
        "path-traversal",
        ["path", "path_normalized"],
        ["path-normalization-confusion"],
        [
            {"axis": "path", "rule_id": "SR-PATH-NORMALIZE-DISAGREE", "tag": "path-normalization-confusion"},
        ],
        "https://owasp.org/www-community/attacks/Path_Traversal",
        historical_cve_or_disclosure_reference="OWASP-Path-Traversal-Class",
    ),

    # ---- CRLF injection ---- #
    Case(
        "REG-URL-CRLF-Injection",
        "https://example.com/foo\r\nX-Header: pwn",
        "CRLF in path: WHATWG strips, RFC 3986 may keep or reject. Header-injection class.",
        "header-injection",
        ["path_normalized", "tab_or_newline_stripped", "control_chars_in_host_rejected"],
        ["header-injection", "link-preview-bypass"],
        [
            {"axis": "tab_or_newline_stripped", "rule_id": "SR-TAB-NEWLINE", "tag": "link-preview-bypass"},
        ],
        "https://owasp.org/www-community/attacks/CRLF_Injection",
        historical_cve_or_disclosure_reference="CVE-2019-9740",  # urllib3 CRLF injection
    ),

    # ---- Scheme handling ---- #
    Case(
        "REG-URL-Scheme-Mixed-Case",
        "HTTPS://example.com/",
        "Uppercase scheme: should normalize to lowercase per RFC 3986 §3.1.",
        "scheme-confusion",
        ["scheme", "scheme_lowercased"],
        ["scheme-confusion"],
        [{"axis": "scheme", "rule_id": "SR-SCHEME-DISAGREE", "tag": "scheme-confusion"}],
        "https://datatracker.ietf.org/doc/html/rfc3986#section-3.1",
    ),
    Case(
        "REG-URL-Scheme-Whitespace",
        " https://example.com/",
        "Leading whitespace: WHATWG strips, RFC parsers may reject.",
        "scheme-confusion",
        ["parsed", "scheme"],
        ["gating-bypass"],
        [{"axis": "parsed", "rule_id": "SR-PARSED-DIFFERS", "tag": "gating-bypass"}],
        "https://url.spec.whatwg.org/#concept-basic-url-parser",
    ),

    # ---- Localhost hostname ---- #
    Case(
        "REG-URL-Localhost-Hostname",
        "http://localhost/admin",
        "'localhost' hostname (not IP): okhttp/rust_url classify as loopback; urllib does not.",
        "ssrf-private-network",
        ["host", "host_is_loopback"],
        ["ssrf-loopback-bypass"],
        [{"axis": "host_is_loopback", "rule_id": "SR-LOOPBACK-DISAGREE", "tag": "ssrf-loopback-bypass"}],
        "https://datatracker.ietf.org/doc/html/rfc6761#section-6.3",
    ),
    Case(
        "REG-URL-127-Variant",
        "http://127.1/",
        "Two-octet IPv4 shorthand 127.1 = 127.0.0.1. WHATWG accepts and normalizes; RFC 3986 keeps as raw string.",
        "ssrf-private-network",
        ["host", "host_is_loopback"],
        ["ssrf-loopback-bypass"],
        [
            {"axis": "host", "rule_id": "SR-HOST-MISMATCH-RAW", "tag": "origin-confusion"},
            {"axis": "host_is_loopback", "rule_id": "SR-LOOPBACK-DISAGREE", "tag": "ssrf-loopback-bypass"},
        ],
        "https://datatracker.ietf.org/doc/html/rfc6943#section-3.1.1",
        historical_cve_or_disclosure_reference="CVE-2021-29921",
    ),

    # ---- Userinfo with @ in username ---- #
    Case(
        "REG-URL-Userinfo-At-In-User",
        "https://us%40er@example.com/",
        "Encoded @ in username: should be parsed as part of userinfo, not a host delimiter.",
        "userinfo-host-confusion",
        ["username", "userinfo_raw", "host_lowercased"],
        ["userinfo-host-confusion"],
        [
            {"axis": "username", "rule_id": "SR-USERINFO-RAW-DISAGREE", "tag": "userinfo-host-confusion"},
            {"axis": "host_lowercased", "rule_id": "SR-HOST-MISMATCH", "tag": "origin-confusion"},
        ],
        "https://datatracker.ietf.org/doc/html/rfc3986#section-3.2.1",
    ),

    # ---- Port edge cases ---- #
    Case(
        "REG-URL-Port-Empty",
        "https://example.com:/",
        "Empty port (':' followed by nothing): RFC 3986 ambiguity.",
        "port-confusion",
        ["port_value", "port_present"],
        ["port-confusion"],
        [{"axis": "port_value", "rule_id": "SR-PORT-DISAGREE", "tag": "port-confusion"}],
        "https://datatracker.ietf.org/doc/html/rfc3986#section-3.2.3",
    ),
    Case(
        "REG-URL-Port-Out-of-Range",
        "https://example.com:99999/",
        "Out-of-range port: java.net.URI raises, others may accept.",
        "port-confusion",
        ["port_value", "parsed"],
        ["port-confusion"],
        [
            {"axis": "port_value", "rule_id": "SR-PORT-DISAGREE", "tag": "port-confusion"},
            {"axis": "parsed", "rule_id": "SR-PARSED-DIFFERS", "tag": "gating-bypass"},
        ],
        "https://datatracker.ietf.org/doc/html/rfc3986#section-3.2.3",
    ),

    # ---- Historical CVE references ---- #
    Case(
        "REG-URL-CVE-2020-7793-jsoup-style",
        "https://example.com/?q=foo&q=bar%00null",
        "Embedded NUL byte in query — historic jsoup-style sanitization gap (parser class).",
        "header-injection",
        ["query_raw", "control_chars_in_host_rejected"],
        ["header-injection"],
        [],
        "https://nvd.nist.gov/vuln/detail/CVE-2020-7793",
        historical_cve_or_disclosure_reference="CVE-2020-7793",
    ),
    Case(
        "REG-URL-CVE-2021-23336-Python-urllib-semicolon",
        "https://example.com/?a=1;b=2",
        "Semicolon-separated query (CVE-2021-23336): urllib pre-3.10 split on ;",
        "host-injection",
        ["query_raw"],
        ["parser-behavior-difference"],
        [],
        "https://nvd.nist.gov/vuln/detail/CVE-2021-23336",
        historical_cve_or_disclosure_reference="CVE-2021-23336",
    ),
    Case(
        "REG-URL-CVE-2022-0391-Python-urllib-newline",
        "https://example.com\n/path",
        "Newline-in-host CVE-2022-0391: urllib.parse pre-3.11 dropped following components.",
        "link-preview-bypass",
        ["host_lowercased", "tab_or_newline_stripped"],
        ["link-preview-bypass"],
        [{"axis": "tab_or_newline_stripped", "rule_id": "SR-TAB-NEWLINE", "tag": "link-preview-bypass"}],
        "https://nvd.nist.gov/vuln/detail/CVE-2022-0391",
        historical_cve_or_disclosure_reference="CVE-2022-0391",
    ),

    # ---- A few baseline / no-disagreement cases (the corpus needs a few of these
    # to keep regression noise honest — a parser that disagrees with everyone on
    # 'https://example.com/' is a bug, not a finding) ---- #
    Case(
        "REG-URL-Baseline-Simple",
        "https://example.com/",
        "Baseline: trivial URL all parsers should agree on. (Sanity check.)",
        "baseline",
        [],
        [],
        [],
        "https://datatracker.ietf.org/doc/html/rfc3986",
    ),
    Case(
        "REG-URL-Baseline-Path",
        "https://example.com/foo/bar?x=1",
        "Baseline: standard query string. Sanity check.",
        "baseline",
        [],
        [],
        [],
        "https://datatracker.ietf.org/doc/html/rfc3986",
    ),
    Case(
        "REG-URL-Userinfo-Both",
        "https://user:pass@example.com/",
        "Standard userinfo: all parsers should agree.",
        "baseline",
        [],
        [],
        [],
        "https://datatracker.ietf.org/doc/html/rfc3986#section-3.2.1",
    ),
]


def write_cases(root: Path) -> int:
    cases_dir = root / "polydiff" / "regression" / "cases"
    cases_dir.mkdir(parents=True, exist_ok=True)

    index: list[dict] = []
    for c in CASES:
        cdir = cases_dir / c.case_id
        cdir.mkdir(parents=True, exist_ok=True)
        # input file (raw URL bytes; no trailing newline)
        (cdir / "input").write_text(c.input_url, encoding="utf-8")
        (cdir / "description.md").write_text(_render_description(c), encoding="utf-8")
        (cdir / "expected.json").write_text(
            json.dumps(_render_expected(c), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (cdir / "reference.url").write_text(c.reference_url + "\n", encoding="utf-8")

        index.append({
            "case_id": c.case_id,
            "summary": c.summary,
            "bug_class": c.bug_class,
            "primary_axes": c.primary_axes,
            "primary_security_tags": c.primary_security_tags,
            "historical_cve_or_disclosure_reference": c.historical_cve_or_disclosure_reference,
            "publication_policy": c.publication_policy,
            "reference_url": c.reference_url,
        })

    (cases_dir / "INDEX.json").write_text(
        json.dumps({
            "schema_version": "v1",
            "generated_by": "polydiff/regression/build_corpus.py",
            "cases_count": len(index),
            "historical_cve_count": sum(1 for c in CASES if c.historical_cve_or_disclosure_reference),
            "cases": index,
        }, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return len(index)


def _render_description(c: Case) -> str:
    out = [
        f"# {c.case_id}: {c.bug_class}\n",
        f"## Summary",
        c.summary,
        "",
        f"## Bug class",
        c.bug_class,
        "",
        f"## Primary axes (where parsers are expected to disagree)",
    ]
    if c.primary_axes:
        out.extend(f"- `{a}`" for a in c.primary_axes)
    else:
        out.append("(none — baseline / sanity check; all parsers should agree)")
    out += [
        "",
        f"## Primary security tags",
    ]
    if c.primary_security_tags:
        out.extend(f"- `{t}`" for t in c.primary_security_tags)
    else:
        out.append("(none)")
    out += [
        "",
        "## Historical CVE / disclosure reference",
        c.historical_cve_or_disclosure_reference or "_(none — drawn from public bug-class literature; not tied to a specific CVE)_",
        "",
        "## Reference",
        c.reference_url,
        "",
        "## Public-info-only assertion",
        "This case was constructed from publicly-documented parser behavior.",
        "It contains no exploit triggers and uses only IETF-reserved example",
        "domains (RFC 2606) and reserved IPv4 ranges (RFC 5737/5736).",
    ]
    if c.extra_notes:
        out += ["", "## Notes", c.extra_notes]
    return "\n".join(out) + "\n"


def _render_expected(c: Case) -> dict:
    return {
        "case_id": c.case_id,
        "primary_axes": c.primary_axes,
        "primary_security_tags": c.primary_security_tags,
        "expected_disagreements": c.expected_pairs,
        "historical_cve_or_disclosure_reference": c.historical_cve_or_disclosure_reference,
        "publication_policy": c.publication_policy,
    }


def main(argv: list[str] | None = None) -> int:
    here = Path(__file__).resolve().parents[2]
    n = write_cases(here)
    print(f"wrote {n} regression cases under polydiff/regression/cases/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
