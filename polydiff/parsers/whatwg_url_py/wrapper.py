#!/usr/bin/env python3
r"""PolyDiff parser wrapper for the Python `whatwg-url` package.

Subprocess oracle, per SPEC 5.3, replacing the in-process
`parse_whatwg_like` shim from the legacy `aegisgraph/polydiff.py`.

The `whatwg-url` PyPI package implements the WHATWG URL Living Standard,
which is the spec implemented by browsers. It diverges from
`urllib.parse` (RFC 3986) in many security-relevant ways:

- Backslashes in special-scheme URLs are converted to forward slashes
  (e.g. https:\\example.com\ is rewritten before host parsing).
- Tabs and newlines are stripped.
- Trailing dots in hosts are normalized.
- IDN hostnames are punycode-encoded.

This wrapper deliberately runs `whatwg-url` as a subprocess, not
in-process, so the orchestrator never imports a parser library.

stdin  : up to 64 KiB UTF-8
stdout : v2 fact-vector envelope (one JSON line)
exit 0 : parse-or-error
exit !0: wrapper crash
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys

try:
    from whatwg_url import parse_url  # type: ignore[import-not-found]
except Exception as exc:  # pragma: no cover - environment-dependent
    parse_url = None
    _IMPORT_ERROR: str | None = f"whatwg_url package missing or broken: {exc!r}"
else:
    _IMPORT_ERROR = None


def _is_ipv4(host: str | None) -> bool | None:
    if host is None:
        return None
    try:
        ipaddress.IPv4Address(host)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def _is_ipv6(host: str | None) -> bool | None:
    if host is None:
        return None
    candidate = host.strip("[]")
    try:
        ipaddress.IPv6Address(candidate)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def _is_private_or_link_local(host: str | None) -> bool:
    if not host:
        return False
    candidate = host.strip("[]")
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def _is_loopback(host: str | None) -> bool | None:
    if host is None:
        return None
    candidate = host.strip("[]")
    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        if candidate.lower() == "localhost":
            return True
        return False


def parse(input_id: str, raw_url: str) -> dict[str, object]:
    if parse_url is None:
        return _empty_envelope(
            input_id, raw_url, errors=[_IMPORT_ERROR or "whatwg_url unavailable"]
        )

    errors: list[str] = []
    warnings: list[str] = [
        # whatwg-url tells us scheme/host/etc. but not which transformations
        # it performed; we reflect that honestly.
        "axis 'tab_or_newline_stripped' implied by spec, not directly observable from API",
        "axis 'control_chars_in_host_rejected' implied by spec, not directly observable from API",
    ]

    try:
        url = parse_url(raw_url)
    except Exception as exc:
        errors.append(f"whatwg_url.parse_url raised {type(exc).__name__}: {exc}")
        return _empty_envelope(input_id, raw_url, errors=errors, warnings=warnings)

    scheme = url.scheme.lower() if url.scheme else None
    host_raw = url.host
    host = host_raw.lower() if host_raw else None
    port = url.port if url.port is not None else None
    username = url.username or None
    password = url.password or None
    userinfo_raw = None
    if username or password:
        userinfo_raw = (username or "") + (":" + (password or "") if password is not None else "")

    is_ip4 = _is_ipv4(host)
    is_ip6 = _is_ipv6(host)
    has_idn = bool(host_raw and host_raw.startswith("xn--"))
    punycode = host_raw if has_idn else None

    # Input-driven axes (only report when the relevant feature is in the
    # input AND the parser observably acted on it).
    input_has_tab_or_newline = any(c in raw_url for c in "\t\n\r")
    input_has_backslash = "\\" in raw_url
    input_has_dotdot = "/../" in raw_url or raw_url.endswith("/..") or "/./" in raw_url
    serialized = str(url)

    tab_or_newline_stripped: bool | None = None
    if input_has_tab_or_newline:
        tab_or_newline_stripped = not any(c in serialized for c in "\t\n\r")

    backslash_treated_as_slash: bool | None = None
    if input_has_backslash:
        backslash_treated_as_slash = "\\" not in serialized

    path_traversal_resolved: bool | None = None
    if input_has_dotdot:
        path_traversal_resolved = "/.." not in (url.path or "") and "/." not in (url.path or "")

    raw_host_in_input = ""
    if "://" in raw_url:
        after_scheme = raw_url.split("://", 1)[1]
        raw_host_in_input = after_scheme.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].split("@")[-1].split(":")[0]

    leading_zeroes_in_octets_stripped: bool | None = None
    if raw_host_in_input and any(p.startswith("0") and len(p) > 1 and p.isdigit() for p in raw_host_in_input.split(".")):
        leading_zeroes_in_octets_stripped = host is not None and not any(
            p.startswith("0") and len(p) > 1 and p.isdigit() for p in (host or "").split(".")
        )

    percent_decoding_applied_in_host: bool | None = None
    if "%" in raw_host_in_input:
        percent_decoding_applied_in_host = host is not None and "%" not in host

    percent_decoding_applied_in_path: bool | None = None
    if url.path and "%" in (url.path or ""):
        # WHATWG keeps percent-encoding in the path
        percent_decoding_applied_in_path = False

    control_chars_in_host_rejected: bool | None = None
    if any(0 <= ord(c) < 0x20 for c in (raw_host_in_input or "")):
        # WHATWG strips tab/CR/LF from the URL before parsing the host;
        # other control chars are kept (they will produce a punycode
        # error at host-parse). Treat "stripped" tab/cr/lf as
        # observability - control chars per se are not rejected.
        control_chars_in_host_rejected = False

    return {
        "schema_version": "v2",
        "input_id": input_id,
        "parser_profile": "whatwg_url_py",
        "parsed": True,
        "errors": errors,
        "warnings": warnings,
        "scheme": scheme,
        "scheme_lowercased": scheme,
        "userinfo_present": bool(username or password),
        "userinfo_raw": userinfo_raw,
        "username": username,
        "password_present": password is not None,
        "host": host,
        "host_raw": host_raw,
        "host_lowercased": host,
        "host_decoded": host,
        "host_is_ip_literal": (is_ip4 or is_ip6) if host else None,
        "host_is_ipv4": is_ip4,
        "host_is_ipv6": is_ip6,
        "host_is_ipvFuture": False,
        "host_is_loopback": _is_loopback(host),
        "host_is_private_or_link_local": _is_private_or_link_local(host),
        "host_has_idn": has_idn,
        "host_punycode": punycode,
        "port": port,
        "port_present": port is not None,
        "port_value": port,
        "port_default_inferred": _default_port_for(scheme),
        "path": url.path or None,
        "path_raw": url.path or None,
        "path_normalized": url.path or None,
        "path_traversal_resolved": path_traversal_resolved,
        "query_raw": url.query or None,
        "query_pairs": _parse_query(url.query or ""),
        "fragment_raw": url.fragment or None,
        "percent_decoding_applied_in_host": percent_decoding_applied_in_host,
        "percent_decoding_applied_in_path": percent_decoding_applied_in_path,
        "trailing_slash_normalized": None,
        "leading_zeroes_in_octets_stripped": leading_zeroes_in_octets_stripped,
        "tab_or_newline_stripped": tab_or_newline_stripped,
        "backslash_treated_as_slash": backslash_treated_as_slash,
        "control_chars_in_host_rejected": control_chars_in_host_rejected,
        "scheme_authority_separator_strict": None,
        "raw_serialized": serialized,
        "parse_error": None,
    }


def _empty_envelope(
    input_id: str, raw_url: str, errors: list[str], warnings: list[str] | None = None
) -> dict[str, object]:
    return {
        "schema_version": "v2",
        "input_id": input_id,
        "parser_profile": "whatwg_url_py",
        "parsed": False,
        "errors": errors,
        "warnings": warnings or [],
        "scheme": None,
        "scheme_lowercased": None,
        "userinfo_present": False,
        "userinfo_raw": None,
        "username": None,
        "password_present": False,
        "host": None,
        "host_raw": None,
        "host_lowercased": None,
        "host_decoded": None,
        "host_is_ip_literal": None,
        "host_is_ipv4": None,
        "host_is_ipv6": None,
        "host_is_ipvFuture": None,
        "host_is_loopback": None,
        "host_is_private_or_link_local": False,
        "host_has_idn": None,
        "host_punycode": None,
        "port": None,
        "port_present": None,
        "port_value": None,
        "port_default_inferred": None,
        "path": None,
        "path_raw": None,
        "path_normalized": None,
        "path_traversal_resolved": None,
        "query_raw": None,
        "query_pairs": None,
        "fragment_raw": None,
        "percent_decoding_applied_in_host": None,
        "percent_decoding_applied_in_path": None,
        "trailing_slash_normalized": None,
        "leading_zeroes_in_octets_stripped": None,
        "tab_or_newline_stripped": None,
        "backslash_treated_as_slash": None,
        "control_chars_in_host_rejected": None,
        "scheme_authority_separator_strict": None,
        "raw_serialized": None,
        "parse_error": (errors[0] if errors else "parse_error"),
    }


def _default_port_for(scheme: str | None) -> int | None:
    if not scheme:
        return None
    return {"http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21}.get(scheme.lower())


def _parse_query(query: str) -> list[dict[str, str]]:
    if not query:
        return []
    out: list[dict[str, str]] = []
    for raw in query.split("&"):
        if "=" in raw:
            k, v = raw.split("=", 1)
        else:
            k, v = raw, ""
        out.append({"key": k, "value": v})
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-id", required=True)
    args = parser.parse_args(argv)

    raw = sys.stdin.buffer.read(64 * 1024)
    try:
        url = raw.decode("utf-8", errors="replace")
    except Exception as exc:  # pragma: no cover
        print(json.dumps({"error": f"decode failed: {exc}"}))
        return 2

    fv = parse(args.input_id, url)
    sys.stdout.write(json.dumps(fv, ensure_ascii=True))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
