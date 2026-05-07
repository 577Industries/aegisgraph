#!/usr/bin/env python3
"""PolyDiff parser wrapper for CPython 3.11+ stdlib urllib.parse.

Subprocess oracle, per SPEC §5.3:

  stdin  : up to 64 KiB of raw bytes (the candidate URL string, UTF-8)
  stdout : exactly one JSON line; v2 fact-vector envelope
  exit 0 : parse-or-error (parser's verdict, not infrastructure failure)
  exit !0: wrapper crash (handled as a Finding by the orchestrator)

This wrapper deliberately does NOT import any 577 Industries module. It
uses only the Python standard library so it can be containerized (or run
with a different CPython interpreter) without dragging the rest of the
repo along.

Read input_id from CLI arg --input-id (the orchestrator passes it
in). The URL itself comes from stdin to keep the contract uniform
across language runtimes.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
import urllib.parse


def _safe_port(parsed: urllib.parse.SplitResult) -> int | None:
    try:
        return parsed.port
    except ValueError:
        return None


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
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        # Hostname-based loopback (e.g. "localhost") is not directly observable
        # from urllib.parse without resolution; report null to avoid lying.
        if candidate.lower() == "localhost":
            return True
        return False
    return ip.is_loopback


def parse(input_id: str, raw_url: str) -> dict[str, object]:
    """Parse `raw_url` with urllib.parse and emit a v2 fact vector."""
    errors: list[str] = []
    warnings: list[str] = [
        "axis 'host_has_idn' not directly observable by parser 'python_urllib'",
        "axis 'host_punycode' not directly observable by parser 'python_urllib'",
        "axis 'control_chars_in_host_rejected' not directly observable by parser 'python_urllib'",
    ]
    parsed_ok = True

    try:
        parsed = urllib.parse.urlsplit(raw_url)
    except ValueError as exc:
        errors.append(f"urllib.parse.urlsplit raised ValueError: {exc}")
        parsed_ok = False
        return _empty_envelope(input_id, raw_url, errors, warnings)

    scheme = parsed.scheme or None
    host = parsed.hostname  # already lowercased by urllib
    port = _safe_port(parsed)
    if port is None and parsed.netloc:
        # urllib raises on out-of-range ports; treat as wrapper-visible error.
        if ":" in parsed.netloc.split("@", 1)[-1]:
            errors.append("urllib could not parse port (out-of-range or non-numeric)")

    userinfo_raw = None
    if parsed.username is not None or parsed.password is not None:
        # Reconstruct what was between scheme and host
        netloc = parsed.netloc
        if "@" in netloc:
            userinfo_raw = netloc.rsplit("@", 1)[0]

    is_ip4 = _is_ipv4(host)
    is_ip6 = _is_ipv6(host) or _is_ipv6(parsed.hostname or "")

    # Compute input-driven axes ("did this input exhibit X feature, and did
    # the parser act on it?"). This is materially different from
    # spec-conformance flags — we only report a boolean if the relevant
    # feature was present in the input. Otherwise: None ("no opinion").
    input_has_tab_or_newline = any(c in raw_url for c in "\t\n\r")
    input_has_backslash = "\\" in raw_url
    input_has_dotdot = "/../" in raw_url or raw_url.endswith("/..") or "/." in raw_url
    serialized = parsed.geturl()

    tab_or_newline_stripped: bool | None = None
    if input_has_tab_or_newline:
        tab_or_newline_stripped = not any(c in serialized for c in "\t\n\r")

    backslash_treated_as_slash: bool | None = None
    if input_has_backslash:
        backslash_treated_as_slash = "\\" not in serialized

    path_traversal_resolved: bool | None = None
    if input_has_dotdot:
        path_traversal_resolved = "/.." not in (parsed.path or "") and "/." not in (parsed.path or "")

    leading_zeroes_in_octets_stripped: bool | None = None
    # Heuristic: input host had a leading-zero IPv4 octet (e.g. 0177.0.0.1)
    # AND the parser produced a host without it.
    raw_host_in_input = ""
    if "://" in raw_url:
        after_scheme = raw_url.split("://", 1)[1]
        raw_host_in_input = after_scheme.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].split("@")[-1].split(":")[0]
    if raw_host_in_input and any(p.startswith("0") and len(p) > 1 and p.isdigit() for p in raw_host_in_input.split(".")):
        leading_zeroes_in_octets_stripped = host is not None and not any(
            p.startswith("0") and len(p) > 1 and p.isdigit() for p in (host or "").split(".")
        )

    percent_decoding_applied_in_host: bool | None = None
    if "%" in raw_host_in_input:
        percent_decoding_applied_in_host = host is not None and "%" not in host

    percent_decoding_applied_in_path: bool | None = None
    if parsed.path and "%" in parsed.path:
        # urllib does not percent-decode path on parse; stays raw
        percent_decoding_applied_in_path = False

    control_chars_in_host_rejected: bool | None = None
    if any(0 <= ord(c) < 0x20 for c in (raw_host_in_input or "")):
        # urllib silently keeps control chars in host
        control_chars_in_host_rejected = False

    return {
        "schema_version": "v2",
        "input_id": input_id,
        "parser_profile": "python_urllib",
        "parsed": parsed_ok,
        "errors": errors,
        "warnings": warnings,
        "scheme": scheme,
        "scheme_lowercased": scheme.lower() if scheme else None,
        "userinfo_present": bool(parsed.username or parsed.password),
        "userinfo_raw": userinfo_raw,
        "username": parsed.username,
        "password_present": parsed.password is not None,
        "host": host,
        "host_raw": parsed.hostname,
        "host_lowercased": host.lower() if host else None,
        "host_decoded": host,  # urllib does no IDN decoding
        "host_is_ip_literal": (is_ip4 or is_ip6) if host else None,
        "host_is_ipv4": is_ip4,
        "host_is_ipv6": is_ip6,
        "host_is_ipvFuture": False,
        "host_is_loopback": _is_loopback(host),
        "host_is_private_or_link_local": _is_private_or_link_local(host),
        "host_has_idn": None,
        "host_punycode": None,
        "port": port,
        "port_present": port is not None,
        "port_value": port,
        "port_default_inferred": _default_port_for(scheme),
        "path": parsed.path or None,
        "path_raw": parsed.path or None,
        "path_normalized": _normalize_path(parsed.path),
        "path_traversal_resolved": path_traversal_resolved,
        "query_raw": parsed.query or None,
        "query_pairs": _parse_query(parsed.query),
        "fragment_raw": parsed.fragment or None,
        "percent_decoding_applied_in_host": percent_decoding_applied_in_host,
        "percent_decoding_applied_in_path": percent_decoding_applied_in_path,
        "trailing_slash_normalized": None,
        "leading_zeroes_in_octets_stripped": leading_zeroes_in_octets_stripped,
        "tab_or_newline_stripped": tab_or_newline_stripped,
        "backslash_treated_as_slash": backslash_treated_as_slash,
        "control_chars_in_host_rejected": control_chars_in_host_rejected,
        "scheme_authority_separator_strict": True,
        "raw_serialized": serialized,
        "parse_error": None if parsed_ok else (errors[0] if errors else "parse_error"),
    }


def _empty_envelope(
    input_id: str, raw_url: str, errors: list[str], warnings: list[str]
) -> dict[str, object]:
    return {
        "schema_version": "v2",
        "input_id": input_id,
        "parser_profile": "python_urllib",
        "parsed": False,
        "errors": errors,
        "warnings": warnings,
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


def _normalize_path(raw: str | None) -> str | None:
    if raw is None or raw == "":
        return raw
    # urllib.parse does not resolve `.` / `..`; just return what it gave us.
    return raw


def _parse_query(query: str) -> list[dict[str, str]] | None:
    if not query:
        return [] if query == "" else None
    pairs: list[dict[str, str]] = []
    for raw in query.split("&"):
        if "=" in raw:
            k, v = raw.split("=", 1)
        else:
            k, v = raw, ""
        pairs.append({"key": k, "value": v})
    return pairs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-id", required=True)
    args = parser.parse_args(argv)

    raw_bytes = sys.stdin.buffer.read(64 * 1024)
    try:
        raw_url = raw_bytes.decode("utf-8", errors="replace")
    except Exception as exc:  # pragma: no cover - decode("replace") never raises
        print(json.dumps({"error": f"decode failed: {exc}"}))
        return 2

    fv = parse(args.input_id, raw_url)
    sys.stdout.write(json.dumps(fv, ensure_ascii=True))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
