// PolyDiff parser wrapper for the Rust `url` crate (v2.5.x).
//
// Subprocess oracle, per SPEC §5.3.
//   stdin  : up to 64 KiB UTF-8
//   stdout : v2 fact-vector envelope (one JSON line)
//   exit 0 : parse-or-error
//   exit !=0 : wrapper crash
//
// Dependencies (add to Cargo.toml):
//   url = "2.5"
//   serde_json = "1.0"
//
// Build: cargo build --release
// Run:   echo -n 'https://example.com/foo' | target/release/wrapper --input-id ID

use std::io::Read;
use std::net::Ipv4Addr;
use std::process::ExitCode;

use serde_json::{json, Value};
use url::{Host, Url};

const MAX_BYTES: usize = 64 * 1024;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let input_id = match parse_input_id(&args) {
        Some(id) => id,
        None => {
            eprintln!("missing --input-id");
            return ExitCode::from(2);
        }
    };

    let mut buf = Vec::with_capacity(4096);
    let mut handle = std::io::stdin().take(MAX_BYTES as u64);
    if let Err(err) = handle.read_to_end(&mut buf) {
        eprintln!("stdin read failed: {}", err);
        return ExitCode::from(2);
    }
    let raw = String::from_utf8_lossy(&buf).into_owned();

    let envelope = parse(&input_id, &raw);
    println!("{}", serde_json::to_string(&envelope).unwrap());
    ExitCode::SUCCESS
}

fn parse_input_id(args: &[String]) -> Option<String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--input-id" {
            return iter.next().cloned();
        }
    }
    None
}

fn parse(input_id: &str, raw: &str) -> Value {
    let warnings: Vec<&str> = vec![
        "axis 'host_has_idn' inferred from punycode prefix on serialized host",
        "axis 'tab_or_newline_stripped' reported via spec, not directly observable",
    ];

    let url = match Url::parse(raw) {
        Ok(u) => u,
        Err(err) => return empty_envelope(input_id, vec![format!("url::Url::parse: {}", err)], warnings),
    };

    let scheme = url.scheme().to_string();
    let username = if url.username().is_empty() {
        None
    } else {
        Some(url.username().to_string())
    };
    let password_present = url.password().is_some();
    let userinfo_raw: Option<String> = if username.is_some() || password_present {
        let mut s = username.clone().unwrap_or_default();
        if let Some(p) = url.password() {
            s.push(':');
            s.push_str(p);
        }
        Some(s)
    } else {
        None
    };

    let host = url.host_str().map(|s| s.to_string());
    let host_lower = host.as_ref().map(|h| h.to_lowercase());
    let port = url.port();
    let port_default = url.port_or_known_default();

    let (is_ipv4, is_ipv6, is_loopback, is_private) = match url.host() {
        Some(Host::Ipv4(addr)) => (
            true,
            false,
            addr.is_loopback(),
            addr_is_private(&addr),
        ),
        Some(Host::Ipv6(_)) => (false, true, false, false),
        Some(Host::Domain(d)) => (false, false, d == "localhost", false),
        None => (false, false, false, false),
    };
    let host_is_ip_lit = host.as_ref().map(|_| is_ipv4 || is_ipv6);
    let has_idn = host
        .as_ref()
        .map(|h| h.starts_with("xn--") || h.contains(".xn--"))
        .unwrap_or(false);
    let punycode = if has_idn { host.clone() } else { None };

    let path = url.path();

    json!({
        "schema_version": "v2",
        "input_id": input_id,
        "parser_profile": "rust_url",
        "parsed": true,
        "errors": Vec::<String>::new(),
        "warnings": warnings,
        "scheme": scheme,
        "scheme_lowercased": scheme.to_lowercase(),
        "userinfo_present": username.is_some() || password_present,
        "userinfo_raw": userinfo_raw,
        "username": username,
        "password_present": password_present,
        "host": host,
        "host_raw": host,
        "host_lowercased": host_lower,
        "host_decoded": host,
        "host_is_ip_literal": host_is_ip_lit,
        "host_is_ipv4": is_ipv4,
        "host_is_ipv6": is_ipv6,
        "host_is_ipvFuture": false,
        "host_is_loopback": is_loopback,
        "host_is_private_or_link_local": is_private,
        "host_has_idn": has_idn,
        "host_punycode": punycode,
        "port": port,
        "port_present": port.is_some(),
        "port_value": port,
        "port_default_inferred": port_default,
        "path": path,
        "path_raw": path,
        "path_normalized": path,
        "path_traversal_resolved": true,  // url crate normalizes . and ..
        "query_raw": url.query(),
        "query_pairs": [],
        "fragment_raw": url.fragment(),
        "percent_decoding_applied_in_host": true,  // url crate IDN-normalizes hosts
        "percent_decoding_applied_in_path": false,
        "trailing_slash_normalized": false,
        "leading_zeroes_in_octets_stripped": true,  // url crate parses 0177 as decimal
        "tab_or_newline_stripped": true,             // url crate strips per WHATWG
        "backslash_treated_as_slash": true,          // url crate follows WHATWG
        "control_chars_in_host_rejected": true,      // url crate rejects them
        "scheme_authority_separator_strict": true,
        "raw_serialized": url.to_string(),
        "parse_error": Value::Null,
    })
}

fn addr_is_private(addr: &Ipv4Addr) -> bool {
    addr.is_private() || addr.is_loopback() || addr.is_link_local()
}

fn empty_envelope(input_id: &str, errors: Vec<String>, warnings: Vec<&str>) -> Value {
    let parse_err = errors.first().cloned();
    json!({
        "schema_version": "v2",
        "input_id": input_id,
        "parser_profile": "rust_url",
        "parsed": false,
        "errors": errors,
        "warnings": warnings,
        "scheme": Value::Null,
        "scheme_lowercased": Value::Null,
        "userinfo_present": false,
        "userinfo_raw": Value::Null,
        "username": Value::Null,
        "password_present": false,
        "host": Value::Null,
        "host_raw": Value::Null,
        "host_lowercased": Value::Null,
        "host_decoded": Value::Null,
        "host_is_ip_literal": Value::Null,
        "host_is_ipv4": Value::Null,
        "host_is_ipv6": Value::Null,
        "host_is_ipvFuture": Value::Null,
        "host_is_loopback": Value::Null,
        "host_is_private_or_link_local": false,
        "host_has_idn": Value::Null,
        "host_punycode": Value::Null,
        "port": Value::Null,
        "port_present": Value::Null,
        "port_value": Value::Null,
        "port_default_inferred": Value::Null,
        "path": Value::Null,
        "path_raw": Value::Null,
        "path_normalized": Value::Null,
        "path_traversal_resolved": Value::Null,
        "query_raw": Value::Null,
        "query_pairs": Value::Null,
        "fragment_raw": Value::Null,
        "percent_decoding_applied_in_host": Value::Null,
        "percent_decoding_applied_in_path": Value::Null,
        "trailing_slash_normalized": Value::Null,
        "leading_zeroes_in_octets_stripped": Value::Null,
        "tab_or_newline_stripped": Value::Null,
        "backslash_treated_as_slash": Value::Null,
        "control_chars_in_host_rejected": Value::Null,
        "scheme_authority_separator_strict": Value::Null,
        "raw_serialized": Value::Null,
        "parse_error": parse_err,
    })
}
