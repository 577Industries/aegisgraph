// PolyDiff parser wrapper for okhttp3.HttpUrl (OkHttp 4.12.x).
//
// Subprocess oracle, per SPEC §5.3.
//   stdin  : up to 64 KiB UTF-8
//   stdout : v2 fact-vector envelope (one JSON line)
//   exit 0 : parse-or-error
//   exit !=0 : wrapper crash
//
// OkHttp dependency is added at Docker-build time. Compile against the
// okhttp jar on the classpath; see Dockerfile.
//
// Compile (with okhttp on classpath):
//   javac -cp okhttp.jar Wrapper.java
// Run:
//   echo -n 'https://example.com/foo' | java -cp .:okhttp.jar:okio.jar Wrapper --input-id ID

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import okhttp3.HttpUrl;

public class Wrapper {
    private static final int MAX_BYTES = 64 * 1024;

    public static void main(String[] args) throws IOException {
        String inputId = parseInputId(args);
        String raw = readStdin();
        System.out.println(parse(inputId, raw));
    }

    private static String parseInputId(String[] args) {
        for (int i = 0; i + 1 < args.length; i++) {
            if ("--input-id".equals(args[i])) {
                return args[i + 1];
            }
        }
        throw new IllegalArgumentException("missing --input-id");
    }

    private static String readStdin() throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        InputStream in = System.in;
        byte[] chunk = new byte[4096];
        int total = 0;
        int n;
        while ((n = in.read(chunk)) != -1 && total < MAX_BYTES) {
            int allow = Math.min(n, MAX_BYTES - total);
            buf.write(chunk, 0, allow);
            total += allow;
        }
        return buf.toString(java.nio.charset.StandardCharsets.UTF_8);
    }

    private static String parse(String inputId, String raw) {
        List<String> errors = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        warnings.add("axis 'host_has_idn' inferred from punycode prefix only");
        warnings.add("axis 'control_chars_in_host_rejected' - okhttp normalizes some, rejects others");

        HttpUrl url = HttpUrl.parse(raw);
        if (url == null) {
            errors.add("okhttp3.HttpUrl.parse returned null (input not a valid http(s) URL)");
            return emptyEnvelope(inputId, errors, warnings);
        }

        String scheme = url.scheme();
        String host = url.host();
        Integer port = url.port();
        String username = url.username();
        if (username.isEmpty()) username = null;
        String password = url.password();
        boolean passwordPresent = !password.isEmpty();
        String userinfoRaw = null;
        if (username != null || passwordPresent) {
            userinfoRaw = (username == null ? "" : username) + (passwordPresent ? ":" + password : "");
        }
        String path = url.encodedPath();
        String query = url.encodedQuery();
        String fragment = url.encodedFragment();

        boolean isIPv4 = isIPv4Literal(host);
        boolean isIPv6 = host != null && host.contains(":");
        boolean isIpLit = isIPv4 || isIPv6;
        boolean isLoopback = isIPv4 && host.startsWith("127.");
        boolean isPrivate = isPrivateOrLinkLocal(host);
        boolean hasIdn = host != null && (host.startsWith("xn--") || host.contains(".xn--"));
        String punycode = hasIdn ? host : null;

        StringBuilder b = new StringBuilder(2048);
        b.append('{');
        appendKV(b, "schema_version", "v2"); b.append(',');
        appendKV(b, "input_id", inputId); b.append(',');
        appendKV(b, "parser_profile", "okhttp_httpurl"); b.append(',');
        appendBool(b, "parsed", true); b.append(',');
        appendStringArray(b, "errors", errors); b.append(',');
        appendStringArray(b, "warnings", warnings); b.append(',');
        appendKV(b, "scheme", scheme); b.append(',');
        appendKV(b, "scheme_lowercased", scheme); b.append(',');
        appendBool(b, "userinfo_present", username != null || passwordPresent); b.append(',');
        appendKV(b, "userinfo_raw", userinfoRaw); b.append(',');
        appendKV(b, "username", username); b.append(',');
        appendBool(b, "password_present", passwordPresent); b.append(',');
        appendKV(b, "host", host); b.append(',');
        appendKV(b, "host_raw", host); b.append(',');
        appendKV(b, "host_lowercased", host == null ? null : host.toLowerCase()); b.append(',');
        appendKV(b, "host_decoded", host); b.append(',');
        appendBool(b, "host_is_ip_literal", isIpLit); b.append(',');
        appendBool(b, "host_is_ipv4", isIPv4); b.append(',');
        appendBool(b, "host_is_ipv6", isIPv6); b.append(',');
        appendBool(b, "host_is_ipvFuture", false); b.append(',');
        appendBool(b, "host_is_loopback", isLoopback); b.append(',');
        appendBool(b, "host_is_private_or_link_local", isPrivate); b.append(',');
        appendBool(b, "host_has_idn", hasIdn); b.append(',');
        appendKV(b, "host_punycode", punycode); b.append(',');
        appendInt(b, "port", port); b.append(',');
        appendBool(b, "port_present", port != null && port != HttpUrl.defaultPort(scheme)); b.append(',');
        appendInt(b, "port_value", port); b.append(',');
        appendInt(b, "port_default_inferred", HttpUrl.defaultPort(scheme)); b.append(',');
        appendKV(b, "path", path); b.append(',');
        appendKV(b, "path_raw", path); b.append(',');
        appendKV(b, "path_normalized", path); b.append(',');
        appendBool(b, "path_traversal_resolved", true); b.append(','); // okhttp resolves dot-segments
        appendKV(b, "query_raw", query); b.append(',');
        appendKey(b, "query_pairs"); b.append("[]"); b.append(',');
        appendKV(b, "fragment_raw", fragment); b.append(',');
        appendBool(b, "percent_decoding_applied_in_host", true); b.append(','); // okhttp normalizes IDN
        appendBool(b, "percent_decoding_applied_in_path", false); b.append(',');
        appendBool(b, "trailing_slash_normalized", false); b.append(',');
        appendBool(b, "leading_zeroes_in_octets_stripped", false); b.append(',');
        appendBool(b, "tab_or_newline_stripped", false); b.append(',');
        appendBool(b, "backslash_treated_as_slash", false); b.append(',');
        appendNull(b, "control_chars_in_host_rejected"); b.append(',');
        appendBool(b, "scheme_authority_separator_strict", true); b.append(',');
        appendKV(b, "raw_serialized", url.toString()); b.append(',');
        appendKV(b, "parse_error", null);
        b.append('}');
        return b.toString();
    }

    private static String emptyEnvelope(String inputId, List<String> errors, List<String> warnings) {
        StringBuilder b = new StringBuilder(1024);
        b.append('{');
        appendKV(b, "schema_version", "v2"); b.append(',');
        appendKV(b, "input_id", inputId); b.append(',');
        appendKV(b, "parser_profile", "okhttp_httpurl"); b.append(',');
        appendBool(b, "parsed", false); b.append(',');
        appendStringArray(b, "errors", errors); b.append(',');
        appendStringArray(b, "warnings", warnings); b.append(',');
        for (String key : new String[]{
                "scheme","scheme_lowercased","userinfo_raw","username","host","host_raw",
                "host_lowercased","host_decoded","host_punycode","path","path_raw",
                "path_normalized","query_raw","fragment_raw","raw_serialized"
        }) { appendKV(b, key, null); b.append(','); }
        appendKV(b, "parse_error", errors.isEmpty() ? null : errors.get(0)); b.append(',');
        for (String key : new String[]{
                "userinfo_present","password_present","host_is_private_or_link_local",
                "trailing_slash_normalized","percent_decoding_applied_in_host",
                "percent_decoding_applied_in_path","leading_zeroes_in_octets_stripped",
                "backslash_treated_as_slash","tab_or_newline_stripped"
        }) { appendBool(b, key, false); b.append(','); }
        for (String key : new String[]{
                "host_is_ip_literal","host_is_ipv4","host_is_ipv6","host_is_ipvFuture",
                "host_is_loopback","host_has_idn","port_present",
                "path_traversal_resolved","control_chars_in_host_rejected",
                "scheme_authority_separator_strict"
        }) { appendNull(b, key); b.append(','); }
        for (String key : new String[]{"port","port_value","port_default_inferred"}) {
            appendInt(b, key, null); b.append(',');
        }
        appendKey(b, "query_pairs"); b.append("[]");
        b.append('}');
        return b.toString();
    }

    private static boolean isIPv4Literal(String host) {
        if (host == null || host.isEmpty()) return false;
        String[] parts = host.split("\\.");
        if (parts.length != 4) return false;
        for (String p : parts) {
            if (p.isEmpty() || p.length() > 3) return false;
            for (int i = 0; i < p.length(); i++) {
                if (!Character.isDigit(p.charAt(i))) return false;
            }
            int v;
            try { v = Integer.parseInt(p); } catch (NumberFormatException e) { return false; }
            if (v < 0 || v > 255) return false;
        }
        return true;
    }

    private static boolean isPrivateOrLinkLocal(String host) {
        if (!isIPv4Literal(host)) return false;
        String[] parts = host.split("\\.");
        int o0 = Integer.parseInt(parts[0]);
        int o1 = Integer.parseInt(parts[1]);
        if (o0 == 10) return true;
        if (o0 == 127) return true;
        if (o0 == 172 && o1 >= 16 && o1 <= 31) return true;
        if (o0 == 192 && o1 == 168) return true;
        if (o0 == 169 && o1 == 254) return true;
        return false;
    }

    private static void appendKey(StringBuilder b, String k) {
        b.append('"').append(escape(k)).append('"').append(':');
    }
    private static void appendKV(StringBuilder b, String k, String v) {
        appendKey(b, k);
        if (v == null) b.append("null"); else b.append('"').append(escape(v)).append('"');
    }
    private static void appendBool(StringBuilder b, String k, Boolean v) {
        appendKey(b, k);
        if (v == null) b.append("null"); else b.append(v.booleanValue() ? "true" : "false");
    }
    private static void appendInt(StringBuilder b, String k, Integer v) {
        appendKey(b, k);
        if (v == null) b.append("null"); else b.append(v.intValue());
    }
    private static void appendNull(StringBuilder b, String k) {
        appendKey(b, k); b.append("null");
    }
    private static void appendStringArray(StringBuilder b, String k, List<String> v) {
        appendKey(b, k); b.append('[');
        for (int i = 0; i < v.size(); i++) {
            if (i > 0) b.append(',');
            b.append('"').append(escape(v.get(i))).append('"');
        }
        b.append(']');
    }
    private static String escape(String s) {
        if (s == null) return "";
        StringBuilder out = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20 || c > 0x7E) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        return out.toString();
    }
}
