// PolyDiff parser wrapper for java.net.URI (JDK 21).
//
// Subprocess oracle, per SPEC §5.3.
//   stdin  : up to 64 KiB UTF-8
//   stdout : v2 fact-vector envelope (one JSON line)
//   exit 0 : parse-or-error (parser's verdict)
//   exit !=0 : wrapper crash
//
// This wrapper uses ONLY the JDK standard library (no Maven, no Gradle,
// no third-party jars) so it builds in the pinned devcontainer with
// just `javac`.
//
// Compile:
//   javac Wrapper.java
// Run:
//   echo -n 'https://example.com/foo' | java -cp . Wrapper --input-id ID

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

public class Wrapper {
    private static final int MAX_BYTES = 64 * 1024;

    public static void main(String[] args) throws IOException {
        String inputId = parseInputId(args);
        String raw = readStdin();
        String json = parse(inputId, raw);
        System.out.println(json);
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
        warnings.add("axis 'host_has_idn' not directly observable by parser 'jdk_uri'");
        warnings.add("axis 'host_punycode' not directly observable by parser 'jdk_uri'");
        warnings.add("axis 'control_chars_in_host_rejected' not directly observable by parser 'jdk_uri'");

        URI uri;
        try {
            uri = new URI(raw);
        } catch (URISyntaxException ex) {
            errors.add("java.net.URI: " + ex.getMessage());
            return emptyEnvelope(inputId, errors, warnings);
        }

        String scheme = uri.getScheme();
        String host = uri.getHost();
        // java.net.URI does NOT lowercase host on construction; getHost()
        // returns case-preserving.
        String userInfo = uri.getUserInfo();
        String username = null;
        boolean passwordPresent = false;
        if (userInfo != null) {
            int colon = userInfo.indexOf(':');
            if (colon >= 0) {
                username = userInfo.substring(0, colon);
                passwordPresent = colon + 1 < userInfo.length();
            } else {
                username = userInfo;
            }
        }
        int rawPort = uri.getPort();
        Integer port = (rawPort == -1) ? null : rawPort;
        String path = uri.getRawPath();
        String query = uri.getRawQuery();
        String fragment = uri.getRawFragment();

        boolean userinfoPresent = userInfo != null;
        boolean isIPv4 = host != null && isIPv4Literal(host);
        boolean isIPv6 = host != null && (host.startsWith("[") && host.endsWith("]"));
        boolean isIpLit = isIPv4 || isIPv6;
        boolean isLoopback = isIPv4 && host.startsWith("127.");
        boolean isPrivate = isPrivateOrLinkLocal(host);

        StringBuilder b = new StringBuilder(2048);
        b.append('{');
        appendKV(b, "schema_version", "v2"); b.append(',');
        appendKV(b, "input_id", inputId); b.append(',');
        appendKV(b, "parser_profile", "jdk_uri"); b.append(',');
        appendBool(b, "parsed", true); b.append(',');
        appendStringArray(b, "errors", errors); b.append(',');
        appendStringArray(b, "warnings", warnings); b.append(',');
        appendKV(b, "scheme", scheme); b.append(',');
        appendKV(b, "scheme_lowercased", scheme == null ? null : scheme.toLowerCase()); b.append(',');
        appendBool(b, "userinfo_present", userinfoPresent); b.append(',');
        appendKV(b, "userinfo_raw", userInfo); b.append(',');
        appendKV(b, "username", username); b.append(',');
        appendBool(b, "password_present", passwordPresent); b.append(',');
        appendKV(b, "host", host); b.append(',');
        appendKV(b, "host_raw", host); b.append(',');
        appendKV(b, "host_lowercased", host == null ? null : host.toLowerCase()); b.append(',');
        appendKV(b, "host_decoded", host); b.append(',');
        appendBool(b, "host_is_ip_literal", host == null ? null : isIpLit); b.append(',');
        appendBool(b, "host_is_ipv4", host == null ? null : isIPv4); b.append(',');
        appendBool(b, "host_is_ipv6", host == null ? null : isIPv6); b.append(',');
        appendBool(b, "host_is_ipvFuture", host == null ? null : false); b.append(',');
        appendBool(b, "host_is_loopback", host == null ? null : isLoopback); b.append(',');
        appendBool(b, "host_is_private_or_link_local", isPrivate); b.append(',');
        appendNull(b, "host_has_idn"); b.append(',');
        appendNull(b, "host_punycode"); b.append(',');
        appendInt(b, "port", port); b.append(',');
        appendBool(b, "port_present", port != null); b.append(',');
        appendInt(b, "port_value", port); b.append(',');
        appendInt(b, "port_default_inferred", defaultPortFor(scheme)); b.append(',');
        appendKV(b, "path", path); b.append(',');
        appendKV(b, "path_raw", path); b.append(',');
        appendKV(b, "path_normalized", path); b.append(',');
        appendBool(b, "path_traversal_resolved", false); b.append(',');
        appendKV(b, "query_raw", query); b.append(',');
        appendKey(b, "query_pairs"); b.append("[]"); b.append(',');
        appendKV(b, "fragment_raw", fragment); b.append(',');
        appendBool(b, "percent_decoding_applied_in_host", false); b.append(',');
        appendBool(b, "percent_decoding_applied_in_path", false); b.append(',');
        appendBool(b, "trailing_slash_normalized", false); b.append(',');
        appendBool(b, "leading_zeroes_in_octets_stripped", false); b.append(',');
        // java.net.URI does NOT strip tabs/newlines; it raises URISyntaxException
        // on most control chars, but not all; report null to be honest.
        appendNull(b, "tab_or_newline_stripped"); b.append(',');
        appendBool(b, "backslash_treated_as_slash", false); b.append(',');
        appendNull(b, "control_chars_in_host_rejected"); b.append(',');
        appendBool(b, "scheme_authority_separator_strict", true); b.append(',');
        appendKV(b, "raw_serialized", uri.toString()); b.append(',');
        appendKV(b, "parse_error", null);
        b.append('}');
        return b.toString();
    }

    private static String emptyEnvelope(String inputId, List<String> errors, List<String> warnings) {
        StringBuilder b = new StringBuilder(1024);
        b.append('{');
        appendKV(b, "schema_version", "v2"); b.append(',');
        appendKV(b, "input_id", inputId); b.append(',');
        appendKV(b, "parser_profile", "jdk_uri"); b.append(',');
        appendBool(b, "parsed", false); b.append(',');
        appendStringArray(b, "errors", errors); b.append(',');
        appendStringArray(b, "warnings", warnings); b.append(',');
        for (String key : new String[]{
                "scheme","scheme_lowercased","userinfo_raw","username","host","host_raw",
                "host_lowercased","host_decoded","host_punycode","path","path_raw",
                "path_normalized","query_raw","fragment_raw","raw_serialized",
                "parse_error"
        }) {
            appendKV(b, key, key.equals("parse_error") ? (errors.isEmpty() ? null : errors.get(0)) : null);
            b.append(',');
        }
        for (String key : new String[]{
                "userinfo_present","password_present","host_is_private_or_link_local",
                "trailing_slash_normalized","percent_decoding_applied_in_host",
                "percent_decoding_applied_in_path","leading_zeroes_in_octets_stripped",
                "backslash_treated_as_slash"
        }) {
            appendBool(b, key, false); b.append(',');
        }
        for (String key : new String[]{
                "host_is_ip_literal","host_is_ipv4","host_is_ipv6","host_is_ipvFuture",
                "host_is_loopback","host_has_idn","port_present",
                "path_traversal_resolved","tab_or_newline_stripped",
                "control_chars_in_host_rejected","scheme_authority_separator_strict"
        }) {
            appendNull(b, key); b.append(',');
        }
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
        if (host == null) return false;
        if (host.startsWith("[")) return false;
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

    private static Integer defaultPortFor(String scheme) {
        if (scheme == null) return null;
        switch (scheme.toLowerCase()) {
            case "http": return 80;
            case "https": return 443;
            case "ws": return 80;
            case "wss": return 443;
            case "ftp": return 21;
            default: return null;
        }
    }

    private static void appendKey(StringBuilder b, String k) {
        b.append('"').append(escape(k)).append('"').append(':');
    }
    private static void appendKV(StringBuilder b, String k, String v) {
        appendKey(b, k);
        if (v == null) b.append("null");
        else b.append('"').append(escape(v)).append('"');
    }
    private static void appendBool(StringBuilder b, String k, Boolean v) {
        appendKey(b, k);
        if (v == null) b.append("null");
        else b.append(v.booleanValue() ? "true" : "false");
    }
    private static void appendInt(StringBuilder b, String k, Integer v) {
        appendKey(b, k);
        if (v == null) b.append("null");
        else b.append(v.intValue());
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
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else if (c > 0x7E) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        return out.toString();
    }
}
