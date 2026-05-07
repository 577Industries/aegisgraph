/*
 * PolyDiff parser wrapper for libcurl's curl_url_* API.
 *
 * Subprocess oracle, per SPEC §5.3.
 *   stdin  : up to 64 KiB UTF-8
 *   stdout : v2 fact-vector envelope (one JSON line)
 *   exit 0 : parse-or-error
 *   exit !=0 : wrapper crash
 *
 * Build:
 *   clang -O2 -Wall -Wextra -o wrapper wrapper.c -lcurl
 *
 * Run:
 *   echo -n 'https://example.com/foo' | ./wrapper --input-id ID
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>

#define MAX_BYTES 65536

static const char *find_input_id(int argc, char **argv) {
    for (int i = 0; i + 1 < argc; ++i) {
        if (strcmp(argv[i], "--input-id") == 0) return argv[i + 1];
    }
    return NULL;
}

static void json_escape(FILE *out, const char *s) {
    if (!s) { fputs("null", out); return; }
    fputc('"', out);
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {
        unsigned char c = *p;
        switch (c) {
            case '"':  fputs("\\\"", out); break;
            case '\\': fputs("\\\\", out); break;
            case '\n': fputs("\\n", out); break;
            case '\r': fputs("\\r", out); break;
            case '\t': fputs("\\t", out); break;
            default:
                if (c < 0x20 || c > 0x7E) fprintf(out, "\\u%04x", c);
                else fputc(c, out);
        }
    }
    fputc('"', out);
}

static void emit_kv_str(FILE *out, const char *k, const char *v, int last) {
    fputc('"', out); fputs(k, out); fputs("\":", out);
    json_escape(out, v);
    if (!last) fputc(',', out);
}

static void emit_kv_bool(FILE *out, const char *k, int v, int is_null, int last) {
    fputc('"', out); fputs(k, out); fputs("\":", out);
    if (is_null) fputs("null", out);
    else fputs(v ? "true" : "false", out);
    if (!last) fputc(',', out);
}

static void emit_kv_int(FILE *out, const char *k, long v, int is_null, int last) {
    fputc('"', out); fputs(k, out); fputs("\":", out);
    if (is_null) fputs("null", out);
    else fprintf(out, "%ld", v);
    if (!last) fputc(',', out);
}

static int is_ipv4_literal(const char *host) {
    if (!host || !*host) return 0;
    int dots = 0;
    int seg = 0; int has_digit = 0;
    for (const char *p = host; *p; ++p) {
        if (*p >= '0' && *p <= '9') { has_digit = 1; seg = seg * 10 + (*p - '0'); if (seg > 255) return 0; }
        else if (*p == '.') { if (!has_digit) return 0; dots++; seg = 0; has_digit = 0; }
        else return 0;
    }
    return dots == 3 && has_digit;
}

static int is_private_or_link_local(const char *host) {
    if (!is_ipv4_literal(host)) return 0;
    int o[4] = {0};
    sscanf(host, "%d.%d.%d.%d", &o[0], &o[1], &o[2], &o[3]);
    if (o[0] == 10) return 1;
    if (o[0] == 127) return 1;
    if (o[0] == 172 && o[1] >= 16 && o[1] <= 31) return 1;
    if (o[0] == 192 && o[1] == 168) return 1;
    if (o[0] == 169 && o[1] == 254) return 1;
    return 0;
}

static long default_port_for(const char *scheme) {
    if (!scheme) return -1;
    if (strcmp(scheme, "http") == 0) return 80;
    if (strcmp(scheme, "https") == 0) return 443;
    if (strcmp(scheme, "ws") == 0) return 80;
    if (strcmp(scheme, "wss") == 0) return 443;
    if (strcmp(scheme, "ftp") == 0) return 21;
    return -1;
}

static void emit_empty(FILE *out, const char *input_id, const char *err) {
    fputc('{', out);
    emit_kv_str(out, "schema_version", "v2", 0);
    emit_kv_str(out, "input_id", input_id, 0);
    emit_kv_str(out, "parser_profile", "libcurl", 0);
    emit_kv_bool(out, "parsed", 0, 0, 0);
    fputs("\"errors\":[", out); json_escape(out, err); fputs("],", out);
    fputs("\"warnings\":[],", out);
    const char *str_keys[] = {
        "scheme","scheme_lowercased","userinfo_raw","username","host","host_raw",
        "host_lowercased","host_decoded","host_punycode","path","path_raw",
        "path_normalized","query_raw","fragment_raw","raw_serialized"
    };
    for (size_t i = 0; i < sizeof(str_keys)/sizeof(*str_keys); ++i)
        emit_kv_str(out, str_keys[i], NULL, 0);
    emit_kv_str(out, "parse_error", err, 0);
    const char *bool_false_keys[] = {
        "userinfo_present","password_present","host_is_private_or_link_local",
        "trailing_slash_normalized","percent_decoding_applied_in_host",
        "percent_decoding_applied_in_path","leading_zeroes_in_octets_stripped",
        "backslash_treated_as_slash","tab_or_newline_stripped"
    };
    for (size_t i = 0; i < sizeof(bool_false_keys)/sizeof(*bool_false_keys); ++i)
        emit_kv_bool(out, bool_false_keys[i], 0, 0, 0);
    const char *bool_null_keys[] = {
        "host_is_ip_literal","host_is_ipv4","host_is_ipv6","host_is_ipvFuture",
        "host_is_loopback","host_has_idn","port_present",
        "path_traversal_resolved","control_chars_in_host_rejected",
        "scheme_authority_separator_strict"
    };
    for (size_t i = 0; i < sizeof(bool_null_keys)/sizeof(*bool_null_keys); ++i)
        emit_kv_bool(out, bool_null_keys[i], 0, 1, 0);
    emit_kv_int(out, "port", 0, 1, 0);
    emit_kv_int(out, "port_value", 0, 1, 0);
    emit_kv_int(out, "port_default_inferred", 0, 1, 0);
    fputs("\"query_pairs\":[]", out);
    fputs("}", out);
}

int main(int argc, char **argv) {
    const char *input_id = find_input_id(argc, argv);
    if (!input_id) {
        fprintf(stderr, "missing --input-id\n");
        return 2;
    }

    char *buf = malloc(MAX_BYTES + 1);
    if (!buf) return 2;
    ssize_t total = 0;
    while (total < MAX_BYTES) {
        ssize_t n = read(STDIN_FILENO, buf + total, MAX_BYTES - total);
        if (n <= 0) break;
        total += n;
    }
    buf[total] = '\0';

    CURLU *u = curl_url();
    if (!u) { emit_empty(stdout, input_id, "curl_url_init failed"); fputc('\n', stdout); free(buf); return 0; }

    CURLUcode rc = curl_url_set(u, CURLUPART_URL, buf, CURLU_NON_SUPPORT_SCHEME | CURLU_ALLOW_SPACE);
    if (rc != CURLUE_OK) {
        char err[128]; snprintf(err, sizeof(err), "curl_url_set: rc=%d", rc);
        emit_empty(stdout, input_id, err);
        fputc('\n', stdout);
        curl_url_cleanup(u); free(buf);
        return 0;
    }

    char *scheme = NULL, *user = NULL, *pwd = NULL, *host = NULL,
         *port = NULL, *path = NULL, *query = NULL, *frag = NULL,
         *full = NULL;

    curl_url_get(u, CURLUPART_SCHEME, &scheme, 0);
    curl_url_get(u, CURLUPART_USER, &user, 0);
    curl_url_get(u, CURLUPART_PASSWORD, &pwd, 0);
    curl_url_get(u, CURLUPART_HOST, &host, 0);
    curl_url_get(u, CURLUPART_PORT, &port, 0);
    curl_url_get(u, CURLUPART_PATH, &path, 0);
    curl_url_get(u, CURLUPART_QUERY, &query, 0);
    curl_url_get(u, CURLUPART_FRAGMENT, &frag, 0);
    curl_url_get(u, CURLUPART_URL, &full, 0);

    long portInt = port ? strtol(port, NULL, 10) : -1;
    long port_default = default_port_for(scheme);
    int has_userinfo = (user != NULL) || (pwd != NULL);
    int isIPv4 = is_ipv4_literal(host);
    int isIPv6 = host && strchr(host, ':') != NULL;
    int isLoop = isIPv4 && host && strncmp(host, "127.", 4) == 0;
    int isPriv = is_private_or_link_local(host);
    int hasIDN = host && (strncmp(host, "xn--", 4) == 0 || strstr(host, ".xn--") != NULL);

    fputc('{', stdout);
    emit_kv_str(stdout, "schema_version", "v2", 0);
    emit_kv_str(stdout, "input_id", input_id, 0);
    emit_kv_str(stdout, "parser_profile", "libcurl", 0);
    emit_kv_bool(stdout, "parsed", 1, 0, 0);
    fputs("\"errors\":[],", stdout);
    fputs("\"warnings\":[\"axis 'tab_or_newline_stripped' partially observable\",\"axis 'control_chars_in_host_rejected' partially observable\"],", stdout);
    emit_kv_str(stdout, "scheme", scheme, 0);
    emit_kv_str(stdout, "scheme_lowercased", scheme, 0);
    emit_kv_bool(stdout, "userinfo_present", has_userinfo, 0, 0);
    emit_kv_str(stdout, "userinfo_raw", user, 0);
    emit_kv_str(stdout, "username", user, 0);
    emit_kv_bool(stdout, "password_present", pwd != NULL, 0, 0);
    emit_kv_str(stdout, "host", host, 0);
    emit_kv_str(stdout, "host_raw", host, 0);
    emit_kv_str(stdout, "host_lowercased", host, 0);
    emit_kv_str(stdout, "host_decoded", host, 0);
    emit_kv_bool(stdout, "host_is_ip_literal", host && (isIPv4 || isIPv6), host == NULL, 0);
    emit_kv_bool(stdout, "host_is_ipv4", isIPv4, host == NULL, 0);
    emit_kv_bool(stdout, "host_is_ipv6", isIPv6, host == NULL, 0);
    emit_kv_bool(stdout, "host_is_ipvFuture", 0, host == NULL, 0);
    emit_kv_bool(stdout, "host_is_loopback", isLoop, host == NULL, 0);
    emit_kv_bool(stdout, "host_is_private_or_link_local", isPriv, 0, 0);
    emit_kv_bool(stdout, "host_has_idn", hasIDN, 0, 0);
    emit_kv_str(stdout, "host_punycode", hasIDN ? host : NULL, 0);
    emit_kv_int(stdout, "port", portInt, port == NULL, 0);
    emit_kv_bool(stdout, "port_present", port != NULL, 0, 0);
    emit_kv_int(stdout, "port_value", portInt, port == NULL, 0);
    emit_kv_int(stdout, "port_default_inferred", port_default, port_default < 0, 0);
    emit_kv_str(stdout, "path", path, 0);
    emit_kv_str(stdout, "path_raw", path, 0);
    emit_kv_str(stdout, "path_normalized", path, 0);
    emit_kv_bool(stdout, "path_traversal_resolved", 0, 0, 0);
    emit_kv_str(stdout, "query_raw", query, 0);
    fputs("\"query_pairs\":[],", stdout);
    emit_kv_str(stdout, "fragment_raw", frag, 0);
    emit_kv_bool(stdout, "percent_decoding_applied_in_host", 0, 0, 0);
    emit_kv_bool(stdout, "percent_decoding_applied_in_path", 0, 0, 0);
    emit_kv_bool(stdout, "trailing_slash_normalized", 0, 0, 0);
    emit_kv_bool(stdout, "leading_zeroes_in_octets_stripped", 0, 0, 0);
    emit_kv_bool(stdout, "tab_or_newline_stripped", 0, 0, 0);
    emit_kv_bool(stdout, "backslash_treated_as_slash", 0, 0, 0);
    emit_kv_bool(stdout, "control_chars_in_host_rejected", 0, 1, 0);
    emit_kv_bool(stdout, "scheme_authority_separator_strict", 1, 0, 0);
    emit_kv_str(stdout, "raw_serialized", full, 0);
    fputs("\"parse_error\":null", stdout);
    fputc('}', stdout);
    fputc('\n', stdout);

    curl_free(scheme); curl_free(user); curl_free(pwd); curl_free(host);
    curl_free(port); curl_free(path); curl_free(query); curl_free(frag);
    curl_free(full);
    curl_url_cleanup(u);
    free(buf);
    return 0;
}
