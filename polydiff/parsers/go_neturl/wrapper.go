// PolyDiff parser wrapper for Go's net/url (Go 1.22).
//
// Subprocess oracle, per SPEC §5.3.
//   stdin  : up to 64 KiB UTF-8
//   stdout : v2 fact-vector envelope (one JSON line)
//   exit 0 : parse-or-error
//   exit !=0 : wrapper crash
//
// Build: go build -o wrapper wrapper.go
// Run:   echo -n 'https://example.com/foo' | ./wrapper --input-id ID

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
)

const maxBytes = 64 * 1024

func main() {
	inputID := flag.String("input-id", "", "input identifier")
	flag.Parse()
	if *inputID == "" {
		fmt.Fprintln(os.Stderr, "missing --input-id")
		os.Exit(2)
	}

	limited := io.LimitReader(os.Stdin, maxBytes)
	raw, err := io.ReadAll(limited)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stdin read failed: %s\n", err)
		os.Exit(2)
	}

	envelope := parse(*inputID, string(raw))
	out, _ := json.Marshal(envelope)
	fmt.Println(string(out))
}

func parse(inputID, raw string) map[string]interface{} {
	warnings := []string{
		"axis 'host_has_idn' inferred from punycode prefix only; net/url does not perform IDN conversion",
		"axis 'control_chars_in_host_rejected' partially observable; net/url accepts most controls",
	}

	u, err := url.Parse(raw)
	if err != nil {
		return emptyEnvelope(inputID, []string{fmt.Sprintf("net/url.Parse: %s", err.Error())}, warnings)
	}

	scheme := strings.ToLower(u.Scheme)
	host := u.Hostname()
	port := u.Port()
	username := ""
	passwordPresent := false
	if u.User != nil {
		username = u.User.Username()
		_, passwordPresent = u.User.Password()
	}
	userinfoRaw := ""
	if u.User != nil {
		userinfoRaw = u.User.String()
	}
	var portInt *int
	if port != "" {
		var p int
		if _, perr := fmt.Sscanf(port, "%d", &p); perr == nil {
			portInt = &p
		}
	}

	isIPv4 := false
	isIPv6 := false
	isLoopback := false
	isPrivate := false
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			isIPv4 = true
			isLoopback = ip4.IsLoopback()
			isPrivate = ip4.IsPrivate() || ip4.IsLoopback() || ip4.IsLinkLocalUnicast()
		} else {
			isIPv6 = true
		}
	} else if strings.ToLower(host) == "localhost" {
		isLoopback = true
	}
	hasIDN := strings.HasPrefix(host, "xn--") || strings.Contains(host, ".xn--")
	punycode := interface{}(nil)
	if hasIDN {
		punycode = host
	}

	envelope := map[string]interface{}{
		"schema_version":                       "v2",
		"input_id":                             inputID,
		"parser_profile":                       "go_neturl",
		"parsed":                               true,
		"errors":                               []string{},
		"warnings":                             warnings,
		"scheme":                               nilIfEmpty(u.Scheme),
		"scheme_lowercased":                    nilIfEmpty(scheme),
		"userinfo_present":                     u.User != nil,
		"userinfo_raw":                         nilIfEmpty(userinfoRaw),
		"username":                             nilIfEmpty(username),
		"password_present":                     passwordPresent,
		"host":                                 nilIfEmpty(host),
		"host_raw":                             nilIfEmpty(host),
		"host_lowercased":                      nilIfEmpty(strings.ToLower(host)),
		"host_decoded":                         nilIfEmpty(host),
		"host_is_ip_literal":                   ifPresent(host, isIPv4 || isIPv6),
		"host_is_ipv4":                         ifPresent(host, isIPv4),
		"host_is_ipv6":                         ifPresent(host, isIPv6),
		"host_is_ipvFuture":                    false,
		"host_is_loopback":                     ifPresent(host, isLoopback),
		"host_is_private_or_link_local":        isPrivate,
		"host_has_idn":                         hasIDN,
		"host_punycode":                        punycode,
		"port":                                 maybeInt(portInt),
		"port_present":                         portInt != nil,
		"port_value":                           maybeInt(portInt),
		"port_default_inferred":                defaultPortFor(scheme),
		"path":                                 nilIfEmpty(u.Path),
		"path_raw":                             nilIfEmpty(u.RawPath),
		"path_normalized":                      nilIfEmpty(u.Path),
		"path_traversal_resolved":              false,
		"query_raw":                            nilIfEmpty(u.RawQuery),
		"query_pairs":                          []map[string]string{},
		"fragment_raw":                         nilIfEmpty(u.Fragment),
		"percent_decoding_applied_in_host":     false,
		"percent_decoding_applied_in_path":     true,
		"trailing_slash_normalized":            false,
		"leading_zeroes_in_octets_stripped":    false,
		"tab_or_newline_stripped":              false,
		"backslash_treated_as_slash":           false,
		"control_chars_in_host_rejected":       nil,
		"scheme_authority_separator_strict":    true,
		"raw_serialized":                       u.String(),
		"parse_error":                          nil,
	}
	return envelope
}

func emptyEnvelope(inputID string, errors, warnings []string) map[string]interface{} {
	var perr interface{}
	if len(errors) > 0 {
		perr = errors[0]
	}
	return map[string]interface{}{
		"schema_version":                       "v2",
		"input_id":                             inputID,
		"parser_profile":                       "go_neturl",
		"parsed":                               false,
		"errors":                               errors,
		"warnings":                             warnings,
		"scheme":                               nil,
		"scheme_lowercased":                    nil,
		"userinfo_present":                     false,
		"userinfo_raw":                         nil,
		"username":                             nil,
		"password_present":                     false,
		"host":                                 nil,
		"host_raw":                             nil,
		"host_lowercased":                      nil,
		"host_decoded":                         nil,
		"host_is_ip_literal":                   nil,
		"host_is_ipv4":                         nil,
		"host_is_ipv6":                         nil,
		"host_is_ipvFuture":                    nil,
		"host_is_loopback":                     nil,
		"host_is_private_or_link_local":        false,
		"host_has_idn":                         nil,
		"host_punycode":                        nil,
		"port":                                 nil,
		"port_present":                         nil,
		"port_value":                           nil,
		"port_default_inferred":                nil,
		"path":                                 nil,
		"path_raw":                             nil,
		"path_normalized":                      nil,
		"path_traversal_resolved":              nil,
		"query_raw":                            nil,
		"query_pairs":                          nil,
		"fragment_raw":                         nil,
		"percent_decoding_applied_in_host":     nil,
		"percent_decoding_applied_in_path":     nil,
		"trailing_slash_normalized":            nil,
		"leading_zeroes_in_octets_stripped":    nil,
		"tab_or_newline_stripped":              nil,
		"backslash_treated_as_slash":           nil,
		"control_chars_in_host_rejected":       nil,
		"scheme_authority_separator_strict":    nil,
		"raw_serialized":                       nil,
		"parse_error":                          perr,
	}
}

func nilIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func ifPresent(host string, val bool) interface{} {
	if host == "" {
		return nil
	}
	return val
}

func maybeInt(v *int) interface{} {
	if v == nil {
		return nil
	}
	return *v
}

func defaultPortFor(scheme string) interface{} {
	switch scheme {
	case "http":
		return 80
	case "https":
		return 443
	case "ws":
		return 80
	case "wss":
		return 443
	case "ftp":
		return 21
	default:
		return nil
	}
}
