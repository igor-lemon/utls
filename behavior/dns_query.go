package behavior

import "fmt"

// dnsQueryChoices describe the independently constructed HTTPS RR transaction.
// Values are profile data, not defaults. Older archived policies can lack the
// whole group; executable owner profiles require it before any network I/O.
// The 16-bit EDNS field is limited to512..65535; RFC6891 treats smaller values
// as512. The engine accepts1..60000ms per server exchange, including TCP retry.
var dnsQueryChoices = []string{"dns.https_query_recursion_desired", "dns.https_query_udp_payload_bytes", "dns.https_query_timeout_ms"}

func validateDNSQuery(p Policy) error {
	present := false
	for _, key := range dnsQueryChoices {
		present = present || p.Has(key)
	}
	if !present {
		return nil
	}
	for _, key := range dnsQueryChoices {
		if !p.Has(key) {
			return fmt.Errorf("DNS query policy requires %s", key)
		}
	}
	return nil
}
