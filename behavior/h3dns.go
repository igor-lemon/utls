package behavior

import "fmt"

// dnsH3 are the keys that say how a request goes over HTTP/3 where the HTTPS
// record its connection takes names h3 (dns.https_h3): how long TCP waits
// behind QUIC, whether a request a QUIC connection failed before its answer
// goes again over TCP, for how long QUIC is not tried again after it failed
// where TCP did not, how many servers' breaks and RTTs are remembered, and
// how long a TCP connection that lost to QUIC is kept unused.
var dnsH3 = []string{"quic.tcp_wait_cold_ms", "quic.tcp_wait_broken_ms", "quic.tcp_wait_rtt_percent",
	"quic.tcp_wait_default_ms", "quic.tcp_wait_extra_ms", "quic.tcp_wait_max_ms", "quic.tcp_waits_with_connection",
	"quic.retry_over_tcp", "quic.broken_ms", "quic.broken_doublings", "quic.broken_max_ms", "quic.broken_recent_max",
	"quic.server_rtts_max", "http.unused_idle_connection_timeout_ms"}

// validateDNSH3 holds dns.https_h3 to what the engine can do: it reads the
// records the profile asks for (dns.https_records) and goes over the QUIC the
// profile says how to speak (quic.enabled), and it is told every one of its
// numbers, which a profile without it says none of; a first break no longer
// than the longest.
func validateDNSH3(p Policy) error {
	on := p.Flag("dns.https_h3")
	if on && !p.Flag("dns.https_records") {
		return fmt.Errorf("dns.https_h3 requires dns.https_records")
	}
	if on && !p.Flag("quic.enabled") {
		return fmt.Errorf("dns.https_h3 requires quic.enabled")
	}
	for _, k := range dnsH3 {
		if on && !p.Has(k) {
			return fmt.Errorf("dns.https_h3 requires %s", k)
		}
		if !on && p.Has(k) {
			return fmt.Errorf("%s is set while dns.https_h3 is not", k)
		}
	}
	if p.Uint("quic.broken_ms") > p.Uint("quic.broken_max_ms") {
		return fmt.Errorf("quic.broken_ms exceeds quic.broken_max_ms")
	}
	return nil
}
