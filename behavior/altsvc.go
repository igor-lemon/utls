package behavior

import "fmt"

// altSvc are the keys that say how a request follows the alternative
// services its origin's answers advertised (quic.alt_svc), as Chromium's
// JobController takes them (GetAdvertisedAltSvcInternal): whether one on a
// port of 1024 or more is taken for an origin on a port below it
// (enable_user_alternate_protocol_ports), whether one on another host is
// (allow_remote_alt_svc), and whether the request's TCP connection waits
// behind its QUIC one where the origin has an HTTP/2 connection
// (delay_main_job_with_available_spdy_session).
var altSvc = []string{"quic.alt_svc_user_ports", "quic.alt_svc_remote_hosts", "quic.alt_svc_tcp_waits_with_h2"}

// validateAltSvc holds quic.alt_svc to what the engine can do: an
// alternative's QUIC connection is raced as an HTTPS record's is
// (dns.https_h3), and it is told each of its choices, which a profile without
// it says none of.
func validateAltSvc(p Policy) error {
	on := p.Flag("quic.alt_svc")
	if on && !p.Flag("dns.https_h3") {
		return fmt.Errorf("quic.alt_svc requires dns.https_h3")
	}
	for _, k := range altSvc {
		if on && !p.Has(k) {
			return fmt.Errorf("quic.alt_svc requires %s", k)
		}
		if !on && p.Has(k) {
			return fmt.Errorf("%s is set while quic.alt_svc is not", k)
		}
	}
	return nil
}
