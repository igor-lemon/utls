package behavior

import "fmt"

// An explicit transport owns both initial and maximum windows. This is separate
// from quic.enabled, the legacy selection of the TCP-to-QUIC TLS adapter.
var explicitQUICConfigKeys = []string{
	"quic.versions", "quic.dedicated_socket", "quic.source_cid_bytes", "quic.initial_dcid_bytes",
	"quic.stream_receive_window", "quic.max_stream_receive_window", "quic.connection_receive_window",
	"quic.max_connection_receive_window", "quic.incoming_bidi_streams", "quic.incoming_uni_streams",
	"quic.idle_timeout_ms", "quic.keep_alive_ms", "quic.initial_packet_bytes", "quic.datagrams",
	"quic.max_udp_payload", "quic.active_cid_limit", "quic.ack_timer_ms", "quic.max_ack_delay_ms",
}

func validateQUICConfig(p Policy) error {
	if p.Has("quic.tls_source") {
		if !p.Has("quic.config") {
			return fmt.Errorf("quic.tls_source requires quic.config explicit")
		}
		if (p.Text("quic.tls_source") == "tcp-adapter") != p.Flag("quic.enabled") {
			return fmt.Errorf("quic.tls_source conflicts with legacy quic.enabled adapter selection")
		}
	}
	if p.Has("quic.session_cache") && !p.Has("quic.session_cache_entries") {
		return fmt.Errorf("quic.session_cache requires quic.session_cache_entries")
	}

	if !p.Has("quic.config") {
		for _, key := range []string{"quic.max_stream_receive_window", "quic.max_connection_receive_window", "quic.keep_alive_ms"} {
			if p.Has(key) {
				return fmt.Errorf("%s requires quic.config explicit", key)
			}
		}
		return nil
	}
	for _, key := range explicitQUICConfigKeys {
		if !p.Has(key) {
			return fmt.Errorf("quic.config explicit requires %s", key)
		}
	}
	versions := p.Numbers("quic.versions")
	if len(versions) != 1 || versions[0] != 1 {
		return fmt.Errorf("only QUIC v1 is supported by the explicit transport")
	}
	if !p.Flag("quic.dedicated_socket") && p.Uint("quic.source_cid_bytes") == 0 {
		return fmt.Errorf("zero source CID requires a dedicated socket")
	}
	if n := p.Uint("quic.initial_dcid_bytes"); n < 8 || n > 20 {
		return fmt.Errorf("quic.initial_dcid_bytes requires 8..20 bytes")
	}
	for _, key := range []string{"quic.stream_receive_window", "quic.connection_receive_window", "quic.idle_timeout_ms"} {
		if p.Uint(key) == 0 {
			return fmt.Errorf("%s must be nonzero; zero selects a library default", key)
		}
	}
	for _, pair := range [][2]string{{"quic.stream_receive_window", "quic.max_stream_receive_window"}, {"quic.connection_receive_window", "quic.max_connection_receive_window"}} {
		if p.Uint(pair[0]) > p.Uint(pair[1]) {
			return fmt.Errorf("%s is smaller than its initial receive window", pair[1])
		}
	}
	if p.Uint("quic.ack_timer_ms") > p.Uint("quic.max_ack_delay_ms") {
		return fmt.Errorf("ACK timer exceeds advertised delay")
	}
	return nil
}
