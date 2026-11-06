package behavior

import (
	"encoding/json"
	"strings"
	"testing"
)

func explicitQUICConfig(t *testing.T) Policy {
	t.Helper()
	p := Generic()
	var data Policy
	if err := json.Unmarshal([]byte(`{"quic.config":"explicit", "quic.enabled":false,
 "quic.versions":[1], "quic.dedicated_socket":false, "quic.source_cid_bytes":4,
 "quic.initial_dcid_bytes":8, "quic.stream_receive_window":524288,
 "quic.max_stream_receive_window":6291456, "quic.connection_receive_window":786432,
 "quic.max_connection_receive_window":15728640, "quic.incoming_bidi_streams":0,
 "quic.incoming_uni_streams":100, "quic.idle_timeout_ms":30000,
 "quic.keep_alive_ms":10000, "quic.initial_packet_bytes":1280,
 "quic.datagrams":true, "quic.max_udp_payload":1452, "quic.active_cid_limit":4,
 "quic.ack_timer_ms":25, "quic.max_ack_delay_ms":26}`), &data); err != nil {
		t.Fatal(err)
	}
	for k, v := range data {
		p[k] = v
	}
	return p
}

func TestExplicitQUICConfigIsIndependentOfTLSAdapter(t *testing.T) {
	p := explicitQUICConfig(t)
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"quic.versions", "quic.dedicated_socket", "quic.source_cid_bytes", "quic.initial_dcid_bytes", "quic.stream_receive_window", "quic.max_stream_receive_window", "quic.connection_receive_window", "quic.max_connection_receive_window", "quic.incoming_bidi_streams", "quic.incoming_uni_streams", "quic.idle_timeout_ms", "quic.keep_alive_ms", "quic.initial_packet_bytes", "quic.datagrams", "quic.max_udp_payload", "quic.active_cid_limit", "quic.ack_timer_ms", "quic.max_ack_delay_ms"} {
		q := p.Clone()
		delete(q, key)
		if err := q.Validate(); err == nil {
			t.Errorf("missing %s accepted", key)
		}
	}
	for _, tc := range []struct{ key, value, want string }{
		{"quic.versions", "[2]", "only QUIC v1"},
		{"quic.source_cid_bytes", "0", "dedicated socket"},
		{"quic.stream_receive_window", "0", "nonzero"},
		{"quic.idle_timeout_ms", "0", "nonzero"},
		{"quic.max_stream_receive_window", "1", "initial receive window"},
		{"quic.max_connection_receive_window", "1", "initial receive window"},
		{"quic.ack_timer_ms", "27", "advertised delay"},
		{"quic.initial_dcid_bytes", "7", "8..20"},
		{"quic.keep_alive_ms", "null", "null"},
		{"quic.keep_alive_ms", "-1", "cannot unmarshal"},
	} {
		t.Run(tc.key+tc.value, func(t *testing.T) {
			q := p.Clone()
			q[tc.key] = json.RawMessage(tc.value)
			if err := q.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%v, want %s", err, tc.want)
			}
		})
	}
	q := p.Clone()
	q["quic.dedicated_socket"] = json.RawMessage("true")
	q["quic.source_cid_bytes"] = json.RawMessage("0")
	q["quic.keep_alive_ms"] = json.RawMessage("0")
	if err := q.Validate(); err != nil {
		t.Fatal(err)
	}
	q = p.Clone()
	delete(q, "quic.config")
	if err := q.Validate(); err == nil || !strings.Contains(err.Error(), "quic.config") {
		t.Fatal("orphan controls", err)
	}
}

func TestSessionCacheCapacitiesAreExplicitAndBounded(t *testing.T) {
	for _, key := range []string{"tls.session_cache_entries", "quic.session_cache_entries"} {
		for _, value := range []string{"1", "32", "65536"} {
			p := Generic()
			p[key] = json.RawMessage(value)
			if err := p.Validate(); err != nil {
				t.Fatal(err)
			}
		}
		for _, value := range []string{"0", "65537", "-1", "null", "1.5", "\"32\""} {
			p := Generic()
			p[key] = json.RawMessage(value)
			if err := p.Validate(); err == nil {
				t.Errorf("%s=%s accepted", key, value)
			}
		}
	}
}

func TestSessionsPerCacheEntryAreExplicitAndBounded(t *testing.T) {
	for _, key := range []string{"tls.session_cache_sessions_per_entry", "quic.session_cache_sessions_per_entry"} {
		for _, value := range []string{"1", "2", "16"} {
			p := Generic()
			p[key] = json.RawMessage(value)
			if err := p.Validate(); err != nil {
				t.Fatal(err)
			}
		}
		for _, value := range []string{"0", "17", "-1", "null", "1.5", "\"2\""} {
			p := Generic()
			p[key] = json.RawMessage(value)
			if err := p.Validate(); err == nil {
				t.Errorf("%s=%s accepted", key, value)
			}
		}
	}
}

func TestQUICTLSAndCacheChoicesAreCoherent(t *testing.T) {
	for _, tc := range []struct {
		source  string
		adapter bool
		valid   bool
	}{{"independent", false, true}, {"tcp-adapter", false, false}} {
		p := explicitQUICConfig(t)
		p["quic.tls_source"], _ = json.Marshal(tc.source)
		if err := p.Validate(); (err == nil) != tc.valid {
			t.Fatal(tc, err)
		}
	}
	p := Generic()
	p["quic.tls_source"] = json.RawMessage(`"independent"`)
	if err := p.Validate(); err == nil {
		t.Fatal("source without transport accepted")
	}
	p = Generic()
	p["quic.session_cache"] = json.RawMessage("false")
	if err := p.Validate(); err == nil {
		t.Fatal("cache without capacity accepted")
	}
	p["quic.session_cache_entries"] = json.RawMessage("1")
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestExplicitNativeACKPoliciesRejectUnusedParameters(t *testing.T) {
	p := Generic()
	p["quic.ack_gap_policy"] = json.RawMessage(`"new-gap"`)
	p["quic.ack_decimation"] = json.RawMessage(`"none"`)
	p["quic.ack_initial_packets"] = json.RawMessage("2")
	p["quic.ack_reordering_threshold"] = json.RawMessage("1")
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ key, value string }{{"quic.ack_gap_packets", "2"}, {"quic.ack_decimation_after", "100"}, {"quic.ack_initial_packets", "0"}, {"quic.ack_reordering_threshold", "0"}, {"quic.ack_gap_policy", `"bounded-gap"`}, {"quic.ack_decimation", `"threshold"`}} {
		q := p.Clone()
		q[tc.key] = json.RawMessage(tc.value)
		if err := q.Validate(); err == nil {
			t.Error("invalid ACK data accepted", tc)
		}
	}
}
