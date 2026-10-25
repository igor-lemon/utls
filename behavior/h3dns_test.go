package behavior

import (
	"encoding/json"
	"strings"
	"testing"
)

// chromeDNSH3 is Chrome 155's choice of HTTP/3 by an HTTPS record's alpn,
// laid over its ECH and DNS policy and the frozen Chromium data's QUIC.
const chromeDNSH3 = `{"dns.https_h3": true, "quic.tcp_wait_cold_ms": 0, "quic.tcp_wait_broken_ms": 0,
 "quic.tcp_wait_rtt_percent": 150, "quic.tcp_wait_default_ms": 300, "quic.tcp_wait_extra_ms": 0,
 "quic.tcp_wait_max_ms": 3000, "quic.tcp_waits_with_connection": false, "quic.retry_over_tcp": true, "quic.broken_ms": 300000,
 "quic.broken_doublings": 18, "quic.broken_max_ms": 172800000, "quic.broken_recent_max": 200,
 "quic.server_rtts_max": 500, "http.unused_idle_connection_timeout_ms": 60000}`

func TestDNSH3PolicyIsTypedAndCoherent(t *testing.T) {
	base := Legacy()
	for _, layer := range []string{chromeECH, chromeDNSH3} {
		var over Policy
		if err := json.Unmarshal([]byte(layer), &over); err != nil {
			t.Fatal(err)
		}
		for k, v := range over {
			base[k] = v
		}
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("Chrome's: %v", err)
	}
	none := map[string]string{"dns.https_h3": ""}
	for _, k := range dnsH3 {
		none[k] = ""
	}
	for _, tc := range []struct {
		name    string
		changes map[string]string // a key's new value, or "" to leave it out
		err     string            // "" when it is valid
	}{
		{"none of it", none, ""},
		{"said off, and its numbers", map[string]string{"dns.https_h3": "false"}, "is set while dns.https_h3 is not"},
		{"numbers without it", map[string]string{"dns.https_h3": ""}, "is set while dns.https_h3 is not"},
		{"no records", map[string]string{"dns.https_records": "false", "dns.https_wait_percent": "",
			"dns.https_wait_min_ms": "", "dns.https_wait_max_ms": "", "dns.https_upgrade": ""}, "dns.https_h3 requires dns.https_records"},
		{"no QUIC", map[string]string{"quic.enabled": "false"}, "dns.https_h3 requires quic.enabled"},
		{"no cold wait said", map[string]string{"quic.tcp_wait_cold_ms": ""}, "dns.https_h3 requires quic.tcp_wait_cold_ms"},
		{"no retry over TCP said", map[string]string{"quic.retry_over_tcp": ""}, "dns.https_h3 requires quic.retry_over_tcp"},
		{"no retry over TCP", map[string]string{"quic.retry_over_tcp": "false"}, ""},
		{"no unused timeout said", map[string]string{"http.unused_idle_connection_timeout_ms": ""},
			"dns.https_h3 requires http.unused_idle_connection_timeout_ms"},
		{"a wait past a minute", map[string]string{"quic.tcp_wait_max_ms": "60001"}, "must be in"},
		{"a wait of a minute", map[string]string{"quic.tcp_wait_max_ms": "60000"}, ""},
		{"an RTT ten times over", map[string]string{"quic.tcp_wait_rtt_percent": "1000"}, ""},
		{"an RTT past ten times", map[string]string{"quic.tcp_wait_rtt_percent": "1001"}, "must be in"},
		{"no first break", map[string]string{"quic.broken_ms": "0"}, "must be in"},
		{"a first break past a day", map[string]string{"quic.broken_ms": "86400001"}, "must be in"},
		{"a first break past the longest", map[string]string{"quic.broken_max_ms": "299999"}, "exceeds quic.broken_max_ms"},
		{"a first break that is the longest", map[string]string{"quic.broken_max_ms": "300000"}, ""},
		{"no doubling", map[string]string{"quic.broken_doublings": "0"}, ""},
		{"doublings past a shift", map[string]string{"quic.broken_doublings": "63"}, "must be in"},
		{"no recent break kept", map[string]string{"quic.broken_recent_max": "0"}, "must be in"},
		{"no RTT kept", map[string]string{"quic.server_rtts_max": "0"}, "must be in"},
		{"no RTT bound said", map[string]string{"quic.server_rtts_max": ""}, "dns.https_h3 requires quic.server_rtts_max"},
		{"an unused connection closed at once", map[string]string{"http.unused_idle_connection_timeout_ms": "0"}, ""},
		{"waits as a word", map[string]string{"quic.tcp_waits_with_connection": `"no"`}, "cannot unmarshal string"},
	} {
		p := base.Clone()
		for k, v := range tc.changes {
			if v == "" {
				delete(p, k)
				continue
			}
			p[k] = json.RawMessage(v)
		}
		err := p.Validate()
		if tc.err == "" && err != nil || tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.err)
		}
	}
}
