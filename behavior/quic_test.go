package behavior

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// chromeQUICHandshake is Chrome 155's QUIC handshake (quiche at its DEPS
// revision, measured on the bench), laid over the frozen Chromium data.
const chromeQUICHandshake = `{"quic.packet_numbers": "shared", "quic.first_packet_number": 1,
 "quic.packet_number_length": "window", "quic.pto_skip": "every-space", "quic.pto_probes": 1,
 "quic.pto_initial_rtt_ms": 100, "quic.pto_no_sample_multiplier": 3, "quic.pto_no_sample_min_ms": 10,
 "quic.pto_rttvar_multiplier": 2, "quic.alarm_slack_ms": 8, "quic.handshake_idle_timeout_ms": 4000,
 "quic.handshake_timeout_ms": 10000, "quic.handshake_ack_timer_ms": 1, "quic.idle_close": "after-pto",
 "quic.idle_close_code": 0, "quic.idle_close_reason": "25:No recent network activity after {elapsed}. Timeout:{timeout}",
 "quic.handshake_idle_close_reason": "25:No recent network activity after {elapsed}. Timeout:{timeout} num_undecryptable_packets: {undecryptable_count} {{{undecryptable}}}",
 "quic.undecryptable_level_names": ["ENCRYPTION_INITIAL", "ENCRYPTION_HANDSHAKE", "ENCRYPTION_ZERO_RTT", "ENCRYPTION_FORWARD_SECURE"],
 "quic.initial_layout": "chaos", "quic.chaos_first_frame_min": 55, "quic.chaos_first_frame_spread": 32,
 "quic.chaos_crypto_splits_min": 2, "quic.chaos_crypto_splits_max": 10, "quic.chaos_pings_min": 2,
 "quic.chaos_pings_max": 10, "quic.padding_position": "end", "quic.connected_socket": true}`

func TestQUICHandshakePolicyIsTypedAndCoherent(t *testing.T) {
	base := Legacy()
	var over Policy
	if err := json.Unmarshal([]byte(chromeQUICHandshake), &over); err != nil {
		t.Fatal(err)
	}
	for k, v := range over {
		base[k] = v
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("Chrome's: %v", err)
	}
	none := map[string]string{}
	for k := range over {
		none[k] = ""
	}
	for _, tc := range []struct {
		name    string
		changes map[string]string // a key's new value, or "" to leave it out
		err     string            // "" when it is valid
	}{
		{"none of it", none, ""},
		{"separate numbers, as quic-go", map[string]string{"quic.packet_numbers": `"separate"`, "quic.first_packet_number": "",
			"quic.packet_number_length": `"two-byte-minimum"`, "quic.pto_skip": `"application"`}, ""},
		{"a first number of separate spaces", map[string]string{"quic.packet_numbers": `"separate"`,
			"quic.packet_number_length": "", "quic.pto_skip": ""}, "quic.first_packet_number requires quic.packet_numbers shared"},
		{"the window rule of separate spaces", map[string]string{"quic.packet_numbers": "", "quic.first_packet_number": "",
			"quic.pto_skip": ""}, "quic.packet_number_length requires quic.packet_numbers shared"},
		{"a skip in every space of separate ones", map[string]string{"quic.packet_numbers": "", "quic.first_packet_number": "",
			"quic.packet_number_length": ""}, "quic.pto_skip requires quic.packet_numbers shared"},
		{"an unknown way to number", map[string]string{"quic.packet_numbers": `"random"`}, "unsupported primitive"},
		{"a first number past the bound", map[string]string{"quic.first_packet_number": "1048577"}, "must be in"},
		{"three probes", map[string]string{"quic.pto_probes": "3"}, "must be in"},
		{"no probe", map[string]string{"quic.pto_probes": "0"}, "must be in"},
		{"no initial RTT", map[string]string{"quic.pto_initial_rtt_ms": "0"}, "must be in"},
		{"no multiplier", map[string]string{"quic.pto_no_sample_multiplier": "0"}, "must be in"},
		{"no RTT variation", map[string]string{"quic.pto_rttvar_multiplier": "0"}, "must be in"},
		{"no slack", map[string]string{"quic.alarm_slack_ms": "0"}, ""},
		{"a slack past a second", map[string]string{"quic.alarm_slack_ms": "1001"}, "must be in"},
		{"no handshake idle timeout", map[string]string{"quic.handshake_idle_timeout_ms": "0"}, "must be in"},
		{"a handshake shorter than its idle time", map[string]string{"quic.handshake_timeout_ms": "3999"},
			"quic.handshake_timeout_ms is shorter than quic.handshake_idle_timeout_ms"},
		{"a handshake as long as its idle time", map[string]string{"quic.handshake_timeout_ms": "4000"}, ""},
		{"a handshake timeout alone", map[string]string{"quic.handshake_idle_timeout_ms": ""}, ""},
		{"handshake ACKs at once", map[string]string{"quic.handshake_ack_timer_ms": "0"}, ""},
		{"no chaos numbers", map[string]string{"quic.chaos_pings_max": ""}, "quic.initial_layout chaos requires quic.chaos_pings_max"},
		{"chaos numbers with the scramble", map[string]string{"quic.initial_layout": `"scramble"`}, "is set while quic.initial_layout is not chaos"},
		{"chaos numbers alone", map[string]string{"quic.initial_layout": ""}, "is set while quic.initial_layout is not chaos"},
		{"more splits at least than at most", map[string]string{"quic.chaos_crypto_splits_min": "11"},
			"quic.chaos_crypto_splits_min exceeds quic.chaos_crypto_splits_max"},
		{"more pings at least than at most", map[string]string{"quic.chaos_pings_min": "11"},
			"quic.chaos_pings_min exceeds quic.chaos_pings_max"},
		{"no first frame spread", map[string]string{"quic.chaos_first_frame_spread": "0"}, "must be in"},
		{"no split, no ping", map[string]string{"quic.chaos_crypto_splits_min": "0", "quic.chaos_crypto_splits_max": "0",
			"quic.chaos_pings_min": "0", "quic.chaos_pings_max": "0"}, ""},
		{"an unknown layout", map[string]string{"quic.initial_layout": `"shuffle"`}, "unsupported primitive"},
		{"no close code", map[string]string{"quic.idle_close_code": ""}, "quic.idle_close after-pto requires quic.idle_close_code"},
		{"a reason without the close", map[string]string{"quic.idle_close": `"silent"`}, "is set while quic.idle_close is not after-pto"},
		{"a silent close", map[string]string{"quic.idle_close": `"silent"`, "quic.idle_close_code": "", "quic.idle_close_reason": "",
			"quic.handshake_idle_close_reason": "", "quic.undecryptable_level_names": ""}, ""},
		{"level names without a list", map[string]string{"quic.handshake_idle_close_reason": `"idle"`},
			"quic.undecryptable_level_names goes with a reason that lists {undecryptable}"},
		{"a list without level names", map[string]string{"quic.undecryptable_level_names": ""},
			"quic.undecryptable_level_names goes with a reason that lists {undecryptable}"},
		{"three level names", map[string]string{"quic.undecryptable_level_names": `["a", "b", "c"]`},
			"names the Initial, Handshake, 0-RTT and 1-RTT levels"},
		{"five level names", map[string]string{"quic.undecryptable_level_names": `["a", "b", "c", "d", "e"]`},
			"names the Initial, Handshake, 0-RTT and 1-RTT levels"},
		{"an empty level name", map[string]string{"quic.undecryptable_level_names": `["a", "", "c", "d"]`}, "is no level name"},
		{"a brace in a level name", map[string]string{"quic.undecryptable_level_names": `["a", "{b}", "c", "d"]`}, "is no level name"},
		{"an unknown placeholder", map[string]string{"quic.idle_close_reason": `"{stream_id}"`}, "unsupported diagnostic placeholder"},
		{"a brace left open", map[string]string{"quic.idle_close_reason": `"after {elapsed"`}, "unsupported diagnostic placeholder"},
		{"a lone closing brace", map[string]string{"quic.idle_close_reason": `"after }"`}, "unsupported diagnostic placeholder"},
		{"a reason past its bound", map[string]string{"quic.idle_close_reason": `"` + strings.Repeat("x", 1025) + `"`}, "text exceeds 1024 bytes"},
		{"a new line in a reason", map[string]string{"quic.idle_close_reason": `"a\nb"`}, "control byte"},
		{"a code past a varint", map[string]string{"quic.idle_close_code": "4611686018427387904"}, "must be in"},
		{"an unknown padding position", map[string]string{"quic.padding_position": `"start"`}, "unsupported primitive"},
		{"a connected socket shared", map[string]string{"quic.dedicated_socket": "false", "quic.enabled": "false"},
			"quic.connected_socket requires quic.dedicated_socket"},
		{"a connected socket as a word", map[string]string{"quic.connected_socket": `"yes"`}, "cannot unmarshal string"},
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

func TestAReasonIsWrittenAsQuicheWritesIt(t *testing.T) {
	chrome := "25:No recent network activity after {elapsed}. Timeout:{timeout} num_undecryptable_packets: {undecryptable_count} {{{undecryptable}}}"
	for _, tc := range []struct {
		template string
		values   QUICReasonValues
		want     string
	}{
		// Chrome 155 into a port that never answered, h3a-hole on the bench.
		{chrome, QUICReasonValues{Elapsed: 4008694 * time.Microsecond, Timeout: 4 * time.Second},
			"25:No recent network activity after 4008694us. Timeout:4s num_undecryptable_packets: 0 {}"},
		{chrome, QUICReasonValues{Elapsed: 4100 * time.Millisecond, Timeout: 4 * time.Second,
			Undecryptable: []QUICUndecryptable{{"ENCRYPTION_HANDSHAKE", 1200}, {"ENCRYPTION_FORWARD_SECURE", 40}}},
			"25:No recent network activity after 4100ms. Timeout:4s num_undecryptable_packets: 2 {[ENCRYPTION_HANDSHAKE, 1200][ENCRYPTION_FORWARD_SECURE, 40]}"},
		{"{elapsed}", QUICReasonValues{Elapsed: 999 * time.Microsecond}, "999us"},
		{"{elapsed}", QUICReasonValues{Elapsed: time.Millisecond}, "1ms"},
		{"{elapsed}", QUICReasonValues{Elapsed: 1500 * time.Microsecond}, "1500us"},
		{"{elapsed}", QUICReasonValues{Elapsed: 60 * time.Second}, "60s"},
		{"{elapsed}", QUICReasonValues{Elapsed: 1999 * time.Nanosecond}, "1us"},
		{"{elapsed}", QUICReasonValues{}, "0us"},
		{"{elapsed}", QUICReasonValues{Elapsed: -2 * time.Second}, "-2s"},
		{"{elapsed}", QUICReasonValues{Elapsed: -3 * time.Millisecond}, "-3ms"},
		{"{{}}", QUICReasonValues{}, "{}"},
		{"a{{b", QUICReasonValues{}, "a{b"},
		{"plain", QUICReasonValues{}, "plain"},
	} {
		got, err := QUICReason(tc.template, tc.values)
		if err != nil || got != tc.want {
			t.Errorf("%q: %q, %v, want %q", tc.template, got, err, tc.want)
		}
	}
	for _, bad := range []string{"{", "}", "{x}", "{elapsed", "a}b", "{{x}"} {
		if got, err := QUICReason(bad, QUICReasonValues{}); err == nil {
			t.Errorf("%q: %q, want a refusal", bad, got)
		}
	}
}
