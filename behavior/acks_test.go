package behavior

import (
	"encoding/json"
	"strings"
	"testing"
)

// chromeQUICAcks is how Chrome 155's QUIC client acknowledges (quiche at its
// DEPS revision, measured on the bench): every tenth ack-eliciting packet
// from the server's 100th, or a quarter of the least round trip, a
// millisecond at least, after the first one not acknowledged; each of the
// four packets after a gap at once; an ACK sent right after the packet that
// makes it due; the twentieth ACK-only packet in a row carrying MAX_DATA;
// its ACK alarm a fifth of its delay late, the median of what the macOS kernel
// makes of its timer (a quarter at most).
const chromeQUICAcks = `{"quic.ack_decimation_after": 100, "quic.ack_decimation_packets": 10,
 "quic.ack_decimation_rtt_percent": 25, "quic.ack_decimation_min_ms": 1, "quic.ack_gap_packets": 4,
 "quic.ack_sent_after": "packet", "quic.ack_only_max": 19, "quic.ack_only_frame": "max-data",
 "quic.alarm_slack_ms": 4, "quic.ack_alarm_slack_percent": 20}`

func TestQUICAckPolicyIsTypedAndCoherent(t *testing.T) {
	base := Legacy()
	var over Policy
	if err := json.Unmarshal([]byte(chromeQUICAcks), &over); err != nil {
		t.Fatal(err)
	}
	for k, v := range over {
		base[k] = v
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("Chrome's: %v", err)
	}
	none := map[string]string{"quic.ack_gap_packets": "", "quic.ack_sent_after": "", "quic.ack_alarm_slack_percent": ""}
	for _, k := range append(append([]string(nil), ackDecimation...), ackOnly...) {
		none[k] = ""
	}
	noDecimation := map[string]string{}
	for _, k := range ackDecimation {
		noDecimation[k] = ""
	}
	for _, tc := range []struct {
		name    string
		changes map[string]string // a key's new value, or "" to leave it out
		err     string            // "" when it is valid
	}{
		{"none of it", none, ""},
		{"no decimation", noDecimation, ""},
		{"quic-go's choices", map[string]string{"quic.ack_sent_after": `"batch"`, "quic.ack_only_frame": `"ping"`}, ""},
		{"decimation from the first packet", map[string]string{"quic.ack_decimation_after": "0"}, "must be in [1,"},
		{"decimation past every packet number", map[string]string{"quic.ack_decimation_after": "4611686018427387904"}, "must be in [1,"},
		{"decimation at the last packet number", map[string]string{"quic.ack_decimation_after": "4611686018427387903"}, ""},
		{"decimation without its count", map[string]string{"quic.ack_decimation_packets": ""}, "quic.ack_decimation_after requires quic.ack_decimation_packets"},
		{"decimation without its round trip", map[string]string{"quic.ack_decimation_rtt_percent": ""}, "quic.ack_decimation_after requires quic.ack_decimation_rtt_percent"},
		{"decimation without its floor", map[string]string{"quic.ack_decimation_min_ms": ""}, "quic.ack_decimation_after requires quic.ack_decimation_min_ms"},
		{"a count without the rest", merge(noDecimation, map[string]string{"quic.ack_decimation_packets": "10"}), "quic.ack_decimation_packets requires quic.ack_decimation_after"},
		{"a floor without the rest", merge(noDecimation, map[string]string{"quic.ack_decimation_min_ms": "1"}), "quic.ack_decimation_min_ms requires quic.ack_decimation_after"},
		{"an ACK for no packet", map[string]string{"quic.ack_decimation_packets": "0"}, "must be in [1,65535]"},
		{"an ACK of every packet", map[string]string{"quic.ack_decimation_packets": "1"}, ""},
		{"too many packets to an ACK", map[string]string{"quic.ack_decimation_packets": "65536"}, "must be in [1,65535]"},
		{"no part of the round trip", map[string]string{"quic.ack_decimation_rtt_percent": "0"}, "must be in [1,1000]"},
		{"ten round trips", map[string]string{"quic.ack_decimation_rtt_percent": "1000"}, ""},
		{"more than ten round trips", map[string]string{"quic.ack_decimation_rtt_percent": "1001"}, "must be in [1,1000]"},
		{"a round trip's part as a fraction", map[string]string{"quic.ack_decimation_rtt_percent": "0.25"}, "cannot unmarshal number"},
		{"no floor", map[string]string{"quic.ack_decimation_min_ms": "0"}, ""},
		{"a floor past a second", map[string]string{"quic.ack_decimation_min_ms": "1001"}, "must be in [0,1000]"},
		{"a count as a word", map[string]string{"quic.ack_decimation_packets": `"ten"`}, "cannot unmarshal string"},
		{"no packet after a gap", map[string]string{"quic.ack_gap_packets": "0"}, "must be in [1,255]"},
		{"one packet after a gap (quiche's 1ACK)", map[string]string{"quic.ack_gap_packets": "1"}, ""},
		{"too many packets after a gap", map[string]string{"quic.ack_gap_packets": "256"}, "must be in [1,255]"},
		{"a gap's packets as a word", map[string]string{"quic.ack_gap_packets": `"4"`}, "cannot unmarshal string"},
		{"an ACK sent after a timer", map[string]string{"quic.ack_sent_after": `"timer"`}, "unsupported primitive"},
		{"an ACK sent after a packet in another case", map[string]string{"quic.ack_sent_after": `"Packet"`}, "unsupported primitive"},
		{"an ACK sent at once as a flag", map[string]string{"quic.ack_sent_after": "true"}, "cannot unmarshal bool"},
		{"an ACK-eliciting frame in every ACK", map[string]string{"quic.ack_only_max": "0"}, ""},
		{"a thousand ACK-only packets", map[string]string{"quic.ack_only_max": "1000"}, ""},
		{"more ACK-only packets", map[string]string{"quic.ack_only_max": "1001"}, "must be in [0,1000]"},
		{"a frame no client sends for it", map[string]string{"quic.ack_only_frame": `"max-stream-data"`}, "unsupported primitive"},
		{"a frame as a number", map[string]string{"quic.ack_only_frame": "16"}, "cannot unmarshal number"},
		{"a count without its frame", map[string]string{"quic.ack_only_frame": ""}, "quic.ack_only_max requires quic.ack_only_frame"},
		{"a frame without its count", map[string]string{"quic.ack_only_max": ""}, "quic.ack_only_frame requires quic.ack_only_max"},
		{"a part of no slack", map[string]string{"quic.alarm_slack_ms": ""}, "quic.ack_alarm_slack_percent requires quic.alarm_slack_ms"},
		{"no part of the delay", map[string]string{"quic.ack_alarm_slack_percent": "0"}, "must be in [1,100]"},
		{"the whole delay", map[string]string{"quic.ack_alarm_slack_percent": "100"}, ""},
		{"more than the delay", map[string]string{"quic.ack_alarm_slack_percent": "101"}, "must be in [1,100]"},
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
