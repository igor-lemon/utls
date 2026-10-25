package behavior

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// quicChaos are the keys that say how a client's Initial packets are laid
// out when quic.initial_layout is chaos (quiche's QuicChaosProtector and
// MultiPacketChaosProtect): how long the first CRYPTO frame of a ClientHello
// that takes more than one packet is, and how many CRYPTO splits and PING
// frames each Initial with CRYPTO and PADDING gets.
var quicChaos = []string{"quic.chaos_first_frame_min", "quic.chaos_first_frame_spread",
	"quic.chaos_crypto_splits_min", "quic.chaos_crypto_splits_max", "quic.chaos_pings_min", "quic.chaos_pings_max"}

// quicIdleClose are the keys that say what a connection that went idle with
// probes unanswered sends (quic.idle_close after-pto, quiche's
// OnIdleNetworkDetected): the error code of its CONNECTION_CLOSE and the
// reason it gives, before the handshake completed and after.
var quicIdleClose = []string{"quic.idle_close_code", "quic.idle_close_reason", "quic.handshake_idle_close_reason"}

// sharedPacketNumbers are the keys that are about one packet number counter
// for all three spaces, quiche's: where it begins, how many bytes a number
// takes, and a number skipped at every probe timeout.
var sharedPacketNumbers = []string{"quic.first_packet_number", "quic.packet_number_length", "quic.pto_skip"}

// validateQUICHandshake holds the keys of a QUIC client's handshake to what
// the engine can do: the first packet number, the window rule of a packet
// number's length and a number skipped in every space are the one counter's
// (quic.packet_numbers shared); a chaos layout is told every one of its
// numbers, each range in order, and the numbers say nothing without it; an
// idle connection that closes after its probes says the code and both
// reasons, which say nothing otherwise, and names the four encryption levels
// when a reason lists undecryptable packets; a handshake is given no less
// time than an idle one; a connected socket is the connection's own.
func validateQUICHandshake(p Policy) error {
	shared := p.Text("quic.packet_numbers") == "shared"
	for _, k := range sharedPacketNumbers {
		if !shared && p.Has(k) && (k == "quic.first_packet_number" || p.Text(k) == "window" || p.Text(k) == "every-space") {
			return fmt.Errorf("%s requires quic.packet_numbers shared", k)
		}
	}
	chaos := p.Text("quic.initial_layout") == "chaos"
	for _, k := range quicChaos {
		if chaos && !p.Has(k) {
			return fmt.Errorf("quic.initial_layout chaos requires %s", k)
		}
		if !chaos && p.Has(k) {
			return fmt.Errorf("%s is set while quic.initial_layout is not chaos", k)
		}
	}
	for _, r := range [][2]string{{"quic.chaos_crypto_splits_min", "quic.chaos_crypto_splits_max"},
		{"quic.chaos_pings_min", "quic.chaos_pings_max"}} {
		if p.Uint(r[0]) > p.Uint(r[1]) {
			return fmt.Errorf("%s exceeds %s", r[0], r[1])
		}
	}
	after := p.Text("quic.idle_close") == "after-pto"
	listed := false
	for _, k := range quicIdleClose {
		if after && !p.Has(k) {
			return fmt.Errorf("quic.idle_close after-pto requires %s", k)
		}
		if !after && p.Has(k) {
			return fmt.Errorf("%s is set while quic.idle_close is not after-pto", k)
		}
		listed = listed || strings.Contains(p.Text(k), "{undecryptable}")
	}
	names := p.Strings("quic.undecryptable_level_names")
	if listed != p.Has("quic.undecryptable_level_names") {
		return fmt.Errorf("quic.undecryptable_level_names goes with a reason that lists {undecryptable}")
	}
	if listed && len(names) != 4 {
		return fmt.Errorf("quic.undecryptable_level_names names the Initial, Handshake, 0-RTT and 1-RTT levels")
	}
	for _, n := range names {
		if n == "" || strings.ContainsAny(n, "\r\n\x00{}") {
			return fmt.Errorf("quic.undecryptable_level_names: %q is no level name", n)
		}
	}
	if p.Has("quic.handshake_timeout_ms") && p.Has("quic.handshake_idle_timeout_ms") &&
		p.Uint("quic.handshake_timeout_ms") < p.Uint("quic.handshake_idle_timeout_ms") {
		return fmt.Errorf("quic.handshake_timeout_ms is shorter than quic.handshake_idle_timeout_ms")
	}
	if p.Flag("quic.connected_socket") && !p.Flag("quic.dedicated_socket") {
		return fmt.Errorf("quic.connected_socket requires quic.dedicated_socket")
	}
	return nil
}

// QUICReasonValues are what a CONNECTION_CLOSE's reason says of the
// connection it closes: how long it was idle and its idle timeout, and the
// packets it kept that it could not decrypt yet, each its encryption level's
// name and its length.
type QUICReasonValues struct {
	Elapsed, Timeout time.Duration
	Undecryptable    []QUICUndecryptable
}

// QUICUndecryptable is a packet a connection kept until it has the keys to
// decrypt it: the name of its encryption level and its length.
type QUICUndecryptable struct {
	Level  string
	Length int
}

// QUICReason writes a reason template with its values: {elapsed} and
// {timeout} as quiche writes a QuicTime::Delta (ToDebuggingValue: whole
// seconds as Ns, whole milliseconds as Nms, else microseconds as Nus),
// {undecryptable_count} the number of packets kept, {undecryptable} each as
// [LEVEL, LENGTH], {{ and }} a brace. Any other brace is refused, so a
// profile's template is held to it before anything is sent.
func QUICReason(template string, v QUICReasonValues) (string, error) {
	var b strings.Builder
	for i := 0; i < len(template); i++ {
		c := template[i]
		switch {
		case c == '{' && strings.HasPrefix(template[i:], "{{"):
			b.WriteByte('{')
			i++
		case c == '}' && strings.HasPrefix(template[i:], "}}"):
			b.WriteByte('}')
			i++
		case c == '{':
			end := strings.IndexByte(template[i:], '}')
			if end < 0 {
				return "", fmt.Errorf("unsupported diagnostic placeholder")
			}
			switch template[i : i+end+1] {
			case "{elapsed}":
				b.WriteString(quicheDelta(v.Elapsed))
			case "{timeout}":
				b.WriteString(quicheDelta(v.Timeout))
			case "{undecryptable_count}":
				b.WriteString(strconv.Itoa(len(v.Undecryptable)))
			case "{undecryptable}":
				for _, u := range v.Undecryptable {
					fmt.Fprintf(&b, "[%s, %d]", u.Level, u.Length)
				}
			default:
				return "", fmt.Errorf("unsupported diagnostic placeholder")
			}
			i += end
		case c == '}':
			return "", fmt.Errorf("unsupported diagnostic placeholder")
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), nil
}

// quicheDelta is d as quiche's QuicTime::Delta::ToDebuggingValue writes it,
// to the microsecond.
func quicheDelta(d time.Duration) string {
	us := d.Microseconds()
	abs := us
	if abs < 0 {
		abs = -abs
	}
	switch {
	case abs >= 1e6 && abs%1e6 == 0:
		return strconv.FormatInt(us/1e6, 10) + "s"
	case abs >= 1e3 && abs%1e3 == 0:
		return strconv.FormatInt(us/1e3, 10) + "ms"
	}
	return strconv.FormatInt(us, 10) + "us"
}
