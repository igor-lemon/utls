package behavior

import "fmt"

// ackDecimation are the keys that say how a QUIC client acknowledges once
// the peer has sent many packets, as quiche's QuicReceivedPacketManager does
// (MaybeEnableAckDecimation, GetMaxAckDelay): from the packet numbered the
// peer's first plus quic.ack_decimation_after, every
// quic.ack_decimation_packets ack-eliciting packets, or
// quic.ack_decimation_rtt_percent of the least round trip after the first
// one not acknowledged came, no less than quic.ack_decimation_min_ms and no
// more than the ACK timer.
var ackDecimation = []string{"quic.ack_decimation_after", "quic.ack_decimation_packets",
	"quic.ack_decimation_rtt_percent", "quic.ack_decimation_min_ms"}

// ackOnly are the keys that say how many packets carrying an ACK and nothing
// ack-eliciting a client sends in a row, and the frame that makes the next
// one ack-eliciting (quiche's kMaxConsecutiveNonRetransmittablePackets and
// OnAckNeedsRetransmittableFrame; quic-go's MaxNonAckElicitingAcks, a PING).
var ackOnly = []string{"quic.ack_only_max", "quic.ack_only_frame"}

// validateQUICAcks holds the keys of how a QUIC client acknowledges to what
// the engine can do: decimation is told each of its numbers or none, the
// ACK-only packets their count and their frame together, and an ACK alarm's
// slack as a part of its delay is a part of a slack said.
func validateQUICAcks(p Policy) error {
	for _, set := range [][]string{ackDecimation, ackOnly} {
		for _, k := range set {
			for _, other := range set {
				if p.Has(k) && !p.Has(other) {
					return fmt.Errorf("%s requires %s", k, other)
				}
			}
		}
	}
	if p.Has("quic.ack_alarm_slack_percent") && !p.Has("quic.alarm_slack_ms") {
		return fmt.Errorf("quic.ack_alarm_slack_percent requires quic.alarm_slack_ms")
	}
	return nil
}
