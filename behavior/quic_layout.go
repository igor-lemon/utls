package behavior

import (
	"fmt"
	"slices"
)

// These are implemented client parameter slots, not a browser's chosen order.
// Optional fields occupy their slot only when current connection state emits them.
var quicParameterSlots = []string{"grease", "1", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "14", "15", "17", "32", "6745883625174385", "4278509083"}

func validateQUICParameterLayout(p Policy) error {
	keys := []string{"quic.parameter_order", "quic.grease_parameter_length_rule", "quic.grease_parameter_length_min", "quic.grease_parameter_length_max"}
	selected := false
	for _, key := range keys {
		selected = selected || p.Has(key)
	}
	if !selected {
		return nil
	}
	for _, key := range keys {
		if !p.Has(key) {
			return fmt.Errorf("explicit QUIC parameter layout requires %s", key)
		}
	}
	if p.Uint(keys[2]) > p.Uint(keys[3]) {
		return fmt.Errorf("QUIC GREASE parameter minimum length exceeds maximum")
	}
	order := p.Strings(keys[0])
	if len(order) != len(quicParameterSlots) {
		return fmt.Errorf("quic.parameter_order must name every supported client slot once")
	}
	for i, name := range order {
		if !slices.Contains(quicParameterSlots, name) || slices.Contains(order[:i], name) {
			return fmt.Errorf("quic.parameter_order: unsupported or repeated slot %q", name)
		}
	}
	return nil
}
