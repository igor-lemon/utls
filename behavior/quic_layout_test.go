package behavior

import (
	"encoding/json"
	"testing"
)

func TestQUICParameterLayoutNamesEverySlot(t *testing.T) {
	p := Generic()
	p["quic.parameter_order"] = json.RawMessage(`["grease", "1", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "14", "15", "17", "32", "6745883625174385", "4278509083"]`)
	p["quic.grease_parameter_length_rule"] = json.RawMessage(`"byte-modulo"`)
	p["quic.grease_parameter_length_min"] = json.RawMessage("0")
	p["quic.grease_parameter_length_max"] = json.RawMessage("15")
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"quic.parameter_order", "quic.grease_parameter_length_rule", "quic.grease_parameter_length_min", "quic.grease_parameter_length_max"} {
		q := p.Clone()
		delete(q, key)
		if err := q.Validate(); err == nil {
			t.Error("missing", key)
		}
	}
	for _, order := range [][]string{nil, {}, quicParameterSlots[:len(quicParameterSlots)-1], append(append([]string{}, quicParameterSlots[:len(quicParameterSlots)-1]...), "grease"), append(append([]string{}, quicParameterSlots[:len(quicParameterSlots)-1]...), "999")} {
		q := p.Clone()
		q["quic.parameter_order"], _ = json.Marshal(order)
		if err := q.Validate(); err == nil {
			t.Error("bad order accepted", order)
		}
	}
	for _, pair := range [][2]int{{16, 16}, {0, 0}, {0, 16}} {
		q := p.Clone()
		q["quic.grease_parameter_length_min"], _ = json.Marshal(pair[0])
		q["quic.grease_parameter_length_max"], _ = json.Marshal(pair[1])
		if err := q.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, pair := range [][2]int{{16, 15}, {0, 17}, {17, 17}, {-1, 0}} {
		q := p.Clone()
		q["quic.grease_parameter_length_min"], _ = json.Marshal(pair[0])
		q["quic.grease_parameter_length_max"], _ = json.Marshal(pair[1])
		if err := q.Validate(); err == nil {
			t.Error("bad length accepted", pair)
		}
	}
}
