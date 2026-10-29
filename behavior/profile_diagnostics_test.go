package behavior

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestHTTP3ProfileBoundsNameValueAndLimit(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want []string
	}{
		{`[4097]`, []string{"h3.grease_payload_lengths[0]", "4097", "0..4096"}},
		{`[]`, []string{"h3.grease_payload_lengths", "0 values", "1..256"}},
	} {
		p := Legacy()
		p["h3.grease_payload_lengths"] = json.RawMessage(tc.raw)
		err := p.Validate()
		if err == nil {
			t.Fatal("invalid policy accepted")
		}
		for _, want := range tc.want {
			if !strings.Contains(err.Error(), want) {
				t.Error(err, "lacks", want)
			}
		}
	}
}

func TestGREASESettingPlacementIsExplicitAndValidated(t *testing.T) {
	for _, choice := range []string{"last", "before-greater-id"} {
		p := Legacy()
		p["h3.grease_setting_placement"], _ = json.Marshal(choice)
		if err := p.Validate(); err != nil {
			t.Fatal(choice, err)
		}
	}
	for _, raw := range []string{`"unknown"`, `0`, `null`, `true`} {
		p := Legacy()
		p["h3.grease_setting_placement"] = json.RawMessage(raw)
		if err := p.Validate(); err == nil {
			t.Fatal("invalid placement accepted", raw)
		}
	}
	p := Legacy()
	delete(p, "h3.grease_setting_placement")
	if err := p.Validate(); err == nil {
		t.Fatal("implicit placement accepted")
	}
}
