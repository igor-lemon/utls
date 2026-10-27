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
