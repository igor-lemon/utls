package behavior

import (
	"encoding/json"
	"testing"
)

func TestPolicyJSONDoesNotInventChoices(t *testing.T) {
	for _, tc := range []struct{ name, key, raw string }{
		{"setting missing value", "h3.settings", `[{"id":51}]`},
		{"setting null value", "h3.settings", `[{"id":51,"value":null}]`},
		{"setting folded field", "h3.settings", `[{"id":51,"Value":0}]`},
		{"setting duplicate field", "h3.settings", `[{"id":51,"value":0,"value":1}]`},
		{"setting trailing value", "h3.settings", `[{"id":51,"value":0}] []`},
		{"number null element", "url.blocked_ports", `[null]`},
		{"text null element", "h3.qpack.never_index", `[null]`},
		{"invalid utf8 text", "headers.accept_fetch", string([]byte{'"', 255, '"'})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := Policy{tc.key: json.RawMessage(tc.raw)}
			if err := p.Validate(); err == nil {
				t.Fatal("invalid JSON representation was accepted and selected a zero/empty/last/default choice")
			}
		})
	}
	for _, name := range []string{"null template", "duplicate template"} {
		t.Run(name, func(t *testing.T) {
			p := withALPS(t, nil)
			fields := map[string]json.RawMessage{}
			if err := json.Unmarshal(p["h3.settings_errors"], &fields); err != nil {
				t.Fatal(err)
			}
			if err := p.Validate(); err != nil {
				t.Fatalf("invalid positive template fixture: %v", err)
			}
			if name == "null template" {
				fields["boolean"] = json.RawMessage(`null`)
				p["h3.settings_errors"], _ = json.Marshal(fields)
			} else {
				raw := p["h3.settings_errors"]
				p["h3.settings_errors"] = append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"boolean":"fixed"}`)...)
			}
			if err := p.Validate(); err == nil {
				t.Fatal("invalid template JSON representation selected a fallback")
			}
		})
	}
}
