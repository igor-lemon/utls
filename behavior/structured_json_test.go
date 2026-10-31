package behavior

import (
	"encoding/json"
	"testing"
)

func TestPolicyJSONPreservesExplicitZeroEmptyAndLiteralNullText(t *testing.T) {
	for _, raw := range []string{`0`, `false`, `""`, `"null"`, `[]`, `[0,"",false,"null"]`, `{"a":0,"b":"","c":[],"null":"literal"}`, `[{"id":1},{"id":1}]`} {
		if err := validateJSONChoices([]byte(raw)); err != nil {
			t.Errorf("valid representation %s: %v", raw, err)
		}
	}
	for _, raw := range []string{`[]`, `[{"id":51,"value":0}]`} {
		p := Policy{"h3.settings": json.RawMessage(raw)}
		if err := p.Validate(); err != nil {
			t.Fatal(raw, err)
		}
		settings := p.Settings("h3.settings")
		if raw != "[]" && (len(settings) != 1 || settings[0].ID != 51 || settings[0].Value != 0) {
			t.Fatal("explicit zero lost")
		}
		if raw == "[]" && len(settings) != 0 {
			t.Fatal("empty settings invented entries")
		}
	}
	if err := (Policy{"h3.datagram_setting_error_reason": json.RawMessage(`""`)}).Validate(); err != nil {
		t.Fatal("explicit empty template", err)
	}
}

func TestPolicyJSONRejectsLossyContainers(t *testing.T) {
	for _, raw := range []string{`null`, `[null]`, `{"a":null}`, `{"a":[{"b":null}]}`, `{"a":0,"a":1}`, `[0] [1]`, ``, `[`, `{"a":`} {
		if err := validateJSONChoices([]byte(raw)); err == nil {
			t.Errorf("accepted lossy/malformed representation %s", raw)
		}
	}
	for _, raw := range []string{`[{"id":null,"value":0}]`, `[{"value":0}]`, `[{"id":51,"value":0,"extra":1}]`, `[null]`, `[1]`, `[{"ID":51,"value":0}]`, `[{"id":51,"value":0.0}]`, `[{"id":51,"value":"0"}]`} {
		if err := (Policy{"h3.settings": json.RawMessage(raw)}).Validate(); err == nil {
			t.Error("invalid settings accepted", raw)
		}
	}
}
