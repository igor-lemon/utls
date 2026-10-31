package behavior

import (
	"encoding/json"
	"testing"
)

func TestA13HTTP3SettingsCapabilitiesStayExplicit(t *testing.T) {
	for _, test := range []struct {
		raw   string
		valid bool
	}{
		{`[{"id":8,"value":0}]`, true}, {`[{"id":8,"value":1}]`, true},
		{`[{"id":51,"value":1},{"id":16765559,"value":1},{"id":727725890,"value":0}]`, true},
		{`[{"id":16765559,"value":0}]`, true},
		{`[{"id":16765559,"value":2}]`, false}, {`[{"id":8,"value":2}]`, false},
		{`[{"id":727725890,"value":1}]`, false}, {`[{"id":727725890,"value":2}]`, false},
		{`[{"id":12345,"value":0}]`, false}, {`[{"id":0,"value":0}]`, false},
		{`[{"id":16765559,"value":1},{"id":16765559,"value":1}]`, false},
	} {
		p := Generic()
		p["h3.datagram_setting_error_reason"] = json.RawMessage(`""`)
		p["h3.settings"] = json.RawMessage(test.raw)
		err := p.Validate()
		if (err == nil) != test.valid {
			t.Errorf("%s: %v", test.raw, err)
		}
	}
}

func TestA13DraftDatagramReasonValidation(t *testing.T) {
	p := Generic()
	p["h3.settings"] = json.RawMessage(`[{"id":16765559,"value":1}]`)
	delete(p, "h3.datagram_setting_error_reason")
	if err := p.Validate(); err == nil {
		t.Fatal("missing explicit draft error reason accepted")
	}
	for _, raw := range []string{`null`, `123`, `"{unknown}"`, `"{value"`, `"line\nfeed"`} {
		p["h3.datagram_setting_error_reason"] = json.RawMessage(raw)
		if err := p.Validate(); err == nil {
			t.Fatal("bad template accepted", raw)
		}
	}
	p["h3.datagram_setting_error_reason"] = json.RawMessage(`"setting {id} value {value}"`)
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
}
