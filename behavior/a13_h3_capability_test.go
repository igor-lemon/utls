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
		p["h3.settings"] = json.RawMessage(test.raw)
		err := p.Validate()
		if (err == nil) != test.valid {
			t.Errorf("%s: %v", test.raw, err)
		}
	}
}
