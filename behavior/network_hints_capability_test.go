package behavior

import (
	"encoding/json"
	"testing"
)

func TestNetworkHintCapabilityHasExplicitImplementedChoices(t *testing.T) {
	for _, value := range []string{"none", "literal", "weighted-observations"} {
		raw, _ := json.Marshal(value)
		p := Policy{"headers.network_hints": raw}
		if err := p.Validate(); err != nil {
			t.Fatal(value, err)
		}
	}
	for _, value := range []string{"chrome", "default"} {
		raw, _ := json.Marshal(value)
		if err := (Policy{"headers.network_hints": raw}).Validate(); err == nil {
			t.Fatal("unsupported capability accepted", value)
		}
	}
	for _, raw := range []string{"true", "null", "123"} {
		if err := (Policy{"headers.network_hints": json.RawMessage(raw)}).Validate(); err == nil {
			t.Fatal("unsupported type accepted", raw)
		}
	}
	if Legacy().Has("headers.network_hints") || Generic().Has("headers.network_hints") {
		t.Fatal("new selector silently added to frozen legacy data")
	}
}
