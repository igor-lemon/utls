package behavior

import (
	"encoding/json"
	"testing"
)

func TestCacheAndInstancePolicy(t *testing.T) {
	for key, values := range map[string][]string{
		"http.instance_scope":              {`"request"`, `"client"`},
		"http.cache_scope":                 {`"browser-context"`, `"explicit-context"`},
		"http.cache_validators":            {`[]`, `["if-none-match","if-modified-since"]`, `["if-modified-since"]`},
		"cache.duplicate_freshness_policy": {`"first"`, `"stale"`},
		"cache.invalid_freshness_policy":   {`"ignore"`, `"stale"`},
		"cache.freshness_quoted_values":    {`true`, `false`},
		"cache.delta_seconds_limit":        {`1`, `4294967295`, `9223372036`},
	} {
		for _, value := range values {
			if err := (Policy{key: json.RawMessage(value)}).Validate(); err != nil {
				t.Fatal(key, value, err)
			}
		}
		for _, value := range []string{`null`, `{}`, `"unknown"`} {
			if err := (Policy{key: json.RawMessage(value)}).Validate(); err == nil {
				t.Fatal("accepted", key, value)
			}
		}
	}
	for _, value := range []string{`["etag"]`, `["If-None-Match"]`, `["if-none-match","if-none-match"]`, `[false]`, `"if-none-match"`} {
		if err := (Policy{"http.cache_validators": json.RawMessage(value)}).Validate(); err == nil {
			t.Fatal("accepted", value)
		}
	}
	for _, value := range []string{`0`, `-1`, `1.5`, `9223372037`, `18446744073709551615`} {
		if err := (Policy{"cache.delta_seconds_limit": json.RawMessage(value)}).Validate(); err == nil {
			t.Fatal("accepted", value)
		}
	}
	for _, raw := range []string{`[]`, `["range"]`, `["range","if-range","range"]`, `["range","if-range","X"]`, `["range","if-range","a b"]`, `["range","if-range",""]`, `["range","if-range","x:y"]`, `false`} {
		if err := (Policy{"cache.generated_header_order": json.RawMessage(raw)}).Validate(); err == nil {
			t.Fatal("accepted cache order", raw)
		}
	}
	if err := (Policy{"cache.generated_header_order": json.RawMessage(`["range","if-range","priority"]`)}).Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (Policy{"http.cache_validators": json.RawMessage(`["if-none-match"]`), "cache.generated_header_order": json.RawMessage(`["range","if-range"]`)}).Validate(); err == nil {
		t.Fatal("lost validator slot")
	}

	for _, p := range []Policy{Legacy(), Generic()} {
		if p.Text("http.instance_scope") != "request" {
			t.Fatal("migration shares browser state")
		}
	}
}
