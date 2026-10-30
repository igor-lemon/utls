package behavior

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDNSQueryChoicesAreTypedBoundedAndComplete(t *testing.T) {
	const original = `{"dns.https_query_recursion_desired":true,"dns.https_query_udp_payload_bytes":4096,"dns.https_query_timeout_ms":2000}`
	var base Policy
	if err := json.Unmarshal([]byte(original), &base); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		key, value string
		valid      bool
	}{
		{"dns.https_query_recursion_desired", "false", true},
		{"dns.https_query_recursion_desired", `"false"`, false},
		{"dns.https_query_recursion_desired", "0", false},
		{"dns.https_query_recursion_desired", "null", false},
		{"dns.https_query_udp_payload_bytes", "511", false},
		{"dns.https_query_udp_payload_bytes", "512", true},
		{"dns.https_query_udp_payload_bytes", "513", true},
		{"dns.https_query_udp_payload_bytes", "65534", true},
		{"dns.https_query_udp_payload_bytes", "65535", true},
		{"dns.https_query_udp_payload_bytes", "65536", false},
		{"dns.https_query_udp_payload_bytes", "0", false},
		{"dns.https_query_udp_payload_bytes", "-1", false},
		{"dns.https_query_udp_payload_bytes", "512.5", false},
		{"dns.https_query_udp_payload_bytes", `"4096"`, false},
		{"dns.https_query_timeout_ms", "0", false},
		{"dns.https_query_timeout_ms", "1", true},
		{"dns.https_query_timeout_ms", "2", true},
		{"dns.https_query_timeout_ms", "59999", true},
		{"dns.https_query_timeout_ms", "60000", true},
		{"dns.https_query_timeout_ms", "60001", false},
		{"dns.https_query_timeout_ms", "18446744073709551615", false},
		{"dns.https_query_timeout_ms", "1.5", false},
		{"dns.https_query_timeout_ms", `"2000"`, false},
	} {
		p := base.Clone()
		p[tc.key] = json.RawMessage(tc.value)
		if err := p.Validate(); (err == nil) != tc.valid {
			t.Errorf("%s=%s: %v, valid=%v", tc.key, tc.value, err, tc.valid)
		}
	}
	for key := range base {
		p := base.Clone()
		delete(p, key)
		if err := p.Validate(); err == nil || !strings.Contains(err.Error(), key) {
			t.Errorf("missing%s: %v", key, err)
		}
	}
	if err := (Policy{}).Validate(); err != nil {
		t.Fatalf("offline policy without new group: %v", err)
	}
	unknown := base.Clone()
	unknown["dns.https_query_timeout_mss"] = json.RawMessage("1")
	if err := unknown.Validate(); err == nil {
		t.Fatal("unknown key accepted")
	}
	duplicate := strings.TrimSuffix(original, "}") + `,"dns.https_query_timeout_ms":1}`
	if err := json.Unmarshal([]byte(duplicate), new(Policy)); err == nil {
		t.Fatal("duplicate choice accepted")
	}
	for _, policy := range []Policy{Legacy(), Generic()} {
		for key := range base {
			if !policy.Has(key) {
				t.Errorf("migration data missing%s", key)
			}
		}
	}
}
