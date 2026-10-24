package behavior

import (
	"encoding/json"
	"strings"
	"testing"
)

// chromeECH is Chrome 155's ECH and DNS HTTPS record policy.
const chromeECH = `{"tls.ech": true, "tls.ech_inner_own": [0, 43, 65037],
 "tls.ech_inner_omitted": [11, 23, 35, 65281], "tls.ech_inner_min_version": 772,
 "tls.ech_padding_block": 32, "tls.ech_kems": [32], "tls.ech_kdfs": [1], "tls.ech_aeads": [1, 2, 3],
 "tls.ech_chacha_without_aes": true, "tls.ech_outer_psk": "none", "tls.ech_retries": 1,
 "tls.ech_retry_without": true, "dns.https_records": true, "dns.https_wait_percent": 20,
 "dns.https_wait_min_ms": 5, "dns.https_wait_max_ms": 50, "dns.https_upgrade": true, "dns.resolver": "built-in"}`

func TestECHPolicyIsTypedAndCoherent(t *testing.T) {
	var base Policy
	if err := json.Unmarshal([]byte(chromeECH), &base); err != nil {
		t.Fatal(err)
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("Chrome's: %v", err)
	}
	for _, tc := range []struct {
		name    string
		changes map[string]string // a key's new value, or "" to leave it out
		err     string            // "" when it is valid
	}{
		{"no ECH, no DNS", map[string]string{"tls.ech": "", "tls.ech_inner_own": "", "tls.ech_inner_omitted": "",
			"tls.ech_inner_min_version": "", "tls.ech_padding_block": "", "tls.ech_kems": "", "tls.ech_kdfs": "",
			"tls.ech_aeads": "", "tls.ech_chacha_without_aes": "", "tls.ech_outer_psk": "", "tls.ech_retries": "",
			"tls.ech_retry_without": "", "dns.https_records": "", "dns.https_wait_percent": "",
			"dns.https_wait_min_ms": "", "dns.https_wait_max_ms": "", "dns.https_upgrade": ""}, ""},
		{"ECH said off, and its layout", map[string]string{"tls.ech": "false"}, "is set while tls.ech is not"},
		{"a layout without tls.ech", map[string]string{"tls.ech": ""}, "is set while tls.ech is not"},
		{"no retries said", map[string]string{"tls.ech_retries": ""}, "tls.ech requires tls.ech_retries"},
		{"no inner layout", map[string]string{"tls.ech_inner_own": ""}, "tls.ech requires tls.ech_inner_own"},
		{"no server name of its own", map[string]string{"tls.ech_inner_own": "[43, 65037]"}, "must name server_name"},
		{"no inner marker", map[string]string{"tls.ech_inner_own": "[0, 43]"}, "must name server_name"},
		{"twice in one list", map[string]string{"tls.ech_inner_own": "[0, 43, 43, 65037]"}, "twice"},
		{"in both lists", map[string]string{"tls.ech_inner_omitted": "[11, 43]"}, "twice"},
		{"the PSK", map[string]string{"tls.ech_inner_omitted": "[11, 41]"}, "the engine's to place"},
		{"the padding", map[string]string{"tls.ech_inner_omitted": "[11, 21]"}, "the engine's to place"},
		{"the reference list", map[string]string{"tls.ech_inner_own": "[0, 64768, 65037]"}, "the engine's to place"},
		{"no extension", map[string]string{"tls.ech_inner_omitted": "[65536]"}, "is no extension"},
		{"a version below TLS 1.0", map[string]string{"tls.ech_inner_min_version": "768"}, "must be in"},
		{"a block past a byte", map[string]string{"tls.ech_padding_block": "256"}, "must be in"},
		{"no block", map[string]string{"tls.ech_padding_block": "0"}, ""},
		{"P-256's KEM", map[string]string{"tls.ech_kems": "[16]"}, "HPKE primitive API is unavailable"},
		{"HKDF-SHA384", map[string]string{"tls.ech_kdfs": "[2]"}, "HPKE primitive API is unavailable"},
		{"an export-only AEAD", map[string]string{"tls.ech_aeads": "[65535]"}, "HPKE primitive API is unavailable"},
		{"no AEAD", map[string]string{"tls.ech_aeads": "[]"}, "names nothing"},
		{"an AEAD twice", map[string]string{"tls.ech_aeads": "[1, 3, 1]"}, "twice"},
		{"a GREASE PSK in the outer", map[string]string{"tls.ech_outer_psk": `"grease"`}, "unsupported primitive"},
		{"retries past the bound", map[string]string{"tls.ech_retries": "9"}, "must be in"},
		{"no wait said", map[string]string{"dns.https_wait_max_ms": ""}, "dns.https_records requires dns.https_wait_max_ms"},
		{"a wait without records", map[string]string{"dns.https_records": "false"}, "is set while dns.https_records is not"},
		{"an upgrade without records", map[string]string{"dns.https_records": "", "dns.https_wait_percent": "",
			"dns.https_wait_min_ms": "", "dns.https_wait_max_ms": ""}, "dns.https_upgrade requires dns.https_records"},
		{"no upgrade, no records", map[string]string{"dns.https_records": "", "dns.https_wait_percent": "",
			"dns.https_wait_min_ms": "", "dns.https_wait_max_ms": "", "dns.https_upgrade": "false"}, ""},
		{"records the machine's resolver asks", map[string]string{"dns.resolver": `"system"`},
			"dns.https_records requires dns.resolver built-in"},
		{"records with no resolver said", map[string]string{"dns.resolver": ""},
			"dns.https_records requires dns.resolver built-in"},
		{"an unknown resolver", map[string]string{"dns.resolver": `"getaddrinfo"`}, "unsupported primitive"},
		{"the built-in resolver without records", map[string]string{"dns.https_records": "", "dns.https_wait_percent": "",
			"dns.https_wait_min_ms": "", "dns.https_wait_max_ms": "", "dns.https_upgrade": ""}, ""},
		{"the machine's resolver without records", map[string]string{"dns.https_records": "", "dns.https_wait_percent": "",
			"dns.https_wait_min_ms": "", "dns.https_wait_max_ms": "", "dns.https_upgrade": "", "dns.resolver": `"system"`}, ""},
		{"a floor above the ceiling", map[string]string{"dns.https_wait_min_ms": "60"}, "exceeds"},
		{"a floor that is the ceiling", map[string]string{"dns.https_wait_min_ms": "50"}, ""},
		{"no ceiling", map[string]string{"dns.https_wait_max_ms": "0", "dns.https_wait_min_ms": "60"}, ""},
		{"a percent past whole", map[string]string{"dns.https_wait_percent": "101"}, "must be in"},
	} {
		p := base.Clone()
		for k, v := range tc.changes {
			if v == "" {
				delete(p, k)
				continue
			}
			p[k] = json.RawMessage(v)
		}
		err := p.Validate()
		if tc.err == "" && err != nil || tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.err)
		}
	}
}
