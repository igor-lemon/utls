package behavior

import (
	"encoding/json"
	"strings"
	"testing"
)

// chromeCache is how Chrome 156's HTTP cache keeps responses, as measured.
const chromeCache = `{"cache.store_any_status": true, "cache.validated_statuses": [200],
 "cache.response_pragma_no_cache": true, "cache.request_no_cache": "bypass", "cache.heuristic_percent": 10,
 "cache.heuristic_statuses": [200, 203, 206], "cache.heuristic_with_must_revalidate": false,
 "cache.implicit_fresh_statuses": [300, 301, 308, 410]}`

func TestCacheKeepingPolicyIsTypedAndCoherent(t *testing.T) {
	base := Legacy()
	var over Policy
	if err := json.Unmarshal([]byte(chromeCache), &over); err != nil {
		t.Fatal(err)
	}
	for k, v := range over {
		base[k] = v
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("Chrome's: %v", err)
	}
	none := map[string]string{}
	for k := range over {
		none[k] = ""
	}
	for _, tc := range []struct {
		name    string
		changes map[string]string // a key's new value, or "" to leave it out
		err     string            // "" when it is valid
	}{
		{"none of it", none, ""},
		{"no heuristic", map[string]string{"cache.heuristic_percent": "", "cache.heuristic_statuses": "",
			"cache.heuristic_with_must_revalidate": ""}, ""},
		{"a heuristic without its statuses", map[string]string{"cache.heuristic_statuses": ""}, "heuristic freshness needs"},
		{"a heuristic without its must-revalidate", map[string]string{"cache.heuristic_with_must_revalidate": ""},
			"heuristic freshness needs"},
		{"statuses without a heuristic", map[string]string{"cache.heuristic_percent": ""}, "heuristic freshness needs"},
		{"a heuristic of none", map[string]string{"cache.heuristic_percent": "0"}, "must be in [1,100]"},
		{"a heuristic of the whole", map[string]string{"cache.heuristic_percent": "100"}, ""},
		{"a heuristic past the whole", map[string]string{"cache.heuristic_percent": "101"}, "must be in [1,100]"},
		{"an informational status", map[string]string{"cache.validated_statuses": "[199]"}, "199, which is not a final status"},
		{"the first final status", map[string]string{"cache.implicit_fresh_statuses": "[200]"}, ""},
		{"the last final status", map[string]string{"cache.heuristic_statuses": "[599]"}, ""},
		{"no status", map[string]string{"cache.heuristic_statuses": "[600]"}, "600, which is not a final status"},
		{"a status twice", map[string]string{"cache.implicit_fresh_statuses": "[301, 301]"}, "301, which is not a final status said once"},
		{"another no-cache", map[string]string{"cache.request_no_cache": `"validate"`}, ""},
		{"a no-cache of neither", map[string]string{"cache.request_no_cache": `"reload"`}, "unsupported primitive"},
	} {
		p := Policy{}
		for k, v := range base {
			p[k] = v
		}
		for k, v := range tc.changes {
			if v == "" {
				delete(p, k)
			} else {
				p[k] = json.RawMessage(v)
			}
		}
		err := p.Validate()
		if tc.err == "" && err != nil || tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.err)
		}
	}
}
