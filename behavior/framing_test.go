package behavior

import (
	"encoding/json"
	"testing"
)

func TestContentLengthUsesDataAndRealBodyState(t *testing.T) {
	p := Policy{"http.zero_content_length_methods": json.RawMessage(`["POST","PUT"]`), "http.content_length_empty_body": json.RawMessage(`true`)}
	for _, c := range []struct {
		method         string
		length         int64
		provided, want bool
	}{{"PATCH", 0, false, false}, {"PATCH", 0, true, true}, {"REPORT", 0, true, true}, {"POST", 0, false, true}, {"PUT", 0, false, true}, {"DELETE", 0, false, false}, {"PATCH", 123, true, true}, {"PATCH", -1, true, false}} {
		if got := p.SendContentLength(c.method, c.length, c.provided, false); got != c.want {
			t.Fatal(c, got)
		}
	}
	p["http.zero_content_length_methods"] = json.RawMessage(`["PATCH"]`)
	p["http.content_length_empty_body"] = json.RawMessage(`false`)
	if !p.SendContentLength("PATCH", 0, false, false) || p.SendContentLength("POST", 0, false, false) || p.SendContentLength("DELETE", 0, true, false) {
		t.Fatal("JSON selectors ignored")
	}
	for _, key := range []string{"http.zero_content_length_methods", "h1.zero_length_identity_excluded_methods"} {
		for _, raw := range []string{`null`, `1`, `[true]`, `[""]`, `["GET","GET"]`, `["bad method"]`, `["x:y"]`} {
			q := Policy{key: json.RawMessage(raw)}
			if q.Validate() == nil {
				t.Fatal(key, raw)
			}
		}
	}
}
