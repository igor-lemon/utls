package behavior

import (
	"encoding/json"
	"testing"
)

func TestContentCodingPolicy(t *testing.T) {
	for _, limit := range []string{"0", "1", "10", "64"} {
		for _, action := range []string{`"error"`, `"raw"`} {
			p := Policy{"http.max_content_codings": json.RawMessage(limit), "http.content_coding_overflow": json.RawMessage(action), "http.ignored_content_codings": json.RawMessage(`[]`)}
			if err := p.Validate(); err != nil {
				t.Fatal(limit, action, err)
			}
		}
	}
	for _, raw := range []string{
		`{"http.max_content_codings":65,"http.content_coding_overflow":"error"}`,
		`{"http.max_content_codings":-1,"http.content_coding_overflow":"error"}`,
		`{"http.max_content_codings":1.5,"http.content_coding_overflow":"error"}`,
		`{"http.max_content_codings":"10","http.content_coding_overflow":"error"}`,
		`{"http.max_content_codings":null,"http.content_coding_overflow":"error"}`,
		`{"http.max_content_codings":10,"http.content_coding_overflow":"ignore"}`,
		`{"http.max_content_codings":10}`,
		`{"http.content_coding_overflow":"error"}`,
		`{"http.ignored_content_codings":null}`,
		`{"http.ignored_content_codings":["gzip"]}`,
		`{"http.ignored_content_codings":["identity","identity"]}`,
		`{"http.ignored_content_codings":[false]}`,
		`{"http.max_content_codings":10,"http.max_content_codings":1}`,
	} {
		var p Policy
		err := json.Unmarshal([]byte(raw), &p)
		if err == nil {
			err = p.Validate()
		}
		if err == nil {
			t.Fatal("accepted invalid policy:", raw)
		}
	}
	if err := (Policy{"http.ignored_content_codings": json.RawMessage(`["identity"]`)}).Validate(); err != nil {
		t.Fatal(err)
	}
	first, second := Legacy(), Legacy()
	first["http.max_content_codings"] = json.RawMessage(`1`)
	if second.Uint("http.max_content_codings") != 10 || Generic().Uint("http.max_content_codings") != MaxContentCodings {
		t.Fatal("migration choices lost data ownership or clone isolation")
	}
}
