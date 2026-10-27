package behavior

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCookiePrefixPolicy(t *testing.T) {
	valid := `[{"prefix":"__Host-","case_sensitive":false,"reject_nameless":true,"attributes":["secure","host-only","root-path"]}]`
	for _, raw := range []string{`[]`, valid} {
		p := Policy{"cookie.prefixes": json.RawMessage(raw)}
		if err := p.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, raw := range []string{
		`null`, `{}`, `[null]`, `[{}]`,
		strings.Replace(valid, `"prefix":"__Host-"`, `"prefix":null`, 1),
		strings.Replace(valid, `"__Host-"`, `""`, 1),
		strings.Replace(valid, `"__Host-"`, `"é"`, 1),
		strings.Replace(valid, `"__Host-"`, `"x=y"`, 1),
		strings.Replace(valid, `"__Host-"`, `"`+strings.Repeat("x", 257)+`"`, 1),
		strings.Replace(valid, `"case_sensitive":false`, `"case_sensitive":"false"`, 1),
		strings.Replace(valid, `"case_sensitive":false`, `"case_sensitive":false,"case_sensitive":true`, 1),
		strings.Replace(valid, `"root-path"`, `"unsupported"`, 1),
		strings.Replace(valid, `"root-path"`, `"secure"`, 1),
		strings.Replace(valid, `"attributes":["secure","host-only","root-path"]`, `"attributes":null`, 1),
		strings.Replace(valid, `"reject_nameless":true`, `"unknown":true`, 1),
		`[` + strings.TrimSuffix(strings.TrimPrefix(valid, "["), "]") + `,` + strings.TrimSuffix(strings.TrimPrefix(valid, "["), "]") + `]`,
		`[` + strings.TrimSuffix(strings.Repeat(strings.TrimSuffix(strings.TrimPrefix(valid, "["), "]")+",", 65), ",") + `]`,
	} {
		if err := (Policy{"cookie.prefixes": json.RawMessage(raw)}).Validate(); err == nil {
			t.Fatal("accepted invalid prefix policy:", raw)
		}
	}
	p := Policy{"cookie.prefixes": json.RawMessage(valid)}
	rules := p.CookiePrefixes()
	rules[0].Attributes[0] = "http-only"
	rules[0].Prefix = "changed"
	clone := p.Clone()
	clone["cookie.prefixes"][0] = 'x'
	if p.CookiePrefixes()[0].Prefix != "__Host-" || p.CookiePrefixes()[0].Attributes[0] != "secure" {
		t.Fatal("rules alias policy")
	}
}
