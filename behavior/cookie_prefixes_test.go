package behavior

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestCookiePrefixPolicy(t *testing.T) {
	valid := `[{"prefix":"__Host-","case_sensitive":false,"reject_nameless":true,"attributes":["secure","host-only","root-path"]}]`
	// The engine's ceilings, at their edges: 64 rules, and a prefix of 256 bytes.
	var most []string
	for i := 0; i < 64; i++ {
		most = append(most, strings.Replace(strings.Trim(valid, "[]"), `"__Host-"`, fmt.Sprintf(`"__Rule%d-"`, i), 1))
	}
	longest := strings.Replace(valid, `"__Host-"`, `"`+strings.Repeat("x", 256)+`"`, 1)
	for _, raw := range []string{`[]`, valid, "[" + strings.Join(most, ",") + "]", longest} {
		p := Policy{"cookie.prefixes": json.RawMessage(raw)}
		if err := p.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	if rules := (Policy{"cookie.prefixes": json.RawMessage("[" + strings.Join(most, ",") + "]")}).CookiePrefixes(); len(rules) != 64 || rules[63].Prefix != "__Rule63-" {
		t.Fatal("64 rules not kept as given")
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
