package behavior

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// CookiePrefix selects implemented storage constraints. All choices, including
// case matching and treatment of a nameless value, are explicit profile data.
type CookiePrefix struct {
	Prefix         string   `json:"prefix"`
	CaseSensitive  bool     `json:"case_sensitive"`
	RejectNameless bool     `json:"reject_nameless"`
	Attributes     []string `json:"attributes"`
}

// CookiePrefixes returns independent rules from a policy validated at the
// profile boundary. It never supplies browser defaults for an absent field.
func (p Policy) CookiePrefixes() []CookiePrefix {
	var rules []CookiePrefix
	_ = json.Unmarshal(p["cookie.prefixes"], &rules)
	return rules
}

func parseCookiePrefixes(raw []byte) ([]CookiePrefix, error) {
	var records []json.RawMessage
	if err := json.Unmarshal(raw, &records); err != nil {
		return nil, err
	}
	// Engine safety ceilings, independent of a browser's chosen rule count.
	if len(records) > 64 {
		return nil, fmt.Errorf("at most 64 cookie prefix rules")
	}
	var rules []CookiePrefix
	seen := map[string]bool{}
	for _, record := range records {
		var fields Policy
		if err := json.Unmarshal(record, &fields); err != nil {
			return nil, err
		}
		for key, value := range fields {
			if !slices.Contains([]string{"prefix", "case_sensitive", "reject_nameless", "attributes"}, key) {
				return nil, fmt.Errorf("unknown cookie prefix field %q", key)
			}
			if bytes.Equal(value, []byte("null")) {
				return nil, fmt.Errorf("cookie prefix %s must not be null", key)
			}
		}
		if len(fields) != 4 {
			return nil, fmt.Errorf("cookie prefix requires prefix, case_sensitive, reject_nameless and attributes")
		}
		var rule CookiePrefix
		if err := json.Unmarshal(record, &rule); err != nil {
			return nil, err
		}
		if rule.Prefix == "" || len(rule.Prefix) > 256 {
			return nil, fmt.Errorf("cookie prefix must contain 1..256 bytes")
		}
		for _, c := range rule.Prefix {
			if c <= 32 || c >= 127 || strings.ContainsRune("()<>@,;:\\\"/[]?={} ", c) {
				return nil, fmt.Errorf("cookie prefix must be an ASCII token")
			}
		}
		key := strings.ToLower(rule.Prefix) // Prefix is already restricted to ASCII.
		if seen[key] {
			return nil, fmt.Errorf("duplicate cookie prefix %q", rule.Prefix)
		}
		seen[key] = true
		attrs := map[string]bool{}
		for _, attr := range rule.Attributes {
			if !slices.Contains([]string{"secure", "http-only", "host-only", "root-path"}, attr) || attrs[attr] {
				return nil, fmt.Errorf("unknown or duplicate cookie prefix attribute %q", attr)
			}
			attrs[attr] = true
		}
		rules = append(rules, rule)
	}
	return rules, nil
}
