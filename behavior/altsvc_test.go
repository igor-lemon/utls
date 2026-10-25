package behavior

import (
	"encoding/json"
	"strings"
	"testing"
)

// chromeAltSvc is Chrome 155's following of Alt-Svc, laid over its HTTP/3 by
// an HTTPS record's alpn.
const chromeAltSvc = `{"quic.alt_svc": true, "quic.alt_svc_user_ports": false, "quic.alt_svc_remote_hosts": true,
 "quic.alt_svc_tcp_waits_with_h2": false}`

func TestAltSvcPolicyIsTypedAndCoherent(t *testing.T) {
	base := Legacy()
	for _, layer := range []string{chromeECH, chromeDNSH3, chromeAltSvc} {
		var over Policy
		if err := json.Unmarshal([]byte(layer), &over); err != nil {
			t.Fatal(err)
		}
		for k, v := range over {
			base[k] = v
		}
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("Chrome's: %v", err)
	}
	none := map[string]string{"quic.alt_svc": ""}
	for _, k := range altSvc {
		none[k] = ""
	}
	noDNSH3 := map[string]string{"dns.https_h3": ""}
	for _, k := range dnsH3 {
		noDNSH3[k] = ""
	}
	for _, tc := range []struct {
		name    string
		changes map[string]string // a key's new value, or "" to leave it out
		err     string            // "" when it is valid
	}{
		{"none of it", none, ""},
		{"said off, and its choices", map[string]string{"quic.alt_svc": "false"}, "is set while quic.alt_svc is not"},
		{"choices without it", map[string]string{"quic.alt_svc": ""}, "is set while quic.alt_svc is not"},
		{"said off alone", merge(none, map[string]string{"quic.alt_svc": "false"}), ""},
		{"without HTTP/3 by records", noDNSH3, "quic.alt_svc requires dns.https_h3"},
		{"no user ports said", map[string]string{"quic.alt_svc_user_ports": ""}, "quic.alt_svc requires quic.alt_svc_user_ports"},
		{"no remote hosts said", map[string]string{"quic.alt_svc_remote_hosts": ""}, "quic.alt_svc requires quic.alt_svc_remote_hosts"},
		{"no wait with HTTP/2 said", map[string]string{"quic.alt_svc_tcp_waits_with_h2": ""}, "quic.alt_svc requires quic.alt_svc_tcp_waits_with_h2"},
		{"every choice the other way", map[string]string{"quic.alt_svc_user_ports": "true", "quic.alt_svc_remote_hosts": "false",
			"quic.alt_svc_tcp_waits_with_h2": "true"}, ""},
		{"a choice as a word", map[string]string{"quic.alt_svc_remote_hosts": `"yes"`}, "cannot unmarshal string"},
		{"user ports as a number", map[string]string{"quic.alt_svc_user_ports": "0"}, "cannot unmarshal number"},
		{"a wait as a word", map[string]string{"quic.alt_svc_tcp_waits_with_h2": `"no"`}, "cannot unmarshal string"},
		{"it as a number", map[string]string{"quic.alt_svc": "1"}, "cannot unmarshal number"},
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

// merge is a's changes with b's over them.
func merge(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}
