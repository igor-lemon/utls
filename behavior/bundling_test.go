package behavior

import (
	"encoding/json"
	"strings"
	"testing"
)

// chromeQUICBundling is how Chrome 155's HTTP/3 client puts its writes in
// packets (quiche at its DEPS revision, measured on the bench): a request's
// PRIORITY_UPDATE, QPACK encoder instructions and HEADERS under one flush
// (QuicHttpStream::DoLoop's ScopedPacketFlusher), and its QPACK decoder's
// instructions only in packets it sends for something else
// (QuicSpdySession::MaybeBundleOpportunistically).
const chromeQUICBundling = `{"h3.request_writes": "one-flush", "h3.qpack.decoder_writes": "opportunistic"}`

func TestQUICBundlingPolicyIsTyped(t *testing.T) {
	base := Legacy()
	var over Policy
	if err := json.Unmarshal([]byte(chromeQUICBundling), &over); err != nil {
		t.Fatal(err)
	}
	for k, v := range over {
		base[k] = v
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("Chrome's: %v", err)
	}
	for _, tc := range []struct {
		name    string
		changes map[string]string // a key's new value, or "" to leave it out
		err     string            // "" when it is valid
	}{
		{"none of it", map[string]string{"h3.request_writes": "", "h3.qpack.decoder_writes": ""}, ""},
		{"quic-go's", map[string]string{"h3.request_writes": `"as-written"`, "h3.qpack.decoder_writes": `"as-written"`}, ""},
		{"a request in a packet a stream", map[string]string{"h3.request_writes": `"per-stream"`}, "unsupported primitive"},
		{"one flush as a flag", map[string]string{"h3.request_writes": "true"}, "cannot unmarshal bool"},
		{"decoder data that waits for a timer", map[string]string{"h3.qpack.decoder_writes": `"delayed"`}, "unsupported primitive"},
		{"decoder data said by number", map[string]string{"h3.qpack.decoder_writes": "1"}, "cannot unmarshal number"},
		{"decoder data in another case", map[string]string{"h3.qpack.decoder_writes": `"Opportunistic"`}, "unsupported primitive"},
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
