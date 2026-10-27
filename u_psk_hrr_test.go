package tls

import (
	stdtls "crypto/tls"
	"fmt"
	"testing"
)

// A standard-library peer verifies the binder and reports actual acceptance;
// falling back to a full handshake does not satisfy the resumed cases.
func TestProfilePSKAfterHelloRetryRequest(t *testing.T) {
	s := newECHTestServer(t)
	for _, curve := range []stdtls.CurveID{stdtls.CurveP256, stdtls.CurveP384, stdtls.X25519} {
		t.Run(fmt.Sprint(curve), func(t *testing.T) {
			cfg := s.serverConfig(false)
			cfg.MinVersion, cfg.MaxVersion = stdtls.VersionTLS13, stdtls.VersionTLS13
			cfg.CurvePreferences = []stdtls.CurveID{curve}
			cache := NewLRUClientSessionCache(8)
			for n := 1; n <= 6; n++ {
				run := s.handshake(t, nil, cfg, cache)
				if run.clientErr != nil || run.serverErr != nil {
					t.Fatalf("request %d: client %v, server %v", n, run.clientErr, run.serverErr)
				}
				if run.client.DidResume != (n > 1) || run.server.DidResume != (n > 1) {
					t.Fatalf("request %d: client resumed %v, server resumed %v", n, run.client.DidResume, run.server.DidResume)
				}
			}
		})
	}
}
