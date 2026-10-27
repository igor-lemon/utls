package tls

import (
	stdtls "crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"
)

func TestProfileResumptionRechecksCurrentRoots(t *testing.T) {
	for _, version := range []uint16{stdtls.VersionTLS12, stdtls.VersionTLS13} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			s := newECHTestServer(t)
			cfg := s.serverConfig(false)
			cfg.MinVersion, cfg.MaxVersion = version, version
			cache := NewLRUClientSessionCache(8)
			for n := 0; n < 2; n++ {
				run := s.handshake(t, nil, cfg, cache)
				if run.clientErr != nil || run.serverErr != nil || run.client.DidResume != (n == 1) || run.server.DidResume != (n == 1) {
					t.Fatalf("initial request%d: %+v", n, run)
				}
			}
			roots := s.roots
			s.roots = x509.NewCertPool()
			run := s.handshake(t, nil, cfg, cache)
			var verification *CertificateVerificationError
			if !errors.As(run.clientErr, &verification) || run.client.DidResume {
				t.Fatalf("untrusted cached chain resumed: %v, resumed %v", run.clientErr, run.client.DidResume)
			}
			s.roots = roots
			for n := 0; n < 2; n++ {
				run := s.handshake(t, nil, cfg, cache)
				if run.clientErr != nil || run.serverErr != nil || run.client.DidResume != (n == 1) || run.server.DidResume != (n == 1) {
					t.Fatalf("restored roots request%d: client %v, server %v, resumed %v/%v", n, run.clientErr, run.serverErr, run.client.DidResume, run.server.DidResume)
				}
			}
		})
	}
}
