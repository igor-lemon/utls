package tls

import (
	stdtls "crypto/tls"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestRealECHWaitsForAuthenticatedTLS12Finished(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "corrupt"}[corrupt], func(t *testing.T) {
			s := newECHTestServer(t)
			cfg := s.serverConfig(false)
			cfg.MinVersion, cfg.MaxVersion = stdtls.VersionTLS12, stdtls.VersionTLS12
			cfg.NextProtos = []string{"h2"}
			clientRaw, serverRaw := localPipe(t)
			held := &heldConn{Conn: serverRaw, held: make(chan struct{}), release: make(chan struct{}), corrupt: corrupt}
			var once sync.Once
			release := func() { once.Do(func() { close(held.release) }) }
			t.Cleanup(func() { release(); _ = clientRaw.Close(); _ = serverRaw.Close() })
			server := stdtls.Server(held, cfg)
			_ = server.SetDeadline(time.Now().Add(10 * time.Second))
			served := make(chan error, 1)
			go func() { served <- server.Handshake() }()
			uc := UClient(clientRaw, &Config{ServerName: "secret.example", RootCAs: s.roots,
				EncryptedClientHelloConfigList: listOf(s.config), Behavior: policyOf(t, chromeECHPolicy),
				OmitEmptyPsk: true, FalseStart: true}, HelloCustom, false, false, false)
			if err := uc.ApplyPreset(chromeHelloSpec(t)); err != nil {
				t.Fatal(err)
			}
			_ = uc.SetDeadline(time.Now().Add(10 * time.Second))
			done := make(chan error, 1)
			go func() { done <- uc.Handshake() }()
			select {
			case <-held.held:
			case <-time.After(5 * time.Second):
				t.Fatal("server did not reach its Finished")
			}
			var err error
			early := false
			select {
			case err = <-done:
				early = true
				t.Error("ECH rejection returned before server Finished was authenticated")
			case <-time.After(100 * time.Millisecond):
			}
			release()
			if !early {
				err = <-done
			}
			var rejected *ECHRejectionError
			if corrupt {
				if err == nil || errors.As(err, &rejected) {
					t.Errorf("unauthenticated rejection: %v", err)
				}
			} else if !errors.As(err, &rejected) {
				t.Errorf("valid Finished did not yield ECH rejection: %v", err)
			}
			if uc.falseStarted.Load() || uc.ConnectionState().HandshakeComplete {
				t.Error("real ECH entered False Start or completed TLS1.2")
			}
			_ = uc.Close()
			<-served
		})
	}
}
