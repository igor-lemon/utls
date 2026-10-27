// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// Ported from Go1.26.10 security regressions (CVE-2025-61730).

package tls

import (
	"context"
	"testing"
)

// TestServerHelloTrailingMessage (handshake_test.go) holds Go's own client to
// it; a parrot's handshake reads the ServerHello's record the same way.
func TestAParrotRefusesAServerHellosTrailingMessage(t *testing.T) {
	testServerHelloTrailingMessage(t, true)
}
func testServerHelloTrailingMessage(t *testing.T, parrot bool) {
	// In TLS 1.3 the change cipher spec message is optional. If a CCS message
	// is not sent, after reading the ServerHello, the read traffic secret is
	// set, and all following messages must be encrypted. If the server sends
	// additional unencrypted messages in a record with the ServerHello, the
	// client must either fail or ignore the additional messages.

	c, s := localPipe(t)
	go func() {
		ctx := context.Background()
		srv := Server(s, testConfig)
		clientHello, _, err := srv.readClientHello(ctx)
		if err != nil {
			testFatal(t, err)
		}

		hs := serverHandshakeStateTLS13{
			c:           srv,
			ctx:         ctx,
			clientHello: clientHello,
		}
		if err := hs.processClientHello(); err != nil {
			testFatal(t, err)
		}
		if err := transcriptMsg(hs.clientHello, hs.transcript); err != nil {
			testFatal(t, err)
		}

		record, err := concatHandshakeMessages(hs.hello, &encryptedExtensionsMsg{alpnProtocol: "h2"})
		if err != nil {
			testFatal(t, err)
		}

		if _, err := s.Write(record); err != nil {
			testFatal(t, err)
		}
		srv.Close()
	}()

	var cli tlsClient = Client(c, testConfig)
	if parrot {
		cfg := testConfig.Clone()
		cfg.OmitEmptyPsk = true
		uc := UClient(c, cfg, HelloCustom, false, false, false)
		if err := uc.ApplyPreset(chromeHelloSpec(t)); err != nil {
			t.Fatal(err)
		}
		cli = uc
	}
	expectedErr := "tls: handshake buffer not empty before setting read traffic secret"
	if err := cli.Handshake(); err == nil {
		t.Fatal("expected error from incomplete handshake, got nil")
	} else if err.Error() != expectedErr {
		t.Fatalf("expected error %q, got %q", expectedErr, err.Error())
	}
}
