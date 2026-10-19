// Copyright 2026 tls-forge. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import "errors"

// False Start, as Chrome does it: a client whose TLS 1.2 handshake allows it
// sends its application data right after its Finished, a round trip before
// the server's would let it. Chromium sets SSL_MODE_ENABLE_FALSE_START for
// every connection, and BoringSSL false starts where can_false_start says,
// which falseStarts mirrors. Chrome 155 was measured doing so with ECDHE and
// AES-GCM or ChaCha20-Poly1305 over h2 and http/1.1, and waiting without
// ALPN, with a CBC suite and with an RSA key exchange.

// falseStarts says whether a client's full TLS 1.2 handshake goes on to its
// application data before the server's Finished: with Config.FalseStart, on
// the connection's first handshake, with an ECDHE key exchange, an AEAD and a
// protocol ALPN negotiated.
func (hs *clientHandshakeState) falseStarts() bool {
	c := hs.c
	return c.config.FalseStart && c.handshakes == 0 && c.vers == VersionTLS12 &&
		hs.suite.flags&suiteECDHE != 0 && hs.suite.aead != nil && c.clientProtocol != ""
}

// finishFalseStart reads what is left of a handshake the client false
// started, the server's session ticket, ChangeCipherSpec and Finished, and
// checks the Finished before any application data is read, as BoringSSL's
// SSL_read does. An error ends the connection for writes too: Handshake
// says it from then on.
func (c *Conn) finishFalseStart() error {
	if !c.falseStarted.Load() {
		return nil
	}
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()
	if !c.falseStarted.Load() {
		// Another Read finished it.
		return c.handshakeErr
	}
	c.in.Lock()
	defer c.in.Unlock()
	hs := c.falseStart
	c.falseStart = nil
	err := hs.readServerFlight()
	if err == nil {
		err = hs.complete()
	}
	c.handshakeErr = err
	c.falseStarted.Store(false)
	return err
}

// noEKMDuringFalseStart is ConnectionState.ekm while the server's Finished is
// not yet read.
func noEKMDuringFalseStart(label string, context []byte, length int) ([]byte, error) {
	return nil, errors.New("tls: ExportKeyingMaterial is unavailable until the server's Finished is read after False Start")
}
