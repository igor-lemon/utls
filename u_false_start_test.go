// Copyright 2026 tls-forge. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// heldConn is a server's connection whose second write, the flight that
// carries its Finished in a full TLS 1.2 handshake, waits for release; held
// is closed once it waits, and corrupt changes the flight's last byte, which
// is its Finished's.
type heldConn struct {
	net.Conn
	writes  int
	held    chan struct{}
	release chan struct{}
	corrupt bool
}

func (c *heldConn) Write(b []byte) (int, error) {
	if c.writes++; c.writes == 2 {
		close(c.held)
		<-c.release
		if c.corrupt {
			b = bytes.Clone(b)
			b[len(b)-1] ^= 1
		}
	}
	return c.Conn.Write(b)
}

// falseStartCase is a TLS 1.2 server's cipher suite, certificate and
// protocols, and a client of it: Go's own, or Chrome's hello in a UConn.
type falseStartCase struct {
	name   string
	suite  uint16
	ecdsa  bool
	protos []string
	parrot bool
	off    bool
}

// tlsClient is a Conn or a UConn.
type tlsClient interface {
	net.Conn
	Handshake() error
	ConnectionState() ConnectionState
}

// connOf is the Conn of a client.
func connOf(client tlsClient) *Conn {
	if u, ok := client.(*UConn); ok {
		return u.Conn
	}
	return client.(*Conn)
}

// countingConn counts the bytes a client writes.
type countingConn struct {
	net.Conn
	mu      sync.Mutex
	written int
}

func (c *countingConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.written += len(b)
	c.mu.Unlock()
	return c.Conn.Write(b)
}

func (c *countingConn) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.written
}

// falseStartPair is a server of tc that reads "ping" and answers "pong" as
// many times as it is given, its Finished held until held.release is closed,
// and a client of it, set to false start unless tc says otherwise.
func falseStartPair(t *testing.T, tc falseStartCase, pongs int, corrupt bool) (tlsClient, *heldConn, chan error) {
	t.Helper()
	raw, s := localPipe(t)
	t.Cleanup(func() { _ = raw.Close(); _ = s.Close() })
	c := &countingConn{Conn: raw}
	held := &heldConn{Conn: s, held: make(chan struct{}), release: make(chan struct{}), corrupt: corrupt}
	serverConfig := testConfig.Clone()
	serverConfig.MaxVersion = VersionTLS12
	serverConfig.CipherSuites = []uint16{tc.suite}
	serverConfig.NextProtos = tc.protos
	if tc.ecdsa {
		serverConfig.Certificates = []Certificate{{Certificate: [][]byte{testP256Certificate}, PrivateKey: testP256PrivateKey}}
	}
	served := make(chan error, 1)
	go func() {
		server := Server(held, serverConfig)
		buf := make([]byte, 4)
		for range pongs {
			if _, err := io.ReadFull(server, buf); err != nil {
				served <- err
				return
			}
			if _, err := server.Write([]byte("pong")); err != nil {
				served <- err
				return
			}
		}
		served <- nil
	}()
	clientConfig := testConfig.Clone()
	clientConfig.NextProtos = []string{"h2", "http/1.1"}
	clientConfig.FalseStart = !tc.off
	if tc.parrot {
		return UClient(c, clientConfig, HelloChrome_133, false, false, false), held, served
	}
	return Client(c, clientConfig), held, served
}

// handshaking is the result of the client's handshake, once it has one.
func handshaking(client tlsClient) chan error {
	out := make(chan error, 1)
	go func() { out <- client.Handshake() }()
	return out
}

// pong writes ping and reads the answer.
func pong(t *testing.T, client tlsClient) {
	t.Helper()
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(client, buf); err != nil || string(buf) != "pong" {
		t.Fatalf("read %q, %v", buf, err)
	}
}

func TestAClientFalseStartsWhereBoringSSLDoes(t *testing.T) {
	for _, tc := range []falseStartCase{
		{name: "ECDHE-ECDSA AES-128-GCM, h2", suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, ecdsa: true, protos: []string{"h2"}},
		{name: "ECDHE-RSA ChaCha20-Poly1305, http/1.1", suite: TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, protos: []string{"http/1.1"}},
		{name: "Chrome's hello, ECDHE-ECDSA AES-128-GCM, h2", suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, ecdsa: true,
			protos: []string{"h2", "http/1.1"}, parrot: true},
		{name: "Chrome's hello, ECDHE-RSA AES-256-GCM, http/1.1", suite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			protos: []string{"http/1.1"}, parrot: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, held, served := falseStartPair(t, tc, 1, false)
			// The handshake is over for the client while the server's Finished
			// waits.
			select {
			case err := <-handshaking(client):
				if err != nil {
					t.Fatalf("Handshake: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the handshake waited for the server's Finished")
			}
			state := client.ConnectionState()
			if state.HandshakeComplete || state.Version != VersionTLS12 || state.NegotiatedProtocol != tc.protos[0] {
				t.Errorf("while false started: complete %v, version %x, protocol %q", state.HandshakeComplete,
					state.Version, state.NegotiatedProtocol)
			}
			if _, err := state.ExportKeyingMaterial("label", nil, 8); err == nil || !strings.Contains(err.Error(), "False Start") {
				t.Errorf("keying material while false started: %v", err)
			}
			// Read(nil) reads nothing, the server's Finished neither.
			if n, err := client.Read(nil); n != 0 || err != nil || client.ConnectionState().HandshakeComplete {
				t.Errorf("Read(nil): %d, %v", n, err)
			}
			if _, err := client.Write([]byte("ping")); err != nil {
				t.Fatalf("Write while false started: %v", err)
			}
			<-held.held
			close(held.release)
			buf := make([]byte, 4)
			if _, err := io.ReadFull(client, buf); err != nil || string(buf) != "pong" {
				t.Fatalf("read %q, %v", buf, err)
			}
			state = client.ConnectionState()
			if !state.HandshakeComplete || connOf(client).falseStart != nil {
				t.Error("the handshake is not complete once the server's Finished is read, or its state kept")
			}
			// Chrome's hello asks for renegotiation, which keeps keying material
			// from being exported whatever False Start does.
			if _, err := state.ExportKeyingMaterial("label", nil, 8); err != nil &&
				(!tc.parrot || strings.Contains(err.Error(), "False Start")) {
				t.Errorf("keying material: %v", err)
			}
			if err := <-served; err != nil {
				t.Errorf("the server: %v", err)
			}
		})
	}
}

func TestAClientWaitsForTheServersFinishedWhereBoringSSLDoes(t *testing.T) {
	for _, tc := range []falseStartCase{
		{name: "not asked to", suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, ecdsa: true, protos: []string{"h2"}, off: true},
		{name: "Chrome's hello, not asked to", suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, ecdsa: true,
			protos: []string{"h2"}, parrot: true, off: true},
		{name: "no ALPN", suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, ecdsa: true},
		{name: "CBC", suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, protos: []string{"http/1.1"}},
		{name: "an RSA key exchange", suite: TLS_RSA_WITH_AES_128_GCM_SHA256, protos: []string{"http/1.1"}},
		{name: "Chrome's hello, CBC", suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, protos: []string{"http/1.1"}, parrot: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, held, served := falseStartPair(t, tc, 1, false)
			done := handshaking(client)
			<-held.held
			select {
			case err := <-done:
				t.Fatalf("the handshake was over before the server's Finished: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			close(held.release)
			if err := <-done; err != nil {
				t.Fatalf("Handshake: %v", err)
			}
			if !client.ConnectionState().HandshakeComplete {
				t.Error("the handshake is not complete")
			}
			pong(t, client)
			if err := <-served; err != nil {
				t.Errorf("the server: %v", err)
			}
		})
	}
}

func TestAFalseStartedClientTakesNoFinishedThatDoesNotCheck(t *testing.T) {
	for _, parrot := range []bool{false, true} {
		tc := falseStartCase{suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, ecdsa: true, protos: []string{"h2"}, parrot: parrot}
		client, held, _ := falseStartPair(t, tc, 1, true)
		if err := <-handshaking(client); err != nil {
			t.Fatalf("Handshake: %v", err)
		}
		if _, err := client.Write([]byte("ping")); err != nil {
			t.Fatalf("Write: %v", err)
		}
		close(held.release)
		_, err := client.Read(make([]byte, 4))
		if err == nil || !strings.Contains(err.Error(), "bad record MAC") {
			t.Fatalf("Read after a Finished that does not check: %v", err)
		}
		// The handshake says it from then on, and sends nothing more.
		written := connOf(client).conn.(*countingConn).count()
		if again := client.Handshake(); again == nil || again.Error() != err.Error() {
			t.Errorf("Handshake after: %v", again)
		}
		// Neither reading nor writing goes on, and the handshake is not taken
		// as complete.
		if _, again := client.Read(make([]byte, 4)); again == nil || again.Error() != err.Error() {
			t.Errorf("Read again: %v", again)
		}
		if _, werr := client.Write([]byte("ping")); werr == nil || werr.Error() != err.Error() {
			t.Errorf("Write after: %v", werr)
		}
		if client.ConnectionState().HandshakeComplete {
			t.Error("the handshake is taken as complete")
		}
		if n := connOf(client).conn.(*countingConn).count(); n != written {
			t.Errorf("%d bytes more were sent after the handshake failed", n-written)
		}
	}
}

func TestReadsAndWritesGoOnTogetherWhileAFalseStartFinishes(t *testing.T) {
	for _, parrot := range []bool{false, true} {
		tc := falseStartCase{suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, protos: []string{"http/1.1"}, parrot: parrot}
		client, held, served := falseStartPair(t, tc, 3, false)
		if err := <-handshaking(client); err != nil {
			t.Fatalf("Handshake: %v", err)
		}
		// Three readers wait for the server's Finished; one reads it, and
		// each reads an answer.
		var readers sync.WaitGroup
		read := make(chan string, 3)
		for range 3 {
			readers.Add(1)
			go func() {
				defer readers.Done()
				buf := make([]byte, 4)
				if _, err := io.ReadFull(client, buf); err != nil {
					read <- err.Error()
					return
				}
				read <- string(buf)
			}()
		}
		// Once a reader waits for the server's Finished, holding the
		// handshake's lock, writes go on all the same.
		mu := &connOf(client).handshakeMutex
		for deadline := time.Now().Add(5 * time.Second); mu.TryLock(); time.Sleep(time.Millisecond) {
			mu.Unlock()
			if time.Now().After(deadline) {
				t.Fatal("no reader waits for the server's Finished")
			}
		}
		for range 3 {
			if _, err := client.Write([]byte("ping")); err != nil {
				t.Fatalf("Write: %v", err)
			}
		}
		<-held.held
		close(held.release)
		readers.Wait()
		close(read)
		for got := range read {
			if got != "pong" {
				t.Errorf("a reader read %q", got)
			}
		}
		if err := <-served; err != nil {
			t.Errorf("the server: %v", err)
		}
	}
}

func TestTheSessionOfAFalseStartIsResumed(t *testing.T) {
	// The session ticket of the server's flight is kept once the server's
	// Finished is read, and the next connection resumes it: an abbreviated
	// handshake, whose server's Finished comes first, starts nothing early.
	cache := NewLRUClientSessionCache(1)
	tc := falseStartCase{suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, ecdsa: true, protos: []string{"h2"}}
	first, held, served := falseStartPair(t, tc, 1, false)
	first.(*Conn).config.ClientSessionCache = cache
	if err := first.Handshake(); err != nil {
		t.Fatalf("Handshake: %v", err)
	}
	if _, err := first.Write([]byte("ping")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	close(held.release)
	if _, err := io.ReadFull(first, make([]byte, 4)); err != nil {
		t.Fatalf("Read: %v", err)
	}
	<-served
	second, held, _ := falseStartPair(t, tc, 1, false)
	second.(*Conn).config.ClientSessionCache = cache
	close(held.release)
	if err := second.Handshake(); err != nil {
		t.Fatalf("the second Handshake: %v", err)
	}
	if state := second.ConnectionState(); !state.DidResume || !state.HandshakeComplete {
		t.Errorf("the second connection: resumed %v, complete %v", state.DidResume, state.HandshakeComplete)
	}
}

func TestFalseStartsOnlyWhereItsRuleSays(t *testing.T) {
	base := func() *clientHandshakeState {
		return &clientHandshakeState{c: &Conn{config: &Config{FalseStart: true}, vers: VersionTLS12, clientProtocol: "h2"},
			suite: cipherSuiteByID(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)}
	}
	for _, tc := range []struct {
		name   string
		change func(hs *clientHandshakeState)
		want   bool
	}{
		{"ECDHE, AES-GCM and ALPN", func(*clientHandshakeState) {}, true},
		{"ChaCha20-Poly1305", func(hs *clientHandshakeState) {
			hs.suite = cipherSuiteByID(TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)
		}, true},
		{"not asked to", func(hs *clientHandshakeState) { hs.c.config.FalseStart = false }, false},
		{"a renegotiation", func(hs *clientHandshakeState) { hs.c.handshakes = 1 }, false},
		{"TLS 1.1", func(hs *clientHandshakeState) { hs.c.vers = VersionTLS11 }, false},
		{"an RSA key exchange", func(hs *clientHandshakeState) {
			hs.suite = cipherSuiteByID(TLS_RSA_WITH_AES_128_GCM_SHA256)
		}, false},
		{"CBC", func(hs *clientHandshakeState) { hs.suite = cipherSuiteByID(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA) }, false},
		{"no ALPN", func(hs *clientHandshakeState) { hs.c.clientProtocol = "" }, false},
	} {
		hs := base()
		tc.change(hs)
		if got := hs.falseStarts(); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestHandshakesAtOnceFalseStartOnce(t *testing.T) {
	// The second waits for the first, and goes on once the client's Finished
	// is out, rather than shaking hands again.
	for _, parrot := range []bool{false, true} {
		tc := falseStartCase{suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, ecdsa: true, protos: []string{"h2"}, parrot: parrot}
		client, held, served := falseStartPair(t, tc, 1, false)
		first, second := handshaking(client), handshaking(client)
		for _, done := range []chan error{first, second} {
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("Handshake: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("a handshake waited for the server's Finished")
			}
		}
		<-held.held
		close(held.release)
		pong(t, client)
		if err := <-served; err != nil {
			t.Errorf("the server: %v", err)
		}
	}
}
