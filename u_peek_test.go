// Copyright 2026 tls-forge. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// puttingCache is a session cache that says the key of each session put in
// it.
type puttingCache struct {
	ClientSessionCache
	puts chan string
}

func (c *puttingCache) Put(key string, cs *ClientSessionState) {
	c.ClientSessionCache.Put(key, cs)
	if cs != nil {
		c.puts <- key
	}
}

// peeker is a client that peeks.
type peeker interface {
	tlsClient
	Peek() error
}

// peekPair is a TLS 1.3 server that gives its session tickets after its
// handshake and then does what serve does with its connection, and a client
// of it, Go's own or Chrome's hello in a UConn, whose sessions go to a cache
// that says each.
func peekPair(t *testing.T, parrot bool, serve func(*Conn)) (peeker, *puttingCache) {
	t.Helper()
	c, s := localPipe(t)
	t.Cleanup(func() { _ = c.Close(); _ = s.Close() })
	serverConfig := testConfig.Clone()
	serverConfig.MinVersion = VersionTLS13
	go func() {
		server := Server(s, serverConfig)
		if server.Handshake() == nil {
			serve(server)
		}
	}()
	cache := &puttingCache{ClientSessionCache: NewLRUClientSessionCache(4), puts: make(chan string, 8)}
	clientConfig := testConfig.Clone()
	clientConfig.ServerName = "example.golang"
	clientConfig.ClientSessionCache = cache
	if parrot {
		return UClient(c, clientConfig, HelloChrome_133, false, false, false), cache
	}
	return Client(c, clientConfig), cache
}

// peeking is the result of the client's Peek, once it has one.
func peeking(client peeker) chan error {
	out := make(chan error, 1)
	go func() { out <- client.Peek() }()
	return out
}

func TestAPeekCachesTheSessionOfAConnectionNothingReadsAndLeavesItsData(t *testing.T) {
	for _, parrot := range []bool{false, true} {
		// The server answers a ping with a pong.
		client, cache := peekPair(t, parrot, func(server *Conn) {
			buf := make([]byte, 4)
			if _, err := io.ReadFull(server, buf); err == nil {
				_, _ = server.Write([]byte("pong"))
			}
		})
		if err := client.Handshake(); err != nil {
			t.Fatalf("Handshake: %v", err)
		}
		peeked := peeking(client)
		// The ticket is taken with nothing read.
		select {
		case key := <-cache.puts:
			if key != "example.golang" {
				t.Errorf("session cached under %q", key)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("parrot %v: no session cached while the connection was peeked", parrot)
		}
		select {
		case err := <-peeked:
			t.Fatalf("Peek returned %v with no data to read", err)
		case <-time.After(50 * time.Millisecond):
		}
		// A write goes while the peek waits, and the answer is left for Read
		// whole.
		written := make(chan error, 1)
		go func() {
			_, err := client.Write([]byte("ping"))
			written <- err
		}()
		select {
		case err := <-written:
			if err != nil {
				t.Fatalf("Write: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a Write waited for the peek")
		}
		if err := <-peeked; err != nil {
			t.Fatalf("Peek: %v", err)
		}
		// With data waiting a peek reads nothing more.
		if err := client.Peek(); err != nil {
			t.Fatalf("Peek again: %v", err)
		}
		buf := make([]byte, 8)
		if n, err := client.Read(buf); err != nil || string(buf[:n]) != "pong" {
			t.Errorf("Read after the peek: %q, %v", buf[:n], err)
		}
	}
}

func TestAPeekTakesEveryMessageOfARecord(t *testing.T) {
	// Two session tickets in one record, as BoringSSL packs them, and
	// nothing after: a peek caches both while it waits.
	for _, parrot := range []bool{false, true} {
		c, s := localPipe(t)
		t.Cleanup(func() { _ = c.Close(); _ = s.Close() })
		serverConfig := testConfig.Clone()
		serverConfig.MinVersion = VersionTLS13
		serverConfig.SessionTicketsDisabled = true
		go func() {
			server := Server(s, serverConfig)
			if server.Handshake() != nil {
				return
			}
			var record []byte
			for i := byte(1); i <= 2; i++ {
				m, err := (&newSessionTicketMsgTLS13{lifetime: 3600, ageAdd: uint32(i), nonce: []byte{i}, label: []byte{'t', i}}).marshal()
				if err != nil {
					return
				}
				record = append(record, m...)
			}
			server.out.Lock()
			_, _ = server.writeRecordLocked(recordTypeHandshake, record)
			server.out.Unlock()
		}()
		cache := &puttingCache{ClientSessionCache: NewLRUClientSessionCache(4), puts: make(chan string, 8)}
		clientConfig := testConfig.Clone()
		clientConfig.ServerName = "example.golang"
		clientConfig.ClientSessionCache = cache
		var client peeker = Client(c, clientConfig)
		if parrot {
			client = UClient(c, clientConfig, HelloChrome_133, false, false, false)
		}
		if err := client.Handshake(); err != nil {
			t.Fatalf("Handshake: %v", err)
		}
		go func() { _ = client.Peek() }()
		for i := 1; i <= 2; i++ {
			select {
			case <-cache.puts:
			case <-time.After(5 * time.Second):
				t.Fatalf("parrot %v: %d tickets of the record cached, want 2", parrot, i-1)
			}
		}
	}
}

func TestAPeekSaysTheEndAsAReadThenDoes(t *testing.T) {
	for _, parrot := range []bool{false, true} {
		client, _ := peekPair(t, parrot, func(server *Conn) { _ = server.Close() })
		if err := client.Handshake(); err != nil {
			t.Fatalf("Handshake: %v", err)
		}
		if err := client.Peek(); !errors.Is(err, io.EOF) {
			t.Errorf("parrot %v: Peek at the server's close: %v", parrot, err)
		}
		if n, err := client.Read(make([]byte, 4)); n != 0 || !errors.Is(err, io.EOF) {
			t.Errorf("parrot %v: Read after: %d, %v", parrot, n, err)
		}
	}
}

func TestAPeekSaysAMessageAfterTheHandshakeItCannotTake(t *testing.T) {
	for _, parrot := range []bool{false, true} {
		client, _ := peekPair(t, parrot, func(server *Conn) {
			_, _ = server.writeHandshakeRecord(&encryptedExtensionsMsg{}, nil)
		})
		if err := client.Handshake(); err != nil {
			t.Fatalf("Handshake: %v", err)
		}
		err := client.Peek()
		if err == nil || !strings.Contains(err.Error(), "unexpected handshake message") {
			t.Errorf("parrot %v: Peek at EncryptedExtensions after the handshake: %v", parrot, err)
		}
		// The alert it sent ends the connection's writing, as after a Read
		// that met the message.
		if _, werr := client.Write([]byte("ping")); werr == nil || !strings.Contains(werr.Error(), "unexpected message") {
			t.Errorf("parrot %v: Write after the peek's error: %v", parrot, werr)
		}
	}
}

func TestAPeekSaysAHandshakeThatFailed(t *testing.T) {
	for _, parrot := range []bool{false, true} {
		c, s := localPipe(t)
		go func() {
			_, _ = s.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			_ = s.Close()
		}()
		var client peeker = Client(c, testConfig)
		if parrot {
			client = UClient(c, testConfig, HelloChrome_133, false, false, false)
		}
		err := client.Peek()
		if err == nil || !strings.Contains(err.Error(), "first record does not look like a TLS handshake") {
			t.Errorf("parrot %v: Peek of a handshake that failed: %v", parrot, err)
		}
		_ = c.Close()
	}
}

func TestAPeekFinishesAFalseStart(t *testing.T) {
	for _, parrot := range []bool{false, true} {
		for _, corrupt := range []bool{false, true} {
			tc := falseStartCase{suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, ecdsa: true, protos: []string{"h2"}, parrot: parrot}
			client, held, _ := falseStartPair(t, tc, 1, corrupt)
			if err := <-handshaking(client); err != nil {
				t.Fatalf("Handshake: %v", err)
			}
			if client.ConnectionState().HandshakeComplete {
				t.Fatal("the handshake did not false start")
			}
			peeked := peeking(client.(peeker))
			close(held.release)
			if _, err := client.Write([]byte("ping")); err != nil && !corrupt {
				t.Fatalf("Write: %v", err)
			}
			err := <-peeked
			if corrupt {
				if err == nil || !strings.Contains(err.Error(), "bad record MAC") {
					t.Errorf("Peek after a Finished that does not check: %v", err)
				}
				if _, again := client.Read(make([]byte, 4)); again == nil || again.Error() != err.Error() {
					t.Errorf("Read after: %v", again)
				}
				continue
			}
			if err != nil {
				t.Fatalf("Peek: %v", err)
			}
			if !client.ConnectionState().HandshakeComplete {
				t.Error("the handshake is not complete after the peek")
			}
			buf := make([]byte, 4)
			if _, err := io.ReadFull(client, buf); err != nil || string(buf) != "pong" {
				t.Errorf("Read after the peek: %q, %v", buf, err)
			}
		}
	}
}

func TestAReadWaitsForAPeek(t *testing.T) {
	for _, parrot := range []bool{false, true} {
		client, cache := peekPair(t, parrot, func(server *Conn) {
			buf := make([]byte, 4)
			if _, err := io.ReadFull(server, buf); err == nil {
				_, _ = server.Write([]byte("pong"))
			}
		})
		if err := client.Handshake(); err != nil {
			t.Fatalf("Handshake: %v", err)
		}
		peeked := peeking(client)
		<-cache.puts
		read := make(chan string, 1)
		go func() {
			buf := make([]byte, 8)
			n, _ := client.Read(buf)
			read <- string(buf[:n])
		}()
		if _, err := client.Write([]byte("ping")); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := <-peeked; err != nil {
			t.Fatalf("Peek: %v", err)
		}
		if got := <-read; got != "pong" {
			t.Errorf("parrot %v: the Read beside the peek read %q", parrot, got)
		}
	}
}

func TestAPeekSaysAHandshakeThatFailedOnItsOwnSide(t *testing.T) {
	// The client refuses the server's certificate: its handshake's error,
	// not what the connection says after it.
	for _, parrot := range []bool{false, true} {
		c, s := localPipe(t)
		go func() {
			server := Server(s, testConfig)
			_ = server.Handshake()
			_, _ = io.Copy(io.Discard, server)
		}()
		config := testConfig.Clone()
		config.InsecureSkipVerify = false
		config.ServerName = "example.golang"
		var client peeker = Client(c, config)
		if parrot {
			client = UClient(c, config, HelloChrome_133, false, false, false)
		}
		if err := client.Peek(); err == nil || !strings.Contains(err.Error(), "x509") {
			t.Errorf("parrot %v: Peek of a handshake that refused the certificate: %v", parrot, err)
		}
		_ = c.Close()
		_ = s.Close()
	}
}

func TestAPeekRenegotiatesAsItsConnectionReadsDo(t *testing.T) {
	// A TLS 1.2 server asks for renegotiation after its handshake: a UConn's
	// peek answers with the UConn's own hello, as its Read would, not Go's.
	c, s := localPipe(t)
	t.Cleanup(func() { _ = c.Close(); _ = s.Close() })
	serverConfig := testConfig.Clone()
	serverConfig.MaxVersion = VersionTLS12
	hellos := make(chan *clientHelloMsg, 1)
	go func() {
		server := Server(s, serverConfig)
		if server.Handshake() != nil {
			return
		}
		if _, err := server.writeHandshakeRecord(&helloRequestMsg{}, nil); err != nil {
			return
		}
		if msg, err := server.readHandshake(nil); err == nil {
			if hello, ok := msg.(*clientHelloMsg); ok {
				hellos <- hello
			}
		}
	}()
	config := testConfig.Clone()
	config.Renegotiation = RenegotiateOnceAsClient
	client := UClient(c, config, HelloChrome_133, false, false, false)
	if err := client.Handshake(); err != nil {
		t.Fatalf("Handshake: %v", err)
	}
	go func() { _ = client.Peek() }()
	select {
	case hello := <-hellos:
		if len(hello.cipherSuites) == 0 || !isGREASEUint16(hello.cipherSuites[0]) {
			t.Errorf("the renegotiation's hello leads with %#04x, not the parrot's GREASE", hello.cipherSuites)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no renegotiation")
	}
}
