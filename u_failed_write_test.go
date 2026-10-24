package tls

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// errWriteFailed is the error of a write the tests fail, which no deadline of
// a pipe can say for it.
var errWriteFailed = errors.New("tls test: the write failed")

// failingConn fails the write it is told to, having written nothing of it, or
// its first seven bytes if partial, and counts the writes asked of it.
type failingConn struct {
	net.Conn
	fail    atomic.Bool
	partial bool
	writes  atomic.Int32
}

func (c *failingConn) Write(p []byte) (int, error) {
	c.writes.Add(1)
	if c.fail.Swap(false) {
		if c.partial {
			n, _ := c.Conn.Write(p[:7])
			return n, errWriteFailed
		}
		return 0, errWriteFailed
	}
	return c.Conn.Write(p)
}

// TestOnlyAFailedWriteStopsTheAlertsAfterIt holds a client of any Config to
// the record a failed write leaves behind: it took its sequence number, and
// with it a nonce, however few of its bytes went out, so the peer cannot read
// a record after it. After an application write that failed, having sent
// nothing or a part, Close only closes the connection and says the write's
// error. An alert that went out, a warning (TestWarningAlertFlood sends
// maxUselessRecords+1) or a fatal one, is followed by the close_notify, as in
// crypto/tls (the renegotiation recordings end with it). An alert whose own
// write failed is followed by nothing, nor is anything after a close_notify
// that failed, and what is refused says the write's error, never nil. A
// server sends its close_notify after a failed write, as crypto/tls does.
func TestOnlyAFailedWriteStopsTheAlertsAfterIt(t *testing.T) {
	for _, version := range []uint16{VersionTLS13, VersionTLS12} {
		for _, partial := range []bool{false, true} {
			t.Run(fmt.Sprintf("%x/write failed/partial=%v", version, partial), func(t *testing.T) {
				client, _, wrapped := overAFailingConn(t, version, true)
				wrapped.partial = partial
				failAWrite(t, client, wrapped)
				before := wrapped.writes.Load()
				if err := client.Close(); !errors.Is(err, errWriteFailed) {
					t.Fatalf("Close after a failed write: %v, want the write's error", err)
				}
				if wrapped.writes.Load() != before {
					t.Fatal("a close_notify went out after a failed write")
				}
			})
		}
		t.Run(fmt.Sprintf("%x/warning written", version), func(t *testing.T) {
			client, _, wrapped := overAFailingConn(t, version, true)
			before := wrapped.writes.Load()
			client.sendAlert(alertNoRenegotiation)
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if got := wrapped.writes.Load() - before; got != 2 {
				t.Fatalf("%d records after a warning was written, want it and the close_notify", got)
			}
		})
		t.Run(fmt.Sprintf("%x/fatal written", version), func(t *testing.T) {
			client, _, wrapped := overAFailingConn(t, version, true)
			before := wrapped.writes.Load()
			client.sendAlert(alertInternalError)
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if got := wrapped.writes.Load() - before; got != 2 {
				t.Fatalf("%d records after a fatal alert was written, want it and the close_notify", got)
			}
		})
		t.Run(fmt.Sprintf("%x/alert failed", version), func(t *testing.T) {
			client, _, wrapped := overAFailingConn(t, version, true)
			wrapped.fail.Store(true)
			client.sendAlert(alertInternalError)
			before := wrapped.writes.Load()
			if err := client.Close(); !errors.Is(err, errWriteFailed) {
				t.Fatalf("Close after an alert's write failed: %v, want the write's error", err)
			}
			if wrapped.writes.Load() != before {
				t.Fatal("a close_notify went out after the alert's write failed")
			}
		})
		t.Run(fmt.Sprintf("%x/close_notify failed", version), func(t *testing.T) {
			client, _, wrapped := overAFailingConn(t, version, true)
			wrapped.fail.Store(true)
			if err := client.CloseWrite(); !errors.Is(err, errWriteFailed) {
				t.Fatalf("CloseWrite: %v", err)
			}
			before := wrapped.writes.Load()
			// Nothing has put an error in c.out.err: a close_notify that
			// failed leaves it, so the refusal is the write's own error.
			if err := client.sendAlert(alertBadRecordMAC); !errors.Is(err, errWriteFailed) {
				t.Fatalf("an alert after a failed close_notify said %v, want the write's error", err)
			}
			if wrapped.writes.Load() != before {
				t.Fatal("an alert went out after the close_notify's write failed")
			}
		})
		t.Run(fmt.Sprintf("%x/server", version), func(t *testing.T) {
			server, _, wrapped := overAFailingConn(t, version, false)
			wrapped.fail.Store(true)
			if _, err := server.Write([]byte("lost")); !errors.Is(err, errWriteFailed) {
				t.Fatalf("failed write: %v", err)
			}
			before := wrapped.writes.Load()
			server.Close()
			if got := wrapped.writes.Load() - before; got != 1 {
				t.Fatalf("a server wrote %d records on Close after a failed write, want crypto/tls's close_notify", got)
			}
		})
	}
}

// TestAClientWritesNoRecordAfterAFailedWrite holds writeRecordLocked to the
// rule for the records that are not alerts. A client answers a KeyUpdate that
// asks for one and goes on under its next keys, unless a write failed before:
// then nothing goes out, its keys stay, and what the server sent after the
// KeyUpdate is read all the same. A TLS 1.2 client that allows renegotiation
// answers a HelloRequest with a ClientHello, unless a write failed before:
// then the Read says the write's error at once rather than wait for a
// ServerHello.
func TestAClientWritesNoRecordAfterAFailedWrite(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(fmt.Sprintf("KeyUpdate/failed=%v", failed), func(t *testing.T) {
			client, server, wrapped := overAFailingConn(t, VersionTLS13, true)
			if failed {
				failAWrite(t, client, wrapped)
			}
			before := wrapped.writes.Load()
			keys := bytes.Clone(client.out.trafficSecret)
			askForAKeyUpdate(t, client, server)
			answered := wrapped.writes.Load() - before
			moved := !bytes.Equal(client.out.trafficSecret, keys)
			if failed && (answered != 0 || moved) {
				t.Fatalf("%d records written, keys moved on %v; want none and no", answered, moved)
			}
			if !failed && (answered != 1 || !moved) {
				t.Fatalf("%d records written, keys moved on %v; want the answer and the next keys", answered, moved)
			}
		})
		t.Run(fmt.Sprintf("renegotiation/failed=%v", failed), func(t *testing.T) {
			client, server, wrapped := overAFailingConn(t, VersionTLS12, true)
			// Allowed once the handshake is over, before the server asks.
			client.config.Renegotiation = RenegotiateOnceAsClient
			if failed {
				failAWrite(t, client, wrapped)
			}
			before := wrapped.writes.Load()
			asked := make(chan error, 1)
			go func() { asked <- sendHelloRequest(server) }()
			read := make(chan error, 1)
			go func() {
				_, err := client.Read(make([]byte, 1))
				read <- err
			}()
			if failed {
				if err := <-read; !errors.Is(err, errWriteFailed) {
					t.Fatalf("Read after a HelloRequest said %v, want the failed write's error", err)
				}
				if wrapped.writes.Load() != before {
					t.Fatal("a ClientHello went out after a failed write")
				}
			} else {
				for wrapped.writes.Load() == before {
					select {
					case err := <-read:
						t.Fatalf("Read ended with %v and no ClientHello went out", err)
					case <-time.After(time.Millisecond):
					}
				}
				// The ClientHello is out; no ServerHello comes.
				wrapped.Close()
				<-read
			}
			if err := <-asked; err != nil {
				t.Fatal(err)
			}
		})
	}
}

// askForAKeyUpdate has the server send a KeyUpdate that asks the client for
// one, and then "after", which the client reads.
func askForAKeyUpdate(t *testing.T, client, server *Conn) {
	t.Helper()
	sent := make(chan error, 1)
	go func() {
		if err := sendKeyUpdate(server, true); err != nil {
			sent <- err
			return
		}
		_, err := server.Write([]byte("after"))
		sent <- err
	}()
	got := make([]byte, len("after"))
	if _, err := io.ReadFull(client, got); err != nil || string(got) != "after" {
		t.Fatalf("read %q, %v after the KeyUpdate, want what came after it", got, err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
}

// failAWrite has the client's next write fail, as a socket that times out.
func failAWrite(t *testing.T, client *Conn, wrapped *failingConn) {
	t.Helper()
	wrapped.fail.Store(true)
	if _, err := client.Write([]byte("lost")); !errors.Is(err, errWriteFailed) {
		t.Fatalf("failed write: %v", err)
	}
}

// sendKeyUpdate sends a KeyUpdate from c once its handshake is over, which
// asks the peer to update its keys too if requested, and goes on under c's
// next keys, as handleKeyUpdate answers one. Go's TLS has no call that sends
// one.
func sendKeyUpdate(c *Conn, requested bool) error {
	// Handshake waits for the handshake c's peer goroutine is in, whose
	// flush is done with the record layer only after its last write.
	if err := c.Handshake(); err != nil {
		return err
	}
	msg, err := (&keyUpdateMsg{updateRequested: requested}).marshal()
	if err != nil {
		return err
	}
	c.out.Lock()
	defer c.out.Unlock()
	if _, err := c.writeRecordLocked(recordTypeHandshake, msg); err != nil {
		return err
	}
	suite := cipherSuiteTLS13ByID(c.cipherSuite)
	c.out.setTrafficSecret(suite, QUICEncryptionLevelInitial, suite.nextTrafficSecret(c.out.trafficSecret))
	return nil
}

// sendHelloRequest sends a HelloRequest from c once its handshake is over: a
// TLS 1.2 server asking for a new handshake, which Go's servers never do.
func sendHelloRequest(c *Conn) error {
	if err := c.Handshake(); err != nil {
		return err
	}
	msg, err := (&helloRequestMsg{}).marshal()
	if err != nil {
		return err
	}
	c.out.Lock()
	defer c.out.Unlock()
	_, err = c.writeRecordLocked(recordTypeHandshake, msg)
	return err
}

// overAFailingConn is a Conn of a plain Config over a conn that fails the
// write it is told to, the client if client, else the server, handshaken
// with its peer, which reads whatever it writes after the handshake raw.
func overAFailingConn(t *testing.T, version uint16, client bool) (tested, peer *Conn, wrapped *failingConn) {
	t.Helper()
	raw, theirs := net.Pipe()
	raw.SetDeadline(time.Now().Add(5 * time.Second))
	theirs.SetDeadline(time.Now().Add(5 * time.Second))
	wrapped = &failingConn{Conn: raw}
	serverConfig := testConfig.Clone()
	serverConfig.MinVersion, serverConfig.MaxVersion = version, version
	clientConfig := testConfig.Clone()
	clientConfig.InsecureSkipVerify = true
	clientConfig.MinVersion, clientConfig.MaxVersion = version, version
	tested, peer = Client(wrapped, clientConfig), Server(theirs, serverConfig)
	if !client {
		tested, peer = Server(wrapped, serverConfig), Client(theirs, clientConfig)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer theirs.Close()
		if err := peer.Handshake(); err != nil {
			return
		}
		io.Copy(io.Discard, theirs)
	}()
	t.Cleanup(func() {
		raw.Close()
		<-done
	})
	if err := tested.Handshake(); err != nil {
		t.Fatal(err)
	}
	return tested, peer, wrapped
}
