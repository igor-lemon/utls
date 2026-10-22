package tls

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestChromeTicketAgeAndAtomicConsumption(t *testing.T) {
	c := &Conn{config: &Config{ChromeBehavior: true}}
	if c.ticketAge(1750*time.Millisecond) != 1000 {
		t.Fatal("ticket age is not quantized")
	}
	c.config.ChromeBehavior = false
	if c.ticketAge(1750*time.Millisecond) != 1750 {
		t.Fatal("ordinary TLS policy changed")
	}
	cache := NewLRUClientSessionCache(2).(*lruSessionCache)
	cache.Put("origin", &ClientSessionState{session: &SessionState{version: VersionTLS13}})
	var n atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := cache.Take("origin"); ok {
				n.Add(1)
			}
		}()
	}
	wg.Wait()
	if n.Load() != 1 {
		t.Fatalf("ticket offered %d times", n.Load())
	}
	cache.Put("tls12", &ClientSessionState{session: &SessionState{version: VersionTLS12}})
	for range 2 {
		if _, ok := cache.Take("tls12"); !ok {
			t.Fatal("TLS1.2 session consumed")
		}
	}
}
func TestChromeSNISerializationRetainsDNSDotOnly(t *testing.T) {
	for _, tc := range []struct {
		name   string
		chrome bool
		want   string
	}{{"example.com.", true, "example.com."}, {"example.com.", false, "example.com"}, {"127.0.0.1", true, ""}, {"[::1]", true, ""}} {
		e := &SNIExtension{ServerName: tc.name, chromeBehavior: tc.chrome}
		if tc.want == "" {
			if e.Len() != 0 {
				t.Fatal("IP literal named in SNI")
			}
			continue
		}
		b := make([]byte, e.Len())
		if _, err := e.Read(b); err != io.EOF {
			t.Fatal(err)
		}
		if !bytes.Equal(b[9:], []byte(tc.want)) {
			t.Fatalf("SNI %q", b[9:])
		}
	}
}
func TestChromeRejectsUnsolicitedEncryptedExtensions(t *testing.T) {
	for _, bad := range []bool{false, true} {
		a, b := net.Pipe()
		a.SetDeadline(time.Now().Add(time.Second))
		go io.Copy(io.Discard, b)
		u := UClient(a, &Config{ServerName: "example.com", ChromeBehavior: true, OmitEmptyPsk: true}, HelloChrome_Auto, false, false, true)
		if err := u.BuildHandshakeState(); err != nil {
			t.Fatal(err)
		}
		id := uint16(0)
		if bad {
			id = 65000
		}
		ee := []byte{8, 0, 0, 6, 0, 4, byte(id >> 8), byte(id), 0, 0}
		err := u.Conn.validateServerExtensions(ee)
		if (err != nil) != bad {
			t.Fatalf("unsolicited=%v,error=%v", bad, err)
		}
		a.Close()
		b.Close()
	}
}

// A socket can fail one write and later accept another. The first record has
// consumed its nonce even when zero bytes escaped. A later alert would have
// a sequence the peer cannot infer; neither partial nor zero writes permit it.
func TestChromeDoesNotSendAlertAfterFailedRecord(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(fmt.Sprintf("partial=%v", partial), func(t *testing.T) {
			raw, peer := net.Pipe()
			raw.SetDeadline(time.Now().Add(2 * time.Second))
			peer.SetDeadline(time.Now().Add(2 * time.Second))
			wrapped := &chromeFailedRecordConn{Conn: raw, partial: partial}
			serverConfig := testConfig.Clone()
			serverConfig.MinVersion, serverConfig.MaxVersion = VersionTLS13, VersionTLS13
			server := Server(peer, serverConfig)
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer peer.Close()
				if err := server.Handshake(); err != nil {
					return
				}
				io.Copy(io.Discard, server)
			}()
			cfg := testConfig.Clone()
			cfg.InsecureSkipVerify = true
			cfg.MinVersion, cfg.MaxVersion = VersionTLS13, VersionTLS13
			cfg.ChromeBehavior = true
			client := Client(wrapped, cfg)
			if err := client.Handshake(); err != nil {
				t.Fatal(err)
			}
			wrapped.fail.Store(true)
			if _, err := client.Write([]byte("owned payload")); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("failed write: %v", err)
			}
			before := wrapped.writes.Load()
			_ = client.Close()
			if wrapped.writes.Load() != before {
				t.Fatal("TLS wrote after a failed record,creating a sequence gap")
			}
			<-done
		})
	}
}

type chromeFailedRecordConn struct {
	net.Conn
	fail    atomic.Bool
	partial bool
	writes  atomic.Int32
}

func (c *chromeFailedRecordConn) Write(p []byte) (int, error) {
	c.writes.Add(1)
	if c.fail.Swap(false) {
		if c.partial {
			n, _ := c.Conn.Write(p[:7])
			return n, os.ErrDeadlineExceeded
		}
		return 0, os.ErrDeadlineExceeded
	}
	return c.Conn.Write(p)
}

func TestChromeUnofferedALPNAlertReachesTheWire(t *testing.T) {
	for _, chrome := range []bool{false, true} {
		t.Run(fmt.Sprint(chrome), func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			a.SetDeadline(time.Now().Add(2 * time.Second))
			b.SetDeadline(time.Now().Add(2 * time.Second))
			done := make(chan []byte, 1)
			go func() {
				head := make([]byte, 5)
				if _, err := io.ReadFull(b, head); err != nil {
					done <- nil
					return
				}
				ch := make([]byte, int(binary.BigEndian.Uint16(head[3:])))
				if _, err := io.ReadFull(b, ch); err != nil {
					done <- nil
					return
				}
				hello := &serverHelloMsg{vers: VersionTLS12, random: make([]byte, 32), cipherSuite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, alpnProtocol: "bad"}
				raw, err := hello.marshal()
				if err != nil {
					done <- nil
					return
				}
				record := append([]byte{22, 3, 3, byte(len(raw) >> 8), byte(len(raw))}, raw...)
				if _, err = b.Write(record); err != nil {
					done <- nil
					return
				}
				alert := make([]byte, 7)
				_, err = io.ReadFull(b, alert)
				if err != nil {
					done <- nil
					return
				}
				done <- alert
			}()
			c := UClient(a, &Config{ServerName: "example.com", InsecureSkipVerify: true, ChromeBehavior: chrome, OmitEmptyPsk: true}, HelloChrome_Auto, false, false, true)
			if err := c.Handshake(); err == nil {
				t.Fatal("unoffered ALPN accepted")
			}
			got := <-done
			want := byte(alertUnsupportedExtension)
			if chrome {
				want = byte(alertIllegalParameter)
			}
			if len(got) != 7 || got[0] != 21 || got[5] != 2 || got[6] != want {
				t.Fatalf("alert %x,want fatal %d", got, want)
			}
		})
	}
}
