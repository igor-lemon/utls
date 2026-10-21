package tls

import (
	"bytes"
	"io"
	"net"
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
