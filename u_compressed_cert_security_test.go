package tls

import (
	"bytes"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"net"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/igor-lemon/utls/behavior"
	"github.com/klauspost/compress/zstd"
)

func compressedCertificateFor(t *testing.T, alg CertCompressionAlgo, body []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	switch alg {
	case CertCompressionBrotli:
		w := brotli.NewWriter(&out)
		_, _ = w.Write(body)
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	case CertCompressionZlib:
		w := zlib.NewWriter(&out)
		_, _ = w.Write(body)
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	case CertCompressionZstd:
		w, err := zstd.NewWriter(&out)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(body)
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return out.Bytes()
}

// A real encrypted handshake reaches the production UConn certificate path;
// the peer decrypts the client's alert under the negotiated handshake keys.
func TestCompressedCertificateErrorsOnEncryptedWire(t *testing.T) {
	for _, test := range []struct {
		name           string
		extra, corrupt bool
		want           alert
	}{
		{"trailing-output", true, false, alertBadCertificate},
		{"codec-failure", false, true, alertDecodeError},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, s := localPipe(t)
			defer c.Close()
			defer s.Close()
			cfg := testConfig.Clone()
			cfg.MinVersion, cfg.MaxVersion = VersionTLS13, VersionTLS13
			server := Server(s, cfg)
			_ = server.SetDeadline(time.Now().Add(5 * time.Second))
			served := make(chan error, 1)
			go func() {
				ctx := context.Background()
				ch, ech, err := server.readClientHello(ctx)
				if err != nil {
					served <- err
					return
				}
				hs := &serverHandshakeStateTLS13{c: server, ctx: ctx, clientHello: ch, echContext: ech}
				if err = hs.processClientHello(); err == nil {
					err = hs.checkForResumption()
				}
				if err == nil {
					err = hs.pickCertificate()
				}
				if err != nil {
					served <- err
					return
				}
				server.buffering = true
				if err = hs.sendServerParameters(); err != nil {
					served <- err
					return
				}
				msg := &certificateMsgTLS13{certificate: *hs.cert}
				raw, err := msg.marshal()
				if err != nil {
					served <- err
					return
				}
				body := raw[4:]
				declared := len(body)
				if test.extra {
					body = append(bytes.Clone(body), 0)
				}
				encoded := compressedCertificateFor(t, CertCompressionBrotli, body)
				if test.corrupt {
					encoded = []byte{0xff, 0xff}
				}
				if _, err = server.writeHandshakeRecord(&utlsCompressedCertificateMsg{algorithm: uint16(CertCompressionBrotli), uncompressedLength: uint32(declared), compressedCertificateMessage: encoded}, nil); err == nil {
					_, err = server.flush()
				}
				if err == nil {
					_, err = server.readHandshake(nil)
				}
				served <- err
			}()
			cc := testConfig.Clone()
			cc.OmitEmptyPsk = true
			cc.Behavior = behavior.Legacy()
			cc.Behavior["tls.certificate_decode_alert"] = []byte("50")
			uc := UClient(c, cc, HelloCustom, false, false, false)
			if err := uc.ApplyPreset(chromeHelloSpec(t)); err != nil {
				t.Fatal(err)
			}
			_ = uc.SetDeadline(time.Now().Add(5 * time.Second))
			err := uc.Handshake()
			if err == nil {
				t.Fatal("malformed certificate handshake succeeded")
			}
			var actual alert
			remote := <-served
			if !errors.As(remote, &actual) || actual != test.want {
				t.Fatalf("peer observed %v, want %v (client %v)", remote, test.want, err)
			}
		})
	}
}

func TestCompressedCertificateLengthIntegrity(t *testing.T) {
	msg := &certificateMsgTLS13{certificate: Certificate{Certificate: [][]byte{testP256Certificate}}}
	raw, err := msg.marshal()
	if err != nil {
		t.Fatal(err)
	}
	body := raw[4:]
	for _, alg := range []CertCompressionAlgo{CertCompressionBrotli, CertCompressionZlib, CertCompressionZstd} {
		for _, delta := range []int{-1, 0, 1, 2} {
			t.Run(fmt.Sprintf("%d/%d", alg, delta), func(t *testing.T) {
				c, s := net.Pipe()
				defer c.Close()
				defer s.Close()
				_ = c.SetDeadline(time.Now().Add(time.Second))
				alerted := make(chan []byte, 1)
				go func() { b := make([]byte, 7); n, _ := s.Read(b); alerted <- b[:n] }()
				conn := Client(c, &Config{})
				conn.vers = VersionTLS13
				hs := &clientHandshakeStateTLS13{c: conn, uconn: &UConn{certCompressionAlgs: []CertCompressionAlgo{alg}}}
				declared, encoded := len(body)+delta, body
				if delta == 2 { // A valid Certificate followed by extra decompressed output.
					declared, encoded = len(body), append(bytes.Clone(body), 0)
				}
				decoded, err := hs.decompressCert(utlsCompressedCertificateMsg{algorithm: uint16(alg), uncompressedLength: uint32(declared), compressedCertificateMessage: compressedCertificateFor(t, alg, encoded)})
				if delta == 0 {
					if err != nil || decoded == nil {
						t.Fatal(err)
					}
					_ = c.Close()
					<-alerted
					return
				}
				if err == nil {
					t.Error("decompressed length mismatch accepted")
				}
				_ = c.Close()
				wire := <-alerted
				if len(wire) != 7 || wire[6] != byte(alertBadCertificate) {
					t.Errorf("length mismatch alert=%x, error=%v", wire, err)
				}
			})
		}
	}
}

func TestCompressedCertificateAllocationBounded(t *testing.T) {
	if os.Getenv("UTLS_CERT_ALLOCATION_CHILD") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(ctx, exe, "-test.run=^TestCompressedCertificateAllocationBounded$", "-test.timeout=8s", "-test.v")
		cmd.Env = append(os.Environ(), "UTLS_CERT_ALLOCATION_CHILD=1", "GOMEMLIMIT=64MiB")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("bounded certificate probe: %v\n%s", err, out)
		}
		t.Logf("%s", out)
		return
	}
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	done := make(chan struct{})
	go func() { b := make([]byte, 7); _, _ = s.Read(b); close(done) }()
	conn := Client(c, &Config{})
	conn.vers = VersionTLS13
	hs := &clientHandshakeStateTLS13{c: conn, uconn: &UConn{certCompressionAlgs: []CertCompressionAlgo{CertCompressionZlib}}}
	compressed := compressedCertificateFor(t, CertCompressionZlib, []byte{0, 0, 0, 0})
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := hs.decompressCert(utlsCompressedCertificateMsg{algorithm: uint16(CertCompressionZlib), uncompressedLength: 0xffffff, compressedCertificateMessage: compressed})
	runtime.ReadMemStats(&after)
	_ = c.Close()
	<-done
	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("claimed16MiB allocated=%d error=%v", allocated, err)
	if err == nil || allocated > 2<<20 {
		t.Fatalf("certificate allocation unbounded: %d, %v", allocated, err)
	}
}

func TestABrotliCertificateWindowIsWhatItsLengthNeeds(t *testing.T) {
	rest := []byte{0xa5, 0x5a}
	read := func(stream []byte, n uint32) []byte {
		got, err := io.ReadAll(brotliWindowFor(stream, n))
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	// nothing, and windows of 2^17 bytes or less, as they are
	for _, first := range []byte{0x00, 0x10, 0xf0, 0x01, 0x21, 0x71, 0xf1} {
		for _, n := range []uint32{0, 1 << 17, maxHandshakeCertificateMsg} {
			stream := append([]byte{first}, rest...)
			if got := read(stream, n); !bytes.Equal(got, stream) {
				t.Errorf("%#02x for %d: %x", first, n, got)
			}
		}
	}
	if got := read(nil, 1); len(got) != 0 {
		t.Errorf("nothing became %x", got)
	}
	// WBITS 18 to 24: the least that n needs, the other bits kept
	for code := byte(1); code <= 7; code++ {
		for _, n := range []uint32{0, 1, 1<<18 - 16, 1<<18 - 15, maxHandshakeCertificateMsg} {
			for _, high := range []byte{0x00, 0xf0, 0x50} {
				stream := append([]byte{high | code<<1 | 1}, rest...)
				need := uint32(18)
				if n > 1<<18-16 {
					need = 19
				}
				want := min(17+uint32(code), need)
				got := read(stream, n)
				if got[0]&1 != 1 || got[0]&0xf0 != high || uint32(17+got[0]>>1&7) != want || !bytes.Equal(got[1:], rest) {
					t.Errorf("WBITS %d for %d (%#02x): %x, want WBITS %d", 17+code, n, stream[0], got, want)
				}
			}
		}
	}
}

// longDistanceCertificate is a Certificate message of n bytes whose twelve
// bytes before its last two are its first twelve, and are nowhere else: words
// between make it worth compressing, so an encoder copies them from n - 14
// bytes back, which for the largest message is further than a window of 2^18
// reaches, and a decoder given that window reads a dictionary word there.
func longDistanceCertificate(t *testing.T, n int) []byte {
	t.Helper()
	words := []string{"alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliett"}
	draw := mathrand.New(mathrand.NewPCG(1, 2))
	blob := []byte{0xfe, 0xfd, 0xfc, 0xfb, 0xfa}
	for len(blob) < n-9-12 {
		blob = append(append(blob, words[draw.IntN(len(words))]...), ' ')
	}
	blob = append(blob[:n-9-12], make([]byte, 12)...)
	marshal := func() []byte {
		raw, err := (&certificateMsgTLS13{certificate: Certificate{Certificate: [][]byte{blob}}}).marshal()
		if err != nil {
			t.Fatal(err)
		}
		return raw[4:]
	}
	body := marshal()
	copy(blob[len(blob)-12:], body[:12])
	body = marshal()
	if len(body) != n || !bytes.Equal(body[n-14:n-2], body[:12]) {
		t.Fatalf("a message of %d bytes, not %d", len(body), n)
	}
	return body
}

func TestABrotliCertificateDecodesAsItsOwnWindowSays(t *testing.T) {
	msg := &certificateMsgTLS13{certificate: Certificate{Certificate: [][]byte{testP256Certificate}}}
	raw, err := msg.marshal()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name    string
		body    []byte
		quality int
		windows []int
	}{
		{"a certificate", raw[4:], 5, []int{10, 16, 17, 18, 19, 22, 24}},
		{"one of 2^18 - 16 bytes", longDistanceCertificate(t, 1<<18-16), 5, []int{18, 19, 22, 24}},
		{"one of the largest", longDistanceCertificate(t, maxHandshakeCertificateMsg), 5, []int{18, 19, 22, 24}},
	} {
		for _, window := range c.windows {
			t.Run(fmt.Sprintf("%s/%d", c.name, window), func(t *testing.T) {
				var compressed bytes.Buffer
				w := brotli.NewWriterOptions(&compressed, brotli.WriterOptions{Quality: c.quality, LGWin: window})
				_, _ = w.Write(c.body)
				if err := w.Close(); err != nil {
					t.Fatal(err)
				}
				own, err := io.ReadAll(brotli.NewReader(bytes.NewReader(compressed.Bytes())))
				if err != nil || !bytes.Equal(own, c.body) {
					t.Fatalf("its own window: %d bytes, %v", len(own), err)
				}
				conn := Client(nil, &Config{})
				conn.vers = VersionTLS13
				hs := &clientHandshakeStateTLS13{c: conn, uconn: &UConn{certCompressionAlgs: []CertCompressionAlgo{CertCompressionBrotli}}}
				got, err := hs.decompressCert(utlsCompressedCertificateMsg{algorithm: uint16(CertCompressionBrotli), uncompressedLength: uint32(len(c.body)), compressedCertificateMessage: compressed.Bytes()})
				if err != nil {
					t.Fatal(err)
				}
				again, err := got.marshal()
				if err != nil || !bytes.Equal(again[4:], c.body) {
					t.Fatalf("decoded otherwise than its own window: %v", err)
				}
			})
		}
	}
}

func TestABrotliCertificateAllocatesNoMoreThanItsLengthNeeds(t *testing.T) {
	if os.Getenv("UTLS_BROTLI_WINDOW_CHILD") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(ctx, exe, "-test.run=^TestABrotliCertificateAllocatesNoMoreThanItsLengthNeeds$", "-test.timeout=15s", "-test.v")
		cmd.Env = append(os.Environ(), "UTLS_BROTLI_WINDOW_CHILD=1", "GOMEMLIMIT=64MiB")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("bounded brotli window probe: %v\n%s", err, out)
		}
		t.Logf("%s", out)
		return
	}
	// a window of 24 bits and a meta-block, not the last, of 2^24 bytes that
	// are not compressed, of which 64 come
	stream := append([]byte{0xcf, 0xff, 0xff, 0xff}, bytes.Repeat([]byte{'a'}, 64)...)
	for _, n := range []uint32{64, maxHandshakeCertificateMsg} {
		c, s := net.Pipe()
		_ = c.SetDeadline(time.Now().Add(time.Second))
		done := make(chan struct{})
		go func() { b := make([]byte, 7); _, _ = s.Read(b); close(done) }()
		conn := Client(c, &Config{})
		conn.vers = VersionTLS13
		hs := &clientHandshakeStateTLS13{c: conn, uconn: &UConn{certCompressionAlgs: []CertCompressionAlgo{CertCompressionBrotli}}}
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		_, err := hs.decompressCert(utlsCompressedCertificateMsg{algorithm: uint16(CertCompressionBrotli), uncompressedLength: n, compressedCertificateMessage: stream})
		runtime.ReadMemStats(&after)
		_ = c.Close()
		<-done
		_ = s.Close()
		allocated := after.TotalAlloc - before.TotalAlloc
		t.Logf("declared %d: allocated=%d error=%v", n, allocated, err)
		if err == nil || allocated > 2<<20 {
			t.Fatalf("a brotli window of 2^24 for %d bytes allocated %d: %v", n, allocated, err)
		}
	}
}

// A brotli stream cut short is refused, however much of the message it gave.
// One flushed before it was closed holds the message in a meta-block that is
// not the last, and ends with an empty last one: cut before that end it gives
// the whole message, which only the decoder can tell from a whole stream.
func TestATruncatedBrotliCertificateIsRefused(t *testing.T) {
	msg := &certificateMsgTLS13{certificate: Certificate{Certificate: [][]byte{testP256Certificate}}}
	raw, err := msg.marshal()
	if err != nil {
		t.Fatal(err)
	}
	body := raw[4:]
	var flushed bytes.Buffer
	w := brotli.NewWriter(&flushed)
	_, _ = w.Write(body)
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	whole := flushed.Len()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	compressed := flushed.Bytes()
	if got, err := io.ReadAll(brotli.NewReader(bytes.NewReader(compressed[:whole]))); !bytes.Equal(got, body) {
		t.Fatalf("the stream before its end gave %d bytes of %d (%v)", len(got), len(body), err)
	}
	for cut := range len(compressed) {
		c, s := net.Pipe()
		_ = c.SetDeadline(time.Now().Add(time.Second))
		done := make(chan struct{})
		go func() { b := make([]byte, 7); _, _ = s.Read(b); close(done) }()
		conn := Client(c, &Config{})
		conn.vers = VersionTLS13
		hs := &clientHandshakeStateTLS13{c: conn, uconn: &UConn{certCompressionAlgs: []CertCompressionAlgo{CertCompressionBrotli}}}
		_, err := hs.decompressCert(utlsCompressedCertificateMsg{algorithm: uint16(CertCompressionBrotli), uncompressedLength: uint32(len(body)), compressedCertificateMessage: compressed[:cut]})
		_ = c.Close()
		<-done
		_ = s.Close()
		if err == nil {
			t.Fatalf("a stream cut to %d of its %d bytes was taken", cut, len(compressed))
		}
	}
}
