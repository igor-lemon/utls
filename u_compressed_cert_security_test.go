package tls

import (
	"bytes"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
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
