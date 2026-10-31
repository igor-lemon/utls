package tls

import (
	"bytes"
	"crypto/rand"
	stdtls "crypto/tls"
	"errors"
	"fmt"
	"net"
	"testing"
)

func sharedHybridSpec(reverse bool, reuse bool) *ClientHelloSpec {
	shares := []KeyShare{{Group: X25519MLKEM768}, {Group: X25519}}
	if reuse {
		shares[1].ReuseWith = X25519MLKEM768
	}
	if reverse {
		shares[0], shares[1] = shares[1], shares[0]
	}
	return &ClientHelloSpec{TLSVersMin: VersionTLS13, TLSVersMax: VersionTLS13, CipherSuites: []uint16{TLS_AES_128_GCM_SHA256}, CompressionMethods: []uint8{0}, Extensions: []TLSExtension{&SNIExtension{}, &SupportedCurvesExtension{Curves: []CurveID{X25519MLKEM768, X25519, CurveP256}}, &SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{PSSWithSHA256, ECDSAWithP256AndSHA256}}, &SupportedVersionsExtension{Versions: []uint16{VersionTLS13}}, &KeyShareExtension{KeyShares: shares}, &PSKKeyExchangeModesExtension{Modes: []uint8{1}}, &UtlsPreSharedKeyExtension{}}}
}

func TestExplicitHybridKeyShareReuseAndIndependentDefault(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		for _, reuse := range []bool{false, true} {
			t.Run(fmt.Sprint(reverse, "/", reuse), func(t *testing.T) {
				c := UClient(&net.TCPConn{}, &Config{ServerName: "native.quic.test", OmitEmptyPsk: true}, HelloCustom, false, false, false)
				spec := sharedHybridSpec(reverse, reuse)
				if err := c.ApplyPreset(spec); err != nil {
					t.Fatal(err)
				}
				if err := c.BuildHandshakeState(); err != nil {
					t.Fatal(err)
				}
				keys := c.HandshakeState.State13.KeyShareKeys
				if (keys.MlkemEcdhe == keys.Keys[X25519]) != reuse {
					t.Fatal("private keys do not implement selected relationship")
				}
				if reuse {
					var hybrid, x []byte
					for _, e := range spec.Extensions {
						if k, ok := e.(*KeyShareExtension); ok {
							for _, s := range k.KeyShares {
								if s.Group == X25519MLKEM768 {
									hybrid = s.Data
								}
								if s.Group == X25519 {
									x = s.Data
								}
							}
						}
					}
					if len(hybrid) != 1216 || len(x) != 32 || !bytes.Equal(hybrid[len(hybrid)-32:], x) {
						t.Fatal("wire relationship differs from private-key ownership")
					}
				}
			})
		}
	}
}

type sharedKeyFailureReader struct{ err error }

func (r sharedKeyFailureReader) Read([]byte) (int, error) { return 0, r.err }

func TestHybridKeyShareReuseRejectsUnsafeSources(t *testing.T) {
	good := []KeyShare{{Group: X25519MLKEM768}, {Group: X25519, ReuseWith: X25519MLKEM768}}
	for name, shares := range map[string][]KeyShare{
		"wrong target":       {{Group: X25519MLKEM768}, {Group: CurveP256, ReuseWith: X25519MLKEM768}},
		"unsupported source": {{Group: CurveP256}, {Group: X25519, ReuseWith: CurveP256}},
		"missing source":     {{Group: X25519, ReuseWith: X25519MLKEM768}},
		"duplicate source":   {{Group: X25519MLKEM768}, {Group: X25519MLKEM768}, {Group: X25519, ReuseWith: X25519MLKEM768}},
		"duplicate target":   {{Group: X25519MLKEM768}, {Group: X25519}, {Group: X25519, ReuseWith: X25519MLKEM768}},
		"captured target":    {{Group: X25519MLKEM768}, {Group: X25519, Data: []byte{1}, ReuseWith: X25519MLKEM768}},
		"captured source":    {{Group: X25519MLKEM768, Data: []byte{1}}, {Group: X25519, ReuseWith: X25519MLKEM768}},
		"recursive source":   {{Group: X25519MLKEM768, ReuseWith: X25519}, {Group: X25519, ReuseWith: X25519MLKEM768}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := keyShareReuseKeys(shares, rand.Reader); err == nil {
				t.Fatal("accepted unsafe key source")
			}
		})
	}
	failed := errors.New("key generation failed")
	if _, err := keyShareReuseKeys(good, sharedKeyFailureReader{failed}); !errors.Is(err, failed) {
		t.Fatalf("random failure: %v", err)
	}
	if keys, err := keyShareReuseKeys([]KeyShare{{Group: X25519MLKEM768}, {Group: X25519}}, sharedKeyFailureReader{failed}); err != nil || keys != nil {
		t.Fatalf("independent mode consumed extra randomness: %v", err)
	}
	raw := `{"client_shares":[{"group":"x25519","reuse_with":4588}]}`
	var ext KeyShareExtension
	if err := ext.UnmarshalJSON([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	if len(ext.KeyShares) != 1 || ext.KeyShares[0].ReuseWith != X25519MLKEM768 {
		t.Fatal("JSON lost reuse source")
	}
	for _, value := range []string{"null", `"4588"`, "4588.0", "-1", "65536"} {
		var invalid KeyShareExtension
		raw := `{"client_shares":[{"group":"x25519","reuse_with":` + value + `}]}`
		if err := invalid.UnmarshalJSON([]byte(raw)); err == nil {
			t.Fatalf("accepted invalid reuse source %s", value)
		}
	}
}

func TestSharedHybridKeyShareAuthenticatedHandshakeAndHRR(t *testing.T) {
	s := newECHTestServer(t)
	for _, curve := range []stdtls.CurveID{stdtls.X25519MLKEM768, stdtls.X25519, stdtls.CurveP256} {
		t.Run(fmt.Sprint(curve), func(t *testing.T) {
			cfg := s.serverConfig(false)
			cfg.MinVersion, cfg.MaxVersion = stdtls.VersionTLS13, stdtls.VersionTLS13
			cfg.CurvePreferences = []stdtls.CurveID{curve}
			cache := NewLRUClientSessionCache(8)
			for n := 0; n < 3; n++ {
				run := s.handshakeWith(t, cfg, cache, func(c *Config) { c.Behavior = nil }, func(p *ClientHelloSpec) { *p = *sharedHybridSpec(false, true) }, nil)
				if run.clientErr != nil || run.serverErr != nil {
					t.Fatalf("request%d: client %v server %v", n, run.clientErr, run.serverErr)
				}
				if run.client.DidResume != (n > 0) || run.server.DidResume != (n > 0) {
					t.Fatalf("request%d: not an authenticated resumption", n)
				}
				if curve == stdtls.CurveP256 && len(run.hellos) != 2 {
					t.Fatalf("expected HRR, got%d ClientHellos", len(run.hellos))
				}
			}
		})
	}
}
