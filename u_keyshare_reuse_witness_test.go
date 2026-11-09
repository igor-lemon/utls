package tls

import (
	"bytes"
	"net"
	"reflect"
	"testing"
)

func TestA13NativeHybridKeyShareRelationship(t *testing.T) {
	shares := []KeyShare{{Group: X25519MLKEM768}, {Group: X25519}}
	if field := reflect.ValueOf(&shares[1]).Elem().FieldByName("ReuseWith"); field.IsValid() {
		field.SetUint(uint64(X25519MLKEM768))
	}
	ext := &KeyShareExtension{KeyShares: shares}
	c := UClient(&net.TCPConn{}, &Config{ServerName: "native.quic.test"}, HelloCustom, false, false, false)
	spec := &ClientHelloSpec{TLSVersMin: VersionTLS13, TLSVersMax: VersionTLS13, CipherSuites: []uint16{TLS_AES_128_GCM_SHA256}, CompressionMethods: []uint8{0}, Extensions: []TLSExtension{&SNIExtension{}, &SupportedCurvesExtension{Curves: []CurveID{X25519MLKEM768, X25519}}, &SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{PSSWithSHA256}}, &SupportedVersionsExtension{Versions: []uint16{VersionTLS13}}, ext}}
	if err := c.ApplyPreset(spec); err != nil {
		t.Fatal(err)
	}
	if err := c.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	// ApplyPreset works on a copy of the spec: what goes out is the UConn's.
	ext = c.Extensions[len(c.Extensions)-1].(*KeyShareExtension)
	hybrid, x := ext.KeyShares[0].Data, ext.KeyShares[1].Data
	if len(hybrid) != 1216 || len(x) != 32 {
		t.Fatalf("lengths %d %d", len(hybrid), len(x))
	}
	if !bytes.Equal(hybrid[len(hybrid)-32:], x) {
		t.Fatal("native relationship unavailable: hybrid and fallback X25519 differ")
	}
	keys := c.HandshakeState.State13.KeyShareKeys
	if keys.MlkemEcdhe != keys.Keys[X25519] {
		t.Fatal("wire key relation is not bound to the same private key")
	}
}
