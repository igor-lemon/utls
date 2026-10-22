package tls

import (
	"context"
	"testing"
	"time"
)

func TestQUICFreshPresetEvents(t *testing.T) {
	c := testConfig.Clone()
	c.MinVersion = VersionTLS13
	c.QUICClientHelloSpec = func(p []byte) (ClientHelloSpec, error) {
		return ClientHelloSpec{TLSVersMin: VersionTLS13, TLSVersMax: VersionTLS13, CipherSuites: []uint16{TLS_AES_128_GCM_SHA256}, CompressionMethods: []uint8{0}, Extensions: []TLSExtension{&SupportedVersionsExtension{Versions: []uint16{VersionTLS13}}, &SupportedCurvesExtension{Curves: []CurveID{X25519}}, &KeyShareExtension{KeyShares: []KeyShare{{Group: X25519}}}, &SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{ECDSAWithP256AndSHA256, PSSWithSHA256}}, &GenericExtension{Id: 57, Data: p}}}, nil
	}
	cli := newTestQUICClient(t, &QUICConfig{TLSConfig: c})
	cli.conn.SetTransportParameters([]byte{1, 0})
	srv := newTestQUICServer(t, &QUICConfig{TLSConfig: testConfig.Clone()})
	srv.conn.conn.config.MinVersion = VersionTLS13
	srv.conn.SetTransportParameters(nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := runTestQUICConnection(ctx, cli, srv, nil); err != nil {
		t.Fatal(err)
	}
}
