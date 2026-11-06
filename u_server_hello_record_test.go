package tls

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// writtenHelloConn is helloConn whose first write is kept: the alert a
// refused ServerHello sends.
func writtenHelloConn(t *testing.T) (*UConn, <-chan []byte) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	a.SetDeadline(time.Now().Add(2 * time.Second))
	written := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := b.Read(buf)
		written <- buf[:n]
	}()
	u := UClient(a, &Config{ServerName: "example.com", Behavior: policyOf(t, serverHelloPolicy), OmitEmptyPsk: true},
		HelloChrome_Auto, false, false, true)
	if err := u.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	return u, written
}

// legacy is a ServerHello of another legacy version.
func legacy(h []byte, major, minor byte) []byte {
	h[4], h[5] = major, minor
	return h
}

// A ServerHello is refused as BoringSSL 2ea3200c refuses it, its alert in the
// record BoringSSL writes it in: what parse_server_version reads before the
// version is known (the list, supported_versions twice or of other than two
// bytes) in a record of TLS 1.0, the rest in one of the version, TLS 1.2's for
// TLS 1.3. Of TLS 1.2, what the client offered that only TLS 1.3 answers is
// refused too, and compress_certificate is a list that does not decode.
func TestAServerHelloIsRefusedInTheRecordBoringSSLWritesItIn(t *testing.T) {
	random := bytes.Repeat([]byte{7}, 32)
	versions := [2]any{ExtensionSupportedVersions, []byte{3, 4}}
	share := [2]any{ExtensionKeyShare, []byte{0, 29, 0, 1, 0}}
	tls10, tls12 := []byte{3, 1}, []byte{3, 3}
	for _, tc := range []struct {
		name   string
		hello  []byte
		alert  alert // 0: taken, nothing written
		record []byte
	}{
		{"TLS 1.3 with ec_point_formats", serverHello(random, [][2]any{versions, share,
			{ExtensionSupportedPoints, []byte{1, 0}}}), 110, tls12},
		{"TLS 1.3 with key_share twice", serverHello(random, [][2]any{versions, share, share}), 47, tls12},
		{"supported_versions twice, after one no client sends", serverHello(random,
			[][2]any{{uint16(65000), []byte{}}, versions, versions}), 47, tls10},
		{"supported_versions of three bytes", serverHello(random,
			[][2]any{{ExtensionSupportedVersions, []byte{3, 4, 0}}, share}), 50, tls10},
		{"a list cut short", append(serverHello(random, nil), 0, 6, 0, 43, 0, 9, 3, 4), 50, tls10},
		{"TLS 1.2 with key_share", serverHello(random, [][2]any{share}), 110, tls12},
		{"TLS 1.2 by supported_versions, with it", serverHello(random,
			[][2]any{{ExtensionSupportedVersions, []byte{3, 3}}}), 110, tls12},
		{"TLS 1.2 with application_settings", serverHello(random, [][2]any{{ExtensionALPS, []byte{}}}), 110, tls12},
		{"TLS 1.2 with encrypted_client_hello", serverHello(random,
			[][2]any{{extensionEncryptedClientHello, []byte{}}}), 110, tls12},
		{"TLS 1.2 with signature_algorithms", serverHello(random,
			[][2]any{{ExtensionSignatureAlgorithms, []byte{0, 2, 4, 3}}}), 110, tls12},
		{"TLS 1.2 with compress_certificate", serverHello(random,
			[][2]any{{ExtensionCompressCertificate, []byte{2, 0, 2}}}), 50, tls12},
		{"TLS 1.2 with session_ticket twice", serverHello(random, [][2]any{{ExtensionSessionTicket, []byte{}},
			{ExtensionSessionTicket, []byte{}}}), 50, tls12},
		{"TLS 1.2 as a server sends it", serverHello(random, [][2]any{{ExtensionSessionTicket, []byte{}},
			{ExtensionRenegotiationInfo, []byte{0}}, {ExtensionExtendedMasterSecret, []byte{}},
			{ExtensionSupportedPoints, []byte{1, 0}}}), 0, nil},
		{"TLS 1.3 as a server sends it", serverHello(random, [][2]any{versions, share}), 0, nil},
		// A version the client does not support is protocol_version, the
		// legacy version the version where it is not TLS 1.2.
		{"TLS 1.0 with key_share", legacy(serverHello(random, [][2]any{share}), 3, 1), 70, tls10},
		{"a legacy TLS 1.0 that says TLS 1.3", legacy(serverHello(random, [][2]any{versions, share}), 3, 1), 70, tls10},
		{"TLS 1.3 of a version not known", serverHello(random,
			[][2]any{{ExtensionSupportedVersions, []byte{3, 9}}, share}), 70, tls10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, written := writtenHelloConn(t)
			offered, _ := u.Conn.offeredExtensions()
			for _, id := range []uint16{ExtensionKeyShare, ExtensionSupportedVersions, ExtensionALPS,
				extensionEncryptedClientHello, ExtensionSignatureAlgorithms, ExtensionCompressCertificate,
				ExtensionSessionTicket, ExtensionRenegotiationInfo, ExtensionExtendedMasterSecret,
				ExtensionSupportedPoints} {
				offered[id] = true
			}
			err := u.Conn.validateServerHelloOffered(offered, tc.hello)
			if (err != nil) != (tc.alert != 0) {
				t.Fatalf("%v", err)
			}
			if u.Conn.vers != 0 {
				t.Errorf("the version is left %x", u.Conn.vers)
			}
			if tc.alert == 0 {
				return
			}
			select {
			case got := <-written:
				want := append(append([]byte{21}, tc.record...), 0, 2, 2, byte(tc.alert))
				if !bytes.Equal(got, want) {
					t.Errorf("wrote % x, want % x", got, want)
				}
			case <-time.After(time.Second):
				t.Fatal("no alert written")
			}
		})
	}
}
