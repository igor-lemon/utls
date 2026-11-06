package tls

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/igor-lemon/utls/behavior"
)

// serverHelloPolicy validates ServerHello extensions with Chrome's alerts.
const serverHelloPolicy = `{"tls.validate_server_hello_extensions": true, "tls.unsolicited_extension_alert": 110,
 "tls.duplicate_extension_alert": 47, "tls.malformed_extension_alert": 50}`

// serverHello is a ServerHello message of these extensions, each as type and
// body; nil for none at all, no list.
func serverHello(random []byte, exts [][2]any) []byte {
	body := []byte{3, 3}
	body = append(body, random...)
	body = append(body, 32)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x13, 0x01, 0)
	if exts != nil {
		var list []byte
		for _, e := range exts {
			data := e[1].([]byte)
			list = binary.BigEndian.AppendUint16(list, e[0].(uint16))
			list = binary.BigEndian.AppendUint16(list, uint16(len(data)))
			list = append(list, data...)
		}
		body = binary.BigEndian.AppendUint16(body, uint16(len(list)))
		body = append(body, list...)
	}
	return append([]byte{typeServerHello, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

// helloConn is a client whose own ClientHello is Chrome's, of a policy.
func helloConn(t *testing.T, policy behavior.Policy) *UConn {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	a.SetDeadline(time.Now().Add(2 * time.Second))
	go io.Copy(io.Discard, b)
	u := UClient(a, &Config{ServerName: "example.com", Behavior: policy, OmitEmptyPsk: true}, HelloChrome_Auto, false, false, true)
	if err := u.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestAServerHelloIsHeldToTheExtensionsBoringSSLTakes(t *testing.T) {
	policy := policyOf(t, serverHelloPolicy)
	random := bytes.Repeat([]byte{7}, 32)
	versions := [2]any{ExtensionSupportedVersions, []byte{3, 4}}
	share := [2]any{ExtensionKeyShare, []byte{0, 29, 0, 1, 0}}
	none := [2]any{ExtensionPreSharedKey, []byte{0, 0}}
	ticket := [2]any{ExtensionSessionTicket, []byte{}}
	for _, tc := range []struct {
		name   string
		random []byte
		exts   [][2]any
		alert  alert // 0: taken
	}{
		{"TLS 1.3 as a server sends it", random, [][2]any{versions, share}, 0},
		// pre_shared_key where the client offered one, and not where it did not.
		{"TLS 1.3 resumed", random, [][2]any{versions, share, none}, 0},
		{"TLS 1.3 with pre_shared_key not offered", random, [][2]any{versions, share, none}, 110},
		{"TLS 1.3 with an extension it does not take there", random, [][2]any{versions, share, ticket}, 110},
		{"TLS 1.3 with one no client sends", random, [][2]any{versions, {uint16(65000), []byte{}}}, 110},
		{"TLS 1.3 with a cookie", random, [][2]any{versions, {ExtensionCookie, []byte{0, 1, 9}}}, 110},
		{"TLS 1.3 with a key_share where none was sent", random, [][2]any{versions, share}, 110},
		{"TLS 1.3 with encrypted_client_hello", random, [][2]any{versions, share,
			{extensionEncryptedClientHello, make([]byte, 8)}}, 110},
		{"TLS 1.3 with key_share twice", random, [][2]any{versions, share, share}, 47},
		{"a HelloRetryRequest", helloRetryRequestRandom, [][2]any{versions, {ExtensionKeyShare, []byte{0, 29}},
			{ExtensionCookie, []byte{0, 1, 9}}}, 0},
		{"a HelloRetryRequest with ECH's confirmation", helloRetryRequestRandom,
			[][2]any{versions, {extensionEncryptedClientHello, make([]byte, 8)}}, 0},
		{"a HelloRetryRequest with pre_shared_key", helloRetryRequestRandom, [][2]any{versions, none}, 110},
		{"a HelloRetryRequest with ECH's confirmation where none was sent", helloRetryRequestRandom,
			[][2]any{versions, {extensionEncryptedClientHello, make([]byte, 8)}}, 110},
		{"TLS 1.2 with what the client offered", random, [][2]any{ticket, {ExtensionRenegotiationInfo, []byte{0}},
			{ExtensionExtendedMasterSecret, []byte{}}}, 0},
		{"TLS 1.2 with one the client did not offer", random, [][2]any{{ExtensionCookie, []byte{0, 1, 9}}}, 110},
		{"TLS 1.2 with GREASE", random, [][2]any{{uint16(0x0a0a), []byte{}}}, 110},
		{"TLS 1.2 with padding", random, [][2]any{{ExtensionPadding, []byte{0}}}, 110},
		{"TLS 1.2 with one twice", random, [][2]any{ticket, ticket}, 50},
		{"TLS 1.2 with none", random, nil, 0},
		{"TLS 1.2 with an empty list", random, [][2]any{}, 0},
	} {
		u := helloConn(t, policy)
		// A Chrome hello sends GREASE and padding of its own; a server sends
		// back none of them.
		offered, _ := u.Conn.offeredExtensions()
		switch tc.name {
		case "TLS 1.2 with GREASE":
			offered[0x0a0a] = true
		case "TLS 1.3 resumed":
			offered[ExtensionPreSharedKey] = true
		case "TLS 1.3 with pre_shared_key not offered":
			delete(offered, ExtensionPreSharedKey)
		case "a HelloRetryRequest with pre_shared_key":
			offered[ExtensionPreSharedKey] = true
		case "TLS 1.2 with padding":
			offered[ExtensionPadding] = true
		case "TLS 1.3 with a key_share where none was sent":
			delete(offered, ExtensionKeyShare)
		case "a HelloRetryRequest with ECH's confirmation where none was sent":
			delete(offered, extensionEncryptedClientHello)
		}
		err := u.Conn.validateServerHelloOffered(offered, serverHello(tc.random, tc.exts))
		if (err != nil) != (tc.alert != 0) {
			t.Errorf("%s: %v", tc.name, err)
		}
		if tc.alert != 0 && !bytes.Contains([]byte(u.Conn.out.err.Error()), []byte(tc.alert.String())) {
			t.Errorf("%s: alerted %v, want %v", tc.name, u.Conn.out.err, tc.alert)
		}
	}
	// A list that does not read, or bytes past it: the malformed alert.
	for _, data := range [][]byte{
		append(serverHello(random, nil), 0, 4, 0, 43),
		append(serverHello(random, [][2]any{versions}), 9),
		// An extension whose length runs past the list.
		append(serverHello(random, nil), 0, 6, 0, 43, 0, 9, 3, 4),
	} {
		u := helloConn(t, policy)
		if err := u.Conn.validateServerHello(data); err == nil || !bytes.Contains([]byte(u.Conn.out.err.Error()), []byte(alertDecodeError.String())) {
			t.Errorf("%x: %v", data, err)
		}
	}
	// A ServerHello cut before its extensions is the message's own to refuse.
	u := helloConn(t, policy)
	if err := u.Conn.validateServerHello(serverHello(random, nil)[:20]); err != nil {
		t.Errorf("a ServerHello cut short: %v", err)
	}
	// A connection of no uTLS spec holds a ServerHello to nothing.
	if err := (&Conn{config: &Config{Behavior: policy}}).validateServerHello(serverHello(random, [][2]any{ticket, ticket})); err != nil {
		t.Errorf("no spec: %v", err)
	}
}

// alertOnTheWire is the alert a client sends back for this ServerHello: its
// handshake run against a peer that answers its ClientHello with it.
func alertOnTheWire(t *testing.T, policy behavior.Policy, hello []byte) byte {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	a.SetDeadline(time.Now().Add(3 * time.Second))
	b.SetDeadline(time.Now().Add(3 * time.Second))
	u := UClient(a, &Config{ServerName: "example.com", Behavior: policy, InsecureSkipVerify: true}, HelloChrome_Auto, false, false, true)
	done := make(chan error, 1)
	go func() { done <- u.Handshake() }()
	header := make([]byte, 5)
	if _, err := io.ReadFull(b, header); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(b, make([]byte, int(header[3])<<8|int(header[4]))); err != nil {
		t.Fatal(err)
	}
	record := append([]byte{byte(recordTypeHandshake), 3, 3, byte(len(hello) >> 8), byte(len(hello))}, hello...)
	if _, err := b.Write(record); err != nil {
		t.Fatal(err)
	}
	answer := make([]byte, 7)
	if _, err := io.ReadFull(b, answer); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Fatal("the handshake went on")
	}
	if answer[0] != byte(recordTypeAlert) {
		t.Fatalf("answered %x", answer)
	}
	return answer[6]
}

func TestAClientAlertsAServerHelloOfAnExtensionItDidNotAskFor(t *testing.T) {
	random := bytes.Repeat([]byte{7}, 32)
	hello := serverHello(random, [][2]any{{ExtensionSupportedVersions, []byte{3, 4}},
		{ExtensionKeyShare, append([]byte{0, 29, 0, 32}, make([]byte, 32)...)}, {uint16(65000), []byte{}}})
	if got := alertOnTheWire(t, policyOf(t, serverHelloPolicy), hello); got != byte(alertUnsupportedExtension) {
		t.Errorf("alerted %d, want unsupported_extension (110)", got)
	}
	// Without the policy, Go's reading of a ServerHello passes over an
	// extension it does not know, and the handshake fails later, otherwise.
	if got := alertOnTheWire(t, behavior.Legacy(), hello); got == byte(alertUnsupportedExtension) {
		t.Errorf("alerted %d without the policy", got)
	}
}

func TestServerHelloValidationNeedsItsAlerts(t *testing.T) {
	var p behavior.Policy
	if err := json.Unmarshal([]byte(`{"tls.validate_server_hello_extensions": true}`), &p); err != nil {
		t.Fatal(err)
	}
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "extension validation requires") {
		t.Errorf("Validate = %v", err)
	}
	if err := policyOf(t, serverHelloPolicy).Validate(); err != nil {
		t.Errorf("with its alerts: %v", err)
	}
}
