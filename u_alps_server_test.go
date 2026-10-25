package tls

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// alpsHelloSpec is a TLS 1.3 hello offering ALPN protocols and ALPS (under
// codepoints, in that order) for alps.
func alpsHelloSpec(alpn, alps []string, codepoints ...uint16) *ClientHelloSpec {
	exts := []TLSExtension{
		&SNIExtension{},
		&SupportedCurvesExtension{Curves: []CurveID{X25519}},
		&KeyShareExtension{KeyShares: []KeyShare{{Group: X25519}}},
		&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{PSSWithSHA256, ECDSAWithP256AndSHA256}},
		&SupportedVersionsExtension{Versions: []uint16{VersionTLS13}},
		&ALPNExtension{AlpnProtocols: alpn},
	}
	for _, c := range codepoints {
		if c == utlsExtensionApplicationSettings {
			exts = append(exts, &ApplicationSettingsExtension{SupportedProtocols: alps})
		} else {
			exts = append(exts, &ApplicationSettingsExtensionNew{SupportedProtocols: alps})
		}
	}
	return &ClientHelloSpec{
		TLSVersMin: VersionTLS13, TLSVersMax: VersionTLS13,
		CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
		CompressionMethods: []uint8{0},
		Extensions:         exts,
	}
}

// alpsHandshake shakes hands between a uTLS client of spec, whose own
// settings are mine, and a server of settings, over TCP; it returns both
// ends' states.
func alpsHandshake(t *testing.T, spec *ClientHelloSpec, mine, settings map[string][]byte, protocols ...string) (ConnectionState, ConnectionState, error) {
	t.Helper()
	c, s := net.Pipe()
	t.Cleanup(func() { c.Close(); s.Close() })
	// a handshake that goes wrong fails rather than waits for good
	c.SetDeadline(time.Now().Add(10 * time.Second))
	s.SetDeadline(time.Now().Add(10 * time.Second))
	server := testConfig.Clone()
	server.NextProtos = protocols
	server.ApplicationSettings = settings
	srv := Server(s, server)
	done := make(chan error, 1)
	go func() { done <- srv.Handshake() }()
	cli := UClient(c, &Config{InsecureSkipVerify: true, ServerName: "example.golang", ApplicationSettings: mine}, HelloCustom, false, false, false)
	if err := cli.ApplyPreset(spec); err != nil {
		t.Fatal(err)
	}
	err := cli.Handshake()
	if err != nil {
		c.Close()
		<-done
		return ConnectionState{}, ConnectionState{}, err
	}
	if err := <-done; err != nil {
		return ConnectionState{}, ConnectionState{}, err
	}
	return cli.ConnectionState(), srv.ConnectionState(), nil
}

func TestAServerGivesItsSettingsToAClientThatOffersALPSForTheProtocol(t *testing.T) {
	settings := []byte{0x04, 0x02, 0x01, 0x00} // an HTTP/3 SETTINGS frame
	for _, codepoint := range []uint16{utlsExtensionApplicationSettingsNew, utlsExtensionApplicationSettings} {
		cli, srv, err := alpsHandshake(t, alpsHelloSpec([]string{"h3"}, []string{"h3"}, codepoint),
			map[string][]byte{"h3": []byte("mine")}, map[string][]byte{"h3": settings}, "h3")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(cli.PeerApplicationSettings, settings) {
			t.Errorf("codepoint %d: the client was given %x, want %x", codepoint, cli.PeerApplicationSettings, settings)
		}
		if string(srv.PeerApplicationSettings) != "mine" {
			t.Errorf("codepoint %d: the server read %q of the client's", codepoint, srv.PeerApplicationSettings)
		}
	}
	// a client of no settings of its own says empty ones, as Chrome does
	cli, srv, err := alpsHandshake(t, alpsHelloSpec([]string{"h3"}, []string{"h3"}, utlsExtensionApplicationSettingsNew),
		nil, map[string][]byte{"h3": {}}, "h3")
	if err != nil {
		t.Fatal(err)
	}
	if cli.PeerApplicationSettings == nil || len(cli.PeerApplicationSettings) != 0 || len(srv.PeerApplicationSettings) != 0 {
		t.Errorf("empty settings read as %x and %x", cli.PeerApplicationSettings, srv.PeerApplicationSettings)
	}
}

func TestAServerGivesNoSettingsWhereALPSWasNotOfferedForTheProtocol(t *testing.T) {
	for _, c := range []struct {
		name      string
		spec      *ClientHelloSpec
		settings  map[string][]byte
		protocols []string
	}{
		{"no ALPS offered", alpsHelloSpec([]string{"h3"}, nil), map[string][]byte{"h3": {1}}, []string{"h3"}},
		{"ALPS for another protocol", alpsHelloSpec([]string{"h3", "h2"}, []string{"h2"}, utlsExtensionApplicationSettingsNew),
			map[string][]byte{"h3": {1}}, []string{"h3"}},
		{"no settings for the protocol", alpsHelloSpec([]string{"h3"}, []string{"h3"}, utlsExtensionApplicationSettingsNew),
			map[string][]byte{"h2": {1}}, []string{"h3"}},
		{"no protocol chosen", alpsHelloSpec([]string{"h3"}, []string{"h3"}, utlsExtensionApplicationSettingsNew),
			map[string][]byte{"": {1}}, nil},
		// ALPS offered for a protocol of no name, the server's settings for
		// it, and no protocol chosen: none, or the client would refuse ALPS
		// without ALPN
		{"no protocol chosen, ALPS for none", alpsHelloSpec([]string{"h3"}, []string{""}, utlsExtensionApplicationSettingsNew),
			map[string][]byte{"": {1}}, nil},
	} {
		cli, srv, err := alpsHandshake(t, c.spec, map[string][]byte{"h3": []byte("mine")}, c.settings, c.protocols...)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if cli.PeerApplicationSettings != nil || srv.PeerApplicationSettings != nil {
			t.Errorf("%s: settings said %x and %x", c.name, cli.PeerApplicationSettings, srv.PeerApplicationSettings)
		}
	}
}

// helloBytes is the ClientHello a uTLS client of spec writes.
func helloBytes(t *testing.T, spec *ClientHelloSpec) []byte {
	t.Helper()
	u := UClient(nil, &Config{InsecureSkipVerify: true, ServerName: "example.golang"}, HelloCustom, false, false, false)
	if err := u.ApplyPreset(spec); err != nil {
		t.Fatal(err)
	}
	if err := u.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	return u.HandshakeState.Hello.Raw
}

func TestTheALPSAHelloOffersIsReadAsBoringSSLReadsIt(t *testing.T) {
	both := helloBytes(t, alpsHelloSpec([]string{"h3", "h2"}, []string{"h2"}, utlsExtensionApplicationSettings, utlsExtensionApplicationSettingsNew))
	for _, c := range []struct {
		name      string
		hello     []byte
		codepoint uint16
		protocols []string
	}{
		{"new", helloBytes(t, alpsHelloSpec([]string{"h3"}, []string{"h3", "h2"}, utlsExtensionApplicationSettingsNew)),
			utlsExtensionApplicationSettingsNew, []string{"h3", "h2"}},
		{"old", helloBytes(t, alpsHelloSpec([]string{"h3"}, []string{"h3"}, utlsExtensionApplicationSettings)),
			utlsExtensionApplicationSettings, []string{"h3"}},
		{"both: the new one", both, utlsExtensionApplicationSettingsNew, []string{"h2"}},
		{"both, the new first: the new one", helloBytes(t, alpsHelloSpec([]string{"h3", "h2"}, []string{"h3"},
			utlsExtensionApplicationSettingsNew, utlsExtensionApplicationSettings)), utlsExtensionApplicationSettingsNew, []string{"h3"}},
		{"none", helloBytes(t, alpsHelloSpec([]string{"h3"}, nil)), 0, nil},
		{"cut short", both[:len(both)-1], 0, nil},
		{"not a hello", []byte{1, 0, 0}, 0, nil},
	} {
		codepoint, protocols := offeredALPS(c.hello)
		if codepoint != c.codepoint || strings.Join(protocols, ",") != strings.Join(c.protocols, ",") {
			t.Errorf("%s: %d %q, want %d %q", c.name, codepoint, protocols, c.codepoint, c.protocols)
		}
	}
	// a list cut short, and a name cut short, offer none
	none := helloBytes(t, alpsHelloSpec([]string{"h3"}, nil))
	for _, data := range [][]byte{{0, 5, 2, 'h'}, {0, 3, 3, 'h', '3'}} {
		hello := helloWithExtension(none, utlsExtensionApplicationSettingsNew, data)
		if codepoint, protocols := offeredALPS(hello); codepoint != 0 || protocols != nil {
			t.Errorf("ALPS %x read as %d %q", data, codepoint, protocols)
		}
	}
}

// helloWithExtension is hello (as BuildHandshakeState writes it) with one
// extension more, last.
func helloWithExtension(hello []byte, ext uint16, data []byte) []byte {
	out := append([]byte{}, hello...)
	// the extensions' length is the hello's last two-byte field before them:
	// find it by walking the fixed fields
	at := 4 + 2 + 32
	at += 1 + int(out[at])
	at += 2 + (int(out[at])<<8 | int(out[at+1]))
	at += 1 + int(out[at])
	n := int(out[at])<<8 | int(out[at+1])
	n += 4 + len(data)
	out[at], out[at+1] = byte(n>>8), byte(n)
	out = append(out, byte(ext>>8), byte(ext), byte(len(data)>>8), byte(len(data)))
	out = append(out, data...)
	body := len(out) - 4
	out[1], out[2], out[3] = byte(body>>16), byte(body>>8), byte(body)
	return out
}

// quicALPS shakes hands as QUIC does between a uTLS client of spec and a
// server of settings for h3, handing what the client writes at the
// handshake level through edit; it returns the server's error.
func quicALPS(t *testing.T, spec *ClientHelloSpec, settings []byte, edit func([]byte) []byte) (ConnectionState, error) {
	t.Helper()
	server := testConfig.Clone()
	server.MinVersion = VersionTLS13
	server.NextProtos = []string{"h3"}
	server.ApplicationSettings = map[string][]byte{"h3": settings}
	srv := QUICServer(&QUICConfig{TLSConfig: server})
	cli := UQUICClient(&QUICConfig{TLSConfig: &Config{InsecureSkipVerify: true, ServerName: "example.golang", MinVersion: VersionTLS13}}, HelloCustom)
	spec.Extensions = append(spec.Extensions, &GenericExtension{Id: 57, Data: []byte{}})
	if err := cli.ApplyPreset(spec); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cli.Close(); srv.Close() })
	cli.SetTransportParameters(nil)
	ctx := context.Background()
	if err := cli.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	type end interface {
		NextEvent() QUICEvent
		HandleData(QUICEncryptionLevel, []byte) error
		SetTransportParameters([]byte)
	}
	var serverErr error
	ends := [2]end{cli, srv}
	for idle := 0; idle < 2; {
		for i, e := range ends {
			ev := e.NextEvent()
			switch ev.Kind {
			case QUICNoEvent:
				idle++
				continue
			case QUICTransportParametersRequired:
				e.SetTransportParameters(nil)
			case QUICWriteData:
				data := append([]byte{}, ev.Data...)
				if i == 0 && ev.Level == QUICEncryptionLevelHandshake {
					data = edit(data)
				}
				if err := ends[1-i].HandleData(ev.Level, data); err != nil {
					if i == 0 {
						serverErr = err
					}
					return srv.ConnectionState(), serverErr
				}
			}
			idle = 0
		}
	}
	return srv.ConnectionState(), serverErr
}

func TestAQUICServerReadsTheClientsSettingsBeforeItsFinished(t *testing.T) {
	spec := func() *ClientHelloSpec {
		return alpsHelloSpec([]string{"h3"}, []string{"h3"}, utlsExtensionApplicationSettingsNew)
	}
	state, err := quicALPS(t, spec(), []byte{0x04, 0x00}, func(b []byte) []byte { return b })
	if err != nil {
		t.Fatal(err)
	}
	if state.PeerApplicationSettings == nil || len(state.PeerApplicationSettings) != 0 {
		t.Errorf("the server read %x of the client's settings", state.PeerApplicationSettings)
	}
	// the client's EncryptedExtensions taken out: its Finished comes where
	// they should
	_, err = quicALPS(t, spec(), []byte{0x04, 0x00}, func(b []byte) []byte {
		if b[0] == typeEncryptedExtensions {
			return b[4+(int(b[1])<<16|int(b[2])<<8|int(b[3])):]
		}
		return b
	})
	if !errors.Is(err, AlertError(alertUnexpectedMessage)) {
		t.Errorf("a Finished for EncryptedExtensions: %v", err)
	}
	// the client's settings under the old codepoint, the new one negotiated
	_, err = quicALPS(t, spec(), []byte{0x04, 0x00}, func(b []byte) []byte {
		if b[0] == typeEncryptedExtensions {
			b = append([]byte{}, b...)
			b[6], b[7] = byte(utlsExtensionApplicationSettings>>8), byte(utlsExtensionApplicationSettings&0xff)
		}
		return b
	})
	if !errors.Is(err, AlertError(alertMissingExtension)) {
		t.Errorf("settings under the old codepoint: %v", err)
	}
}

func TestAClientResumesItsSessionWithAServerOfALPS(t *testing.T) {
	// the server's tickets go after the client's EncryptedExtensions: a
	// ticket worked out without them would not resume
	server := testConfig.Clone() // its time, before the certificate expires
	server.NextProtos = []string{"h2"}
	server.ApplicationSettings = map[string][]byte{"h2": {1, 2, 3}}
	cache := NewLRUClientSessionCache(1)
	for i, want := range []bool{false, true} {
		c, s := net.Pipe()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		s.SetDeadline(time.Now().Add(10 * time.Second))
		srv := Server(s, server)
		done := make(chan error, 1)
		go func() {
			err := srv.Handshake()
			if err == nil {
				// the client reads the ticket with its first read
				_, err = srv.Write([]byte("x"))
			}
			done <- err
		}()
		spec := alpsHelloSpec([]string{"h2"}, []string{"h2"}, utlsExtensionApplicationSettingsNew)
		spec.Extensions = append(spec.Extensions, &SessionTicketExtension{},
			&PSKKeyExchangeModesExtension{Modes: []uint8{PskModeDHE}}, &UtlsPreSharedKeyExtension{})
		cli := UClient(c, &Config{InsecureSkipVerify: true, ServerName: "example.golang", ClientSessionCache: cache, OmitEmptyPsk: true,
			Time: server.Time}, HelloCustom, false, false, false)
		if err := cli.ApplyPreset(spec); err != nil {
			t.Fatal(err)
		}
		if err := cli.Handshake(); err != nil {
			t.Fatalf("handshake %d: %v", i, err)
		}
		if _, err := cli.Read(make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatalf("server %d: %v", i, err)
		}
		if got := cli.ConnectionState(); got.DidResume != want || string(got.PeerApplicationSettings) != "\x01\x02\x03" {
			t.Errorf("handshake %d: resumed %v, settings %x", i, got.DidResume, got.PeerApplicationSettings)
		}
		c.Close()
		s.Close()
	}
}

// countingCache is a client session cache that counts the tickets put in it.
type countingCache struct {
	ClientSessionCache
	puts int
}

func (c *countingCache) Put(k string, v *ClientSessionState) {
	if v != nil {
		c.puts++
	}
	c.ClientSessionCache.Put(k, v)
}

func TestAServerOfALPSThatAsksForACertificateSendsItsTicketOnce(t *testing.T) {
	// the tickets go once the client's certificate is read, not also after
	// its EncryptedExtensions
	server := testConfig.Clone()
	server.NextProtos = []string{"h2"}
	server.ApplicationSettings = map[string][]byte{"h2": {1}}
	server.ClientAuth = RequestClientCert
	cache := &countingCache{ClientSessionCache: NewLRUClientSessionCache(4)}
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	s.SetDeadline(time.Now().Add(10 * time.Second))
	srv := Server(s, server)
	done := make(chan error, 1)
	go func() {
		err := srv.Handshake()
		if err == nil {
			_, err = srv.Write([]byte("x"))
		}
		done <- err
	}()
	spec := alpsHelloSpec([]string{"h2"}, []string{"h2"}, utlsExtensionApplicationSettingsNew)
	spec.Extensions = append(spec.Extensions, &SessionTicketExtension{},
		&PSKKeyExchangeModesExtension{Modes: []uint8{PskModeDHE}}, &UtlsPreSharedKeyExtension{})
	cli := UClient(c, &Config{InsecureSkipVerify: true, ServerName: "example.golang", ClientSessionCache: cache, OmitEmptyPsk: true,
		Time: server.Time}, HelloCustom, false, false, false)
	if err := cli.ApplyPreset(spec); err != nil {
		t.Fatal(err)
	}
	if err := cli.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if cache.puts != 1 {
		t.Errorf("%d tickets, want one", cache.puts)
	}
}
