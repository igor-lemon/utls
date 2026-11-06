package tls

import (
	"bytes"
	stdtls "crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/igor-lemon/utls/behavior"
)

// withServerHelloChecks lays the ServerHello rule and its alerts over a
// config's policy.
func withServerHelloChecks(t testing.TB) func(*Config) {
	return func(c *Config) {
		p := behavior.Policy{}
		for k, v := range c.Behavior {
			p[k] = v
		}
		for k, v := range policyOf(t, serverHelloPolicy) {
			p[k] = v
		}
		c.Behavior = p
	}
}

// A session an ECH offer resumes in its inner hello alone is taken where the
// server accepted ECH, as BoringSSL takes its pre_shared_key: of the inner
// hello's extensions, which the outer's are not.
func TestAServerHelloResumingTheInnerHelloIsTakenWhereECHWasAccepted(t *testing.T) {
	for _, hrr := range []bool{false, true} {
		s := newECHTestServer(t)
		cfg := s.serverConfig(true)
		if hrr {
			cfg = s.serverConfig(true, stdtls.CurveP256)
		}
		cache := NewLRUClientSessionCache(4)
		checked := withServerHelloChecks(t)
		first := s.handshakeWith(t, cfg, cache, func(c *Config) {
			c.EncryptedClientHelloConfigList = listOf(s.config)
			checked(c)
		}, nil, nil)
		second := s.handshakeWith(t, cfg, cache, func(c *Config) {
			c.EncryptedClientHelloConfigList = listOf(s.config)
			checked(c)
		}, nil, nil)
		if first.clientErr != nil || second.clientErr != nil || second.serverErr != nil {
			t.Fatalf("hrr %v: %v, %v, %v", hrr, first.clientErr, second.clientErr, second.serverErr)
		}
		if !second.server.DidResume || !second.client.ECHAccepted {
			t.Errorf("hrr %v: resumed %v, ECH %v", hrr, second.server.DidResume, second.client.ECHAccepted)
		}
	}
}

// resumingServer answers the first ClientHello it reads with a TLS 1.3
// ServerHello that resumes the first session offered and accepts no ECH (its
// random is no confirmation), and gives what the client sends back.
func resumingServer(t *testing.T, conn net.Conn) <-chan []byte {
	t.Helper()
	sent := make(chan []byte, 1)
	go func() {
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		head := make([]byte, 5)
		if _, err := io.ReadFull(conn, head); err != nil {
			sent <- nil
			return
		}
		body := make([]byte, binary.BigEndian.Uint16(head[3:]))
		if _, err := io.ReadFull(conn, body); err != nil {
			sent <- nil
			return
		}
		hello := new(clientHelloMsg)
		if !hello.unmarshal(body) {
			sent <- nil
			return
		}
		sh := &serverHelloMsg{vers: VersionTLS12, random: bytes.Repeat([]byte{7}, 32), sessionId: hello.sessionId,
			cipherSuite: TLS_AES_128_GCM_SHA256, supportedVersion: VersionTLS13,
			serverShare:             keyShare{group: X25519, data: bytes.Repeat([]byte{9}, 32)},
			selectedIdentityPresent: true}
		msg, err := sh.marshal()
		if err != nil {
			sent <- nil
			return
		}
		conn.Write(append([]byte{byte(recordTypeHandshake), 3, 3, byte(len(msg) >> 8), byte(len(msg))}, msg...))
		rest, _ := io.ReadAll(conn)
		sent <- rest
	}()
	return sent
}

// A ServerHello that resumes a session where the server rejected ECH resumes
// one the outer hello did not offer, and is refused as BoringSSL refuses it:
// unsupported_extension, in a record of TLS 1.2. Without the rule, Go's own
// reading says the server picked a PSK the hello has none of.
func TestAServerHelloResumingWhereECHWasRejectedIsRefusedAsBoringSSLRefusesIt(t *testing.T) {
	for _, tc := range []struct {
		name    string
		checked bool
		alert   alert
	}{{"checked", true, alertUnsupportedExtension}, {"not checked", false, alertIllegalParameter}} {
		t.Run(tc.name, func(t *testing.T) {
			s := newECHTestServer(t)
			cache := NewLRUClientSessionCache(4)
			first := s.handshake(t, listOf(s.config), s.serverConfig(true), cache)
			if first.clientErr != nil || !first.client.ECHAccepted {
				t.Fatalf("%v, ECH %v", first.clientErr, first.client.ECHAccepted)
			}
			c, sc := localPipe(t)
			sent := resumingServer(t, sc)
			config := &Config{ServerName: "secret.example", RootCAs: s.roots, Behavior: policyOf(t, chromeECHPolicy),
				ClientSessionCache: cache, OmitEmptyPsk: true, EncryptedClientHelloConfigList: listOf(s.config)}
			if tc.checked {
				withServerHelloChecks(t)(config)
			}
			uc := UClient(c, config, HelloCustom, false, false, false)
			if err := uc.ApplyPreset(chromeHelloSpec(t)); err != nil {
				t.Fatal(err)
			}
			uc.SetDeadline(time.Now().Add(5 * time.Second))
			err := uc.Handshake()
			uc.Close()
			if err == nil {
				t.Fatal("a session the outer hello did not offer was taken")
			}
			want := []byte{byte(recordTypeAlert), 3, 3, 0, 2, 2, byte(tc.alert)}
			if got := <-sent; !bytes.HasPrefix(got, want) {
				t.Errorf("sent % x, want % x first (%v)", got, want, err)
			}
		})
	}
}

// renegotiationConn is a client of TLS 1.2 alone whose hello signals secure
// renegotiation by the SCSV, scsv, or by nothing; neither has the extension.
func renegotiationConn(t *testing.T, scsv bool) *UConn {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	a.SetDeadline(time.Now().Add(2 * time.Second))
	go io.Copy(io.Discard, b)
	suites := []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
	if scsv {
		suites = append(suites, scsvRenegotiation)
	}
	u := UClient(a, &Config{ServerName: "example.com", Behavior: policyOf(t, serverHelloPolicy)}, HelloCustom,
		false, false, true)
	if err := u.ApplyPreset(&ClientHelloSpec{TLSVersMin: VersionTLS12, TLSVersMax: VersionTLS12,
		CipherSuites: suites, CompressionMethods: []byte{0}, Extensions: []TLSExtension{&SNIExtension{},
			&SupportedCurvesExtension{Curves: []CurveID{X25519}}, &SupportedPointsExtension{SupportedPoints: []byte{0}},
			&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{ECDSAWithP256AndSHA256}}}}); err != nil {
		t.Fatal(err)
	}
	if err := u.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	return u
}

// A TLS 1.2 ServerHello's renegotiation_info answers a hello that signalled
// secure renegotiation by the SCSV alone, as RFC 5746 (section 3.4) has a
// server answer it; a hello of neither is not answered so.
func TestRenegotiationInfoAnswersTheSCSV(t *testing.T) {
	hello := serverHello(bytes.Repeat([]byte{7}, 32), [][2]any{{ExtensionRenegotiationInfo, []byte{0}}})
	if err := renegotiationConn(t, true).Conn.validateServerHello(hello); err != nil {
		t.Errorf("signalled by the SCSV: %v", err)
	}
	if err := renegotiationConn(t, false).Conn.validateServerHello(hello); err == nil {
		t.Error("signalled by nothing, taken")
	}
}

// An ECH offer the server rejects without resuming is refused for ECH alone,
// with its retry configs, under the ServerHello rule too.
func TestARejectedOfferThatResumesNothingIsRefusedForECHAlone(t *testing.T) {
	s := newECHTestServer(t)
	run := s.handshakeWith(t, s.serverConfig(true), nil, func(c *Config) {
		c.EncryptedClientHelloConfigList = listOf(s.staleConfig)
		withServerHelloChecks(t)(c)
	}, nil, nil)
	if run.echRejected == nil || !bytes.Equal(run.echRejected.RetryConfigList, s.retryList) {
		t.Errorf("refused with %v", run.clientErr)
	}
}

// A TLS 1.3 ServerHello's pre_shared_key is taken of an ECH offer only where
// its inner hello resumed a session: the outer hello offers none.
func TestPreSharedKeyIsTakenOfAnInnerHelloThatOffersASession(t *testing.T) {
	hello := serverHello(bytes.Repeat([]byte{7}, 32), [][2]any{{ExtensionSupportedVersions, []byte{3, 4}},
		{ExtensionKeyShare, []byte{0, 29, 0, 1, 0}}, {ExtensionPreSharedKey, []byte{0, 0}}})
	for _, tc := range []struct {
		name  string
		ech   *echClientContext
		taken bool
	}{
		{"no ECH", nil, false},
		{"an offer of no inner hello yet", &echClientContext{}, false},
		{"an inner hello of no session", &echClientContext{innerHello: &clientHelloMsg{}}, false},
		{"an inner hello resuming one", &echClientContext{innerHello: &clientHelloMsg{
			pskIdentities: []pskIdentity{{label: []byte{1}}}}}, true},
	} {
		u := helloConn(t, policyOf(t, serverHelloPolicy))
		u.echCtx = tc.ech
		offered, _ := u.Conn.offeredExtensions()
		delete(offered, ExtensionPreSharedKey)
		if err := u.Conn.validateServerHelloOffered(offered, hello); (err == nil) != tc.taken {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

// A connection of no uTLS hello offers no inner hello at all.
func TestAConnectionOfNoUTLSHelloOffersNoInnerSession(t *testing.T) {
	if (&Conn{}).innerOffersPSK() {
		t.Error("a connection of no uTLS hello offers an inner session")
	}
}
