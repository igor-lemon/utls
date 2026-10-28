package tls

import (
	"context"
	stdtls "crypto/tls"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Negative controls of the read-key boundaries, the pre_shared_key a
// HelloRetryRequest leaves and the ticket age it says again: each fails
// should the check it holds be taken away.

const handshakeBufferNotEmpty = "tls: handshake buffer not empty before setting read traffic secret"

// A server's Finished with another handshake message after it in its record:
// the client switches to the application read keys after the Finished, so
// what follows it was read under the handshake keys and is refused.
func TestAServerFinishedWithMoreInItsRecordIsRefused(t *testing.T) {
	for _, parrot := range []bool{false, true} {
		c, s := localPipe(t)
		go func() {
			ctx := context.Background()
			srv := Server(s, testConfig)
			defer srv.Close()
			clientHello, _, err := srv.readClientHello(ctx)
			if err != nil {
				testFatal(t, err)
			}
			hs := serverHandshakeStateTLS13{c: srv, ctx: ctx, clientHello: clientHello}
			for _, step := range []func() error{hs.processClientHello, hs.checkForResumption, hs.pickCertificate} {
				if err := step(); err != nil {
					testFatal(t, err)
				}
			}
			srv.buffering = true
			for _, step := range []func() error{hs.sendServerParameters, hs.sendServerCertificate} {
				if err := step(); err != nil {
					testFatal(t, err)
				}
			}
			finished, err := (&finishedMsg{verifyData: hs.suite.finishedHash(srv.out.trafficSecret, hs.transcript)}).marshal()
			if err != nil {
				testFatal(t, err)
			}
			after, err := (&keyUpdateMsg{}).marshal()
			if err != nil {
				testFatal(t, err)
			}
			srv.out.Lock()
			_, err = srv.writeRecordLocked(recordTypeHandshake, append(finished, after...))
			srv.out.Unlock()
			if err == nil {
				_, err = srv.flush()
			}
			if err != nil {
				testFatal(t, err)
			}
			// Hear the client out, its alert or its Finished.
			srv.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, _ = s.Read(make([]byte, 1024))
		}()
		cli := negativeControlClient(t, c, parrot)
		cli.SetDeadline(time.Now().Add(5 * time.Second))
		if err := cli.Handshake(); err == nil || err.Error() != handshakeBufferNotEmpty {
			t.Errorf("parrot %v: %v, want %q", parrot, err, handshakeBufferNotEmpty)
		}
		cli.Close()
	}
}

// A KeyUpdate with another handshake message after it in its record: the
// message after it was sealed under the keys the KeyUpdate retires.
func TestAKeyUpdateWithMoreInItsRecordIsRefused(t *testing.T) {
	for _, parrot := range []bool{false, true} {
		c, s := localPipe(t)
		go func() {
			srv := Server(s, testConfig)
			defer srv.Close()
			if err := srv.Handshake(); err != nil {
				testFatal(t, err)
			}
			update, err := (&keyUpdateMsg{}).marshal()
			if err != nil {
				testFatal(t, err)
			}
			ticket, err := (&newSessionTicketMsgTLS13{lifetime: 1, ageAdd: 1, nonce: []byte{1}, label: []byte{1}}).marshal()
			if err != nil {
				testFatal(t, err)
			}
			srv.out.Lock()
			_, err = srv.writeRecordLocked(recordTypeHandshake, append(update, ticket...))
			srv.out.Unlock()
			if err != nil {
				testFatal(t, err)
			}
			srv.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, _ = srv.Read(make([]byte, 1))
		}()
		cli := negativeControlClient(t, c, parrot)
		cli.SetDeadline(time.Now().Add(5 * time.Second))
		if err := cli.Handshake(); err != nil {
			t.Fatalf("parrot %v: handshake: %v", parrot, err)
		}
		if _, err := cli.Read(make([]byte, 1)); err == nil || !strings.Contains(err.Error(), handshakeBufferNotEmpty) {
			t.Errorf("parrot %v: %v, want %q", parrot, err, handshakeBufferNotEmpty)
		}
		cli.Close()
	}
}

// negativeControlClient is a client of testConfig on c: crypto/tls's own, or
// a parrot of Chrome's hello.
func negativeControlClient(t *testing.T, c net.Conn, parrot bool) tlsClient {
	t.Helper()
	if !parrot {
		return Client(c, testConfig)
	}
	cfg := testConfig.Clone()
	cfg.OmitEmptyPsk = true
	uc := UClient(c, cfg, HelloCustom, false, false, false)
	if err := uc.ApplyPreset(chromeHelloSpec(t)); err != nil {
		t.Fatal(err)
	}
	return uc
}

// A HelloRetryRequest whose cipher suite hashes otherwise than the session's
// leaves the pre_shared_key out of the second hello (RFC 8446 4.1.4): its
// binder could not be made with the suite's hash, and a server passes it over.
func TestAPSKOfAnotherHashLeavesTheSecondHello(t *testing.T) {
	s := newECHTestServer(t)
	cfg := s.serverConfig(false, stdtls.CurveP256)
	cfg.MinVersion = stdtls.VersionTLS13
	cache := NewLRUClientSessionCache(8)
	if run := s.handshakeWith(t, cfg, cache, nil, nil, nil); run.clientErr != nil || run.serverErr != nil ||
		run.server.CipherSuite != stdtls.TLS_AES_128_GCM_SHA256 {
		t.Fatalf("first connection: client %v, server %v, suite %#x", run.clientErr, run.serverErr, run.server.CipherSuite)
	}
	// Offering a SHA-384 suite first, and a SHA-256 one the session can be
	// offered for, leads a server with AES hardware to the SHA-384 one.
	run := s.handshakeWith(t, cfg, cache, nil, func(spec *ClientHelloSpec) {
		spec.CipherSuites = slices.DeleteFunc(spec.CipherSuites, func(id uint16) bool { return id == TLS_AES_128_GCM_SHA256 })
	}, nil)
	if run.clientErr != nil || run.serverErr != nil {
		t.Fatalf("second connection: client %v, server %v", run.clientErr, run.serverErr)
	}
	if run.server.CipherSuite != stdtls.TLS_AES_256_GCM_SHA384 {
		t.Skipf("the server chose %#x, not the SHA-384 suite: no AES hardware", run.server.CipherSuite)
	}
	if len(run.hellos) != 2 {
		t.Fatalf("%d hellos, want two: no HelloRetryRequest", len(run.hellos))
	}
	if first := helloOf(t, run.hellos[0]); len(first.pskIdentities) != 1 {
		t.Fatalf("the first hello offers %d sessions, want one", len(first.pskIdentities))
	}
	if second := helloOf(t, run.hellos[1]); len(second.pskIdentities) != 0 || second.pskBinders != nil {
		t.Errorf("the second hello offers %d sessions of another hash", len(second.pskIdentities))
	}
	if run.client.DidResume || run.server.DidResume {
		t.Error("resumed a session of another hash")
	}
}

// The second hello says the ticket's age as it is then, not as the first
// said it: time goes on between them, here a second a reading of the clock.
func TestTheSecondHelloSaysTheTicketsAgeAnew(t *testing.T) {
	s := newECHTestServer(t)
	cfg := s.serverConfig(false, stdtls.CurveP256)
	cfg.MinVersion = stdtls.VersionTLS13
	cache := NewLRUClientSessionCache(8)
	start := time.Now()
	var readings atomic.Int64
	clock := func(c *Config) {
		c.Time = func() time.Time { return start.Add(time.Duration(readings.Add(1)) * time.Second) }
	}
	if run := s.handshakeWith(t, cfg, cache, clock, nil, nil); run.clientErr != nil || run.serverErr != nil {
		t.Fatalf("first connection: client %v, server %v", run.clientErr, run.serverErr)
	}
	run := s.handshakeWith(t, cfg, cache, clock, nil, nil)
	if run.clientErr != nil || run.serverErr != nil {
		t.Fatalf("second connection: client %v, server %v", run.clientErr, run.serverErr)
	}
	if len(run.hellos) != 2 || !run.client.DidResume || !run.server.DidResume {
		t.Fatalf("%d hellos, resumed %v and %v: want a resumption after a HelloRetryRequest", len(run.hellos), run.client.DidResume, run.server.DidResume)
	}
	first, second := helloOf(t, run.hellos[0]), helloOf(t, run.hellos[1])
	if len(first.pskIdentities) != 1 || len(second.pskIdentities) != 1 {
		t.Fatalf("%d and %d sessions offered, want one each", len(first.pskIdentities), len(second.pskIdentities))
	}
	if later := second.pskIdentities[0].obfuscatedTicketAge - first.pskIdentities[0].obfuscatedTicketAge; later < 1000 || later > 3600*1000 {
		t.Errorf("the second hello says the ticket %d ms older than the first, want the seconds gone by", int32(later))
	}
}

func helloOf(t *testing.T, raw []byte) *clientHelloMsg {
	t.Helper()
	m := new(clientHelloMsg)
	if !m.unmarshal(raw) {
		t.Fatal("a hello does not read")
	}
	return m
}

// A QUIC server that takes 0-RTT sets its early read key right after the
// ClientHello: anything that came after the hello in its CRYPTO data came
// under the Initial keys and is refused, as Go 1.26.10's crypto/tls refuses it.
func TestAQUICServerRefusesWhatFollowsAHelloWithEarlyData(t *testing.T) {
	clientConfig := &QUICConfig{TLSConfig: testConfig.Clone()}
	clientConfig.TLSConfig.MinVersion = VersionTLS13
	clientConfig.TLSConfig.ClientSessionCache = NewLRUClientSessionCache(1)
	clientConfig.TLSConfig.ServerName = "example.go.dev"
	clientConfig.TLSConfig.NextProtos = []string{"h3"}
	serverConfig := &QUICConfig{TLSConfig: testConfig.Clone()}
	serverConfig.TLSConfig.MinVersion = VersionTLS13
	serverConfig.TLSConfig.NextProtos = []string{"h3"}

	cli := newTestQUICClient(t, clientConfig)
	cli.conn.SetTransportParameters(nil)
	srv := newTestQUICServer(t, serverConfig)
	srv.conn.SetTransportParameters(nil)
	srv.ticketOpts.EarlyData = true
	if err := runTestQUICConnection(context.Background(), cli, srv, nil); err != nil {
		t.Fatalf("first connection: %v", err)
	}

	cli2 := newTestQUICClient(t, clientConfig)
	cli2.conn.SetTransportParameters(nil)
	srv2 := newTestQUICServer(t, serverConfig)
	srv2.conn.SetTransportParameters(nil)
	after, err := (&keyUpdateMsg{}).marshal()
	if err != nil {
		t.Fatal(err)
	}
	var handled error
	sent, answered := false, false
	onEvent := func(e QUICEvent, src, dst *testQUICConn) bool {
		if src == srv2 && e.Kind == QUICWriteData {
			answered = true
		}
		if src != cli2 || e.Kind != QUICWriteData || e.Level != QUICEncryptionLevelInitial || sent {
			return false
		}
		sent = true
		handled = dst.conn.HandleData(e.Level, append(slices.Clone(e.Data), after...))
		return true
	}
	_ = runTestQUICConnection(context.Background(), cli2, srv2, onEvent)
	if handled == nil || !strings.Contains(handled.Error(), handshakeBufferNotEmpty) {
		t.Errorf("the server took a hello with more after it: %v, want %q", handled, handshakeBufferNotEmpty)
	}
	if srv2.readSecret[QUICEncryptionLevelEarly].secret != nil {
		t.Error("the server set its early read key with a message of the Initial keys left")
	}
	if answered {
		t.Error("the server answered a hello with a message of the Initial keys left after it")
	}
}

// A cookie a profile has no extension of its own for goes where BoringSSL's
// permutation puts it, as Chrome's does: among the extensions it permutes,
// after the GREASE extension that opens the hello and before those that
// close it (GREASE, padding, pre_shared_key), each place as likely.
func TestACookieGoesAmongTheExtensionsBoringSSLPermutes(t *testing.T) {
	own := func(n int) []TLSExtension {
		var out []TLSExtension
		for i := 0; i < n; i++ {
			out = append(out, &GenericExtension{Id: uint16(1000 + i)})
		}
		return out
	}
	join := func(parts ...[]TLSExtension) []TLSExtension { return slices.Concat(parts...) }
	opening, closing := []TLSExtension{&UtlsGREASEExtension{}}, []TLSExtension{&UtlsGREASEExtension{}}
	for _, tc := range []struct {
		name        string
		extensions  []TLSExtension
		first, last int // the places the cookie may take, both included
	}{
		{"Chrome's, resumable", join(opening, own(16), closing, []TLSExtension{&UtlsPreSharedKeyExtension{}}), 1, 17},
		{"Chrome's, not resumable", join(opening, own(16), closing), 1, 17},
		{"padded", join(opening, own(5), closing, []TLSExtension{&UtlsPaddingExtension{}, &UtlsPreSharedKeyExtension{}}), 1, 6},
		{"without GREASE", join(own(3), []TLSExtension{&UtlsPaddingExtension{}, &UtlsPreSharedKeyExtension{}}), 0, 3},
		{"nothing of its own", join(opening, closing), 1, 1},
	} {
		seen := map[int]int{}
		for draw := 0; draw < 3000; draw++ {
			uc := &UConn{Extensions: slices.Clone(tc.extensions)}
			uc.cookieForRetry([]byte("c"))
			at := slices.IndexFunc(uc.Extensions, func(e TLSExtension) bool { _, ok := e.(*CookieExtension); return ok })
			if len(uc.Extensions) != len(tc.extensions)+1 || at < 0 {
				t.Fatalf("%s: the cookie went nowhere", tc.name)
			}
			seen[at]++
		}
		for at := range seen {
			if at < tc.first || at > tc.last {
				t.Errorf("%s: the cookie went at %d, out of %d..%d", tc.name, at, tc.first, tc.last)
			}
		}
		for at := tc.first; at <= tc.last; at++ {
			if seen[at] == 0 {
				t.Errorf("%s: the cookie never went at %d of %d..%d", tc.name, at, tc.first, tc.last)
			}
		}
	}
}
