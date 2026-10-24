package tls

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/igor-lemon/utls/behavior"
	"github.com/igor-lemon/utls/internal/hpke"
	"golang.org/x/crypto/cryptobyte"
)

// chromeECHPolicy is how Chrome 155 offers ECH, as tls-forge's profiles say.
const chromeECHPolicy = `{"tls.ech": true, "tls.ech_inner_own": [0, 43, 65037],
 "tls.ech_inner_omitted": [11, 23, 35, 65281], "tls.ech_inner_min_version": 772,
 "tls.ech_padding_block": 32, "tls.ech_kems": [32], "tls.ech_kdfs": [1], "tls.ech_aeads": [1, 2, 3],
 "tls.ech_chacha_without_aes": true, "tls.ech_outer_psk": "none", "tls.ech_retries": 1,
 "tls.ech_retry_without": true}`

func policyOf(t testing.TB, s string) behavior.Policy {
	t.Helper()
	var p behavior.Policy
	if err := json.Unmarshal([]byte(s), &p); err != nil {
		t.Fatal(err)
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	return p
}

// chromeECHHello is a hello of Chrome's a server opened.
type chromeECHHello struct {
	Scenario string
	Cohort   int
	Conn     int
	Hello    int
	Config   string
	Outer    string
	Inner    string
	Encoded  string
}

func chromeECHHellos(t testing.TB) []chromeECHHello {
	t.Helper()
	data, err := os.ReadFile("testdata/chrome155-ech-hellos.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct{ Hellos []chromeECHHello }
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	return f.Hellos
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// configOf reads one ECHConfig.
func configOf(t testing.TB, config []byte) echConfig {
	t.Helper()
	list := append([]byte{byte(len(config) >> 8), byte(len(config))}, config...)
	configs, err := parseECHConfigList(list)
	if err != nil || len(configs) != 1 {
		t.Fatalf("config %x: %v", config, err)
	}
	return configs[0]
}

// chromeSpec is how Chrome's policy makes an inner hello, for a server name
// and a config.
func chromeSpec(t testing.TB, random []byte, name string, config echConfig) *specECH {
	t.Helper()
	set := func(ids ...uint16) map[uint16]bool {
		m := map[uint16]bool{}
		for _, id := range ids {
			m[id] = true
		}
		return m
	}
	return &specECH{own: set(0, 43, 65037), omitted: set(11, 23, 35, 65281), minVersion: VersionTLS13,
		block: 32, random: random, serverName: name, publicName: string(config.PublicName),
		maxNameLength: int(config.MaxNameLength)}
}

// maskBinders zeroes the binders of the pre_shared_key extension a
// ClientHello's body (no header) ends its extensions with.
func maskBinders(t testing.TB, body []byte) {
	t.Helper()
	s := cryptobyte.String(body)
	var exts cryptobyte.String
	if !s.Skip(2+32) || !skipUint8LengthPrefixed(&s) || !skipUint16LengthPrefixed(&s) ||
		!skipUint8LengthPrefixed(&s) || !s.ReadUint16LengthPrefixed(&exts) {
		t.Fatal("hello does not read")
	}
	end := len(body) - len(s) // where the extensions end
	var last []byte
	for !exts.Empty() {
		var id uint16
		var data cryptobyte.String
		if !exts.ReadUint16(&id) || !exts.ReadUint16LengthPrefixed(&data) {
			t.Fatal("extensions do not read")
		}
		if id == ExtensionPreSharedKey {
			last = data
		}
	}
	if last == nil {
		t.Fatal("no pre_shared_key")
	}
	p := cryptobyte.String(last)
	var ids, binders cryptobyte.String
	if !p.ReadUint16LengthPrefixed(&ids) || !p.ReadUint16LengthPrefixed(&binders) {
		t.Fatal("pre_shared_key does not read")
	}
	clear(body[end-len(binders) : end])
}

func TestAnInnerHelloIsMadeOfTheOuterAsChromeMadeIt(t *testing.T) {
	// Chrome's outer hello, with its inner random, its server's name and its
	// config, makes Chrome's inner hello and encoding byte for byte; a
	// session's binders aside, which hash what this test cannot know.
	hellos := chromeECHHellos(t)
	if len(hellos) < 10 {
		t.Fatalf("%d hellos", len(hellos))
	}
	for _, h := range hellos {
		outer, want, wantEncoded := unhex(t, h.Outer), unhex(t, h.Inner), unhex(t, h.Encoded)
		inner := new(clientHelloMsg)
		if !inner.unmarshal(want) {
			t.Fatalf("%s %d/%d: Chrome's inner does not read", h.Scenario, h.Conn, h.Hello)
		}
		s := chromeSpec(t, inner.random, inner.serverName, configOf(t, unhex(t, h.Config)))
		var transcript hash.Hash
		if len(inner.pskIdentities) > 0 {
			var ids []PskIdentity
			for _, id := range inner.pskIdentities {
				ids = append(ids, PskIdentity{Label: id.label, ObfuscatedTicketAge: id.obfuscatedTicketAge})
			}
			s.psk = &echPSK{identities: ids, binderKey: make([]byte, 32), suite: cipherSuiteTLS13ByID(TLS_AES_128_GCM_SHA256)}
			if h.Hello == 2 {
				transcript = sha256.New()
			}
		}
		got, encoded, err := s.innerOf(outer, transcript)
		if err != nil {
			t.Fatalf("%s %d/%d: %v", h.Scenario, h.Conn, h.Hello, err)
		}
		if s.psk != nil {
			for _, b := range [][]byte{got[4:], want[4:], encoded, wantEncoded} {
				maskBinders(t, b)
			}
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s %d/%d: the inner hello\n%x\nis not Chrome's\n%x", h.Scenario, h.Conn, h.Hello, got, want)
		}
		if !bytes.Equal(encoded, wantEncoded) {
			t.Errorf("%s %d/%d: the encoding\n%x\nis not Chrome's\n%x", h.Scenario, h.Conn, h.Hello, encoded, wantEncoded)
		}
	}
}

func TestAnInnerHelloKeepsWhatItsPolicySays(t *testing.T) {
	h := chromeECHHellos(t)[0]
	outer := unhex(t, h.Outer)
	inner := new(clientHelloMsg)
	inner.unmarshal(unhex(t, h.Inner))
	config := configOf(t, unhex(t, h.Config))
	types := func(raw []byte) []uint16 {
		exts, err := extractRawExtensions(&clientHelloMsg{original: raw})
		if err != nil {
			t.Fatal(err)
		}
		var out []uint16
		for _, e := range exts {
			out = append(out, e.extType)
		}
		return out
	}
	outerTypes := types(outer)
	// Every other extension the inner writes itself, as the outer has it;
	// nothing left out; all versions and suites below TLS 1.3 kept.
	s := chromeSpec(t, inner.random, "x.example", config)
	s.own[ExtensionALPN] = true
	s.omitted = map[uint16]bool{}
	s.minVersion = VersionTLS12
	got, encoded, err := s.innerOf(outer, nil)
	if err != nil {
		t.Fatal(err)
	}
	m := new(clientHelloMsg)
	if !m.unmarshal(got) {
		t.Fatal("inner does not read")
	}
	if m.serverName != "x.example" || !slices.Equal(m.alpnProtocols, []string{"h2", "http/1.1"}) ||
		!slices.Contains(m.supportedVersions, VersionTLS12) || len(m.cipherSuites) != 16 {
		t.Errorf("inner %+v", m)
	}
	if got := types(got); len(got) != len(outerTypes) {
		t.Errorf("inner has %v of the outer's %v", got, outerTypes)
	}
	encodedTypes := func(encoded []byte) (own []uint16, refs []uint16) {
		e := cryptobyte.String(encoded)
		var exts cryptobyte.String
		if !e.Skip(34) || !skipUint8LengthPrefixed(&e) || !skipUint16LengthPrefixed(&e) || !skipUint8LengthPrefixed(&e) ||
			!e.ReadUint16LengthPrefixed(&exts) {
			t.Fatal("encoding does not read")
		}
		for !exts.Empty() {
			var id uint16
			var data cryptobyte.String
			exts.ReadUint16(&id)
			exts.ReadUint16LengthPrefixed(&data)
			own = append(own, id)
			if id == extensionECHOuterExtensions {
				var list cryptobyte.String
				data.ReadUint8LengthPrefixed(&list)
				for !list.Empty() {
					var ref uint16
					list.ReadUint16(&ref)
					refs = append(refs, ref)
				}
			}
		}
		return own, refs
	}
	if own, refs := encodedTypes(encoded); !slices.Contains(own, ExtensionALPN) || slices.Contains(refs, ExtensionALPN) {
		t.Errorf("the encoding carries %v and names %v", own, refs)
	}
	// Every extension its own or left out: nothing named by reference.
	s = chromeSpec(t, inner.random, "x.example", config)
	for _, id := range outerTypes {
		s.own[id] = true
	}
	if _, encoded, err = s.innerOf(outer, nil); err != nil {
		t.Fatal(err)
	}
	if own, refs := encodedTypes(encoded); slices.Contains(own, extensionECHOuterExtensions) || refs != nil {
		t.Errorf("the encoding carries %v and names %v", own, refs)
	}
	// The outer's padding is the outer's alone.
	padded := cryptobyte.NewBuilder(nil)
	padded.AddUint8(typeClientHello)
	padded.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(VersionTLS12)
		b.AddBytes(make([]byte, 32))
		b.AddUint8(0)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(TLS_AES_128_GCM_SHA256) })
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(0) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, id := range []uint16{ExtensionServerName, ExtensionPadding, ExtensionALPN, extensionEncryptedClientHello} {
				b.AddUint16(id)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {})
			}
		})
	})
	s = chromeSpec(t, inner.random, "x.example", config)
	got, _, err = s.innerOf(padded.BytesOrPanic(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if exts := types(got); slices.Contains(exts, ExtensionPadding) || !slices.Equal(exts, []uint16{0, 65037, 16}) {
		t.Errorf("an inner of %v", exts)
	}
	// No block: no rounding.
	s = chromeSpec(t, inner.random, "x.example", config)
	s.block = 0
	if _, encoded, _ = s.innerOf(outer, nil); s.padding(10) != 0 {
		t.Errorf("padding %d", s.padding(10))
	}
	// A hello that does not read is refused.
	for _, bad := range [][]byte{outer[:40], append([]byte{2}, outer[1:]...), append(slices.Clone(outer), 0)} {
		if _, _, err := s.innerOf(bad, nil); err == nil {
			t.Errorf("%x: no error", bad[:8])
		}
	}
}

func TestAnInnerHelloIsPaddedAsRFC9849Says(t *testing.T) {
	s := &specECH{block: 32, maxNameLength: 64, serverName: "pad.ech.test"}
	for _, tc := range []struct {
		n, max int
		name   string
		block  int
		want   int
	}{
		{113, 0, "ech.ech.test", 32, 15},
		{113, 64, "pad.ech.test", 32, 79},
		{128, 0, "x", 32, 0},
		{129, 0, "x", 32, 31},
		{100, 10, "", 32, 28},
		{115, 10, "", 32, 45},
		{100, 0, "abc", 0, 0},
		{100, 20, "abc", 0, 17},
	} {
		s.maxNameLength, s.serverName, s.block = tc.max, tc.name, tc.block
		if got := s.padding(tc.n); got != tc.want || (tc.block > 0 && (tc.n+got)%tc.block != 0) {
			t.Errorf("%+v: padding %d", tc, got)
		}
	}
}

func TestTheConfigAndSuiteArePickedAsBoringSSLPicksThem(t *testing.T) {
	p := policyOf(t, chromeECHPolicy)
	key := func(kem uint16, suites []echCipher, name string, exts ...echExtension) echConfig {
		return echConfig{KemID: kem, SymmetricCipherSuite: suites, PublicName: []byte(name), Extensions: exts}
	}
	aes, aes256, chacha := echCipher{1, 1}, echCipher{1, 2}, echCipher{1, 3}
	for _, tc := range []struct {
		name  string
		list  []echConfig
		want  int // the config picked, -1 for none
		suite echCipher
	}{
		{"P-384, P-256, X25519: X25519", []echConfig{key(0x11, []echCipher{aes}, "p.example"),
			key(0x10, []echCipher{aes}, "p.example"), key(0x20, []echCipher{aes}, "p.example")}, 2, aes},
		{"the server's first suite", []echConfig{key(0x20, []echCipher{chacha, aes}, "p.example")}, 0, chacha},
		{"AES-256", []echConfig{key(0x20, []echCipher{aes256, aes}, "p.example")}, 0, aes256},
		{"HKDF-SHA384 alone", []echConfig{key(0x20, []echCipher{{2, 1}}, "p.example")}, -1, echCipher{}},
		{"an AEAD of none, then another config", []echConfig{key(0x20, []echCipher{{1, 0xffff}}, "p.example"),
			key(0x20, []echCipher{aes}, "q.example")}, 1, aes},
		{"an address for a name", []echConfig{key(0x20, []echCipher{aes}, "192.0.2.1")}, -1, echCipher{}},
		{"a mandatory extension, then an optional one", []echConfig{key(0x20, []echCipher{aes}, "p.example",
			echExtension{Type: 0x8001}), key(0x20, []echCipher{aes}, "q.example", echExtension{Type: 0x0001})}, 1, aes},
	} {
		got, suite, ok := pickSpecECHConfig(tc.list, p)
		if tc.want < 0 {
			if ok {
				t.Errorf("%s: picked %v", tc.name, got)
			}
			continue
		}
		if !ok || got != &tc.list[tc.want] || suite != tc.suite {
			t.Errorf("%s: %v %v %v", tc.name, got, suite, ok)
		}
	}
	for _, tc := range []struct {
		suites       []echCipher
		aes, prefers bool
		want         echCipher
	}{
		{[]echCipher{aes, chacha}, false, true, chacha},
		{[]echCipher{aes, chacha}, true, true, aes},
		{[]echCipher{aes, chacha}, false, false, aes},
		{[]echCipher{aes}, false, true, aes},
		{[]echCipher{chacha, aes}, true, true, chacha},
	} {
		q := p.Clone()
		q["tls.ech_chacha_without_aes"] = json.RawMessage(map[bool]string{true: "true", false: "false"}[tc.prefers])
		if got, ok := pickSpecECHCipherSuite(tc.suites, q, tc.aes); !ok || got != tc.want {
			t.Errorf("%+v: %v", tc, got)
		}
	}
}

// echTestServer is a server of crypto/tls's that opens ECH as configured:
// its certificate is for public.example and secret.example.
type echTestServer struct {
	certs                          []stdtls.Certificate
	roots                          *x509.CertPool
	key, stale                     *ecdh.PrivateKey
	config, staleConfig, retryList []byte
}

func newECHTestServer(t testing.TB) *echTestServer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := &echTestServer{roots: x509.NewCertPool()}
	for i, name := range []string{"public.example", "secret.example"} {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)), DNSNames: []string{name},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
		if err != nil {
			t.Fatal(err)
		}
		cert, _ := x509.ParseCertificate(der)
		s.roots.AddCert(cert)
		s.certs = append(s.certs, stdtls.Certificate{Certificate: [][]byte{der}, PrivateKey: k})
	}
	s.key, _ = ecdh.X25519().GenerateKey(rand.Reader)
	s.stale, _ = ecdh.X25519().GenerateKey(rand.Reader)
	s.config = echConfigFor(0x11, s.key.PublicKey().Bytes(), [][2]uint16{{1, 1}}, 0)
	s.staleConfig = echConfigFor(0x66, s.stale.PublicKey().Bytes(), [][2]uint16{{1, 1}}, 0)
	s.retryList = listOf(s.config)
	return s
}

func echConfigFor(id uint8, pub []byte, suites [][2]uint16, maxName uint8) []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(extensionEncryptedClientHello)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(id)
		b.AddUint16(0x0020)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(pub) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, s := range suites {
				b.AddUint16(s[0])
				b.AddUint16(s[1])
			}
		})
		b.AddUint8(maxName)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte("public.example")) })
		b.AddUint16(0)
	})
	return b.BytesOrPanic()
}

func listOf(configs ...[]byte) []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, c := range configs {
			b.AddBytes(c)
		}
	})
	return b.BytesOrPanic()
}

// serverConfig is the server's config: with ECH keys or none, and its
// groups when given.
func (s *echTestServer) serverConfig(withKeys bool, curves ...stdtls.CurveID) *stdtls.Config {
	c := &stdtls.Config{Certificates: s.certs, CurvePreferences: curves, MinVersion: stdtls.VersionTLS12}
	if withKeys {
		c.EncryptedClientHelloKeys = []stdtls.EncryptedClientHelloKey{{Config: s.config, PrivateKey: s.key.Bytes(), SendAsRetry: true}}
	}
	return c
}

// recorder keeps what a client sends in the clear: its ClientHellos.
type recorder struct {
	net.Conn
	mu      sync.Mutex
	buf, hs []byte
	done    bool
	hellos  [][]byte
}

func (r *recorder) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done {
		return n, err
	}
	r.buf = append(r.buf, p[:n]...)
	for len(r.buf) >= 5 {
		l := int(r.buf[3])<<8 | int(r.buf[4])
		if len(r.buf) < 5+l {
			break
		}
		typ, frag := r.buf[0], r.buf[5:5+l]
		r.buf = r.buf[5+l:]
		switch typ {
		case 22:
			r.hs = append(r.hs, frag...)
			for len(r.hs) >= 4 {
				ml := int(r.hs[1])<<16 | int(r.hs[2])<<8 | int(r.hs[3])
				if len(r.hs) < 4+ml {
					break
				}
				if r.hs[0] == typeClientHello {
					r.hellos = append(r.hellos, slices.Clone(r.hs[:4+ml]))
				}
				r.hs = r.hs[4+ml:]
			}
		case 20:
		default:
			r.done = true
		}
	}
	return n, err
}

// chromeHelloSpec is Chrome 155's outer hello as a spec, with a
// pre_shared_key extension last to resume with.
func chromeHelloSpec(t testing.TB) *ClientHelloSpec {
	t.Helper()
	h := unhex(t, chromeECHHellos(t)[0].Outer)
	record := append([]byte{22, 3, 1, byte(len(h) >> 8), byte(len(h))}, h...)
	spec, err := (&Fingerprinter{AllowBluntMimicry: true}).FingerprintClientHello(record)
	if err != nil {
		t.Fatal(err)
	}
	for _, ext := range spec.Extensions {
		if sni, ok := ext.(*SNIExtension); ok {
			sni.ServerName = ""
		}
	}
	spec.Extensions = append(spec.Extensions, &UtlsPreSharedKeyExtension{})
	return spec
}

type echRun struct {
	client      ConnectionState
	server      stdtls.ConnectionState
	clientErr   error
	serverErr   error
	readErr     error // what the server read after the handshake ended in
	hellos      [][]byte
	echRejected *ECHRejectionError
}

// handshake is one connection of a client offering ECH with list, as
// Chrome's policy says, to a server of serverConfig; cache resumes.
func (s *echTestServer) handshake(t testing.TB, list []byte, serverConfig *stdtls.Config, cache ClientSessionCache) echRun {
	t.Helper()
	c, sc := localPipe(t)
	rec := &recorder{Conn: sc}
	var run echRun
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv := stdtls.Server(rec, serverConfig)
		defer srv.Close()
		srv.SetDeadline(time.Now().Add(10 * time.Second))
		if run.serverErr = srv.Handshake(); run.serverErr != nil {
			return
		}
		run.server = srv.ConnectionState()
		srv.Write([]byte("ok"))
		_, run.readErr = io.Copy(io.Discard, srv)
	}()
	config := &Config{ServerName: "secret.example", RootCAs: s.roots, EncryptedClientHelloConfigList: list,
		Behavior: policyOf(t, chromeECHPolicy), ClientSessionCache: cache, OmitEmptyPsk: true}
	uc := UClient(c, config, HelloCustom, false, false, false)
	if err := uc.ApplyPreset(chromeHelloSpec(t)); err != nil {
		t.Fatal(err)
	}
	uc.SetDeadline(time.Now().Add(10 * time.Second))
	if run.clientErr = uc.Handshake(); run.clientErr == nil {
		run.client = uc.ConnectionState()
		buf := make([]byte, 2)
		if _, err := io.ReadFull(uc, buf); err != nil {
			t.Errorf("reading: %v", err)
		}
	}
	errors.As(run.clientErr, &run.echRejected)
	uc.Close()
	<-done
	rec.mu.Lock()
	run.hellos = rec.hellos
	rec.mu.Unlock()
	return run
}

// opened is a hello the client sealed to key: the outer, the inner opened
// and made whole again, and its encoding.
type opened struct {
	outer, inner, encoded []byte
	enc                   []byte
	payload               int
}

// open opens the ECH payloads of hellos, the second with the context of the
// first, as a server does.
func open(t testing.TB, hellos [][]byte, key *ecdh.PrivateKey, config []byte) []opened {
	t.Helper()
	var context *hpke.Receipient
	var out []opened
	for _, raw := range hellos {
		outer := new(clientHelloMsg)
		if !outer.unmarshal(raw) {
			t.Fatal("outer does not read")
		}
		typ, cs, id, enc, payload, err := parseECHExt(outer.encryptedClientHello)
		if err != nil || typ != outerECHExt {
			t.Fatalf("outer ECH %x: %v", outer.encryptedClientHello, err)
		}
		_ = id
		if context == nil {
			info := append([]byte("tls ech\x00"), config...)
			if context, err = hpke.SetupReceipient(hpke.DHKEM_X25519_HKDF_SHA256, cs.KDFID, cs.AEADID, key, info, enc); err != nil {
				t.Fatal(err)
			}
		}
		encoded, err := context.Open(bytes.Replace(raw[4:], payload, make([]byte, len(payload)), 1), payload)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		out = append(out, opened{outer: raw, inner: whole(t, outer, encoded), encoded: encoded, enc: enc, payload: len(payload)})
	}
	return out
}

// whole is the inner hello an encoding says, the outer's extensions it names
// in their place.
func whole(t testing.TB, outer *clientHelloMsg, encoded []byte) []byte {
	t.Helper()
	exts, err := extractRawExtensions(outer)
	if err != nil {
		t.Fatal(err)
	}
	s := cryptobyte.String(encoded)
	var vr, session, suites, compression, inner []byte
	var innerExts cryptobyte.String
	if !s.ReadBytes(&vr, 34) || !readUint8LengthPrefixed(&s, &session) || !readUint16LengthPrefixed(&s, &suites) ||
		!readUint8LengthPrefixed(&s, &compression) || !s.ReadUint16LengthPrefixed(&innerExts) {
		t.Fatal("encoding does not read")
	}
	b := cryptobyte.NewBuilder(nil)
	b.AddUint8(typeClientHello)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(vr)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(outer.sessionId) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(suites) })
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(compression) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for !innerExts.Empty() {
				var id uint16
				var data cryptobyte.String
				innerExts.ReadUint16(&id)
				innerExts.ReadUint16LengthPrefixed(&data)
				if id != extensionECHOuterExtensions {
					b.AddUint16(id)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(data) })
					continue
				}
				var refs cryptobyte.String
				data.ReadUint8LengthPrefixed(&refs)
				for !refs.Empty() {
					var ref uint16
					refs.ReadUint16(&ref)
					i := slices.IndexFunc(exts, func(e rawExtension) bool { return e.extType == ref })
					if i < 0 {
						t.Fatalf("the outer has no %d", ref)
					}
					b.AddUint16(ref)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(exts[i].data) })
				}
			}
		})
	})
	inner = b.BytesOrPanic()
	return inner
}

// chromeShaped says what of a hello pair is not as Chrome makes them: the
// inner's own extensions (the server's name, supported versions of TLS 1.3
// and GREASE, the inner ECH) in the outer's order, then the rest of the
// outer's but those left out, in its order, then a session's PSK; the outer
// with no PSK; suites of TLS 1.3 and GREASE; its own random, the outer's
// session ID, none encoded; padded as RFC 9849 says.
func chromeShaped(t testing.TB, o opened, name string, maxName ...int) []string {
	t.Helper()
	var bad []string
	outer, inner := new(clientHelloMsg), new(clientHelloMsg)
	if !outer.unmarshal(o.outer) || !inner.unmarshal(o.inner) {
		return []string{"does not read"}
	}
	oexts, _ := extractRawExtensions(outer)
	iexts, _ := extractRawExtensions(inner)
	own := map[uint16]bool{0: true, 43: true, 65037: true}
	omitted := map[uint16]bool{11: true, 21: true, 23: true, 35: true, 65281: true} // padding is the outer's
	var want, got []uint16
	for _, e := range oexts {
		if own[e.extType] {
			want = append(want, e.extType)
		}
		if e.extType == ExtensionPreSharedKey {
			bad = append(bad, "outer pre_shared_key")
		}
	}
	for _, e := range oexts {
		if !own[e.extType] && !omitted[e.extType] && e.extType != ExtensionPreSharedKey {
			want = append(want, e.extType)
		}
	}
	if len(inner.pskIdentities) > 0 {
		want = append(want, ExtensionPreSharedKey)
	}
	for _, e := range iexts {
		got = append(got, e.extType)
	}
	if !slices.Equal(got, want) {
		bad = append(bad, "extensions")
	}
	if inner.serverName != name || outer.serverName != "public.example" {
		bad = append(bad, "names "+inner.serverName+" "+outer.serverName)
	}
	if bytes.Equal(inner.random, outer.random) || !bytes.Equal(inner.sessionId, outer.sessionId) || len(outer.sessionId) != 32 {
		bad = append(bad, "random or session")
	}
	var tls13 []uint16
	for _, s := range outer.cipherSuites {
		if isGREASEUint16(s) || cipherSuiteTLS13ByID(s) != nil {
			tls13 = append(tls13, s)
		}
	}
	if !slices.Equal(inner.cipherSuites, tls13) {
		bad = append(bad, "suites")
	}
	if len(inner.supportedVersions) != 2 || !isGREASEUint16(inner.supportedVersions[0]) || inner.supportedVersions[1] != VersionTLS13 {
		bad = append(bad, "versions")
	}
	if !bytes.Equal(inner.encryptedClientHello, []byte{1}) {
		bad = append(bad, "inner ech")
	}
	if o.payload != len(o.encoded)+16 {
		bad = append(bad, "payload")
	}
	// The encoding is padded as RFC 9849 says: past the name to the longest
	// a config allows, then to a multiple of 32.
	body := cryptobyte.String(o.encoded)
	var session, suites, compression, exts cryptobyte.String
	if !body.Skip(34) || !body.ReadUint8LengthPrefixed(&session) || !body.ReadUint16LengthPrefixed(&suites) ||
		!body.ReadUint8LengthPrefixed(&compression) || !body.ReadUint16LengthPrefixed(&exts) {
		return append(bad, "encoding")
	}
	unpadded := len(o.encoded) - len(body)
	pad := 0
	if len(maxName) > 0 {
		pad = max(0, maxName[0]-len(name))
	}
	pad += 31 - (unpadded+pad-1)%32
	if len(body) != pad || bytes.ContainsFunc(body, func(r rune) bool { return r != 0 }) {
		bad = append(bad, fmt.Sprintf("padding %d, want %d", len(body), pad))
	}
	return bad
}

func TestAClientOffersECHAsChromeDoes(t *testing.T) {
	s := newECHTestServer(t)
	run := s.handshake(t, listOf(s.config), s.serverConfig(true), nil)
	if run.clientErr != nil || run.serverErr != nil {
		t.Fatalf("client %v, server %v", run.clientErr, run.serverErr)
	}
	if !run.client.ECHAccepted || !run.server.ECHAccepted || run.server.ServerName != "secret.example" ||
		run.client.ServerName != "secret.example" || len(run.client.VerifiedChains) != 1 {
		t.Errorf("client %+v, server %+v", run.client, run.server)
	}
	hellos := open(t, run.hellos, s.key, s.config)
	if len(hellos) != 1 {
		t.Fatalf("%d hellos", len(hellos))
	}
	if bad := chromeShaped(t, hellos[0], "secret.example"); bad != nil || len(hellos[0].enc) != 32 {
		t.Errorf("not as Chrome's: %v, enc %d", bad, len(hellos[0].enc))
	}
}

func TestAnInnerHelloIsPaddedForTheLongestNameItsConfigAllows(t *testing.T) {
	s := newECHTestServer(t)
	s.config = echConfigFor(0x11, s.key.PublicKey().Bytes(), [][2]uint16{{1, 1}}, 64)
	run := s.handshake(t, listOf(s.config), s.serverConfig(true), nil)
	if run.clientErr != nil || !run.client.ECHAccepted {
		t.Fatalf("%v", run.clientErr)
	}
	if bad := chromeShaped(t, open(t, run.hellos, s.key, s.config)[0], "secret.example", 64); bad != nil {
		t.Errorf("%v", bad)
	}
}

func TestAClientResumesItsSessionInTheInnerHelloAlone(t *testing.T) {
	for _, hrr := range []bool{false, true} {
		s := newECHTestServer(t)
		cfg := s.serverConfig(true)
		if hrr {
			cfg = s.serverConfig(true, stdtls.CurveP256)
		}
		cache := NewLRUClientSessionCache(4)
		first := s.handshake(t, listOf(s.config), cfg, cache)
		second := s.handshake(t, listOf(s.config), cfg, cache)
		if first.clientErr != nil || second.clientErr != nil || second.serverErr != nil {
			t.Fatalf("hrr %v: %v, %v, %v", hrr, first.clientErr, second.clientErr, second.serverErr)
		}
		if !second.server.DidResume || !second.server.ECHAccepted || !second.client.ECHAccepted {
			t.Errorf("hrr %v: resumed %v, ECH %v", hrr, second.server.DidResume, second.server.ECHAccepted)
		}
		hellos := open(t, second.hellos, s.key, s.config)
		firstInner, secondInner := new(clientHelloMsg), new(clientHelloMsg)
		firstInner.unmarshal(open(t, first.hellos, s.key, s.config)[0].inner)
		secondInner.unmarshal(hellos[0].inner)
		if bytes.Equal(firstInner.random, secondInner.random) || bytes.Equal(firstInner.random, make([]byte, 32)) {
			t.Errorf("hrr %v: the inner random is not drawn for each connection", hrr)
		}
		for i, h := range hellos {
			inner := new(clientHelloMsg)
			inner.unmarshal(h.inner)
			if len(inner.pskIdentities) != 1 {
				t.Errorf("hrr %v, hello %d: the inner resumes nothing", hrr, i+1)
			}
			if bad := chromeShaped(t, h, "secret.example"); bad != nil {
				t.Errorf("hrr %v, hello %d: %v", hrr, i+1, bad)
			}
		}
	}
}

func TestAClientRetriedByTheServerSealsAgainAsChromeDoes(t *testing.T) {
	s := newECHTestServer(t)
	run := s.handshake(t, listOf(s.config), s.serverConfig(true, stdtls.CurveP256), nil)
	if run.clientErr != nil || !run.client.ECHAccepted {
		t.Fatalf("%v %+v", run.clientErr, run.server)
	}
	hellos := open(t, run.hellos, s.key, s.config)
	if len(hellos) != 2 {
		t.Fatalf("%d hellos", len(hellos))
	}
	first, second := new(clientHelloMsg), new(clientHelloMsg)
	first.unmarshal(hellos[0].outer)
	second.unmarshal(hellos[1].outer)
	firstInner, secondInner := new(clientHelloMsg), new(clientHelloMsg)
	firstInner.unmarshal(hellos[0].inner)
	secondInner.unmarshal(hellos[1].inner)
	if !bytes.Equal(first.random, second.random) || !bytes.Equal(first.sessionId, second.sessionId) ||
		!bytes.Equal(firstInner.random, secondInner.random) {
		t.Error("the second hellos are not the first's")
	}
	if len(second.keyShares) != 1 || second.keyShares[0].group != CurveP256 || len(hellos[1].enc) != 0 {
		t.Errorf("second key shares %v, enc %d", second.keyShares, len(hellos[1].enc))
	}
	for i, h := range hellos {
		if bad := chromeShaped(t, h, "secret.example"); bad != nil {
			t.Errorf("hello %d: %v", i+1, bad)
		}
	}
}

func TestARefusedOfferSaysWhatTheServerOffersInstead(t *testing.T) {
	s := newECHTestServer(t)
	// A config the server has no key of: its own come back to retry with.
	run := s.handshake(t, listOf(s.staleConfig), s.serverConfig(true), nil)
	if run.echRejected == nil || !bytes.Equal(run.echRejected.RetryConfigList, s.retryList) {
		t.Errorf("refused with %v", run.clientErr)
	}
	if len(open(t, run.hellos, s.stale, s.staleConfig)) != 1 || run.server.ECHAccepted {
		t.Errorf("server %v, %+v", run.serverErr, run.server)
	}
	// A server of no ECH: nothing to retry with.
	run = s.handshake(t, listOf(s.config), s.serverConfig(false), nil)
	if run.echRejected == nil || len(run.echRejected.RetryConfigList) != 0 {
		t.Errorf("refused with %v", run.clientErr)
	}
	// A server that refuses with a certificate that is not the public
	// name's is not believed.
	cfg := s.serverConfig(true)
	cfg.Certificates = cfg.Certificates[1:]
	run = s.handshake(t, listOf(s.staleConfig), cfg, nil)
	var verification *CertificateVerificationError
	if !errors.As(run.clientErr, &verification) || run.echRejected != nil {
		t.Errorf("refused with %v", run.clientErr)
	}
}

func TestAnOfferToAServerOfTLS12IsRefused(t *testing.T) {
	// The server took the outer hello: the connection is the public name's,
	// and the offer refused with nothing to retry with.
	s := newECHTestServer(t)
	cfg := s.serverConfig(false)
	cfg.MaxVersion = stdtls.VersionTLS12
	run := s.handshake(t, listOf(s.config), cfg, nil)
	if run.echRejected == nil || len(run.echRejected.RetryConfigList) != 0 || run.client.HandshakeComplete {
		t.Errorf("refused with %v", run.clientErr)
	}
	if run.server.Version != stdtls.VersionTLS12 || run.server.ServerName != "public.example" ||
		run.readErr == nil || !bytesContains(run.readErr.Error(), "encrypted client hello required") {
		t.Errorf("the server: %v, then %v, %+v", run.serverErr, run.readErr, run.server)
	}
	// Its certificate is not the public name's: not believed.
	cfg = s.serverConfig(false)
	cfg.MaxVersion = stdtls.VersionTLS12
	cfg.Certificates = cfg.Certificates[1:]
	run = s.handshake(t, listOf(s.config), cfg, nil)
	var verification *CertificateVerificationError
	if !errors.As(run.clientErr, &verification) || run.echRejected != nil {
		t.Errorf("refused with %v", run.clientErr)
	}
}

func TestAnOfferNeedsAConfigTheProfileCanUse(t *testing.T) {
	s := newECHTestServer(t)
	for _, list := range [][]byte{
		listOf(echConfigFor(1, s.key.PublicKey().Bytes(), [][2]uint16{{2, 1}}, 0)),
		{0, 1},
	} {
		run := s.handshake(t, list, s.serverConfig(true), nil)
		if run.clientErr == nil || len(run.hellos) != 0 {
			t.Errorf("%x: %v, %d hellos", list, run.clientErr, len(run.hellos))
		}
	}
}

// builtWith is what building uconn's hello for ECH with list says, the
// client offering it as Chrome's policy (or policy) says with spec.
func builtWith(t testing.TB, list []byte, spec *ClientHelloSpec, policy behavior.Policy, after func(*UConn)) error {
	t.Helper()
	c, _ := net.Pipe()
	defer c.Close()
	if policy == nil {
		policy = policyOf(t, chromeECHPolicy)
	}
	uc := UClient(c, &Config{ServerName: "secret.example", EncryptedClientHelloConfigList: list, Behavior: policy,
		OmitEmptyPsk: true}, HelloCustom, false, false, false)
	if err := uc.ApplyPreset(spec); err != nil {
		t.Fatal(err)
	}
	if after != nil {
		after(uc)
	}
	return uc.BuildHandshakeState()
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("no randomness") }

func TestAnOfferThatCannotBeMadeSaysWhy(t *testing.T) {
	s := newECHTestServer(t)
	good := listOf(s.config)
	without := func(drop func(TLSExtension) bool) *ClientHelloSpec {
		spec := chromeHelloSpec(t)
		spec.Extensions = slices.DeleteFunc(spec.Extensions, drop)
		return spec
	}
	with := func(more ...TLSExtension) *ClientHelloSpec {
		spec := chromeHelloSpec(t)
		spec.Extensions = append(spec.Extensions[:len(spec.Extensions)-1], more...)
		return spec
	}
	unchecked := policyOf(t, chromeECHPolicy)
	unchecked["tls.ech_aeads"] = json.RawMessage("[4]")
	for _, tc := range []struct {
		name   string
		list   []byte
		spec   *ClientHelloSpec
		policy behavior.Policy
		after  func(*UConn)
		err    string
	}{
		{"a key that is no X25519 key", listOf(echConfigFor(1, make([]byte, 31), [][2]uint16{{1, 1}}, 0)),
			chromeHelloSpec(t), nil, nil, "public key"},
		{"an AEAD the engine lacks, past an unchecked policy", listOf(echConfigFor(1, s.key.PublicKey().Bytes(),
			[][2]uint16{{1, 4}}, 0)), chromeHelloSpec(t), unchecked, nil, "unsupported AEAD"},
		{"no randomness", good, chromeHelloSpec(t), nil, func(uc *UConn) { uc.config.Rand = failingReader{} },
			"short read from Rand"},
		{"no ECH extension", good, without(func(e TLSExtension) bool { _, ok := e.(EncryptedClientHelloExtension); return ok }),
			nil, nil, "no encrypted_client_hello extension"},
		{"supported versions that do not read", good, with(&GenericExtension{Id: ExtensionSupportedVersions,
			Data: []byte{5, 3, 4}}), nil, nil, "supported_versions do not read"},
		{"an extension twice", good, with(&GenericExtension{Id: 0x1234}, &GenericExtension{Id: 0x1234}), nil, nil,
			"inner hello does not read"},
	} {
		spec := tc.spec
		if tc.name == "supported versions that do not read" {
			spec.Extensions = slices.DeleteFunc(spec.Extensions, func(e TLSExtension) bool {
				_, ok := e.(*SupportedVersionsExtension)
				return ok
			})
		}
		if err := builtWith(t, tc.list, spec, tc.policy, tc.after); err == nil || !bytesContains(err.Error(), tc.err) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.err)
		}
	}
}

func bytesContains(s, sub string) bool { return bytes.Contains([]byte(s), []byte(sub)) }

func TestAnOfferWhoseHelloCannotBeMarshalledSaysWhy(t *testing.T) {
	s := newECHTestServer(t)
	defer func(m func(*UConn, []TLSExtension) ([]byte, error)) { echMarshal = m }(echMarshal)
	for fail := 1; fail <= 3; fail++ {
		calls := 0
		echMarshal = func(uc *UConn, exts []TLSExtension) ([]byte, error) {
			if calls++; calls == fail {
				return nil, errors.New("cannot marshal")
			}
			return uc.marshalHello(exts)
		}
		if err := builtWith(t, listOf(s.config), chromeHelloSpec(t), nil, nil); err == nil || err.Error() != "cannot marshal" {
			t.Errorf("call %d failing: %v", fail, err)
		}
	}
	// The second hellos after a HelloRetryRequest are marshalled again.
	calls := 0
	echMarshal = func(uc *UConn, exts []TLSExtension) ([]byte, error) {
		if calls++; calls == 4 {
			return nil, errors.New("cannot marshal")
		}
		return uc.marshalHello(exts)
	}
	run := s.handshake(t, listOf(s.config), s.serverConfig(true, stdtls.CurveP256), nil)
	if run.clientErr == nil || !bytesContains(run.clientErr.Error(), "cannot marshal") || len(run.hellos) != 1 {
		t.Errorf("%v, %d hellos", run.clientErr, len(run.hellos))
	}
}

func TestAnOuterHelloThatDoesNotReadMakesNoInner(t *testing.T) {
	s := &specECH{own: map[uint16]bool{0: true, 43: true, 65037: true}, minVersion: VersionTLS13, block: 32,
		random: make([]byte, 32)}
	hello := func(suites, exts []byte) []byte {
		b := cryptobyte.NewBuilder(nil)
		b.AddUint8(typeClientHello)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(VersionTLS12)
			b.AddBytes(make([]byte, 32))
			b.AddUint8(0)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(suites) })
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(0) })
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(exts) })
		})
		return b.BytesOrPanic()
	}
	for _, tc := range []struct {
		name         string
		suites, exts []byte
	}{
		{"an odd cipher suite list", []byte{0x13, 0x01, 0x13}, nil},
		{"an extension cut short", []byte{0x13, 0x01}, []byte{0, 43, 0, 9, 1}},
		{"supported versions cut short", []byte{0x13, 0x01}, []byte{0, 43, 0, 2, 1, 3}},
		{"supported versions with more after", []byte{0x13, 0x01}, []byte{0, 43, 0, 4, 2, 3, 4, 0}},
	} {
		if _, _, err := s.innerOf(hello(tc.suites, tc.exts), nil); err == nil {
			t.Errorf("%s: no error", tc.name)
		}
	}
	if _, _, err := s.innerOf(hello([]byte{0x13, 0x01}, []byte{0, 43, 0, 3, 2, 3, 4}), nil); err != nil {
		t.Errorf("a hello that reads: %v", err)
	}
}

func TestAnInnerHelloResumesOnlyASessionItHas(t *testing.T) {
	uc := &UConn{Extensions: []TLSExtension{&SNIExtension{}, &UtlsPreSharedKeyExtension{
		PreSharedKeyCommon: PreSharedKeyCommon{Identities: []PskIdentity{{Label: []byte("t")}}}}}}
	if uc.innerPSK() != nil {
		t.Error("identities with no session resume one")
	}
	uc.Extensions = []TLSExtension{&FakePreSharedKeyExtension{}}
	if uc.innerPSK() != nil {
		t.Error("a pre_shared_key of no session resumes one")
	}
}

func TestTheOuterHelloOffersNoSessionTheInnerResumes(t *testing.T) {
	// The hello that goes out names no PSK identity, so that nothing of the
	// outer is taken for a session's.
	s := newECHTestServer(t)
	cache, cfg := NewLRUClientSessionCache(4), s.serverConfig(true)
	s.handshake(t, listOf(s.config), cfg, cache)
	c, _ := net.Pipe()
	defer c.Close()
	uc := UClient(c, &Config{ServerName: "secret.example", EncryptedClientHelloConfigList: listOf(s.config),
		Behavior: policyOf(t, chromeECHPolicy), ClientSessionCache: cache, OmitEmptyPsk: true}, HelloCustom, false, false, false)
	if err := uc.ApplyPreset(chromeHelloSpec(t)); err != nil {
		t.Fatal(err)
	}
	if err := uc.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	if uc.HandshakeState.Hello.PskIdentities != nil || uc.HandshakeState.Session == nil ||
		len(uc.echCtx.innerHello.pskIdentities) != 1 {
		t.Errorf("outer identities %v, session %v", uc.HandshakeState.Hello.PskIdentities, uc.HandshakeState.Session != nil)
	}
}

func TestASessionIsKeptByTheIdentitiesASecondHelloKeeps(t *testing.T) {
	var none *echPSK
	if none.keptBy([]pskIdentity{{obfuscatedTicketAge: 1}}) != nil {
		t.Error("no session became one")
	}
	p := &echPSK{identities: []PskIdentity{{Label: []byte("t"), ObfuscatedTicketAge: 1}}}
	if p.keptBy(nil) != nil {
		t.Error("a session a second hello does not keep is kept")
	}
	if got := p.keptBy([]pskIdentity{{label: []byte("t"), obfuscatedTicketAge: 7}}); got != p ||
		p.identities[0].ObfuscatedTicketAge != 7 {
		t.Errorf("kept %+v", got)
	}
}

func TestACookieOfAHelloRetryRequestIsEchoed(t *testing.T) {
	uc := &UConn{Extensions: []TLSExtension{&SNIExtension{}, &CookieExtension{}, &UtlsPaddingExtension{}}}
	if err := uc.cookieForRetry(nil); err != nil || uc.Extensions[1].(*CookieExtension).Cookie != nil {
		t.Errorf("no cookie: %v", err)
	}
	if err := uc.cookieForRetry([]byte("c")); err != nil || string(uc.Extensions[1].(*CookieExtension).Cookie) != "c" {
		t.Errorf("the profile's cookie: %v", err)
	}
	uc.Extensions = []TLSExtension{&SNIExtension{}, &UtlsPaddingExtension{}, &UtlsPreSharedKeyExtension{}}
	if err := uc.cookieForRetry([]byte("c")); err != nil || len(uc.Extensions) != 4 {
		t.Fatalf("a cookie of its own: %v", err)
	}
	if _, ok := uc.Extensions[3].(*UtlsPreSharedKeyExtension); !ok {
		t.Error("the cookie went after the pre_shared_key")
	}
	uc.Extensions = []TLSExtension{&SNIExtension{}, &UtlsPaddingExtension{}}
	if err := uc.cookieForRetry([]byte("c")); err == nil {
		t.Error("no place for a cookie, and no error")
	}
}

func TestAPublicNameIsADNSNameAsBoringSSLSays(t *testing.T) {
	for name, want := range map[string]bool{
		"public.example": true, "a": true, "a-b.c": true, "x.0xzz": true, "x.12a": true, "Public.Example": true,
		"": false, ".a": false, "a.": false, "a..b": false, "-a.b": false, "a-.b": false, "a_b.c": false,
		string(bytes.Repeat([]byte("a"), 64)) + ".b": false, "192.0.2.1": false, "x.123": false, "x.0x1f": false,
		"x.0X": false, "x.0xAb": false,
	} {
		if echPublicName(name) != want {
			t.Errorf("%q: %v", name, !want)
		}
	}
}

func TestAClientWithNoConfigsResumesInItsOneHello(t *testing.T) {
	// No configs, no ECH: the hello resumes as it always has, its binders its
	// own, whatever the policy says of ECH.
	s := newECHTestServer(t)
	cache, cfg := NewLRUClientSessionCache(4), s.serverConfig(false)
	s.handshake(t, nil, cfg, cache)
	run := s.handshake(t, nil, cfg, cache)
	if run.clientErr != nil || !run.server.DidResume || run.client.ECHAccepted {
		t.Fatalf("%v, resumed %v", run.clientErr, run.server.DidResume)
	}
	hello := new(clientHelloMsg)
	if len(run.hellos) != 1 || !hello.unmarshal(run.hellos[0]) || len(hello.pskIdentities) != 1 ||
		hello.serverName != "secret.example" {
		t.Errorf("the hello %+v", hello)
	}
}
