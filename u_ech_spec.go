package tls

import (
	"errors"
	"fmt"
	"hash"
	"io"
	mathrand "math/rand/v2"
	"slices"
	"strings"

	"github.com/igor-lemon/utls/behavior"
	"github.com/igor-lemon/utls/internal/hpke"
	"golang.org/x/crypto/cryptobyte"
)

// [uTLS] Encrypted Client Hello with an inner hello made of the profile's own.
//
// A profile whose policy says tls.ech offers ECH, with the configs of
// Config.EncryptedClientHelloConfigList, as BoringSSL offers it in Chrome
// (measured on Chrome 155 against servers that opened every inner hello they
// were sent, testdata of tls-forge's chrome155-ech-dns.json):
//
//   - the outer hello is the profile's, to the config's public name, its
//     encrypted_client_hello the real one, and no pre_shared_key;
//   - the inner hello has a random of its own, the outer's legacy session ID,
//     the outer's GREASE and those of its cipher suites that serve
//     tls.ech_inner_min_version and up, and as extensions: those
//     tls.ech_inner_own names, written for the inner (the server's own name,
//     the supported versions of tls.ech_inner_min_version and up, GREASE kept,
//     the inner encrypted_client_hello), in the outer's order; then every
//     other extension of the outer but those tls.ech_inner_omitted names and
//     its padding (the inner's is the encoding's own), in the outer's order,
//     which its encoding names in one ech_outer_extensions; then a session's
//     pre_shared_key, whose binders are over the inner;
//   - the encoding has no session ID and is padded as RFC 9849 section 6.1.3
//     says, to a multiple of tls.ech_padding_block;
//   - after a HelloRetryRequest both are made again, the inner with its
//     random, the payload sealed with the same context and no enc.
//
// The config is the first of the list whose KEM, KDF and AEAD the policy names
// (tls.ech_kems, tls.ech_kdfs, tls.ech_aeads), and its cipher suite the first
// of its own the policy names, but ChaCha20-Poly1305 where the machine has no
// AES hardware and tls.ech_chacha_without_aes says so.

// specECH is an ECH offer of a profile: how its inner hello is made of the
// outer one, and what it is made for.
type specECH struct {
	own, omitted  map[uint16]bool
	minVersion    uint16
	block         int
	random        []byte
	serverName    string
	publicName    string
	maxNameLength int
	psk           *echPSK
}

// echPSK is the session an inner hello resumes.
type echPSK struct {
	identities []PskIdentity
	binderKey  []byte
	suite      *cipherSuiteTLS13
}

// offersSpecECH says whether c offers ECH with an inner hello of the profile's
// own: it is given configs, and its policy says so.
func (c *Config) offersSpecECH() bool {
	return len(c.EncryptedClientHelloConfigList) > 0 && c.Policy().Flag("tls.ech")
}

// pickSpecECHConfig is the first config of list whose KEM the policy names
// and that has a cipher suite it names, whose public name is a DNS name and
// which asks for no extension the engine does not know.
func pickSpecECHConfig(list []echConfig, p behavior.Policy) (*echConfig, echCipher, bool) {
	kems := p.Numbers("tls.ech_kems")
	for i := range list {
		ec := &list[i]
		if !slices.Contains(kems, uint64(ec.KemID)) || !echPublicName(string(ec.PublicName)) {
			continue
		}
		if slices.ContainsFunc(ec.Extensions, func(e echExtension) bool { return e.Type&(1<<15) != 0 }) {
			continue
		}
		if suite, ok := pickSpecECHCipherSuite(ec.SymmetricCipherSuite, p, hasAESGCMHardwareSupport); ok {
			return ec, suite, true
		}
	}
	return nil, echCipher{}, false
}

// pickSpecECHCipherSuite is the first of suites whose KDF and AEAD the policy
// names, or, where the machine has no AES hardware (aes) and
// tls.ech_chacha_without_aes says so, ChaCha20-Poly1305 when it is one of
// them, as BoringSSL's select_ech_cipher_suite picks.
func pickSpecECHCipherSuite(suites []echCipher, p behavior.Policy, aes bool) (echCipher, bool) {
	kdfs, aeads := p.Numbers("tls.ech_kdfs"), p.Numbers("tls.ech_aeads")
	var picked echCipher
	found := false
	for _, s := range suites {
		if !slices.Contains(kdfs, uint64(s.KDFID)) || !slices.Contains(aeads, uint64(s.AEADID)) {
			continue
		}
		if !found || (!aes && p.Flag("tls.ech_chacha_without_aes") && s.AEADID == hpke.AEAD_ChaCha20Poly1305) {
			picked, found = s, true
		}
	}
	return picked, found
}

// startSpecECH picks the config and suite uconn offers ECH with, sets up the
// HPKE context, and says how its inner hello is made.
func (uconn *UConn) startSpecECH() error {
	p := uconn.config.Policy()
	configs, err := parseECHConfigList(uconn.config.EncryptedClientHelloConfigList)
	if err != nil {
		return err
	}
	config, suite, ok := pickSpecECHConfig(configs, p)
	if !ok {
		return errors.New("tls: EncryptedClientHelloConfigList contains no config the profile can use")
	}
	pk, err := hpke.ParseHPKEPublicKey(config.KemID, config.PublicKey)
	if err != nil {
		return err
	}
	info := append([]byte("tls ech\x00"), config.raw...)
	enc, context, err := hpke.SetupSender(config.KemID, suite.KDFID, suite.AEADID, pk, info)
	if err != nil {
		return err
	}
	random := make([]byte, 32)
	if _, err := io.ReadFull(uconn.config.rand(), random); err != nil {
		return errors.New("tls: short read from Rand: " + err.Error())
	}
	set := func(k string) map[uint16]bool {
		m := map[uint16]bool{}
		for _, t := range p.Numbers(k) {
			m[uint16(t)] = true
		}
		return m
	}
	uconn.echCtx = &echClientContext{config: config, kdfID: suite.KDFID, aeadID: suite.AEADID,
		encapsulatedKey: enc, hpkeContext: context}
	uconn.echSpec = &specECH{own: set("tls.ech_inner_own"), omitted: set("tls.ech_inner_omitted"),
		minVersion: uint16(p.Uint("tls.ech_inner_min_version")), block: p.Int("tls.ech_padding_block"),
		random: random, serverName: uconn.config.ServerName, publicName: string(config.PublicName),
		maxNameLength: int(config.MaxNameLength), psk: uconn.innerPSK()}
	return nil
}

// innerPSK is the session uconn's pre_shared_key resumes, which goes in the
// inner hello alone, or nil.
func (uconn *UConn) innerPSK() *echPSK {
	for _, ext := range uconn.Extensions {
		e, ok := ext.(*UtlsPreSharedKeyExtension)
		if !ok || e.Session == nil || len(e.Identities) == 0 {
			continue
		}
		return &echPSK{identities: slices.Clone(e.Identities), binderKey: e.BinderKey, suite: e.cipherSuite}
	}
	return nil
}

// echMarshal marshals a hello of uconn's with exts; a test may stand in for it.
var echMarshal = (*UConn).marshalHello

// echExtensionData is an outer encrypted_client_hello extension's data.
func echExtensionData(ech *echClientContext, enc, payload []byte) []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint8(0) // outer
	b.AddUint16(ech.kdfID)
	b.AddUint16(ech.aeadID)
	b.AddUint8(ech.config.ConfigID)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(enc) })
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(payload) })
	return b.BytesOrPanic()
}

// sealSpecECH makes the outer and inner hellos of uconn's extensions as they
// are, the outer's ECH payload the inner's encoding sealed with enc (none in a
// second hello), and the binders of a session over transcript (nil for a
// first hello; after a HelloRetryRequest, the inner's so far): the outer goes
// to uconn.HandshakeState.Hello.Raw, the inner to the ECH context. The inner
// is made of the outer as it is with no payload: its padding, which the
// payload's length may change, is the outer's alone.
func (uconn *UConn) sealSpecECH(enc []byte, transcript hash.Hash) error {
	ech, spec := uconn.echCtx, uconn.echSpec
	exts := make([]TLSExtension, 0, len(uconn.Extensions))
	slot := -1
	for _, ext := range uconn.Extensions {
		switch ext.(type) {
		case *SNIExtension:
			ext = &SNIExtension{ServerName: spec.publicName}
		case PreSharedKeyExtension:
			continue
		case EncryptedClientHelloExtension:
			slot = len(exts)
		}
		exts = append(exts, ext)
	}
	if slot < 0 {
		return errors.New("tls: the profile has no encrypted_client_hello extension to offer ECH in")
	}
	exts[slot] = &GenericExtension{Id: extensionEncryptedClientHello, Data: echExtensionData(ech, enc, nil)}
	outer, err := echMarshal(uconn, exts)
	if err != nil {
		return err
	}
	inner, encoded, err := spec.innerOf(outer, transcript)
	if err != nil {
		return err
	}
	// What is sealed is the outer with a payload of zeros as long as the
	// sealed encoding.
	exts[slot] = &GenericExtension{Id: extensionEncryptedClientHello,
		Data: echExtensionData(ech, enc, make([]byte, len(encoded)+16))}
	aad, err := echMarshal(uconn, exts)
	if err != nil {
		return err
	}
	sealed, sealErr := ech.hpkeContext.Seal(aad[4:], encoded)
	exts[slot] = &GenericExtension{Id: extensionEncryptedClientHello, Data: echExtensionData(ech, enc, sealed)}
	outer, err = echMarshal(uconn, exts)
	if err = errors.Join(sealErr, err); err != nil {
		return err
	}
	innerHello := new(clientHelloMsg)
	if !innerHello.unmarshal(inner) {
		return errors.New("tls: the ECH inner hello does not read")
	}
	ech.innerHello = innerHello
	hello := uconn.HandshakeState.Hello
	hello.Raw = outer
	hello.ServerName = spec.publicName
	return nil
}

// innerOf is the ClientHelloInner of outer, a ClientHello handshake message,
// as a handshake message, and its EncodedClientHelloInner, padded. A
// session's binders are over transcript (which is left as it is) and the inner
// up to them, or over the inner alone when transcript is nil.
func (s *specECH) innerOf(outer []byte, transcript hash.Hash) (inner, encoded []byte, err error) {
	h := cryptobyte.String(outer)
	var msgType uint8
	var body, session, suites, compression, extensions cryptobyte.String
	var version uint16
	if !h.ReadUint8(&msgType) || msgType != typeClientHello || !h.ReadUint24LengthPrefixed(&body) || !h.Empty() ||
		!body.ReadUint16(&version) || !body.Skip(32) || !body.ReadUint8LengthPrefixed(&session) ||
		!body.ReadUint16LengthPrefixed(&suites) || !body.ReadUint8LengthPrefixed(&compression) ||
		!body.ReadUint16LengthPrefixed(&extensions) || !body.Empty() {
		return nil, nil, errors.New("tls: internal error: the outer hello does not read")
	}
	var innerSuites []uint16
	for !suites.Empty() {
		var id uint16
		if !suites.ReadUint16(&id) {
			return nil, nil, errors.New("tls: internal error: the outer cipher suites do not read")
		}
		if isGREASEUint16(id) || s.minVersion < VersionTLS13 || cipherSuiteTLS13ByID(id) != nil {
			innerSuites = append(innerSuites, id)
		}
	}
	type ext struct {
		id   uint16
		data []byte
	}
	var own, compressed []ext
	for !extensions.Empty() {
		var id uint16
		var data cryptobyte.String
		if !extensions.ReadUint16(&id) || !extensions.ReadUint16LengthPrefixed(&data) {
			return nil, nil, errors.New("tls: internal error: the outer extensions do not read")
		}
		switch {
		case s.omitted[id] || id == ExtensionPadding:
		case !s.own[id]:
			compressed = append(compressed, ext{id, data})
		case id == ExtensionServerName:
			own = append(own, ext{id, serverNameData(s.serverName)})
		case id == ExtensionSupportedVersions:
			v, ok := s.versions(data)
			if !ok {
				return nil, nil, errors.New("tls: internal error: the outer supported_versions do not read")
			}
			own = append(own, ext{id, v})
		case id == extensionEncryptedClientHello:
			own = append(own, ext{id, []byte{1}})
		default:
			own = append(own, ext{id, data})
		}
	}
	// write is a ClientHello of the session ID and the extensions given; refs,
	// the types of what is taken from the outer, go in one ech_outer_extensions
	// in their stead; psk is the pre_shared_key extension, last.
	write := func(session []byte, refs bool, psk []byte) []byte {
		b := cryptobyte.NewBuilder(nil)
		b.AddUint16(version)
		b.AddBytes(s.random)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(session) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, id := range innerSuites {
				b.AddUint16(id)
			}
		})
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(compression) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			add := func(id uint16, data []byte) {
				b.AddUint16(id)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(data) })
			}
			for _, e := range own {
				add(e.id, e.data)
			}
			if refs && len(compressed) > 0 {
				add(extensionECHOuterExtensions, func() []byte {
					b := cryptobyte.NewBuilder(nil)
					b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
						for _, e := range compressed {
							b.AddUint16(e.id)
						}
					})
					return b.BytesOrPanic()
				}())
			}
			for _, e := range compressed {
				if !refs {
					add(e.id, e.data)
				}
			}
			if psk != nil {
				add(ExtensionPreSharedKey, psk)
			}
		})
		return b.BytesOrPanic()
	}
	message := func(body []byte) []byte {
		return append([]byte{typeClientHello, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	}
	var psk []byte
	if s.psk != nil {
		// The binders are over the inner hello up to them, its lengths as if
		// they were there.
		zeros := make([][]byte, len(s.psk.identities))
		for i := range zeros {
			zeros[i] = make([]byte, s.psk.suite.hash.Size())
		}
		unbound := message(write(session, false, pskData(s.psk.identities, zeros)))
		h := s.psk.suite.hash.New()
		if transcript != nil {
			h = cloneHash(transcript, s.psk.suite.hash)
		}
		h.Write(unbound[:len(unbound)-bindersLength(zeros)])
		binder := s.psk.suite.finishedHash(s.psk.binderKey, h)
		binders := make([][]byte, len(zeros))
		for i := range binders {
			binders[i] = binder
		}
		psk = pskData(s.psk.identities, binders)
	}
	inner = message(write(session, false, psk))
	encoded = write(nil, true, psk)
	return inner, append(encoded, make([]byte, s.padding(len(encoded)))...), nil
}

// versions is what supported_versions data says of the inner: the outer's
// versions of minVersion and up, its GREASE among them (every GREASE value is
// above any version a policy can say).
func (s *specECH) versions(data []byte) ([]byte, bool) {
	in := cryptobyte.String(data)
	var list cryptobyte.String
	if !in.ReadUint8LengthPrefixed(&list) || !in.Empty() {
		return nil, false
	}
	var kept []uint16
	for !list.Empty() {
		var v uint16
		if !list.ReadUint16(&v) {
			return nil, false
		}
		if v >= s.minVersion {
			kept = append(kept, v)
		}
	}
	b := cryptobyte.NewBuilder(nil)
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, v := range kept {
			b.AddUint16(v)
		}
	})
	return b.BytesOrPanic(), true
}

// padding is how many zeros follow an encoding of n bytes, as RFC 9849
// section 6.1.3 says: up to the config's maximum name length past the
// server's name (that and 9 more without one), then to a multiple of the
// block.
func (s *specECH) padding(n int) int {
	pad := s.maxNameLength + 9
	if s.serverName != "" {
		pad = max(0, s.maxNameLength-len(s.serverName))
	}
	if s.block > 0 {
		pad += s.block - 1 - (n+pad-1)%s.block
	}
	return pad
}

func serverNameData(name string) []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(0) // host_name
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(name)) })
	})
	return b.BytesOrPanic()
}

func pskData(identities []PskIdentity, binders [][]byte) []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, id := range identities {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(id.Label) })
			b.AddUint32(id.ObfuscatedTicketAge)
		}
	})
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, binder := range binders {
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(binder) })
		}
	})
	return b.BytesOrPanic()
}

// bindersLength is how much of a pre_shared_key extension its binders take.
func bindersLength(binders [][]byte) int {
	n := 2
	for _, b := range binders {
		n += 1 + len(b)
	}
	return n
}

// keptBy is the session a second hello resumes, of the identities its hello
// keeps after a HelloRetryRequest (none when the server's suite does not fit
// the session): their ticket ages, which tell the time again.
func (p *echPSK) keptBy(identities []pskIdentity) *echPSK {
	if p == nil || len(identities) != len(p.identities) {
		return nil
	}
	for i := range p.identities {
		p.identities[i].ObfuscatedTicketAge = identities[i].obfuscatedTicketAge
	}
	return p
}

// helloRetrySpecECH makes uconn's second hellos after the HelloRetryRequest hs
// read: the key shares (and the cookie) hello now has go into the outer's
// extensions, the session is kept while hello keeps it, and both hellos are
// made and sealed again, the inner with its random and its binders over the
// inner transcript so far; then the second inner goes to that transcript.
func (uconn *UConn) helloRetrySpecECH(hs *clientHandshakeStateTLS13, hello *clientHelloMsg) error {
	for _, ext := range uconn.Extensions {
		if ks, ok := ext.(*KeyShareExtension); ok {
			ks.KeyShares = keyShares(hello.keyShares).ToPublic()
		}
	}
	cookieErr := uconn.cookieForRetry(hs.serverHello.cookie)
	uconn.echSpec.psk = uconn.echSpec.psk.keptBy(hello.pskIdentities)
	if err := errors.Join(cookieErr, uconn.sealSpecECH(nil, cloneHash(hs.echContext.innerTranscript, hs.suite.hash))); err != nil {
		return err
	}
	hs.hello.original = uconn.HandshakeState.Hello.Raw
	return transcriptMsg(hs.echContext.innerHello, hs.echContext.innerTranscript)
}

// cookieForRetry echoes the cookie of a HelloRetryRequest, if it has one, in
// uconn's cookie extension, which goes where the profile has it or, when it
// has none, somewhere before its last two extensions (so that a
// pre_shared_key stays last).
func (uconn *UConn) cookieForRetry(cookie []byte) error {
	if len(cookie) == 0 {
		return nil
	}
	found := false
	for _, ext := range uconn.Extensions {
		if c, ok := ext.(*CookieExtension); ok {
			c.Cookie = cookie
			found = true
		}
	}
	if found {
		return nil
	}
	if len(uconn.Extensions) < 3 {
		return fmt.Errorf("tls: no place for a cookie among %d extensions", len(uconn.Extensions))
	}
	at := mathrand.IntN(len(uconn.Extensions) - 2)
	uconn.Extensions = slices.Insert(uconn.Extensions, at, TLSExtension(&CookieExtension{Cookie: cookie}))
	return nil
}

// echPublicName says whether name may be a config's public name, as
// BoringSSL's ssl_is_valid_ech_public_name says: dot-separated LDH labels of
// 1 to 63 bytes, none beginning or ending with a hyphen, no leading or
// trailing dot, and a last label that the WHATWG URL parser would not take
// for an IPv4 number (decimal, or 0x and hex digits).
func echPublicName(name string) bool {
	if name == "" {
		return false
	}
	labels := strings.Split(name, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range []byte(l) {
			if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-') {
				return false
			}
		}
	}
	last := labels[len(labels)-1]
	digits := strings.TrimLeft(last, "0123456789") == ""
	if hexa := strings.TrimPrefix(strings.TrimPrefix(last, "0x"), "0X"); len(hexa) < len(last) {
		digits = strings.Trim(hexa, "0123456789abcdefABCDEF") == ""
	}
	return !digits
}
