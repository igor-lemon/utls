package tls

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"

	"github.com/igor-lemon/utls/behavior"
	"golang.org/x/crypto/cryptobyte"
)

// offeredExtensions are the extensions of the client's own ClientHello as it
// went, by type; nil, and no error, for a connection of no uTLS spec.
func (c *Conn) offeredExtensions() (map[uint16]bool, error) {
	if c.utls.sessionController == nil {
		return nil, nil
	}
	uc := c.utls.sessionController.uconnRef
	hello := uc.HandshakeState.Hello.Raw
	if len(hello) < 39 {
		return nil, errors.New("tls: missing serialized ClientHello")
	}
	p := 38
	vec := func(width int) ([]byte, bool) {
		if p+width > len(hello) {
			return nil, false
		}
		n := 0
		for _, v := range hello[p : p+width] {
			n = n*256 + int(v)
		}
		p += width
		if p+n > len(hello) {
			return nil, false
		}
		v := hello[p : p+n]
		p += n
		return v, true
	}
	if _, ok := vec(1); !ok {
		return nil, errors.New("tls: malformed own ClientHello")
	}
	if _, ok := vec(2); !ok {
		return nil, errors.New("tls: malformed own ClientHello")
	}
	if _, ok := vec(1); !ok {
		return nil, errors.New("tls: malformed own ClientHello")
	}
	offered, ok := vec(2)
	if !ok {
		return nil, errors.New("tls: malformed own ClientHello")
	}
	allowed := map[uint16]bool{}
	for len(offered) >= 4 {
		id := binary.BigEndian.Uint16(offered)
		n := int(binary.BigEndian.Uint16(offered[2:]))
		if n+4 > len(offered) {
			return nil, errors.New("tls: malformed own extensions")
		}
		allowed[id] = true
		offered = offered[4+n:]
	}
	return allowed, nil
}

// validateServerExtensions enforces RFC8446 4.2 on the original extension IDs.
func (c *Conn) validateServerExtensions(data []byte) error {
	if len(data) < 6 {
		return nil
	}
	allowed, err := c.offeredExtensions()
	if allowed == nil {
		return err
	}
	n := int(binary.BigEndian.Uint16(data[4:6]))
	if n != len(data)-6 {
		return c.sendAlert(alert(c.config.Policy().Uint("tls.malformed_extension_alert")))
	}
	seen := map[uint16]bool{}
	ee := data[6:]
	for len(ee) > 0 {
		if len(ee) < 4 {
			return c.sendAlert(alert(c.config.Policy().Uint("tls.malformed_extension_alert")))
		}
		id := binary.BigEndian.Uint16(ee)
		n := int(binary.BigEndian.Uint16(ee[2:]))
		if n+4 > len(ee) {
			return c.sendAlert(alert(c.config.Policy().Uint("tls.malformed_extension_alert")))
		}
		if !allowed[id] {
			c.sendAlert(alert(c.config.Policy().Uint("tls.unsolicited_extension_alert")))
			return errors.New("tls: server sent an unsolicited EncryptedExtensions extension")
		}
		if seen[id] {
			c.sendAlert(alert(c.config.Policy().Uint("tls.duplicate_extension_alert")))
			return errors.New("tls: repeated EncryptedExtensions extension")
		}
		seen[id] = true
		ee = ee[4+n:]
	}
	return nil
}

// validateServerHello holds a ServerHello's extensions to those BoringSSL
// takes of it, as "tls.validate_server_hello_extensions" asks, in its order.
// Before it knows the version (parse_server_version) it reads the list, and
// supported_versions alone in it where the legacy version is TLS 1.2: a list
// that does not read, or supported_versions of other than one version, is
// the profile's malformed extension alert, and supported_versions twice its
// duplicate extension alert, in a record of TLS 1.0. A version the client
// does not support is protocol_version, as pickTLSVersion says it, in a record
// of TLS 1.0 too: a legacy version other than TLS 1.2 is the version. The rest it
// refuses knowing the version, in a record of it (TLS 1.2's for TLS 1.3): of
// TLS 1.3 (tls13_client.cc, ssl_parse_extensions) supported_versions, a
// key_share where the client sent shares and pre_shared_key where it offered
// one, each once (with ECH, where the inner hello offered one: whether the
// server accepted ECH, which BoringSSL knows by then, the handshake asks once
// it knows, rejectedECHResumed); of a HelloRetryRequest, cookie, key_share,
// supported_versions, and encrypted_client_hello where the client sent one;
// of TLS 1.2 (ssl_scan_serverhello_tlsext) no extension twice, which
// BoringSSL says is a list that does not decode, then each the client
// offered that a TLS 1.2 server may answer (tls12ServerHello),
// renegotiation_info offered by the cipher suite that signals it too
// (RFC 5746, section 3.4: BoringSSL sends the extension, never it), and
// compress_certificate, offered, as a list that does not decode. Another is
// the profile's unsolicited extension alert, one twice in TLS 1.3 its
// duplicate extension alert.
func (c *Conn) validateServerHello(data []byte) error {
	offered, err := c.offeredExtensions()
	if offered == nil {
		return err
	}
	if slices.Contains(c.utls.sessionController.uconnRef.HandshakeState.Hello.CipherSuites, scsvRenegotiation) {
		offered[ExtensionRenegotiationInfo] = true
	}
	return c.validateServerHelloOffered(offered, data)
}

// innerOffersPSK says whether the inner hello of an ECH offer resumes a
// session. BoringSSL offers sessions in the inner hello alone, and takes a
// ServerHello's pre_shared_key where the server accepted ECH
// (tls13_client.cc, do_read_server_hello, its extensions the inner's).
func (c *Conn) innerOffersPSK() bool {
	if c.utls.sessionController == nil {
		return false
	}
	ech := c.utls.sessionController.uconnRef.echCtx
	return ech != nil && ech.innerHello != nil && len(ech.innerHello.pskIdentities) > 0
}

// rejectedECHResumed is the refusal of a ServerHello that resumed a session
// of an ECH offer the server rejected, as BoringSSL refuses it: the outer
// hello offers none, so its pre_shared_key is one the client did not offer
// ("When offering ECH, pre-shared keys are only offered in ClientHelloInner").
// Nil where tls.validate_server_hello_extensions does not say so, or the
// ServerHello resumed nothing.
func (c *Conn) rejectedECHResumed(serverHello *serverHelloMsg) error {
	p := c.config.Policy()
	if !p.Flag("tls.validate_server_hello_extensions") || !serverHello.selectedIdentityPresent {
		return nil
	}
	c.sendAlert(alert(p.Uint("tls.unsolicited_extension_alert")))
	return errors.New("tls: server resumed a session the outer ClientHello did not offer")
}

// tls12ServerHello are the extensions a TLS 1.2 ServerHello may carry where
// the client offered them, as BoringSSL's kExtensions parse them: the others
// of its list are forbid_parse_serverhello's or need TLS 1.3, and one not in
// it (pre_shared_key, padding, GREASE) is unknown.
var tls12ServerHello = map[uint16]bool{
	ExtensionServerName: true, ExtensionStatusRequest: true, ExtensionSupportedCurves: true,
	ExtensionSupportedPoints: true, ExtensionALPN: true, ExtensionSCT: true,
	ExtensionExtendedMasterSecret: true, ExtensionSessionTicket: true, ExtensionRenegotiationInfo: true,
	ExtensionNextProtoNeg: true, fakeExtensionChannelID: true, 14 /* use_srtp */ : true,
}

// validateServerHelloOffered is validateServerHello of a client that offered
// these extensions.
func (c *Conn) validateServerHelloOffered(offered map[uint16]bool, data []byte) error {
	p := c.config.Policy()
	malformed := func() error {
		c.sendAlert(alert(p.Uint("tls.malformed_extension_alert")))
		return errors.New("tls: malformed ServerHello extensions")
	}
	s := cryptobyte.String(data[4:])
	var random, sessionID cryptobyte.String
	var version, suite uint16
	var compression uint8
	if !s.ReadUint16(&version) || !s.ReadBytes((*[]byte)(&random), 32) || !s.ReadUint8LengthPrefixed(&sessionID) ||
		!s.ReadUint16(&suite) || !s.ReadUint8(&compression) {
		return nil // the message's own unmarshal refuses it
	}
	if s.Empty() {
		return nil
	}
	var list cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&list) || !s.Empty() {
		return malformed()
	}
	var ids []uint16
	var versions [][]byte
	for !list.Empty() {
		var id uint16
		var body cryptobyte.String
		if !list.ReadUint16(&id) || !list.ReadUint16LengthPrefixed(&body) {
			return malformed()
		}
		ids = append(ids, id)
		if id == ExtensionSupportedVersions {
			versions = append(versions, body)
		}
	}
	negotiated := version
	if version == VersionTLS12 && len(versions) > 0 {
		if len(versions) > 1 {
			c.sendAlert(alert(p.Uint("tls.duplicate_extension_alert")))
			return errors.New("tls: repeated ServerHello extension")
		}
		if len(versions[0]) != 2 {
			return malformed()
		}
		negotiated = binary.BigEndian.Uint16(versions[0])
	}
	if _, ok := c.config.mutualVersion(roleClient, []uint16{negotiated}); !ok {
		// As pickTLSVersion says it, but of the version BoringSSL reads: a
		// legacy version other than TLS 1.2 is the version, whatever
		// supported_versions says (crypto/tls would take TLS 1.3 of it).
		c.sendAlert(alertProtocolVersion)
		return fmt.Errorf("tls: server selected unsupported protocol version %x", negotiated)
	}
	// The rest goes in a record of the version, as pickTLSVersion would set it.
	known := func(a alert) {
		before := c.vers
		c.vers = negotiated
		c.sendAlert(a)
		c.vers = before
	}
	tls13 := negotiated == VersionTLS13
	retry := bytes.Equal(random, helloRetryRequestRandom) // of TLS 1.3 alone
	takes := func(id uint16) bool {
		switch {
		case !tls13:
			return offered[id] && tls12ServerHello[id]
		case id == ExtensionSupportedVersions:
			return true
		case id == ExtensionKeyShare:
			return offered[id]
		case id == ExtensionPreSharedKey:
			return !retry && (offered[id] || c.innerOffersPSK())
		case id == ExtensionCookie:
			return retry
		case id == extensionEncryptedClientHello:
			return retry && offered[id]
		}
		return false
	}
	seen := map[uint16]bool{}
	for _, id := range ids {
		if !tls13 && seen[id] {
			known(alert(p.Uint("tls.malformed_extension_alert")))
			return errors.New("tls: malformed ServerHello extensions")
		}
		seen[id] = true
	}
	clear(seen)
	for _, id := range ids {
		if !tls13 && id == ExtensionCompressCertificate && offered[id] {
			// cert_compression_parse_serverhello takes none, with the
			// decode_error its caller says by default.
			known(alert(p.Uint("tls.malformed_extension_alert")))
			return errors.New("tls: malformed ServerHello extensions")
		}
		if !takes(id) {
			known(alert(p.Uint("tls.unsolicited_extension_alert")))
			return fmt.Errorf("tls: server sent an unsolicited ServerHello extension %d", id)
		}
		if seen[id] {
			known(alert(p.Uint("tls.duplicate_extension_alert")))
			return errors.New("tls: repeated ServerHello extension")
		}
		seen[id] = true
	}
	return nil
}

// sendPendingKeyUpdate runs with the outgoing half locked.
func (c *Conn) sendPendingKeyUpdate() error {
	msg := &keyUpdateMsg{}
	b, err := msg.marshal()
	if err != nil {
		return err
	}
	if _, err = c.writeRecordLocked(recordTypeHandshake, b); err != nil {
		return err
	}
	suite := cipherSuiteTLS13ByID(c.cipherSuite)
	if suite == nil {
		return errors.New("tls: key update without a TLS1.3 cipher")
	}
	c.out.setTrafficSecret(suite, QUICEncryptionLevelInitial, suite.nextTrafficSecret(c.out.trafficSecret))
	c.utls.pendingKeyUpdate = false
	return nil
}

// ChromeHandshakeRetryable reports the narrowly measured local TLS protocol
// failures eligible for Chromium's single pre-HTTP SSLConnectJob retry. It does
// not authorize replay of a request, failed trust verification, remote alerts,
// TLS 1.2 False Start application writes, or cancellation.
func (c *UConn) ChromeHandshakeRetryable() bool {
	if len(c.config.Policy().Numbers("tls.retry_local_alerts")) == 0 || c.quic != nil {
		return false
	}
	c.out.Lock()
	defer c.out.Unlock()
	var local *net.OpError
	if !errors.As(c.out.err, &local) || local.Op != "local error" {
		return false
	}
	a, ok := local.Err.(alert)
	if ok {
		for _, id := range c.config.Policy().Numbers("tls.retry_local_alerts") {
			if uint64(a) == id {
				return true
			}
		}
	}
	return false
}

// sendsCloseNotify reports whether Close sends a close_notify alert first. A
// profile of a browser that never shuts TLS down says "tls.close_notify": false:
// Chromium's SSLClientSocketImpl::Disconnect calls no SSL_shutdown, so Chrome
// ends a connection with the TCP FIN alone. Without the field Close sends the
// alert, as crypto/tls does. CloseWrite always sends it: it is asked for.
func (c *Conn) sendsCloseNotify() bool {
	p := c.config.Policy()
	return !p.Has("tls.close_notify") || p.Flag("tls.close_notify")
}

// Policy resolves explicit profile data; only deprecated backend callers use legacy migration.
func (c *Config) Policy() behavior.Policy {
	if c == nil {
		return nil
	}
	return behavior.Resolve(c.Behavior, c.ChromeBehavior)
}
