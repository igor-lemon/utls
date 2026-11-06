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
// takes of it, as "tls.validate_server_hello_extensions" asks: of TLS 1.3
// (supported_versions there), supported_versions, a key_share where the
// client sent shares and pre_shared_key where it offered one, each once
// (tls13_client.cc, ssl_parse_extensions); of a HelloRetryRequest, cookie,
// key_share, supported_versions, and encrypted_client_hello where the client
// sent one; of TLS 1.2 (ssl_scan_serverhello_tlsext), each the client
// offered but GREASE and padding, no extension twice, which BoringSSL says
// is a list that does not decode. Another is the profile's unsolicited
// extension alert, one twice in TLS 1.3 its duplicate extension alert, and a
// list that does not read its malformed extension alert.
func (c *Conn) validateServerHello(data []byte) error {
	offered, err := c.offeredExtensions()
	if offered == nil {
		return err
	}
	return c.validateServerHelloOffered(offered, data)
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
	for !list.Empty() {
		var id uint16
		var body cryptobyte.String
		if !list.ReadUint16(&id) || !list.ReadUint16LengthPrefixed(&body) {
			return malformed()
		}
		ids = append(ids, id)
	}
	tls13 := slices.Contains(ids, ExtensionSupportedVersions)
	retry := bytes.Equal(random, helloRetryRequestRandom) // of TLS 1.3 alone
	takes := func(id uint16) bool {
		switch {
		case !tls13:
			return offered[id] && !isGREASEUint16(id) && id != ExtensionPadding
		case id == ExtensionSupportedVersions:
			return true
		case id == ExtensionKeyShare:
			return offered[id]
		case id == ExtensionPreSharedKey:
			return !retry && offered[id]
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
			return malformed()
		}
		seen[id] = true
	}
	clear(seen)
	for _, id := range ids {
		if !takes(id) {
			c.sendAlert(alert(p.Uint("tls.unsolicited_extension_alert")))
			return fmt.Errorf("tls: server sent an unsolicited ServerHello extension %d", id)
		}
		if seen[id] {
			c.sendAlert(alert(p.Uint("tls.duplicate_extension_alert")))
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
