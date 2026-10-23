package tls

import (
	"encoding/binary"
	"errors"
	"github.com/igor-lemon/utls/behavior"
	"net"
)

// validateServerExtensions enforces RFC8446 4.2 on the original extension IDs.
func (c *Conn) validateServerExtensions(data []byte) error {
	if c.utls.sessionController == nil || len(data) < 6 {
		return nil
	}
	uc := c.utls.sessionController.uconnRef
	hello := uc.HandshakeState.Hello.Raw
	if len(hello) < 39 {
		return errors.New("tls: missing serialized ClientHello")
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
		return errors.New("tls: malformed own ClientHello")
	}
	if _, ok := vec(2); !ok {
		return errors.New("tls: malformed own ClientHello")
	}
	if _, ok := vec(1); !ok {
		return errors.New("tls: malformed own ClientHello")
	}
	offered, ok := vec(2)
	if !ok {
		return errors.New("tls: malformed own ClientHello")
	}
	allowed := map[uint16]bool{}
	for len(offered) >= 4 {
		id := binary.BigEndian.Uint16(offered)
		n := int(binary.BigEndian.Uint16(offered[2:]))
		if n+4 > len(offered) {
			return errors.New("tls: malformed own extensions")
		}
		allowed[id] = true
		offered = offered[4+n:]
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
