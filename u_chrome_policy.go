package tls

import (
	"encoding/binary"
	"errors"
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
		return c.sendAlert(alertDecodeError)
	}
	seen := map[uint16]bool{}
	ee := data[6:]
	for len(ee) > 0 {
		if len(ee) < 4 {
			return c.sendAlert(alertDecodeError)
		}
		id := binary.BigEndian.Uint16(ee)
		n := int(binary.BigEndian.Uint16(ee[2:]))
		if n+4 > len(ee) {
			return c.sendAlert(alertDecodeError)
		}
		if !allowed[id] {
			c.sendAlert(alertUnsupportedExtension)
			return errors.New("tls: server sent an unsolicited EncryptedExtensions extension")
		}
		if seen[id] {
			c.sendAlert(alertIllegalParameter)
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
