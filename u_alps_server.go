package tls

import (
	"errors"

	"golang.org/x/crypto/cryptobyte"
)

// The server's side of ALPS (draft-vvv-tls-alps), which uTLS's tests and a
// bench of servers speak to clients that offer it, Chrome's among them: a
// server with Config.ApplicationSettings for the protocol ALPN chose sends
// them in its EncryptedExtensions under the codepoint the client offered
// ALPS with, the new one when it offered both, and reads the client's own
// from the client's EncryptedExtensions, before its Certificate and
// Finished, before it works out the Finished it expects and sends its
// session tickets; ConnectionState.PeerApplicationSettings says them.

// offeredALPS is the codepoint and protocols of the ALPS a ClientHello
// (its original bytes) offers, the new codepoint's when it offers both; 0
// when it offers none, or the hello does not read.
func offeredALPS(original []byte) (uint16, []string) {
	s := cryptobyte.String(original)
	var sessionID, suites, compression, extensions cryptobyte.String
	if !s.Skip(4+2+32) || !s.ReadUint8LengthPrefixed(&sessionID) || !s.ReadUint16LengthPrefixed(&suites) ||
		!s.ReadUint8LengthPrefixed(&compression) || !s.ReadUint16LengthPrefixed(&extensions) {
		return 0, nil
	}
	var codepoint uint16
	var protocols []string
	for !extensions.Empty() {
		var ext uint16
		var data cryptobyte.String
		if !extensions.ReadUint16(&ext) || !extensions.ReadUint16LengthPrefixed(&data) {
			return 0, nil
		}
		if ext != utlsExtensionApplicationSettings && ext != utlsExtensionApplicationSettingsNew ||
			codepoint == utlsExtensionApplicationSettingsNew {
			continue
		}
		var list cryptobyte.String
		if !data.ReadUint16LengthPrefixed(&list) {
			return 0, nil
		}
		var names []string
		for !list.Empty() {
			var name cryptobyte.String
			if !list.ReadUint8LengthPrefixed(&name) {
				return 0, nil
			}
			names = append(names, string(name))
		}
		codepoint, protocols = ext, names
	}
	return codepoint, protocols
}

// serverALPS puts in a server's EncryptedExtensions the settings it has
// for the protocol ALPN chose, when the client offered ALPS for it.
func (hs *serverHandshakeStateTLS13) serverALPS(ee *encryptedExtensionsMsg) {
	c := hs.c
	settings, ok := c.config.ApplicationSettings[c.clientProtocol]
	if !ok || c.clientProtocol == "" {
		return
	}
	codepoint, protocols := offeredALPS(hs.clientHello.original)
	for _, p := range protocols {
		if p == c.clientProtocol {
			ee.utls.applicationSettingsCodepoint = codepoint
			ee.utls.applicationSettings = settings
			c.utls.applicationSettingsCodepoint = codepoint
			c.utls.localApplicationSettings = settings
			return
		}
	}
}

// readClientEncryptedExtensions reads the client's EncryptedExtensions,
// which a client that ALPS was negotiated with sends before its Certificate
// and Finished, and keeps the settings it says under the same codepoint.
func (hs *serverHandshakeStateTLS13) readClientEncryptedExtensions() error {
	c := hs.c
	if c.utls.applicationSettingsCodepoint == 0 {
		return nil
	}
	msg, err := c.readHandshake(hs.transcript)
	if err != nil {
		return err
	}
	ee, ok := msg.(*utlsClientEncryptedExtensionsMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(ee, msg)
	}
	if ee.applicationSettingsCodepoint != c.utls.applicationSettingsCodepoint {
		c.sendAlert(alertMissingExtension)
		return errors.New("tls: client's EncryptedExtensions without the negotiated application settings")
	}
	c.utls.peerApplicationSettings = ee.applicationSettings
	if hs.requestClientCert() {
		return nil // the tickets go once its certificate is read
	}
	// sendServerFinished left the client's Finished to be worked out over
	// these too
	return hs.sendSessionTickets()
}
