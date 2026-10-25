// Copyright 2026 tls-forge. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

// Peek reads what the server sends after the handshake, handling its
// messages (a session ticket is cached as it comes), until there is
// application data to read, which it leaves for Read, or an error, the one a
// Read there would have met: BoringSSL's SSL_peek, which Chromium calls on
// each of its connections as soon as its handshake is done, whether or not
// anything reads it yet (SSLClientSocketImpl::DoPeek). A false start is
// finished first, as a Read finishes it. Like Read it holds the connection's
// input until it returns, so a Read waits for it; a Write does not.
func (c *Conn) Peek() error {
	if err := c.Handshake(); err != nil {
		return err
	}
	return c.peek(c.handlePostHandshakeMessage)
}

// Peek is Conn's, with the messages after the handshake taken as a UConn's
// Read takes them.
func (c *UConn) Peek() error {
	if err := c.Handshake(); err != nil {
		return err
	}
	return c.peek(c.handlePostHandshakeMessage)
}

// peek is Peek once the handshake is done, handle taking each message that
// comes after it.
func (c *Conn) peek(handle func() error) error {
	if err := c.finishFalseStart(); err != nil {
		return err
	}
	c.in.Lock()
	defer c.in.Unlock()
	for c.input.Len() == 0 {
		if err := c.readRecord(); err != nil {
			return err
		}
		for c.hand.Len() > 0 {
			if err := handle(); err != nil {
				return err
			}
		}
	}
	return nil
}
