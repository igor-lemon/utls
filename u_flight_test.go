package tls

import (
	"bytes"
	"net"
	"slices"
	"sync"
	"testing"
)

// writtenConn is a connection that keeps what is written to it.
type writtenConn struct {
	net.Conn
	mu      sync.Mutex
	written []byte
}

func (c *writtenConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.written = append(c.written, p...)
	c.mu.Unlock()
	return c.Conn.Write(p)
}

// encryptedRecords are the lengths of the records of application data, which
// carry what TLS 1.3 encrypts, in what c was written.
func (c *writtenConn) encryptedRecords() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []int
	for rest := c.written; len(rest) >= recordHeaderLen; {
		n := int(rest[3])<<8 | int(rest[4])
		if rest[0] == byte(recordTypeApplicationData) {
			out = append(out, n)
		}
		rest = rest[min(len(rest), recordHeaderLen+n):]
	}
	return out
}

// secondFlight is the records of application data a client's handshake wrote
// to a server that asks for a certificate, the client given chain (none for
// nil), and the server's error.
func secondFlight(t *testing.T, client func(net.Conn, *Config) interface{ Handshake() error }, chain [][]byte) ([]int, error) {
	t.Helper()
	serverEnd, clientEnd := net.Pipe()
	t.Cleanup(func() { _ = serverEnd.Close(); _ = clientEnd.Close() })
	serverConfig := testConfig.Clone()
	// A certificate asked for, and taken when the client has one: a server
	// that refused none would say so to a client no longer reading.
	serverConfig.ClientAuth = RequestClientCert
	serverConfig.SessionTicketsDisabled = true
	served := make(chan error, 1)
	go func() { served <- Server(serverEnd, serverConfig).Handshake() }()
	written := &writtenConn{Conn: clientEnd}
	clientConfig := &Config{InsecureSkipVerify: true, ServerName: "example.golang", MinVersion: VersionTLS13}
	if chain != nil {
		clientConfig.Certificates = []Certificate{{Certificate: chain, PrivateKey: testRSAPrivateKey}}
	}
	if err := client(written, clientConfig).Handshake(); err != nil {
		t.Fatalf("the client's handshake: %v", err)
	}
	return written.encryptedRecords(), <-served
}

func TestAParrotWritesItsSecondFlightAsABrowserDoes(t *testing.T) {
	parrot := func(c net.Conn, config *Config) interface{ Handshake() error } {
		return UClient(c, config, HelloChrome_133, false, false, false)
	}
	golang := func(c net.Conn, config *Config) interface{ Handshake() error } {
		return UClient(c, config, HelloGolang, false, false, false)
	}
	goClient := func(c net.Conn, config *Config) interface{ Handshake() error } { return Client(c, config) }
	one := [][]byte{testRSACertificate}
	// A chain past what a record carries: the flight in a record of 16,384
	// bytes and one of the rest, each with its type and AEAD tag.
	long := slices.Repeat([][]byte{testRSACertificate}, 30)
	full := maxPlaintext + 1 + 16
	for _, tc := range []struct {
		name    string
		client  func(net.Conn, *Config) interface{ Handshake() error }
		chain   [][]byte
		records int
		first   int
	}{
		// Certificate, CertificateVerify and Finished in one record.
		{"a parrot with a certificate", parrot, one, 1, 0},
		{"a parrot with a chain past a record", parrot, long, 2, full},
		// An empty Certificate and Finished.
		{"a parrot without a certificate", parrot, nil, 1, 0},
		// A record each, as crypto/tls writes them.
		{"HelloGolang with a certificate", golang, one, 3, 0},
		{"Go's client with a certificate", goClient, one, 3, 0},
		{"Go's client with a chain past a record", goClient, long, 4, full},
		{"Go's client without a certificate", goClient, nil, 2, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records, err := secondFlight(t, tc.client, tc.chain)
			if err != nil {
				t.Fatalf("the server's handshake: %v", err)
			}
			if len(records) != tc.records || tc.first != 0 && records[0] != tc.first {
				t.Errorf("the client's flight in records of %v", records)
			}
		})
	}
}

func TestAFlightPackedIsWrittenWithTheHandshakesKeys(t *testing.T) {
	// The flight is written before the application's keys take over: what
	// the server reads of it opens with the handshake's, and a client's data
	// after it with the application's.
	serverEnd, clientEnd := net.Pipe()
	t.Cleanup(func() { _ = serverEnd.Close(); _ = clientEnd.Close() })
	serverConfig := testConfig.Clone()
	serverConfig.ClientAuth = RequireAnyClientCert
	serverConfig.SessionTicketsDisabled = true
	read := make(chan []byte, 1)
	go func() {
		server := Server(serverEnd, serverConfig)
		buf := make([]byte, 5)
		n, _ := server.Read(buf)
		read <- buf[:n]
	}()
	client := UClient(clientEnd, &Config{InsecureSkipVerify: true, ServerName: "example.golang",
		Certificates: []Certificate{{Certificate: [][]byte{testRSACertificate}, PrivateKey: testRSAPrivateKey}}}, HelloChrome_133, false, false, false)
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := <-read; !bytes.Equal(got, []byte("hello")) {
		t.Errorf("the server read %q", got)
	}
	if client.utls.packingFlight || client.utls.pendingFlight != nil {
		t.Errorf("still packing: %v, %x", client.utls.packingFlight, client.utls.pendingFlight)
	}
}
