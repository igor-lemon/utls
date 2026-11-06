package tls

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/igor-lemon/utls/behavior"
)

// serverHeard is the error a TLS 1.3 server's handshake ends with when it
// says it chose protocol for a client of policy that offered h2.
func serverHeard(t *testing.T, policy behavior.Policy, protocol string) error {
	t.Helper()
	testingOnlyServerALPN = protocol
	defer func() { testingOnlyServerALPN = "" }()
	// Over TCP, not net.Pipe: the server writes its whole flight before it
	// reads the alert, which a pipe would hold up for good.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serverConfig := testConfig.Clone()
	serverConfig.MinVersion, serverConfig.MaxVersion = VersionTLS13, VersionTLS13
	serverConfig.NextProtos = []string{"h2"}
	heard := make(chan error, 1)
	go func() {
		b, err := ln.Accept()
		if err != nil {
			heard <- err
			return
		}
		defer b.Close()
		b.SetDeadline(time.Now().Add(3 * time.Second))
		heard <- Server(b, serverConfig).Handshake()
	}()
	a, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	a.SetDeadline(time.Now().Add(3 * time.Second))
	client := Client(a, &Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}, Behavior: policy,
		MinVersion: VersionTLS13})
	if err := client.Handshake(); err == nil {
		t.Fatal("the client took a protocol it did not offer")
	} else if !strings.Contains(err.Error(), "unadvertised ALPN protocol") {
		t.Fatalf("the client said %v", err)
	}
	a.Close()
	return <-heard
}

func TestAProtocolNotOfferedIsAlertedAsTheProfileSays(t *testing.T) {
	policy := policyOf(t, `{"tls.alpn_mismatch_alert": 47}`)
	if err := serverHeard(t, policy, "bogus"); err == nil || !strings.Contains(err.Error(), "illegal parameter") {
		t.Errorf("with the profile's alert: %v", err)
	}
	// The profile's, whichever it is.
	if err := serverHeard(t, policyOf(t, `{"tls.alpn_mismatch_alert": 40}`), "bogus"); err == nil ||
		!strings.Contains(err.Error(), "handshake failure") {
		t.Errorf("another alert: %v", err)
	}
	// Without it, crypto/tls's choice: no_application_protocol.
	if err := serverHeard(t, behavior.Policy{}, "bogus"); err == nil || !strings.Contains(err.Error(), "no application protocol") {
		t.Errorf("without one: %v", err)
	}
}
