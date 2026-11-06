package tls

import (
	"bytes"
	stdtls "crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/igor-lemon/utls/internal/hpke"
)

// echKeyLines is a key log written into, a line at a time; fail fails the
// write of a line of that label.
type echKeyLines struct {
	mu    sync.Mutex
	lines [][3]string
	fail  string
}

func (k *echKeyLines) Write(p []byte) (int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	f := strings.Fields(string(p))
	if len(f) != 3 {
		return 0, errors.New("not a key log line: " + string(p))
	}
	if f[0] == k.fail {
		return 0, errors.New("no room for " + f[0])
	}
	k.lines = append(k.lines, [3]string{f[0], f[1], f[2]})
	return len(p), nil
}

// of is the random and the secret of each line of label, in order.
func (k *echKeyLines) of(label string) [][2]string {
	k.mu.Lock()
	defer k.mu.Unlock()
	var out [][2]string
	for _, l := range k.lines {
		if l[0] == label {
			out = append(out, [2]string{l[1], l[2]})
		}
	}
	return out
}

// labels are the labels of the lines, in order.
func (k *echKeyLines) labels() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	var out []string
	for _, l := range k.lines {
		out = append(out, l[0])
	}
	return out
}

// randomOf is the random of a ClientHello message, in hex.
func randomOf(hello []byte) string { return hex.EncodeToString(hello[4+2 : 4+34]) }

// echRecord holds what a key log says of an accepted ECH offer to what the
// server made of it: ECH_SECRET and ECH_CONFIG by the outer hello's random,
// the secret the one the server's key gives of the offer's encapsulated key,
// the config the one offered; and the handshake's secrets by the random of the
// inner hello the server opened, after them.
func echRecord(t *testing.T, s *echTestServer, log *echKeyLines, hellos [][]byte) {
	t.Helper()
	if len(hellos) == 0 {
		t.Fatal("no hello")
	}
	outer := randomOf(hellos[0])
	o := new(clientHelloMsg)
	if !o.unmarshal(hellos[0]) {
		t.Fatal("outer does not read")
	}
	_, cs, _, enc, _, err := parseECHExt(o.encryptedClientHello)
	if err != nil {
		t.Fatal(err)
	}
	context, err := hpke.SetupReceipient(hpke.DHKEM_X25519_HKDF_SHA256, cs.KDFID, cs.AEADID, s.key,
		append([]byte("tls ech\x00"), s.config...), enc)
	if err != nil {
		t.Fatal(err)
	}
	inner := randomOf(open(t, hellos[:1], s.key, s.config)[0].inner)
	secret, config := log.of(keyLogLabelECHSecret), log.of(keyLogLabelECHConfig)
	if len(secret) != 1 || secret[0] != [2]string{outer, hex.EncodeToString(context.SharedSecret())} {
		t.Errorf("ECH_SECRET %v, want the outer random %s and the server's shared secret %x", secret, outer,
			context.SharedSecret())
	}
	if len(config) != 1 || config[0] != [2]string{outer, hex.EncodeToString(s.config)} {
		t.Errorf("ECH_CONFIG %v, want the outer random %s and the config offered", config, outer)
	}
	handshake := log.of(keyLogLabelClientHandshake)
	if len(handshake) != 1 || handshake[0][0] != inner || inner == outer {
		t.Errorf("CLIENT_HANDSHAKE_TRAFFIC_SECRET %v, want the inner random %s", handshake, inner)
	}
	if got := strings.Join(log.labels(), " "); !strings.HasPrefix(got, "ECH_SECRET ECH_CONFIG CLIENT_HANDSHAKE") {
		t.Errorf("lines %s, the offer's first", got)
	}
}

// A uTLS client's ECH offer is in its key log, by the outer hello's random,
// as NSS writes it: what opens the inner hello whose random the handshake's
// secrets go by. So a key log opens a connection whose ECH was accepted.
func TestAnECHOfferIsWrittenToTheKeyLogByTheOuterHellosRandom(t *testing.T) {
	s := newECHTestServer(t)
	log := &echKeyLines{}
	run := s.handshakeWith(t, s.serverConfig(true), nil, func(c *Config) {
		c.EncryptedClientHelloConfigList = listOf(s.config)
		c.KeyLogWriter = log
	}, nil, nil)
	if run.clientErr != nil || !run.client.ECHAccepted {
		t.Fatalf("%v, ECH %v", run.clientErr, run.client.ECHAccepted)
	}
	echRecord(t, s, log, run.hellos)
}

// So does Go's own client, of the config's list.
func TestGosOwnECHOfferIsWrittenToTheKeyLog(t *testing.T) {
	s := newECHTestServer(t)
	log := &echKeyLines{}
	c, sc := localPipe(t)
	rec := &recorder{Conn: sc}
	done := make(chan error, 1)
	go func() {
		srv := stdtls.Server(rec, s.serverConfig(true))
		defer srv.Close()
		srv.SetDeadline(time.Now().Add(10 * time.Second))
		err := srv.Handshake()
		if err == nil {
			_, err = srv.Write([]byte("ok"))
		}
		done <- err
	}()
	client := Client(c, &Config{ServerName: "secret.example", RootCAs: s.roots, MinVersion: VersionTLS13,
		EncryptedClientHelloConfigList: listOf(s.config), KeyLogWriter: log})
	client.SetDeadline(time.Now().Add(10 * time.Second))
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	client.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !client.ConnectionState().ECHAccepted {
		t.Fatal("ECH not accepted")
	}
	rec.mu.Lock()
	hellos := rec.hellos
	rec.mu.Unlock()
	echRecord(t, s, log, hellos)
}

// A hello that offers no ECH, or GREASE alone, writes no line of it; and a
// line of an offer that cannot be written fails the handshake, as any other
// does.
func TestOnlyAnECHOfferIsWrittenAndALineThatCannotBeFailsTheHandshake(t *testing.T) {
	s := newECHTestServer(t)
	log := &echKeyLines{}
	run := s.handshakeWith(t, s.serverConfig(true), nil, func(c *Config) { c.KeyLogWriter = log }, nil, nil)
	if run.clientErr != nil {
		t.Fatal(run.clientErr)
	}
	if got := strings.Join(log.labels(), " "); strings.Contains(got, "ECH") || got == "" {
		t.Errorf("a hello of GREASE wrote %q", got)
	}
	for _, label := range []string{keyLogLabelECHSecret, keyLogLabelECHConfig} {
		log := &echKeyLines{fail: label}
		run := s.handshakeWith(t, s.serverConfig(true), nil, func(c *Config) {
			c.EncryptedClientHelloConfigList = listOf(s.config)
			c.KeyLogWriter = log
		}, nil, nil)
		if run.clientErr == nil || !strings.Contains(run.clientErr.Error(), "no room for "+label) {
			t.Errorf("%s not written: %v", label, run.clientErr)
		}
		if bytes.Contains([]byte(strings.Join(log.labels(), " ")), []byte("HANDSHAKE")) {
			t.Errorf("%s not written, the handshake went on: %v", label, log.labels())
		}
	}
}
