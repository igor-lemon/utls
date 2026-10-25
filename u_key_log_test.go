// Copyright 2026 tls-forge. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// errKeyLog is the error of a key log the tests fail.
var errKeyLog = errors.New("tls test: the key log is full")

// failingKeyLog is a key log that cannot be written.
type failingKeyLog struct{}

func (failingKeyLog) Write([]byte) (int, error) { return 0, errKeyLog }

// keyLines is a key log any goroutine may write to.
type keyLines struct {
	mu   sync.Mutex
	text strings.Builder
}

func (k *keyLines) Write(p []byte) (int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.text.Write(p)
}

// lines are what k holds, line by line, sorted.
func (k *keyLines) lines() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return sortedLines(k.text.String())
}

// sortedLines are the lines of text, sorted.
func sortedLines(text string) []string {
	if text == "" {
		return nil
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	slices.Sort(lines)
	return lines
}

// keyLogLabels are the labels of the lines a client of version writes,
// sorted.
func keyLogLabels(version uint16) []string {
	if version == VersionTLS12 {
		return []string{keyLogLabelTLS12}
	}
	labels := []string{keyLogLabelClientHandshake, keyLogLabelServerHandshake, keyLogLabelClientTraffic, keyLogLabelServerTraffic}
	slices.Sort(labels)
	return labels
}

// labelsOf are the labels of lines, in their order.
func labelsOf(lines []string) []string {
	var labels []string
	for _, line := range lines {
		label, _, _ := strings.Cut(line, " ")
		labels = append(labels, label)
	}
	return labels
}

// keyLogged begins a handshake over a pipe of a client of version whose key
// log is keys with a server that keeps none of its own, and says on the
// channels it returns how the client's and the server's ended.
func keyLogged(t *testing.T, version uint16, keys io.Writer) (client, server <-chan error) {
	t.Helper()
	c, s := localPipe(t)
	t.Cleanup(func() { _ = c.Close(); _ = s.Close() })
	serverConfig := testConfig.Clone()
	serverConfig.MaxVersion = version
	served := make(chan error, 1)
	go func() { served <- Server(s, serverConfig).Handshake() }()
	clientConfig := testConfig.Clone()
	clientConfig.MaxVersion = version
	clientConfig.KeyLogWriter = keys
	ended := make(chan error, 1)
	go func() { ended <- Client(c, clientConfig).Handshake() }()
	return ended, served
}

// shookHands is how a handshake ended, which it must within ten seconds: one
// that waits for the lock of the key logs where nothing lets go of it waits
// for good.
func shookHands(t *testing.T, ended <-chan error) error {
	t.Helper()
	select {
	case err := <-ended:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("the handshake is still going after ten seconds")
		return nil
	}
}

// TestAKeyLogThatFailedHoldsUpNoLaterHandshake holds a handshake whose
// secrets could not be written to crypto/tls's rule, which fails it with the
// write's error, and every handshake after it in the process to going on as
// before: writeKeyLog returned from a write that failed, to the Config's
// writer or to the file SSLKEYLOGFILE names (here one that cannot be opened),
// with the lock of every key log held, and the next handshake to write its
// secrets waited for it for good. A file that can be opened holds the lines of
// both ends, which are the same, the client's as its own writer has them; the
// server that failed with the client ends before the file is named, since a
// TLS 1.2 one writes its secret once it has read the client's key exchange.
func TestAKeyLogThatFailedHoldsUpNoLaterHandshake(t *testing.T) {
	for _, version := range []uint16{VersionTLS13, VersionTLS12} {
		t.Run(fmt.Sprintf("%x/writer", version), func(t *testing.T) {
			t.Setenv("SSLKEYLOGFILE", "")
			client, _ := keyLogged(t, version, failingKeyLog{})
			if err := shookHands(t, client); err == nil || !strings.Contains(err.Error(), errKeyLog.Error()) {
				t.Fatalf("a handshake whose key log failed: %v, want the write's error", err)
			}
			var keys keyLines
			client, _ = keyLogged(t, version, &keys)
			if err := shookHands(t, client); err != nil {
				t.Fatalf("the handshake after it: %v", err)
			}
			if got := labelsOf(keys.lines()); !slices.Equal(got, keyLogLabels(version)) {
				t.Errorf("the handshake after it wrote %q, want %q", got, keyLogLabels(version))
			}
		})
		t.Run(fmt.Sprintf("%x/file", version), func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("SSLKEYLOGFILE", filepath.Join(dir, "missing", "keys"))
			client, server := keyLogged(t, version, nil)
			if err := shookHands(t, client); err == nil || !strings.Contains(err.Error(), "Error opening SSLKEYLOG file") {
				t.Fatalf("a handshake whose key log file could not be opened: %v", err)
			}
			if err := shookHands(t, server); err == nil {
				t.Fatal("the server of a client that failed shook hands")
			}
			file := filepath.Join(dir, "keys")
			t.Setenv("SSLKEYLOGFILE", file)
			var keys keyLines
			client, _ = keyLogged(t, version, &keys)
			if err := shookHands(t, client); err != nil {
				t.Fatalf("the handshake after it: %v", err)
			}
			written, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			own := keys.lines()
			if got := labelsOf(own); !slices.Equal(got, keyLogLabels(version)) {
				t.Errorf("the handshake after it wrote %q, want %q", got, keyLogLabels(version))
			}
			var want []string // each line twice: the client's and the server's
			for _, line := range own {
				want = append(want, line, line)
			}
			if got := sortedLines(string(written)); !slices.Equal(got, want) {
				t.Errorf("the file holds\n%s\nthe client wrote\n%s", strings.Join(got, "\n"), strings.Join(own, "\n"))
			}
		})
	}
}

// heldKeyLog is a key log whose writes wait until it is let go of, the first
// saying when it began.
type heldKeyLog struct {
	keyLines
	began, letGo chan struct{}
	first        sync.Once
}

func (h *heldKeyLog) Write(p []byte) (int, error) {
	h.first.Do(func() { close(h.began) })
	<-h.letGo
	return h.keyLines.Write(p)
}

// TestKeyLogsAreWrittenOneAtATime holds the lock of every key log through
// the write it guards: a handshake that comes to write its secrets while
// another's write is still going waits for it, and goes on once it is done.
func TestKeyLogsAreWrittenOneAtATime(t *testing.T) {
	t.Setenv("SSLKEYLOGFILE", "")
	held := &heldKeyLog{began: make(chan struct{}), letGo: make(chan struct{})}
	letGo := sync.OnceFunc(func() { close(held.letGo) })
	t.Cleanup(letGo)
	first, _ := keyLogged(t, VersionTLS13, held)
	select {
	case <-held.began:
	case err := <-first:
		t.Fatalf("the first handshake ended before it wrote its secrets: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the first handshake wrote no secret within ten seconds")
	}
	var keys keyLines
	second, _ := keyLogged(t, VersionTLS13, &keys)
	select {
	case err := <-second:
		t.Fatalf("a handshake ended (%v) while another's secret was being written", err)
	case <-time.After(500 * time.Millisecond):
	}
	letGo()
	if err := shookHands(t, first); err != nil {
		t.Errorf("the first handshake: %v", err)
	}
	if err := shookHands(t, second); err != nil {
		t.Errorf("the second handshake: %v", err)
	}
	for i, written := range []*keyLines{&held.keyLines, &keys} {
		if got := labelsOf(written.lines()); !slices.Equal(got, keyLogLabels(VersionTLS13)) {
			t.Errorf("handshake %d wrote %q", i+1, got)
		}
	}
}
