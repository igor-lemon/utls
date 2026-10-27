package tls

import (
	"os"
	"path/filepath"
	"testing"
)

func TestKeyLogEnvironmentIsNotConsent(t *testing.T) {
	for _, version := range []uint16{VersionTLS12, VersionTLS13} {
		for _, exists := range []bool{false, true} {
			dir := t.TempDir()
			file := filepath.Join(dir, "keys")
			if exists {
				if err := os.WriteFile(file, []byte("sentinel\n"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				file = filepath.Join(dir, "missing", "keys")
			}
			t.Setenv("SSLKEYLOGFILE", file)
			client, server := keyLogged(t, version, nil)
			if err := shookHands(t, client); err != nil {
				t.Errorf("ambient keylog broke client handshake: %v", err)
			}
			if err := shookHands(t, server); err != nil {
				t.Errorf("ambient keylog broke server handshake: %v", err)
			}
			got, err := os.ReadFile(file)
			if exists && (err != nil || string(got) != "sentinel\n") {
				t.Errorf("ambient keylog exported secrets: %q %v", got, err)
			}
			if !exists && !os.IsNotExist(err) {
				t.Errorf("ambient keylog created a file: %v", err)
			}
			var keys keyLines
			client, server = keyLogged(t, version, &keys)
			if err := shookHands(t, client); err != nil {
				t.Errorf("explicit writer: %v", err)
			}
			if err := shookHands(t, server); err != nil {
				t.Errorf("explicit writer server: %v", err)
			}
			if len(keys.lines()) == 0 {
				t.Error("explicit writer was ignored")
			}
		}
	}
}
