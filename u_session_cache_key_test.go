package tls

import "testing"

// A client's sessions are kept and looked up by the SessionCacheKey its
// dialer gives, in place of ServerName, as Chromium keys them by host and
// port (SSLClientSessionCache::Key): two keys of one name share none, and a
// clone keeps its key.
func TestASessionIsKeptByTheKeyItsDialerGives(t *testing.T) {
	cache := NewLRUClientSessionCache(4)
	client := testConfig.Clone()
	client.ClientSessionCache = cache
	client.ServerName = "example.golang"
	client.SessionCacheKey = "example.golang:443"
	server := testConfig.Clone()
	if _, state, err := testHandshake(t, client, server); err != nil || state.DidResume {
		t.Fatalf("a first handshake: %v, resumed %v", err, state.DidResume)
	}
	if _, ok := cache.Get("example.golang:443"); !ok {
		t.Fatal("the session is not kept by its key")
	}
	if _, ok := cache.Get("example.golang"); ok {
		t.Fatal("the session is kept by its server name too")
	}
	if _, state, err := testHandshake(t, client.Clone(), server); err != nil || !state.DidResume {
		t.Fatalf("the same key: %v, resumed %v", err, state.DidResume)
	}
	other := client.Clone()
	other.SessionCacheKey = "example.golang:8443"
	if _, state, err := testHandshake(t, other, server); err != nil || state.DidResume {
		t.Fatalf("another key of the name: %v, resumed %v", err, state.DidResume)
	}
	// Without one, the server name, as crypto/tls keys it.
	plain := testConfig.Clone()
	plain.ClientSessionCache = cache
	plain.ServerName = "example.golang"
	if _, _, err := testHandshake(t, plain, server); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.Get("example.golang"); !ok {
		t.Fatal("a session without a key is not kept by its server name")
	}
}
