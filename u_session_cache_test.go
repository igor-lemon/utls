package tls

import "testing"

func TestAKeyKeepsTwoSingleUseSessionsAsChromiumDoes(t *testing.T) {
	tls13 := func() *ClientSessionState { return &ClientSessionState{session: &SessionState{version: VersionTLS13}} }
	tls12 := func() *ClientSessionState { return &ClientSessionState{session: &SessionState{version: VersionTLS12}} }
	cache := NewLRUClientSessionCacheOf(4, 2).(*lruSessionCache)
	take := func(key string) *ClientSessionState {
		cs, _ := cache.Take(key)
		return cs
	}

	// A server's two tickets: the second taken first, then the first, then
	// none, as Chromium's Entry pushes and pops them.
	first, second := tls13(), tls13()
	cache.Put("a", first)
	cache.Put("a", second)
	if got, _ := cache.Get("a"); got != second {
		t.Error("Get is not the newest")
	}
	if take("a") != second || take("a") != first || take("a") != nil {
		t.Error("two tickets are not taken newest first, once each")
	}
	// A third pushes the oldest out.
	third := tls13()
	cache.Put("a", first)
	cache.Put("a", second)
	cache.Put("a", third)
	if take("a") != third || take("a") != second || take("a") != nil {
		t.Error("the oldest of three was kept")
	}
	// A session that is not single use is replaced, not kept behind: a TLS
	// 1.2 one is taken again and again.
	old, newer := tls12(), tls12()
	cache.Put("b", old)
	cache.Put("b", newer)
	if take("b") != newer || take("b") != newer {
		t.Error("a TLS 1.2 session is not kept for reuse")
	}
	// One after a TLS 1.2 session replaces it; one before a TLS 1.2 is kept
	// behind it only while it is single use.
	resumed := tls13()
	cache.Put("b", resumed)
	if take("b") != resumed || take("b") != nil {
		t.Error("a TLS 1.3 session put after a TLS 1.2 one kept it")
	}
	cache.Put("c", tls13())
	plain := tls12()
	cache.Put("c", plain)
	if take("c") != plain || take("c") == nil {
		t.Error("a TLS 1.2 session put after a TLS 1.3 one")
	}
	// Removing a key removes all its sessions.
	cache.Put("d", tls13())
	cache.Put("d", tls13())
	cache.Put("d", nil)
	if take("d") != nil {
		t.Error("a removed key kept a session")
	}
	// A key evicted for another takes nothing of the one before.
	small := NewLRUClientSessionCacheOf(1, 2).(*lruSessionCache)
	small.Put("x", tls13())
	small.Put("x", tls13())
	y := tls13()
	small.Put("y", y)
	if cs, _ := small.Take("y"); cs != y {
		t.Error("an evicted key's session")
	}
	if cs, ok := small.Take("y"); cs != nil || ok {
		t.Error("an evicted key's older session went to the next key")
	}
	// One session a key, as before, where perKey is 1 or less.
	for _, perKey := range []int{1, 0} {
		one := NewLRUClientSessionCacheOf(2, perKey).(*lruSessionCache)
		one.Put("a", tls13())
		latest := tls13()
		one.Put("a", latest)
		if cs, _ := one.Take("a"); cs != latest {
			t.Errorf("perKey %d: not the latest", perKey)
		}
		if cs, _ := one.Take("a"); cs != nil {
			t.Errorf("perKey %d: kept two", perKey)
		}
	}
	if NewLRUClientSessionCache(2).(*lruSessionCache).perKey != 1 {
		t.Error("NewLRUClientSessionCache keeps more than one a key")
	}
}
