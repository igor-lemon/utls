package behavior

import (
	"fmt"
	"slices"
)

// echLayout are the keys that say how a ClientHelloInner is made of the outer
// hello and sealed: the engine needs every one of them to offer ECH.
var echLayout = []string{"tls.ech_inner_own", "tls.ech_inner_omitted", "tls.ech_inner_min_version",
	"tls.ech_padding_block", "tls.ech_kems", "tls.ech_kdfs", "tls.ech_aeads", "tls.ech_chacha_without_aes",
	"tls.ech_outer_psk", "tls.ech_retries", "tls.ech_retry_without"}

// echPrimitives are the HPKE KEMs, KDFs and AEADs the engine seals with:
// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and AES-128-GCM, AES-256-GCM and
// ChaCha20-Poly1305.
var echPrimitives = map[string][]uint64{
	"tls.ech_kems":  {0x0020},
	"tls.ech_kdfs":  {0x0001},
	"tls.ech_aeads": {0x0001, 0x0002, 0x0003},
}

// dnsWait are the keys that say how long a connection waits for a name's
// HTTPS records once its addresses are in.
var dnsWait = []string{"dns.https_wait_percent", "dns.https_wait_min_ms", "dns.https_wait_max_ms"}

// validateECH holds the ECH and DNS HTTPS record keys to what the engine can
// do: a profile that offers ECH says how its inner hello is made, every
// extension at most once and in at most one of the lists, the server_name and
// encrypted_client_hello among those the inner writes itself (it names the
// server there, and says it is the inner), padding, pre_shared_key and
// ech_outer_extensions in neither (the outer's padding is its own, the inner's
// is the encoding's; the engine puts a session's PSK last in the inner alone,
// and the reference list in the encoding); the primitives are
// the engine's; a profile that asks for HTTPS records says how long it waits
// for them, and asks them with the client of its own that asks the addresses
// (dns.resolver built-in): the machine's resolver answers addresses alone,
// from its cache too, and a record asked apart from them came in a window
// Chrome's never has.
func validateECH(p Policy) error {
	on := p.Flag("tls.ech")
	for _, k := range echLayout {
		if on && !p.Has(k) {
			return fmt.Errorf("tls.ech requires %s", k)
		}
		if !on && p.Has(k) {
			return fmt.Errorf("%s is set while tls.ech is not", k)
		}
	}
	own, omitted := p.Numbers("tls.ech_inner_own"), p.Numbers("tls.ech_inner_omitted")
	seen := map[uint64]bool{}
	for _, t := range append(slices.Clone(own), omitted...) {
		switch {
		case t > 0xffff:
			return fmt.Errorf("tls.ech_inner_own and tls.ech_inner_omitted: %d is no extension", t)
		case seen[t]:
			return fmt.Errorf("tls.ech_inner_own and tls.ech_inner_omitted name extension %d twice", t)
		case t == 21 || t == 41 || t == 0xfd00:
			return fmt.Errorf("extension %d is the engine's to place in an ECH inner hello", t)
		}
		seen[t] = true
	}
	if p.Has("tls.ech_inner_own") && (!slices.Contains(own, 0) || !slices.Contains(own, 0xfe0d)) {
		return fmt.Errorf("tls.ech_inner_own must name server_name (0) and encrypted_client_hello (65037)")
	}
	for k, can := range echPrimitives {
		if !p.Has(k) {
			continue
		}
		v := p.Numbers(k)
		if len(v) == 0 {
			return fmt.Errorf("%s names nothing", k)
		}
		for i, id := range v {
			if !slices.Contains(can, id) {
				return fmt.Errorf("%s: HPKE primitive API is unavailable: %d", k, id)
			}
			if slices.Contains(v[:i], id) {
				return fmt.Errorf("%s names %d twice", k, id)
			}
		}
	}
	records := p.Flag("dns.https_records")
	for _, k := range dnsWait {
		if records && !p.Has(k) {
			return fmt.Errorf("dns.https_records requires %s", k)
		}
		if !records && p.Has(k) {
			return fmt.Errorf("%s is set while dns.https_records is not", k)
		}
	}
	if records && p.Text("dns.resolver") != "built-in" {
		return fmt.Errorf("dns.https_records requires dns.resolver built-in")
	}
	if p.Flag("dns.https_upgrade") && !records {
		return fmt.Errorf("dns.https_upgrade requires dns.https_records")
	}
	if max := p.Uint("dns.https_wait_max_ms"); max != 0 && p.Uint("dns.https_wait_min_ms") > max {
		return fmt.Errorf("dns.https_wait_min_ms exceeds dns.https_wait_max_ms")
	}
	return nil
}
