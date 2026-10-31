package tls

import (
	"crypto/ecdh"
	"fmt"
	"io"
)

// keyShareReuseKeys creates fresh X25519 components for explicitly linked
// hybrid/fallback shares. It accepts either wire order and never imports keys.
func keyShareReuseKeys(shares []KeyShare, random io.Reader) (map[CurveID]*ecdh.PrivateKey, error) {
	var keys map[CurveID]*ecdh.PrivateKey
	for _, share := range shares {
		if share.ReuseWith == 0 {
			continue
		}
		if share.Group != X25519 || len(share.Data) != 0 ||
			share.ReuseWith != X25519MLKEM768 {
			return nil, fmt.Errorf("tls: key share reuse requires fresh X25519 and a supported hybrid source")
		}
		x25519Shares := 0
		for _, candidate := range shares {
			if candidate.Group == X25519 {
				x25519Shares++
			}
		}
		if x25519Shares != 1 {
			return nil, fmt.Errorf("tls: key share reuse requires exactly one X25519 share")
		}
		found := 0
		for _, source := range shares {
			if source.Group == share.ReuseWith {
				found++
				if len(source.Data) != 0 || source.ReuseWith != 0 {
					return nil, fmt.Errorf("tls: key share reuse source must generate a fresh hybrid share")
				}
			}
		}
		if found != 1 {
			return nil, fmt.Errorf("tls: key share reuse requires exactly one hybrid source")
		}
		if keys == nil {
			keys = make(map[CurveID]*ecdh.PrivateKey)
		}
		if keys[share.ReuseWith] == nil {
			key, err := generateECDHEKey(random, X25519)
			if err != nil {
				return nil, err
			}
			keys[share.ReuseWith] = key
		}
	}
	return keys, nil
}
