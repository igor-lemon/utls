package tls

import (
	"crypto/hpke"

	ihpke "github.com/igor-lemon/utls/internal/hpke"
)

// echSealer seals the payload of an ECH offer and says the KEM's shared
// secret the offer was made of, which a key log writes as ECH_SECRET
// (logECHOffer): nil when the sealer cannot say it.
type echSealer interface {
	Seal(aad, plaintext []byte) ([]byte, error)
	SharedSecret() []byte
}

// stdSealer is a sender of Go's crypto/hpke, which keeps the KEM's shared
// secret to itself.
type stdSealer struct{ *hpke.Sender }

func (stdSealer) SharedSecret() []byte { return nil }

// newECHSender sets up the sender of an ECH offer to config. DHKEM(X25519),
// the KEM every browser offers ECH with, goes through the fork's own HPKE,
// whose shared secret a key log can write; any other KEM Go's crypto/hpke
// knows, through it.
func newECHSender(config *echConfig, pk hpke.PublicKey, kdf hpke.KDF, aead hpke.AEAD, info []byte) ([]byte, echSealer, error) {
	if config.KemID == ihpke.DHKEM_X25519_HKDF_SHA256 {
		_, kdfOK := ihpke.SupportedKDFs[kdf.ID()]
		_, aeadOK := ihpke.SupportedAEADs[aead.ID()]
		if kdfOK && aeadOK {
			key, err := ihpke.ParseHPKEPublicKey(config.KemID, config.PublicKey)
			if err != nil {
				return nil, nil, err
			}
			enc, sender, err := ihpke.SetupSender(config.KemID, kdf.ID(), aead.ID(), key, info)
			if err != nil {
				return nil, nil, err
			}
			return enc, sender, nil
		}
	}
	enc, sender, err := hpke.NewSender(pk, kdf, aead, info)
	if err != nil {
		return nil, nil, err
	}
	return enc, stdSealer{sender}, nil
}
