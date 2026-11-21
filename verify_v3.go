//go:build pgp3

package rpmutils

import (
	"hash"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Using a fork of PM that does parse V3 signatures, so check if that's what it is
func parseSignatureMaybeV3(genpkt packet.Packet, knownKeys openpgp.EntityList) (*Signature, error) {
	pkt, ok := genpkt.(*packet.SignatureV3)
	if !ok {
		return parseSignatureV4(genpkt, knownKeys)
	}
	sig := &Signature{
		Hash:         pkt.Hash,
		CreationTime: pkt.CreationTime,
		KeyId:        pkt.IssuerKeyId,
	}
	// Freeze the keyring generation and the issuer identity at the time the
	// verification candidate is created, see parseSignatureV4.
	var entity *openpgp.Entity
	var key *packet.PublicKey
	if keys := knownKeys.KeysById(pkt.IssuerKeyId); len(keys) != 0 && keys[0].PublicKey != nil {
		entity, key = keys[0].Entity, keys[0].PublicKey
	}
	if entity != nil {
		setEntity(sig, entity)
	}
	sig.validate = func(h hash.Hash) error {
		if knownKeys == nil {
			return nil
		}
		if key == nil {
			return KeyNotFoundError{KeyID: pkt.IssuerKeyId}
		}
		return key.VerifySignatureV3(h, pkt)
	}
	return sig, nil
}
