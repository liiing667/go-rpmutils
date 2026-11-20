package rpmutils

import (
	"bytes"
	"hash"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func parseSignature(blob []byte, knownKeys openpgp.EntityList) (*Signature, error) {
	reader := bytes.NewReader(blob)
	genpkt, err := packet.Read(reader)
	if err != nil {
		return nil, err
	} else if reader.Len() > 0 {
		return nil, ErrTrailingGarbage
	}
	return parseSignatureMaybeV3(genpkt, knownKeys)
}

func parseSignatureV4(genpkt packet.Packet, knownKeys openpgp.EntityList) (*Signature, error) {
	pkt, ok := genpkt.(*packet.Signature)
	if !ok || (pkt.IssuerKeyId == nil && len(pkt.IssuerFingerprint) == 0) {
		return nil, ErrNoPGPSignature
	}
	sig := &Signature{
		Hash:           pkt.Hash,
		CreationTime:   pkt.CreationTime,
		KeyFingerprint: pkt.IssuerFingerprint,
	}
	if pkt.IssuerKeyId != nil {
		sig.KeyId = *pkt.IssuerKeyId
	}
	sig.validate = func(h hash.Hash) error {
		if knownKeys == nil {
			return nil
		}
		entity, key, err := findKey(pkt, knownKeys)
		if err != nil {
			return err
		}
		if key == nil {
			return KeyNotFoundError{
				KeyID:       sig.KeyId,
				Fingerprint: sig.KeyFingerprint,
			}
		}
		setEntity(sig, entity, key)
		return key.VerifySignature(h, pkt)
	}
	return sig, nil
}

// set identity attributes on signature
func setEntity(sig *Signature, entity *openpgp.Entity, key *packet.PublicKey) {
	sig.Signer = entity
	if sig.KeyId == 0 {
		sig.KeyId = key.KeyId
	}
	if sig.KeyFingerprint == nil {
		sig.KeyFingerprint = key.Fingerprint
	}
	if identity := entity.PrimaryIdentity(); identity != nil {
		sig.PrimaryName = identity.Name
	}
}

// findKey locates the key that created a signature. The issuer fingerprint is
// preferred when the signature provides one; older signatures that only carry
// a key ID fall back to a key ID lookup. A key ID that matches multiple
// distinct keys is ambiguous and results in a KeyCollisionError.
func findKey(sig *packet.Signature, knownKeys openpgp.EntityList) (*openpgp.Entity, *packet.PublicKey, error) {
	if len(sig.IssuerFingerprint) >= 20 {
		entity, key := findKeyByFingerprint(knownKeys, sig.IssuerFingerprint)
		return entity, key, nil
	}
	if sig.IssuerKeyId == nil {
		return nil, nil, nil
	}
	return findKeyByKeyId(knownKeys, *sig.IssuerKeyId)
}

// entityKeys returns the primary key and subkeys of an entity
func entityKeys(entity *openpgp.Entity) []*packet.PublicKey {
	keys := make([]*packet.PublicKey, 0, len(entity.Subkeys)+1)
	keys = append(keys, entity.PrimaryKey)
	for i := range entity.Subkeys {
		keys = append(keys, entity.Subkeys[i].PublicKey)
	}
	return keys
}

// find a key by its full fingerprint, which uniquely identifies a key
func findKeyByFingerprint(knownKeys openpgp.EntityList, fingerprint []byte) (*openpgp.Entity, *packet.PublicKey) {
	for _, entity := range knownKeys {
		for _, key := range entityKeys(entity) {
			if bytes.Equal(fingerprint, key.Fingerprint) {
				return entity, key
			}
		}
	}
	return nil, nil
}

// find a key by its key ID, which may be shared by multiple distinct keys
func findKeyByKeyId(knownKeys openpgp.EntityList, keyId uint64) (*openpgp.Entity, *packet.PublicKey, error) {
	var matchEntity *openpgp.Entity
	var matchKey *packet.PublicKey
	var fingerprints [][]byte
	for _, entity := range knownKeys {
		for _, key := range entityKeys(entity) {
			if key.KeyId != keyId {
				continue
			}
			duplicate := false
			for _, fp := range fingerprints {
				if bytes.Equal(fp, key.Fingerprint) {
					duplicate = true
					break
				}
			}
			if duplicate {
				continue
			}
			fingerprints = append(fingerprints, key.Fingerprint)
			if matchKey == nil {
				matchEntity, matchKey = entity, key
			}
		}
	}
	if len(fingerprints) > 1 {
		return nil, nil, KeyCollisionError{KeyID: keyId, Fingerprints: fingerprints}
	}
	return matchEntity, matchKey, nil
}
