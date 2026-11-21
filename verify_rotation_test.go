/*
 * Copyright (c) SAS Institute Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package rpmutils

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"os"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/stretchr/testify/require"
)

// generateSigningEntity creates a fresh RSA entity for use in verification
// tests.
func generateSigningEntity(t *testing.T) *openpgp.Entity {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	now := time.Now()
	return &openpgp.Entity{
		PrimaryKey: packet.NewRSAPublicKey(now, &priv.PublicKey),
		PrivateKey: packet.NewRSAPrivateKey(now, priv),
	}
}

// generateSubkeyEntity creates an entity whose signatures are made by a
// subkey rather than the primary key.
func generateSubkeyEntity(t *testing.T) (entity *openpgp.Entity, subkey *packet.PrivateKey) {
	t.Helper()
	entity = generateSigningEntity(t)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	now := time.Now()
	sub := openpgp.Subkey{
		PublicKey:  packet.NewRSAPublicKey(now, &priv.PublicKey),
		PrivateKey: packet.NewRSAPrivateKey(now, priv),
	}
	entity.Subkeys = append(entity.Subkeys, sub)
	return entity, sub.PrivateKey
}

// signTestPackage signs the shared test RPM and returns the complete signed
// package in a new buffer.
func signTestPackage(t *testing.T, key *packet.PrivateKey, opts *SignatureOptions) *bytes.Buffer {
	t.Helper()
	f, err := os.Open("testdata/simple-1.0.1-1.i386.rpm")
	require.NoError(t, err)
	defer f.Close()
	h, err := SignRpmStream(f, key, opts)
	require.NoError(t, err)
	sigblob, err := h.DumpSignatureHeader(false)
	require.NoError(t, err)
	_, err = f.Seek(int64(h.OriginalSignatureHeaderSize()), io.SeekStart)
	require.NoError(t, err)
	var buf bytes.Buffer
	_, err = io.Copy(&buf, io.MultiReader(bytes.NewReader(sigblob), f))
	require.NoError(t, err)
	return &buf
}

// TestVerifyKeyringRotation signs a package before and after a keyring
// rotation and checks that the issuer, digest chain and verification report
// stay consistent within each keyring generation.
func TestVerifyKeyringRotation(t *testing.T) {
	gen1 := generateSigningEntity(t)
	gen2 := generateSigningEntity(t)

	// a package signed with the pre-rotation key verifies against the old
	// keyring
	signed1 := signTestPackage(t, gen1.PrivateKey, nil)
	_, sigs, err := Verify(signed1, openpgp.EntityList{gen1})
	require.NoError(t, err)
	require.Len(t, sigs, 2)
	for _, sig := range sigs {
		require.Same(t, gen1, sig.Signer)
		require.Equal(t, gen1.PrimaryKey.KeyId, sig.KeyId)
	}

	// after rotation, packages signed with the new key verify against the
	// new keyring
	signed2 := signTestPackage(t, gen2.PrivateKey, nil)
	_, sigs, err = Verify(signed2, openpgp.EntityList{gen2})
	require.NoError(t, err)
	require.Len(t, sigs, 2)
	for _, sig := range sigs {
		require.Same(t, gen2, sig.Signer)
		require.Equal(t, gen2.PrimaryKey.KeyId, sig.KeyId)
	}

	// packages signed before the rotation remain valid and are attributed
	// to the old key as long as the keyring still trusts it
	signed1 = signTestPackage(t, gen1.PrivateKey, nil)
	_, sigs, err = Verify(signed1, openpgp.EntityList{gen2, gen1})
	require.NoError(t, err)
	require.Len(t, sigs, 2)
	for _, sig := range sigs {
		require.Same(t, gen1, sig.Signer)
		require.Equal(t, gen1.PrimaryKey.KeyId, sig.KeyId)
	}

	// a keyring that no longer trusts the old key rejects the old package
	signed1 = signTestPackage(t, gen1.PrivateKey, nil)
	_, _, err = Verify(signed1, openpgp.EntityList{gen2})
	require.Error(t, err)
	require.IsType(t, KeyNotFoundError{}, err)
}

// TestVerifyCandidateFrozen ensures that a verification candidate stays bound
// to the package digest, keyring generation and issuer identity that were in
// effect when it was created: re-validating after a keyring rotation must not
// mix the old issuer with new digest results.
func TestVerifyCandidateFrozen(t *testing.T) {
	gen1 := generateSigningEntity(t)
	gen2 := generateSigningEntity(t)

	signed := signTestPackage(t, gen1.PrivateKey, nil)
	_, sigHeader, err := readSignatureHeader(signed)
	require.NoError(t, err)
	headerDigest, headerDigestType := getHashAndType(sigHeader)
	genHeader, err := readHeader(signed, headerDigest, headerDigestType, sigHeader.isSource, false)
	require.NoError(t, err)

	keyring := openpgp.EntityList{gen1}
	sigs, hashes, err := digestAndVerify(sigHeader, genHeader, signed, keyring)
	require.NoError(t, err)
	require.Len(t, sigs, 2)

	// the issuer identity is frozen when the candidate is created
	for _, sig := range sigs {
		require.Same(t, gen1, sig.Signer)
		require.Equal(t, gen1.PrimaryKey.KeyId, sig.KeyId)
	}
	for i, sig := range sigs {
		require.NoError(t, sig.validate(hashes[i]))
	}

	// rotate the keyring underneath the candidates; re-validation must
	// produce the same result and report the same issuer
	keyring[0] = gen2
	for i, sig := range sigs {
		require.NoError(t, sig.validate(hashes[i]))
		require.Same(t, gen1, sig.Signer)
		require.Equal(t, gen1.PrimaryKey.KeyId, sig.KeyId)
	}
}

// TestVerifySubkeySignature checks that a signature made by a subkey verifies
// against the primary entity and is attributed to the subkey.
func TestVerifySubkeySignature(t *testing.T) {
	entity, subkey := generateSubkeyEntity(t)
	signed := signTestPackage(t, subkey, nil)
	_, sigs, err := Verify(signed, openpgp.EntityList{entity})
	require.NoError(t, err)
	require.Len(t, sigs, 2)
	subkeyId := entity.Subkeys[0].PublicKey.KeyId
	for _, sig := range sigs {
		require.Same(t, entity, sig.Signer)
		require.Equal(t, subkeyId, sig.KeyId)
	}
}

// TestVerifyExplicitWeakHash checks that signatures made with an explicitly
// requested weak digest algorithm still verify.
func TestVerifyExplicitWeakHash(t *testing.T) {
	keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader([]byte(testkey)))
	require.NoError(t, err)
	entity := keyring[0]
	for _, hash := range []crypto.Hash{crypto.SHA1, crypto.MD5} {
		t.Run(hash.String(), func(t *testing.T) {
			signed := signTestPackage(t, entity.PrivateKey, &SignatureOptions{Hash: hash})
			_, sigs, err := Verify(signed, keyring)
			require.NoError(t, err)
			require.Len(t, sigs, 2)
			for _, sig := range sigs {
				require.Equal(t, hash, sig.Hash)
				require.Same(t, entity, sig.Signer)
			}
		})
	}
}

// TestVerifyNilKeyring checks the documented digest-only mode: with no
// keyring the digests are still verified but no signer is reported.
func TestVerifyNilKeyring(t *testing.T) {
	entity := generateSigningEntity(t)
	signed := signTestPackage(t, entity.PrivateKey, nil)
	_, sigs, err := Verify(signed, nil)
	require.NoError(t, err)
	require.Len(t, sigs, 2)
	for _, sig := range sigs {
		require.Nil(t, sig.Signer)
		require.Equal(t, entity.PrimaryKey.KeyId, sig.KeyId)
	}
}
