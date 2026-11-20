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
	"errors"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func testPublicKey(keyId uint64, fingerprint byte) *packet.PublicKey {
	fp := make([]byte, 20)
	for i := range fp {
		fp[i] = fingerprint
	}
	return &packet.PublicKey{KeyId: keyId, Fingerprint: fp}
}

func TestFindKeyPrefersFingerprint(t *testing.T) {
	keyA := testPublicKey(0x1111, 0xaa)
	keyB := testPublicKey(0x2222, 0xbb)
	keys := openpgp.EntityList{
		{PrimaryKey: keyA},
		{PrimaryKey: keyB},
	}
	// the fingerprint of B wins even though the key ID matches A
	sig := &packet.Signature{
		IssuerKeyId:       &keyA.KeyId,
		IssuerFingerprint: keyB.Fingerprint,
	}
	_, key, err := findKey(sig, keys)
	if err != nil {
		t.Fatal(err)
	}
	if key != keyB {
		t.Fatalf("expected fingerprint match to win, got %v", key)
	}
	// an unmatched fingerprint must not fall back to the key ID
	sig.IssuerFingerprint = testPublicKey(0, 0xcc).Fingerprint
	_, key, err = findKey(sig, keys)
	if err != nil {
		t.Fatal(err)
	}
	if key != nil {
		t.Fatalf("expected no match for unknown fingerprint, got %v", key)
	}
}

func TestFindKeyFallsBackToKeyId(t *testing.T) {
	keyA := testPublicKey(0x1111, 0xaa)
	keys := openpgp.EntityList{{PrimaryKey: keyA}}
	// old signatures carry only a key ID
	sig := &packet.Signature{IssuerKeyId: &keyA.KeyId}
	_, key, err := findKey(sig, keys)
	if err != nil {
		t.Fatal(err)
	}
	if key != keyA {
		t.Fatalf("expected key ID fallback to find key, got %v", key)
	}
}

func TestFindKeyCollision(t *testing.T) {
	keyA := testPublicKey(0x1111, 0xaa)
	keyB := testPublicKey(0x1111, 0xbb)
	keys := openpgp.EntityList{
		{PrimaryKey: keyA},
		{PrimaryKey: keyB},
	}
	sig := &packet.Signature{IssuerKeyId: &keyA.KeyId}
	_, _, err := findKey(sig, keys)
	var collision KeyCollisionError
	if !errors.As(err, &collision) {
		t.Fatalf("expected KeyCollisionError, got %v", err)
	}
	if collision.KeyID != 0x1111 || len(collision.Fingerprints) != 2 {
		t.Fatalf("unexpected collision details: %#v", collision)
	}
	// the same key listed twice is a duplicate, not a collision
	keys = openpgp.EntityList{
		{PrimaryKey: keyA},
		{PrimaryKey: keyA},
	}
	_, key, err := findKey(sig, keys)
	if err != nil {
		t.Fatal(err)
	}
	if key != keyA {
		t.Fatalf("expected duplicate key to resolve, got %v", key)
	}
}

func TestFindKeySubkey(t *testing.T) {
	primary := testPublicKey(0x1111, 0xaa)
	sub := testPublicKey(0x2222, 0xbb)
	keys := openpgp.EntityList{
		{
			PrimaryKey: primary,
			Subkeys:    []openpgp.Subkey{{PublicKey: sub}},
		},
	}
	// by fingerprint
	sig := &packet.Signature{IssuerFingerprint: sub.Fingerprint}
	entity, key, err := findKey(sig, keys)
	if err != nil {
		t.Fatal(err)
	}
	if key != sub || entity != keys[0] {
		t.Fatalf("expected subkey match by fingerprint, got %v", key)
	}
	// by key ID
	sig = &packet.Signature{IssuerKeyId: &sub.KeyId}
	entity, key, err = findKey(sig, keys)
	if err != nil {
		t.Fatal(err)
	}
	if key != sub || entity != keys[0] {
		t.Fatalf("expected subkey match by key ID, got %v", key)
	}
	// a key ID shared between a subkey and an unrelated primary collides
	other := testPublicKey(0x2222, 0xcc)
	keys = append(keys, &openpgp.Entity{PrimaryKey: other})
	_, _, err = findKey(sig, keys)
	var collision KeyCollisionError
	if !errors.As(err, &collision) {
		t.Fatalf("expected KeyCollisionError, got %v", err)
	}
}

func TestKeyNotFoundErrorContents(t *testing.T) {
	err := KeyNotFoundError{KeyID: 0x1234, Fingerprint: []byte{0xab, 0xcd}}
	msg := err.Error()
	if msg == "" {
		t.Fatal("empty error message")
	}
	for _, want := range []string{"1234", "abcd"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error message %q missing %q", msg, want)
		}
	}
}
