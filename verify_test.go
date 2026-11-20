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
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
)

const signedTestRpm = "testdata/simple-1.0.1-1.i386.rpm"

func testKeyring(t *testing.T) openpgp.EntityList {
	t.Helper()
	keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader([]byte(testkey)))
	if err != nil {
		t.Fatal("failed to parse test key:", err)
	}
	return keyring
}

// signTestRpm signs the given RPM and returns the detached signature header
// along with the size of the signature header area in the original file.
func signTestRpm(t *testing.T, path string, keyring openpgp.EntityList) (detached []byte, origSigSize int) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal("failed to open test rpm:", err)
	}
	defer f.Close()
	h, err := SignRpmStream(f, keyring[0].PrivateKey, nil)
	if err != nil {
		t.Fatal("error signing rpm:", err)
	}
	detached, err = h.DumpSignatureHeader(false)
	if err != nil {
		t.Fatal("error dumping signature header:", err)
	}
	return detached, h.OriginalSignatureHeaderSize()
}

func TestVerifyDetachedSignature(t *testing.T) {
	keyring := testKeyring(t)
	entity := keyring[0]
	detached, _ := signTestRpm(t, signedTestRpm, keyring)

	f, err := os.Open(signedTestRpm)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	header, sigs, err := VerifyDetachedSignature(detached, f, keyring)
	if err != nil {
		t.Fatal("error verifying detached signature:", err)
	}
	if header == nil {
		t.Fatal("expected header state to be returned")
	}
	// the readable state must identify the signer and what each signature covers
	if len(sigs) != 2 {
		t.Fatalf("expected 2 signatures, got %d", len(sigs))
	}
	var headerOnly, withPayload bool
	for _, sig := range sigs {
		if sig.Signer != entity {
			t.Fatalf("incorrect signer: %#v", sig)
		}
		if sig.KeyId != entity.PrimaryKey.KeyId {
			t.Fatalf("incorrect keyid: got %x, expected %x", sig.KeyId, entity.PrimaryKey.KeyId)
		}
		if sig.CreationTime.IsZero() {
			t.Fatal("expected creation time to be read back")
		}
		if sig.PrimaryName != "test key" {
			t.Fatalf("incorrect primary name: %q", sig.PrimaryName)
		}
		if sig.HeaderOnly {
			headerOnly = true
		} else {
			withPayload = true
		}
	}
	if !headerOnly || !withPayload {
		t.Fatalf("expected one header-only and one header+payload signature, got %#v", sigs)
	}
}

func TestVerifyDetachedSignatureTampered(t *testing.T) {
	keyring := testKeyring(t)
	detached, origSigSize := signTestRpm(t, signedTestRpm, keyring)
	orig, err := os.ReadFile(signedTestRpm)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("payload", func(t *testing.T) {
		tampered := bytes.Clone(orig)
		tampered[len(tampered)-1] ^= 0xff
		_, _, err := VerifyDetachedSignature(detached, bytes.NewReader(tampered), keyring)
		if err == nil {
			t.Fatal("expected error for tampered payload")
		}
	})

	t.Run("general header", func(t *testing.T) {
		tampered := bytes.Clone(orig)
		tampered[origSigSize+64] ^= 0xff
		_, _, err := VerifyDetachedSignature(detached, bytes.NewReader(tampered), keyring)
		if err == nil {
			t.Fatal("expected error for tampered general header")
		}
	})

	t.Run("detached header", func(t *testing.T) {
		// corrupt the PGP signature packet inside the detached header
		f, err := os.Open(signedTestRpm)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		h, err := SignRpmStream(f, keyring[0].PrivateKey, nil)
		if err != nil {
			t.Fatal(err)
		}
		pgp := h.sigHeader.entries[SIG_PGP-_SIGHEADER_TAG_BASE].contents
		blob, err := h.DumpSignatureHeader(false)
		if err != nil {
			t.Fatal(err)
		}
		idx := bytes.Index(blob, pgp)
		if idx < 0 {
			t.Fatal("could not locate PGP signature in detached header")
		}
		tampered := bytes.Clone(blob)
		tampered[idx+len(pgp)/2] ^= 0xff
		_, _, err = VerifyDetachedSignature(tampered, bytes.NewReader(orig), keyring)
		if err == nil {
			t.Fatal("expected error for tampered detached header")
		}
	})

	t.Run("wrong package", func(t *testing.T) {
		other, err := os.Open("testdata/empty-0.1-1.x86_64.rpm")
		if err != nil {
			t.Fatal(err)
		}
		defer other.Close()
		_, _, err = VerifyDetachedSignature(detached, other, keyring)
		if err == nil {
			t.Fatal("expected error for detached header applied to the wrong package")
		}
	})
}

func TestResignPreservesContents(t *testing.T) {
	keyring := testKeyring(t)
	orig, err := os.ReadFile(signedTestRpm)
	if err != nil {
		t.Fatal(err)
	}
	tmpfile := filepath.Join(t.TempDir(), "resigned.rpm")
	if err := os.WriteFile(tmpfile, orig, 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(tmpfile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	header, err := SignRpmFile(f, tmpfile, keyring[0].PrivateKey, nil)
	if err != nil {
		t.Fatal("error signing rpm:", err)
	}
	resigned, err := os.ReadFile(tmpfile)
	if err != nil {
		t.Fatal(err)
	}
	// the lead is unchanged
	if !bytes.Equal(resigned[:96], orig[:96]) {
		t.Fatal("re-signing changed the RPM lead")
	}
	// everything after the original signature header area is unchanged
	rest := orig[header.OriginalSignatureHeaderSize():]
	if !bytes.HasSuffix(resigned, rest) {
		t.Fatal("re-signing changed bytes outside the signature header area")
	}
	// the re-signed package verifies through the detached path
	rf, err := os.Open(tmpfile)
	if err != nil {
		t.Fatal(err)
	}
	defer rf.Close()
	rheader, err := ReadHeader(rf)
	if err != nil {
		t.Fatal(err)
	}
	detached, err := rheader.DumpSignatureHeader(false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rf.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	_, sigs, err := VerifyDetachedSignature(detached, rf, keyring)
	if err != nil {
		t.Fatal("error verifying re-signed rpm via detached header:", err)
	}
	if len(sigs) != 2 {
		t.Fatalf("expected 2 signatures, got %d", len(sigs))
	}
}

func TestDumpSignatureHeaderReservedSpace(t *testing.T) {
	keyring := testKeyring(t)
	f, err := os.Open(signedTestRpm)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h, err := SignRpmStream(f, keyring[0].PrivateKey, nil)
	if err != nil {
		t.Fatal("error signing rpm:", err)
	}
	// pretend the original signature header area had extra slack, the way
	// rpm reserves space for future signatures
	h.sigHeader.orig = make([]byte, len(h.sigHeader.orig)+1024)
	blob, err := h.DumpSignatureHeader(true)
	if err != nil {
		t.Fatal("error dumping signature header:", err)
	}
	if len(blob) != h.OriginalSignatureHeaderSize() {
		t.Fatalf("expected size %d, got %d", h.OriginalSignatureHeaderSize(), len(blob))
	}
	// the reserved space is readable state in the dumped header
	_, sigHeader, err := readSignatureHeader(bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	reserved, err := sigHeader.GetBytes(SIG_RESERVEDSPACE - _SIGHEADER_TAG_BASE)
	if err != nil {
		t.Fatal("expected reserved space to be readable:", err)
	}
	if len(reserved) == 0 {
		t.Fatal("expected non-empty reserved space")
	}
	if !bytes.Equal(reserved, make([]byte, len(reserved))) {
		t.Fatal("expected reserved space to be zero-filled")
	}
	// the padded detached header still verifies against the original package
	orig, err := os.ReadFile(signedTestRpm)
	if err != nil {
		t.Fatal(err)
	}
	_, sigs, err := VerifyDetachedSignature(blob, bytes.NewReader(orig), keyring)
	if err != nil {
		t.Fatal("error verifying detached header with reserved space:", err)
	}
	if len(sigs) != 2 {
		t.Fatalf("expected 2 signatures, got %d", len(sigs))
	}
}
