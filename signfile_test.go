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
	"os"
	"path/filepath"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// loadSigningTestKey parses the shared test key and returns the signing
// entity along with a keyring for verification.
func loadSigningTestKey(t *testing.T) (*openpgp.Entity, openpgp.EntityList) {
	t.Helper()
	keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader([]byte(testkey)))
	if err != nil {
		t.Fatal("failed to parse test key:", err)
	}
	return keyring[0], keyring
}

func copyFileForSignTest(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal("failed to read test rpm:", err)
	}
	if err := os.WriteFile(dst, data, 0644); err != nil {
		t.Fatal("failed to copy test rpm:", err)
	}
}

func readFileForSignTest(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("failed to read file:", err)
	}
	return data
}

// verifySignedRpm checks that the signatures on the given RPM validate
// against the test key and were made by the test entity.
func verifySignedRpm(t *testing.T, path string, entity *openpgp.Entity, keyring openpgp.EntityList) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal("failed to open signed rpm:", err)
	}
	defer f.Close()
	_, sigs, err := Verify(f, keyring)
	if err != nil {
		t.Fatal("error verifying signed rpm:", err)
	}
	if len(sigs) != 2 || sigs[0].Signer != entity || sigs[1].Signer != entity {
		t.Fatalf("error verifying signed rpm: incorrect signers. found: %#v", sigs)
	}
}

// sigHeaderSizeOf returns the size of the lead and signature header area of
// the RPM at the given path.
func sigHeaderSizeOf(t *testing.T, path string) int {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal("failed to open rpm:", err)
	}
	defer f.Close()
	hdr, err := ReadHeader(f)
	if err != nil {
		t.Fatal("failed to read rpm header:", err)
	}
	return hdr.OriginalSignatureHeaderSize()
}

// requireSamePayload requires that everything past the signature header is
// byte-identical between two RPM files.
func requireSamePayload(t *testing.T, pathA, pathB string) {
	t.Helper()
	a := readFileForSignTest(t, pathA)
	b := readFileForSignTest(t, pathB)
	a = a[sigHeaderSizeOf(t, pathA):]
	b = b[sigHeaderSizeOf(t, pathB):]
	if !bytes.Equal(a, b) {
		t.Fatal("package contents after the signature header differ")
	}
}

func dirEntriesForSignTest(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal("failed to read directory:", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

// Signing to a new path must produce a package whose signature header and
// contents verify against each other.
func TestSignRpmFileToNewFile(t *testing.T) {
	entity, keyring := loadSigningTestKey(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "src.rpm")
	dst := filepath.Join(dir, "dst.rpm")
	copyFileForSignTest(t, "testdata/simple-1.0.1-1.i386.rpm", src)

	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := SignRpmFile(in, dst, entity.PrivateKey, nil)
	if err != nil {
		_ = in.Close()
		t.Fatal("error signing rpm:", err)
	}
	if err := in.Close(); err != nil {
		t.Fatal(err)
	}
	if hdr == nil {
		t.Fatal("no header returned")
	}
	nevra, err := hdr.GetNEVRA()
	if err != nil {
		t.Fatal(err)
	}
	if nevra.Name != "simple" || nevra.Version != "1.0.1" {
		t.Fatalf("incorrect nevra: %s", nevra.String())
	}
	verifySignedRpm(t, dst, entity, keyring)
	requireSamePayload(t, src, dst)
}

// Signing in place must keep the signature header and package contents
// consistent, including when the package is signed a second time.
func TestSignRpmFileInPlace(t *testing.T) {
	entity, keyring := loadSigningTestKey(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "pkg.rpm")
	copyFileForSignTest(t, "testdata/simple-1.0.1-1.i386.rpm", path)

	sign := func() {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := SignRpmFile(f, path, entity.PrivateKey, nil); err != nil {
			t.Fatal("error signing rpm:", err)
		}
	}
	sign()
	verifySignedRpm(t, path, entity, keyring)
	requireSamePayload(t, "testdata/simple-1.0.1-1.i386.rpm", path)

	// re-signing the already signed package must keep the same identity
	sign()
	verifySignedRpm(t, path, entity, keyring)
	requireSamePayload(t, "testdata/simple-1.0.1-1.i386.rpm", path)
}

// A failed rewrite must not touch the output file: a retry has to see the
// previous package with its own matching signature header, not a signature
// header left behind by the failed attempt.
func TestSignRpmFileFailedRewriteKeepsOriginal(t *testing.T) {
	entity, keyring := loadSigningTestKey(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "old.rpm")
	copyFileForSignTest(t, "testdata/simple-1.0.1-1.i386.rpm", out)

	// put a valid, authorized signature on the old package
	f, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignRpmFile(f, out, entity.PrivateKey, nil); err != nil {
		_ = f.Close()
		t.Fatal("error signing rpm:", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	verifySignedRpm(t, out, entity, keyring)
	want := readFileForSignTest(t, out)

	// Sign different package contents onto the same path, using an input
	// stream that cannot be rewound so that the rewrite fails after the
	// new signature header has been computed.
	newContent := readFileForSignTest(t, "testdata/nfpm/test-1.0.0.x86_64.rpm")
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = w.Write(newContent)
		_ = w.Close()
	}()
	_, signErr := SignRpmFile(r, out, entity.PrivateKey, nil)
	_ = r.Close()
	if signErr == nil {
		t.Fatal("expected signing to fail")
	}

	// the old package must be untouched and still verify on its own
	if got := readFileForSignTest(t, out); !bytes.Equal(got, want) {
		t.Fatal("failed signing modified the output file")
	}
	verifySignedRpm(t, out, entity, keyring)
	// no temporary files may be left behind
	if entries := dirEntriesForSignTest(t, dir); len(entries) != 1 || entries[0] != "old.rpm" {
		t.Fatalf("unexpected files left behind: %v", entries)
	}
}

// A failed rewrite to a new path must not leave a partial or empty file
// behind.
func TestSignRpmFileFailedRewriteLeavesNoFile(t *testing.T) {
	entity, _ := loadSigningTestKey(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "new.rpm")

	content := readFileForSignTest(t, "testdata/simple-1.0.1-1.i386.rpm")
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = w.Write(content)
		_ = w.Close()
	}()
	_, signErr := SignRpmFile(r, out, entity.PrivateKey, nil)
	_ = r.Close()
	if signErr == nil {
		t.Fatal("expected signing to fail")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("expected no output file, stat error: %v", err)
	}
	if entries := dirEntriesForSignTest(t, dir); len(entries) != 0 {
		t.Fatalf("unexpected files left behind: %v", entries)
	}
}

// The deprecated RewriteWithSignatures API must keep working with the
// atomic rewrite logic.
func TestRewriteWithSignaturesStillWorks(t *testing.T) {
	entity, keyring := loadSigningTestKey(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "src.rpm")
	out := filepath.Join(dir, "out.rpm")
	copyFileForSignTest(t, "testdata/simple-1.0.1-1.i386.rpm", src)

	// make raw signatures over the package contents
	f, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := SignRpmStream(f, entity.PrivateKey, nil)
	if err != nil {
		_ = f.Close()
		t.Fatal("error signing rpm:", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	sigPgp, err := hdr.GetBytes(SIG_PGP)
	if err != nil {
		t.Fatal("error getting PGP signature:", err)
	}
	sigRsa, err := hdr.GetBytes(SIG_RSA)
	if err != nil {
		t.Fatal("error getting RSA signature:", err)
	}

	// insert them into an unsigned copy of the same package
	f2, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RewriteWithSignatures(f2, out, sigPgp, sigRsa); err != nil {
		_ = f2.Close()
		t.Fatal("error rewriting rpm:", err)
	}
	if err := f2.Close(); err != nil {
		t.Fatal(err)
	}
	verifySignedRpm(t, out, entity, keyring)
	requireSamePayload(t, src, out)
}
