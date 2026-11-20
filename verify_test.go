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
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	modernRpm = "testdata/nfpm/test-1.0.0.x86_64.rpm"
	legacyRpm = "testdata/simple-1.0.1-1.i386.rpm"
)

func readRpmBlob(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}

// flipByte returns a copy of data with one byte corrupted
func flipByte(data []byte, offset int) []byte {
	out := make([]byte, len(data))
	copy(out, data)
	out[offset] ^= 0xff
	return out
}

// stripSigHeaderTags rewrites the signature header of a RPM without the given
// tags, keeping the general header and payload untouched
func stripSigHeaderTags(t *testing.T, path string, tags ...int) []byte {
	t.Helper()
	data := readRpmBlob(t, path)
	hdr, err := ReadHeader(bytes.NewReader(data))
	require.NoError(t, err)
	for _, tag := range tags {
		delete(hdr.sigHeader.entries, tag)
	}
	blob, err := hdr.DumpSignatureHeader(false)
	require.NoError(t, err)
	return append(blob, data[hdr.OriginalSignatureHeaderSize():]...)
}

// headerOffset returns a byte offset inside the general header of the RPM
func headerOffset(t *testing.T, path string) int {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	hdr, err := ReadHeader(f)
	require.NoError(t, err)
	r := hdr.GetRange()
	return r.Start + (r.End-r.Start)/2
}

func requireDigestMismatch(t *testing.T, err error, scope string, hash crypto.Hash) {
	t.Helper()
	require.Error(t, err)
	var mismatch *DigestMismatchError
	require.True(t, errors.As(err, &mismatch), "expected DigestMismatchError, got: %v", err)
	require.Equal(t, scope, mismatch.Scope)
	require.Equal(t, hash, mismatch.Hash)
	require.NotEmpty(t, mismatch.Expected)
	require.NotEmpty(t, mismatch.Actual)
}

// A modern package verifies without any keys, purely on the digest chain
func TestVerifyDigestChainWithoutKeys(t *testing.T) {
	for _, path := range []string{modernRpm, "testdata/empty-0.1-1.x86_64.rpm"} {
		f, err := os.Open(path)
		require.NoError(t, err)
		defer f.Close()
		_, _, err = Verify(f, nil)
		require.NoError(t, err, path)
	}
}

// A tampered payload must fail closed on the PAYLOADDIGEST check
func TestVerifyTamperedPayload(t *testing.T) {
	data := readRpmBlob(t, modernRpm)
	tampered := flipByte(data, len(data)-1)
	_, _, err := Verify(bytes.NewReader(tampered), nil)
	requireDigestMismatch(t, err, "payload", crypto.SHA256)
}

// A tampered general header must fail closed on the header digest check
func TestVerifyTamperedHeader(t *testing.T) {
	data := readRpmBlob(t, modernRpm)
	tampered := flipByte(data, headerOffset(t, modernRpm))
	_, _, err := Verify(bytes.NewReader(tampered), nil)
	requireDigestMismatch(t, err, "header", crypto.SHA256)
}

// The header digest is checked before the payload digest
func TestVerifyHeaderDigestCheckedFirst(t *testing.T) {
	data := readRpmBlob(t, modernRpm)
	tampered := flipByte(data, headerOffset(t, modernRpm))
	tampered = flipByte(tampered, len(tampered)-1)
	_, _, err := Verify(bytes.NewReader(tampered), nil)
	requireDigestMismatch(t, err, "header", crypto.SHA256)
}

// A tampered payload in a legacy package must fail closed on the MD5
// digest over header+payload
func TestVerifyTamperedLegacyPayload(t *testing.T) {
	data := readRpmBlob(t, legacyRpm)
	tampered := flipByte(data, len(data)-1)
	opts := &VerifyOptions{AllowWeakDigests: true}
	_, _, err := VerifyWithOptions(bytes.NewReader(tampered), nil, opts)
	requireDigestMismatch(t, err, "header+payload", crypto.MD5)
}

// Legacy packages with only SHA1/MD5 digests require an explicit opt-in
func TestVerifyLegacyRequiresExplicitPolicy(t *testing.T) {
	data := readRpmBlob(t, legacyRpm)
	_, _, err := Verify(bytes.NewReader(data), nil)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrWeakDigest), "expected ErrWeakDigest, got: %v", err)

	_, _, err = VerifyWithOptions(bytes.NewReader(data), nil, &VerifyOptions{AllowWeakDigests: true})
	require.NoError(t, err)
}

// A missing header digest fails closed even when weak digests are allowed
func TestVerifyMissingHeaderDigest(t *testing.T) {
	data := stripSigHeaderTags(t, legacyRpm, SIG_SHA1)
	opts := &VerifyOptions{AllowWeakDigests: true}
	_, _, err := VerifyWithOptions(bytes.NewReader(data), nil, opts)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrNoHeaderDigest), "expected ErrNoHeaderDigest, got: %v", err)
}

// A missing payload digest fails closed even when weak digests are allowed
func TestVerifyMissingPayloadDigest(t *testing.T) {
	data := stripSigHeaderTags(t, legacyRpm, SIG_MD5-_SIGHEADER_TAG_BASE)
	opts := &VerifyOptions{AllowWeakDigests: true}
	_, _, err := VerifyWithOptions(bytes.NewReader(data), nil, opts)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrNoPayloadDigest), "expected ErrNoPayloadDigest, got: %v", err)
}
