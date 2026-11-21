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
	gsbModernRpm     = "testdata/nfpm/test-1.0.0.x86_64.rpm"
	gsbDualDigestRpm = "testdata/empty-0.1-1.x86_64.rpm"
	gsbLegacyRpm     = "testdata/simple-1.0.1-1.i386.rpm"
)

func gsbReadRpmBlob(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}

func gsbFlipByte(data []byte, offset int) []byte {
	out := make([]byte, len(data))
	copy(out, data)
	out[offset] ^= 0xff
	return out
}

func gsbFlipHexNibble(data []byte, start int, end int) []byte {
	out := make([]byte, len(data))
	copy(out, data)
	for i := start; i < end; i++ {
		if out[i] >= '0' && out[i] <= '9' {
			out[i] = 'a' + (out[i] - '0')
			return out
		}
		if out[i] >= 'a' && out[i] <= 'f' {
			out[i] = '0' + (out[i]-'a')
			return out
		}
	}
	return out
}

// gsbStripSigHeaderTags rewrites the signature header without the given raw
// tag IDs, keeping the general header and payload untouched.
func gsbStripSigHeaderTags(t *testing.T, path string, tags ...int) []byte {
	t.Helper()
	data := gsbReadRpmBlob(t, path)
	header, err := ReadHeader(bytes.NewReader(data))
	require.NoError(t, err)
	for _, tag := range tags {
		delete(header.sigHeader.entries, tag)
	}
	blob, err := header.DumpSignatureHeader(false)
	require.NoError(t, err)
	return append(blob, data[header.OriginalSignatureHeaderSize():]...)
}

func gsbHeaderOffset(t *testing.T, path string) int {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	header, err := ReadHeader(f)
	require.NoError(t, err)
	r := header.GetRange()
	return r.Start + (r.End-r.Start)/2
}

func gsbRequireDigestMismatch(t *testing.T, err error, scope string, hashType crypto.Hash, stage HeaderStage) *HeaderError {
	t.Helper()
	require.Error(t, err)
	var mismatch *DigestMismatchError
	require.True(t, errors.As(err, &mismatch), "expected DigestMismatchError, got: %v", err)
	require.Equal(t, scope, mismatch.Scope)
	require.Equal(t, hashType, mismatch.Hash)
	require.NotEmpty(t, mismatch.Expected)
	require.NotEmpty(t, mismatch.Actual)

	var headerErr *HeaderError
	require.True(t, errors.As(err, &headerErr), "expected HeaderError, got: %v", err)
	require.NotZero(t, headerErr.Generation)
	require.Equal(t, stage, headerErr.Stage)
	require.Greater(t, headerErr.Offset, int64(0))
	require.Contains(t, headerErr.Error(), "generation=")
	require.Contains(t, headerErr.Error(), "offset=")
	require.Contains(t, headerErr.Error(), "tag=")
	require.Contains(t, headerErr.Error(), "stage=")
	return headerErr
}

// A modern package verifies without keys purely on the digest chain.
func TestGSBDigestChainWithoutKeys(t *testing.T) {
	for _, path := range []string{gsbModernRpm, gsbDualDigestRpm} {
		f, err := os.Open(path)
		require.NoError(t, err)
		header, _, err := Verify(f, nil)
		f.Close()
		require.NoError(t, err, path)
		require.NotZero(t, header.Generation())
		require.Equal(t, StageComplete, header.Report().Stage)
		require.Greater(t, header.Report().Offset, int64(header.GetRange().End))
	}
}

// A tampered payload must fail closed on PAYLOADDIGEST.
func TestGSBTamperedPayload(t *testing.T) {
	data := gsbReadRpmBlob(t, gsbModernRpm)
	tampered := gsbFlipByte(data, len(data)-1)
	_, _, err := Verify(bytes.NewReader(tampered), nil)
	headerErr := gsbRequireDigestMismatch(t, err, "payload", crypto.SHA256, StagePayloadDigest)
	require.Equal(t, PAYLOADDIGEST, headerErr.Tag)
}

// A tampered general header must fail closed on the header digest.
func TestGSBTamperedHeader(t *testing.T) {
	data := gsbReadRpmBlob(t, gsbModernRpm)
	tampered := gsbFlipByte(data, gsbHeaderOffset(t, gsbModernRpm))
	_, _, err := Verify(bytes.NewReader(tampered), nil)
	headerErr := gsbRequireDigestMismatch(t, err, "header", crypto.SHA256, StageHeaderDigest)
	require.Equal(t, SIG_SHA256, headerErr.Tag)
}

// The header digest is checked before the payload digest.
func TestGSBHeaderDigestCheckedFirst(t *testing.T) {
	data := gsbReadRpmBlob(t, gsbModernRpm)
	tampered := gsbFlipByte(data, gsbHeaderOffset(t, gsbModernRpm))
	tampered = gsbFlipByte(tampered, len(tampered)-1)
	_, _, err := Verify(bytes.NewReader(tampered), nil)
	gsbRequireDigestMismatch(t, err, "header", crypto.SHA256, StageHeaderDigest)
}

// Both SHA1 and SHA256 header digest tags must be checked. A malformed package
// that leaves the preferred SHA256 tag intact but changes SHA1 must not verify.
func TestGSBAllHeaderDigestTags(t *testing.T) {
	data := gsbReadRpmBlob(t, gsbDualDigestRpm)
	header, err := ReadHeader(bytes.NewReader(data))
	require.NoError(t, err)
	sha1Values, err := header.sigHeader.GetStrings(SIG_SHA1)
	require.NoError(t, err)
	require.Len(t, sha1Values, 1)
	sigEnd := 96 + len(header.sigHeader.orig)
	index := bytes.Index(data[:sigEnd], []byte(sha1Values[0]))
	require.GreaterOrEqual(t, index, 0)
	tampered := gsbFlipHexNibble(data, index, index+len(sha1Values[0]))
	_, _, err = Verify(bytes.NewReader(tampered), nil)
	headerErr := gsbRequireDigestMismatch(t, err, "header", crypto.SHA1, StageHeaderDigest)
	require.Equal(t, SIG_SHA1, headerErr.Tag)
}

// The legacy SIG_MD5 tag must also be checked when a modern PAYLOADDIGEST is
// present. A package with a valid payload digest but a bad legacy digest is
// internally inconsistent and must not verify.
func TestGSBAllPayloadDigestTags(t *testing.T) {
	data := gsbReadRpmBlob(t, gsbDualDigestRpm)
	header, err := ReadHeader(bytes.NewReader(data))
	require.NoError(t, err)
	md5Value, err := header.sigHeader.GetBytes(SIG_MD5 - _SIGHEADER_TAG_BASE)
	require.NoError(t, err)
	sigEnd := 96 + len(header.sigHeader.orig)
	index := bytes.Index(data[:sigEnd], md5Value)
	require.GreaterOrEqual(t, index, 0)
	tampered := gsbFlipByte(data, index+len(md5Value)-1)
	_, _, err = Verify(bytes.NewReader(tampered), nil)
	headerErr := gsbRequireDigestMismatch(t, err, "header+payload", crypto.MD5, StagePayloadDigest)
	require.Equal(t, SIG_MD5, headerErr.Tag)
}

// A tampered payload in a legacy package must fail closed on the MD5 digest
// over header+payload when weak digests are explicitly allowed.
func TestGSBTamperedLegacyPayload(t *testing.T) {
	data := gsbReadRpmBlob(t, gsbLegacyRpm)
	tampered := gsbFlipByte(data, len(data)-1)
	opts := &VerifyOptions{AllowWeakDigests: true}
	_, _, err := VerifyWithOptions(bytes.NewReader(tampered), nil, opts)
	gsbRequireDigestMismatch(t, err, "header+payload", crypto.MD5, StagePayloadDigest)
}

// Legacy packages with only SHA1/MD5 digests require an explicit policy.
func TestGSBLegacyRequiresExplicitPolicy(t *testing.T) {
	data := gsbReadRpmBlob(t, gsbLegacyRpm)
	_, _, err := Verify(bytes.NewReader(data), nil)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrWeakDigest), "expected ErrWeakDigest, got: %v", err)

	_, _, err = VerifyWithOptions(bytes.NewReader(data), nil, &VerifyOptions{AllowWeakDigests: true})
	require.NoError(t, err)
}

// A missing header digest fails closed even when weak digests are allowed.
func TestGSBMissingHeaderDigest(t *testing.T) {
	data := gsbStripSigHeaderTags(t, gsbLegacyRpm, SIG_SHA1)
	opts := &VerifyOptions{AllowWeakDigests: true}
	_, _, err := VerifyWithOptions(bytes.NewReader(data), nil, opts)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrNoHeaderDigest), "expected ErrNoHeaderDigest, got: %v", err)
}

// A missing payload digest fails closed even when weak digests are allowed.
func gsbLegacyWithoutMD5(t *testing.T) []byte {
	t.Helper()
	return gsbStripSigHeaderTags(t, gsbLegacyRpm, SIG_MD5-_SIGHEADER_TAG_BASE)
}

func TestGSBMissingPayloadDigest(t *testing.T) {
	data := gsbLegacyWithoutMD5(t)
	opts := &VerifyOptions{AllowWeakDigests: true}
	_, _, err := VerifyWithOptions(bytes.NewReader(data), nil, opts)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrNoPayloadDigest), "expected ErrNoPayloadDigest, got: %v", err)
}
