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
	"crypto"
	"errors"
	"fmt"
	"hash"
	"io"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// Signature describes a PGP signature found within a RPM while verifying it.
type Signature struct {
	// Signer is the PGP identity that created the signature. It may be nil if
	// the public key is not available at verification time, but KeyId will
	// always be set.
	Signer *openpgp.Entity
	// Hash is the algorithm used to digest the signature contents
	Hash crypto.Hash
	// CreationTime is when the signature was created
	CreationTime time.Time
	// HeaderOnly is true for signatures that only cover the general RPM header,
	// and false for signatures that cover the general header plus the payload
	HeaderOnly bool
	// KeyId is the PGP key that created the signature.
	KeyId uint64
	// KeyFingerprint is the fingerprint of the public key that created the
	// signature, if available.
	KeyFingerprint []byte
	// PrimaryName is the primary identity of the signing key, if available.
	PrimaryName string

	validate func(hash.Hash) error
}

// VerifyOptions configures the digest policy used by VerifyWithOptions.
type VerifyOptions struct {
	// AllowWeakDigests permits verification of legacy packages whose
	// strongest available digests use SHA1 or MD5. These algorithms are no
	// longer collision resistant, so packages that rely on them are
	// rejected unless this is explicitly set.
	AllowWeakDigests bool
}

func (opts *VerifyOptions) allowWeakDigests() bool {
	return opts != nil && opts.AllowWeakDigests
}

// Verify the PGP signature over a RPM file. knownKeys should enumerate public
// keys to check against, otherwise the signature validity cannot be verified.
// If knownKeys is nil then digests will be checked but only the raw key ID will
// be available.
//
// The digest chain is always verified and fails closed: every header digest in
// the signature header, the payload digest in the general header, and the
// legacy MD5 digest when present must exist and match. Verifying all present
// tags prevents a malformed header from presenting different tag sets to the
// digest check and to the package identity readers. Packages that only carry
// weak SHA1/MD5 digests are rejected; use VerifyWithOptions to accept them
// explicitly.
func Verify(stream io.Reader, knownKeys openpgp.EntityList) (header *RpmHeader, sigs []*Signature, err error) {
	return VerifyWithOptions(stream, knownKeys, nil)
}

// VerifyWithOptions is Verify with an explicit digest policy.
func VerifyWithOptions(stream io.Reader, knownKeys openpgp.EntityList, opts *VerifyOptions) (header *RpmHeader, sigs []*Signature, err error) {
	ctx := newHeaderContext(stream)
	return verifyWithContext(ctx, knownKeys, opts)
}

func verifyWithContext(ctx *headerContext, knownKeys openpgp.EntityList, opts *VerifyOptions) (header *RpmHeader, sigs []*Signature, err error) {
	lead, sigHeader, err := readSignatureHeaderWithContext(ctx)
	if err != nil {
		return nil, nil, err
	}
	sigStart := ctx.offset() - int64(len(sigHeader.orig))
	// The signature header must carry at least one digest over the general
	// header, and all digest tags that are present must agree.
	checks, err := headerDigestChecks(sigHeader, opts, true)
	if err != nil {
		return nil, nil, ctx.fail(StageHeaderDigest, sigStart, -1, err)
	}
	// parse the general header, verifying every recorded header digest
	genHeader, err := readHeaderWithContext(ctx, sigHeader.isSource, false, checks)
	if err != nil {
		return nil, nil, err
	}
	// verify every payload digest and setup digesters for PGP
	sigs, hashes, err := digestAndVerifyWithContext(ctx, sigHeader, genHeader, ctx.reader, knownKeys, opts)
	if err != nil {
		return nil, nil, err
	}
	// verify PGP signatures
	for i, sig := range sigs {
		h := hashes[i]
		if err := sig.validate(h); err != nil {
			return nil, nil, ctx.fail(StagePGPSignature, ctx.offset(), -1, err)
		}
	}
	hdr := &RpmHeader{
		lead:       lead,
		sigHeader:  sigHeader,
		genHeader:  genHeader,
		isSource:   sigHeader.isSource,
		generation: ctx.generation,
		report:     ctx.complete(),
	}
	return hdr, sigs, nil
}

var (
	ErrNoPGPSignature  = errors.New("no supported PGP signature packet found")
	ErrTrailingGarbage = errors.New("trailing garbage after PGP signature packet")

	// ErrNoHeaderDigest is returned when the signature header carries no
	// digest (SIG_SHA256/SIG_SHA1) over the general header.
	ErrNoHeaderDigest = errors.New("no header digest found in signature header")
	// ErrNoPayloadDigest is returned when neither a PAYLOADDIGEST tag in the
	// general header nor a SIG_MD5 tag in the signature header is present.
	ErrNoPayloadDigest = errors.New("no usable payload digest found")
	// ErrWeakDigest is returned when a verification step can only be covered
	// by a weak SHA1 or MD5 digest and VerifyOptions.AllowWeakDigests was
	// not set.
	ErrWeakDigest = errors.New("only weak SHA1/MD5 digests available")
)

// DigestMismatchError is returned when a digest recorded in the RPM does not
// match the calculated value. Scope is "header" for a digest over the general
// header, "payload" for PAYLOADDIGEST, or "header+payload" for the legacy
// SIG_MD5 digest.
type DigestMismatchError struct {
	Scope    string
	Hash     crypto.Hash
	Expected string
	Actual   string
}

func (err *DigestMismatchError) Error() string {
	if err == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s %s digest mismatch: expected %s, calculated %s",
		err.Scope, err.Hash, err.Expected, err.Actual)
}

type KeyNotFoundError struct {
	KeyID       uint64
	Fingerprint []byte
}

func (e KeyNotFoundError) Error() string {
	if e.KeyID == 0 && len(e.Fingerprint) > 0 {
		return fmt.Sprintf("key with fingerprint %x not found", e.Fingerprint)
	}
	return fmt.Sprintf("keyid %08x not found", e.KeyID)
}
