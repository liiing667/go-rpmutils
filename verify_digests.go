package rpmutils

import (
	"crypto"
	"crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
)

var headerSigTags = []int{SIG_RSA, SIG_DSA}
var payloadSigTags = []int{
	SIG_PGP - _SIGHEADER_TAG_BASE,
	SIG_GPG - _SIGHEADER_TAG_BASE,
}

// Try to parse a PGP signature with the given tag and return its metadata and
// hash function.
func setupDigester(sigHeader *rpmHeader, tag int, knownKeys openpgp.EntityList) (*Signature, error) {
	blob, err := sigHeader.GetBytes(tag)
	if _, ok := err.(NoSuchTagError); ok {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return parseSignature(blob, knownKeys)
}

// isWeakHash reports whether the algorithm is too weak to be accepted
// without an explicit opt-in via VerifyOptions.AllowWeakDigests.
func isWeakHash(hashType crypto.Hash) bool {
	return hashType == crypto.MD5 || hashType == crypto.SHA1
}

// headerDigestChecks collects every header digest tag present in the signature
// header. When require is true at least one digest is mandatory and a
// SHA1-only digest chain needs an explicit weak-digest policy. When require is
// false the function is used by the permissive ReadHeader/SignRpmStream paths,
// but malformed or contradictory digest tags still fail closed.
func headerDigestChecks(sigHeader *rpmHeader, opts *VerifyOptions, require bool) ([]digestCheck, error) {
	specs := []struct {
		tag  int
		hash crypto.Hash
		name string
	}{
		{SIG_SHA256, crypto.SHA256, "SIG_SHA256"},
		{SIG_SHA1, crypto.SHA1, "SIG_SHA1"},
	}

	var checks []digestCheck
	strong := false
	for _, spec := range specs {
		if !sigHeader.HasTag(spec.tag) {
			continue
		}
		values, err := sigHeader.GetStrings(spec.tag)
		if err != nil {
			return nil, fmt.Errorf("malformed %s: %w", spec.name, err)
		}
		if len(values) == 0 {
			return nil, fmt.Errorf("%s is empty", spec.name)
		}
		for _, value := range values {
			if value == "" {
				return nil, fmt.Errorf("%s contains an empty digest", spec.name)
			}
			entry := sigHeader.entries[spec.tag]
			checks = append(checks, digestCheck{
				Tag:      spec.tag,
				Hash:     spec.hash,
				Expected: value,
				Offset:   entry.offset,
			})
			if !isWeakHash(spec.hash) {
				strong = true
			}
		}
	}

	if len(checks) == 0 {
		if require {
			return nil, ErrNoHeaderDigest
		}
		return nil, nil
	}
	if require && !strong && !opts.allowWeakDigests() {
		return nil, fmt.Errorf("%w: header digest is SHA1", ErrWeakDigest)
	}
	return checks, nil
}

// requiredHeaderDigest returns the preferred mandatory header digest. It is
// retained for callers that need a single digest while headerDigestChecks
// performs the complete multi-tag validation.
func requiredHeaderDigest(sigHeader *rpmHeader, opts *VerifyOptions) (string, crypto.Hash, error) {
	checks, err := headerDigestChecks(sigHeader, opts, true)
	if err != nil {
		return "", 0, err
	}
	if len(checks) == 0 {
		return "", 0, ErrNoHeaderDigest
	}
	return checks[0].Expected, checks[0].Hash, nil
}

// payloadDigestCheck describes one digest covering the payload.
type payloadDigestCheck struct {
	Tag      int
	Hash     crypto.Hash
	Expected string
	Scope    string
	Offset   int64
}

func payloadHashType(algo uint32) (crypto.Hash, bool) {
	switch algo {
	case HASH_MD5:
		return crypto.MD5, true
	case HASH_SHA1:
		return crypto.SHA1, true
	case HASH_SHA224:
		return crypto.SHA224, true
	case HASH_SHA256:
		return crypto.SHA256, true
	case HASH_SHA384:
		return crypto.SHA384, true
	case HASH_SHA512:
		return crypto.SHA512, true
	default:
		return 0, false
	}
}

// payloadDigestChecks collects PAYLOADDIGEST entries and the legacy SIG_MD5
// entry. All present digests are checked, so a malformed package cannot make
// the verifier and another consumer disagree about which tag portfolio covers
// the payload.
func payloadDigestChecks(sigHeader, genHeader *rpmHeader, opts *VerifyOptions) ([]payloadDigestCheck, error) {
	var checks []payloadDigestCheck
	strong := false

	if genHeader.HasTag(PAYLOADDIGEST) {
		if !genHeader.HasTag(PAYLOADDIGESTALGO) {
			return nil, fmt.Errorf("PAYLOADDIGEST present without PAYLOADDIGESTALGO")
		}
		values, err := genHeader.GetStrings(PAYLOADDIGEST)
		if err != nil {
			return nil, fmt.Errorf("malformed PAYLOADDIGEST: %w", err)
		}
		algos, err := genHeader.GetUint32s(PAYLOADDIGESTALGO)
		if err != nil {
			return nil, fmt.Errorf("malformed PAYLOADDIGESTALGO: %w", err)
		}
		if len(values) == 0 {
			return nil, fmt.Errorf("PAYLOADDIGEST is empty")
		}
		if len(values) != len(algos) {
			return nil, fmt.Errorf("PAYLOADDIGEST has %d values but PAYLOADDIGESTALGO has %d", len(values), len(algos))
		}
		for i, value := range values {
			if value == "" {
				return nil, fmt.Errorf("PAYLOADDIGEST contains an empty digest")
			}
			hashType, ok := payloadHashType(algos[i])
			if !ok {
				return nil, fmt.Errorf("unsupported PAYLOADDIGESTALGO %d", algos[i])
			}
			if !hashType.Available() {
				return nil, fmt.Errorf("unknown payload digest %s", hashType)
			}
			entry := genHeader.entries[PAYLOADDIGEST]
			checks = append(checks, payloadDigestCheck{
				Tag:      PAYLOADDIGEST,
				Hash:     hashType,
				Expected: value,
				Scope:    "payload",
				Offset:   entry.offset,
			})
			if !isWeakHash(hashType) {
				strong = true
			}
		}
	}

	md5Tag := SIG_MD5 - _SIGHEADER_TAG_BASE
	if sigHeader.HasTag(md5Tag) {
		value, err := sigHeader.GetBytes(md5Tag)
		if err != nil {
			return nil, fmt.Errorf("malformed SIG_MD5: %w", err)
		}
		if len(value) != md5.Size {
			return nil, fmt.Errorf("SIG_MD5 has %d bytes, expected %d", len(value), md5.Size)
		}
		entry := sigHeader.entries[md5Tag]
		checks = append(checks, payloadDigestCheck{
			Tag:      SIG_MD5,
			Hash:     crypto.MD5,
			Expected: hex.EncodeToString(value),
			Scope:    "header+payload",
			Offset:   entry.offset,
		})
	}

	if len(checks) == 0 {
		return nil, ErrNoPayloadDigest
	}
	if !strong && !opts.allowWeakDigests() {
		return nil, fmt.Errorf("%w: payload is only covered by SHA1/MD5", ErrWeakDigest)
	}
	return checks, nil
}

// digestAndVerify is kept as a compatibility wrapper. New callers should use
// digestAndVerifyWithContext so all sections share one generation and offset.
// The optional opts argument preserves compatibility with callers that pass
// the strict verification policy explicitly.
func digestAndVerify(sigHeader, genHeader *rpmHeader, payloadReader io.Reader, knownKeys openpgp.EntityList, opts ...*VerifyOptions) ([]*Signature, []hash.Hash, error) {
	ctx := newHeaderContext(payloadReader)
	verifyOpts := &VerifyOptions{AllowWeakDigests: true}
	if len(opts) > 0 {
		verifyOpts = opts[0]
	}
	return digestAndVerifyWithContext(ctx, sigHeader, genHeader, ctx.reader, knownKeys, verifyOpts)
}

// Parse signatures from the header and determine which hash functions are
// needed to digest the RPM. The caller must write the payload to the returned
// WriteCloser, then call Close to check if the payload digest matches.
func digestAndVerifyWithContext(ctx *headerContext, sigHeader, genHeader *rpmHeader, payloadReader io.Reader, knownKeys openpgp.EntityList, opts *VerifyOptions) ([]*Signature, []hash.Hash, error) {
	var sigs []*Signature
	var hashes []hash.Hash
	// signatures over the general header alone
	for _, tag := range headerSigTags {
		sig, err := setupDigester(sigHeader, tag, knownKeys)
		if err != nil {
			return nil, nil, ctx.fail(StagePGPSignature, ctx.offset(), tag, err)
		} else if sig == nil {
			continue
		}
		sig.HeaderOnly = true
		if !sig.Hash.Available() {
			return nil, nil, ctx.fail(StagePGPSignature, ctx.offset(), tag,
				fmt.Errorf("unsupported signature digest %s", sig.Hash))
		}
		h := sig.Hash.New()
		h.Write(genHeader.orig)
		sigs = append(sigs, sig)
		hashes = append(hashes, h)
	}
	// signatures over the general header + payload
	var payloadWriters []io.Writer
	for _, tag := range payloadSigTags {
		sig, err := setupDigester(sigHeader, tag, knownKeys)
		if err != nil {
			return nil, nil, ctx.fail(StagePGPSignature, ctx.offset(), tag, err)
		} else if sig == nil {
			continue
		}
		sig.HeaderOnly = false
		if !sig.Hash.Available() {
			return nil, nil, ctx.fail(StagePGPSignature, ctx.offset(), tag,
				fmt.Errorf("unsupported signature digest %s", sig.Hash))
		}
		h := sig.Hash.New()
		h.Write(genHeader.orig)
		payloadWriters = append(payloadWriters, h)
		sigs = append(sigs, sig)
		hashes = append(hashes, h)
	}
	err := digestPayloadWithContext(ctx, sigHeader, genHeader, payloadReader, payloadWriters, opts)
	return sigs, hashes, err
}

// digestPayload is kept as a compatibility wrapper for internal callers and
// tests that only have a payload reader. The optional opts argument preserves
// compatibility with callers that pass the strict verification policy
// explicitly.
func digestPayload(sigHeader, genHeader *rpmHeader, payloadReader io.Reader, payloadWriters []io.Writer, opts ...*VerifyOptions) error {
	ctx := newHeaderContext(payloadReader)
	verifyOpts := &VerifyOptions{AllowWeakDigests: true}
	if len(opts) > 0 {
		verifyOpts = opts[0]
	}
	return digestPayloadWithContext(ctx, sigHeader, genHeader, ctx.reader, payloadWriters, verifyOpts)
}

func digestPayloadWithContext(ctx *headerContext, sigHeader, genHeader *rpmHeader, payloadReader io.Reader, payloadWriters []io.Writer, opts *VerifyOptions) error {
	payloadStart := ctx.offset()
	checks, err := payloadDigestChecks(sigHeader, genHeader, opts)
	if err != nil {
		return ctx.fail(StagePayloadDigest, payloadStart, -1, err)
	}

	type hasherState struct {
		check  payloadDigestCheck
		hasher hash.Hash
	}
	states := make([]hasherState, 0, len(checks))
	writers := make([]io.Writer, len(payloadWriters), len(payloadWriters)+len(checks))
	copy(writers, payloadWriters)
	for _, check := range checks {
		hasher := check.Hash.New()
		if check.Scope == "header+payload" {
			hasher.Write(genHeader.orig)
		}
		states = append(states, hasherState{check: check, hasher: hasher})
		writers = append(writers, hasher)
	}

	if _, err := io.Copy(io.MultiWriter(writers...), payloadReader); err != nil {
		return ctx.fail(StagePayloadRead, ctx.offset(), -1, err)
	}
	for _, state := range states {
		calculated := hex.EncodeToString(state.hasher.Sum(nil))
		if !strings.EqualFold(calculated, state.check.Expected) {
			offset := state.check.Offset
			if offset <= 0 {
				offset = payloadStart
			}
			return ctx.fail(StagePayloadDigest, offset, state.check.Tag, &DigestMismatchError{
				Scope:    state.check.Scope,
				Hash:     state.check.Hash,
				Expected: state.check.Expected,
				Actual:   calculated,
			})
		}
	}
	return nil
}
