package rpmutils

import (
	"bytes"
	"crypto"
	"crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"

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

// requiredHeaderDigest determines which digest in the signature header must
// be verified against the general header. Verification fails closed if no
// digest is present, or if only a weak SHA1 digest is available and the
// caller did not explicitly allow weak digests.
func requiredHeaderDigest(sigHeader *rpmHeader, opts *VerifyOptions) (string, crypto.Hash, error) {
	// RPM v4 introduced SHA256 header signatures, prefer them over the
	// previous SHA1
	if h := getSha256(sigHeader); h != "" {
		return h, crypto.SHA256, nil
	}
	if h := getSha1(sigHeader); h != "" {
		if !opts.allowWeakDigests() {
			return "", 0, fmt.Errorf("%w: header digest is SHA1", ErrWeakDigest)
		}
		return h, crypto.SHA1, nil
	}
	return "", 0, ErrNoHeaderDigest
}

// Parse signatures from the header and determine which hash functions are
// needed to digest the RPM. The caller must write the payload to the returned
// WriteCloser, then call Close to check if the payload digest matches.
func digestAndVerify(sigHeader, genHeader *rpmHeader, payloadReader io.Reader, knownKeys openpgp.EntityList, opts *VerifyOptions) ([]*Signature, []hash.Hash, error) {
	var sigs []*Signature
	var hashes []hash.Hash
	// signatures over the general header alone
	for _, tag := range headerSigTags {
		sig, err := setupDigester(sigHeader, tag, knownKeys)
		if err != nil {
			return nil, nil, err
		} else if sig == nil {
			continue
		}
		sig.HeaderOnly = true
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
			return nil, nil, err
		} else if sig == nil {
			continue
		}
		sig.HeaderOnly = false
		h := sig.Hash.New()
		h.Write(genHeader.orig)
		payloadWriters = append(payloadWriters, h)
		sigs = append(sigs, sig)
		hashes = append(hashes, h)
	}
	err := digestPayload(sigHeader, genHeader, payloadReader, payloadWriters, opts)
	return sigs, hashes, err
}

func digestPayload(sigHeader, genHeader *rpmHeader, payloadReader io.Reader, payloadWriters []io.Writer, opts *VerifyOptions) error {
	// Also compute a digest over the payload for integrity checking purposes
	payloadValue, payloadType := getPayloadDigest(genHeader)
	if payloadType == 0 && genHeader.HasTag(PAYLOADDIGEST) {
		return fmt.Errorf("unsupported algorithm in PAYLOADDIGESTALGO")
	}
	if payloadType != 0 && !payloadType.Available() {
		return fmt.Errorf("unknown payload digest %s", payloadType)
	}
	// The legacy MD5 digest in the signature header is the only digest that
	// covers the general header together with the payload. Verify it
	// whenever it is present; for old RPMs without a PAYLOADDIGEST tag it
	// is the only payload digest available.
	sigmd5, _ := sigHeader.GetBytes(SIG_MD5 - _SIGHEADER_TAG_BASE)
	if payloadType == 0 && len(sigmd5) == 0 {
		return ErrNoPayloadDigest
	}
	// Fail closed if the strongest digest covering the payload is a weak
	// algorithm and the caller did not explicitly allow it.
	if payloadType != 0 && isWeakHash(payloadType) && !opts.allowWeakDigests() {
		return fmt.Errorf("%w: payload digest is %s", ErrWeakDigest, payloadType)
	}
	if payloadType == 0 && !opts.allowWeakDigests() {
		return fmt.Errorf("%w: payload is only covered by MD5", ErrWeakDigest)
	}
	var payloadHasher, md5Hasher hash.Hash
	if payloadType != 0 {
		// hash payload only
		payloadHasher = payloadType.New()
		payloadWriters = append(payloadWriters, payloadHasher)
	}
	if len(sigmd5) != 0 {
		// hash header + payload
		md5Hasher = md5.New()
		md5Hasher.Write(genHeader.orig)
		payloadWriters = append(payloadWriters, md5Hasher)
	}
	if _, err := io.Copy(io.MultiWriter(payloadWriters...), payloadReader); err != nil {
		return err
	}
	if payloadHasher != nil {
		calculated := hex.EncodeToString(payloadHasher.Sum(nil))
		if calculated != payloadValue {
			return &DigestMismatchError{
				Scope:    "payload",
				Hash:     payloadType,
				Expected: payloadValue,
				Actual:   calculated,
			}
		}
	}
	if md5Hasher != nil {
		calculated := md5Hasher.Sum(nil)
		if !bytes.Equal(calculated, sigmd5) {
			return &DigestMismatchError{
				Scope:    "header+payload",
				Hash:     crypto.MD5,
				Expected: hex.EncodeToString(sigmd5),
				Actual:   hex.EncodeToString(calculated),
			}
		}
	}
	return nil
}
