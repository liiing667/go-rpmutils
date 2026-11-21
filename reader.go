/*
 * Copyright (c) SAS Institute, Inc.
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
	"io"
	"sync"
	"sync/atomic"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// headerGeneration is process-wide so a new HeaderReader (for example after a
// restart of the calling component) starts above every generation issued by
// the previous reader. Failed and cancelled attempts consume generations too.
var headerGeneration atomic.Uint64

func nextHeaderGeneration() uint64 {
	return headerGeneration.Add(1)
}

// HeaderReader reads RPM headers while assigning a monotonically increasing
// generation to every attempt.
//
// A failed or cancelled attempt still consumes a generation. Retries, a fresh
// reader after a restart, and concurrent readers therefore never observe an
// older generation than one already issued. Every returned RpmHeader exposes
// its generation, and every failure is a *HeaderError carrying the generation,
// absolute offset, failed tag, and stage.
//
// The zero value is ready to use.
type HeaderReader struct {
	mu   sync.Mutex
	last uint64
}

// NewHeaderReader returns a HeaderReader that participates in the process-wide
// generation sequence.
func NewHeaderReader() *HeaderReader {
	return &HeaderReader{}
}

func (reader *HeaderReader) nextGeneration() uint64 {
	if reader == nil {
		return nextHeaderGeneration()
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	generation := nextHeaderGeneration()
	if generation > reader.last {
		reader.last = generation
	}
	return generation
}

// Generation returns the last generation issued by this reader. It is zero
// before the first attempt.
func (reader *HeaderReader) Generation() uint64 {
	if reader == nil {
		return headerGeneration.Load()
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return reader.last
}

// ReadHeader reads the signature and general headers. Every call consumes a
// new generation, including calls that fail.
func (reader *HeaderReader) ReadHeader(stream io.Reader) (*RpmHeader, error) {
	ctx := newHeaderContextWithGeneration(reader.nextGeneration(), stream)
	return readRpmHeaderWithContext(ctx)
}

// ReadHeaderWithReport is ReadHeader with the retained report returned even
// when the read fails.
func (reader *HeaderReader) ReadHeaderWithReport(stream io.Reader) (*RpmHeader, HeaderReport, error) {
	ctx := newHeaderContextWithGeneration(reader.nextGeneration(), stream)
	header, err := readRpmHeaderWithContext(ctx)
	if err != nil {
		var headerErr *HeaderError
		if errors.As(err, &headerErr) {
			return nil, headerErr.Report(), err
		}
		return nil, HeaderReport{
			Generation: ctx.generation,
			Tag:        -1,
			Stage:      StageStart,
			Err:        err,
		}, err
	}
	return header, header.Report(), nil
}

// ReadRpm reads the headers and prepares to read the payload.
func (reader *HeaderReader) ReadRpm(stream io.Reader) (*Rpm, error) {
	header, err := reader.ReadHeader(stream)
	if err != nil {
		return nil, err
	}
	return &Rpm{Header: header, f: stream}, nil
}

// Verify verifies the digest chain and PGP signatures using the same
// generation rules as ReadHeader.
func (reader *HeaderReader) Verify(stream io.Reader, knownKeys openpgp.EntityList) (header *RpmHeader, sigs []*Signature, err error) {
	return reader.VerifyWithOptions(stream, knownKeys, nil)
}

// VerifyWithOptions is Verify with an explicit digest policy.
func (reader *HeaderReader) VerifyWithOptions(stream io.Reader, knownKeys openpgp.EntityList, opts *VerifyOptions) (header *RpmHeader, sigs []*Signature, err error) {
	ctx := newHeaderContextWithGeneration(reader.nextGeneration(), stream)
	return verifyWithContext(ctx, knownKeys, opts)
}
