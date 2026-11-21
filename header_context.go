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
	"bytes"
	"crypto"
	"errors"
	"io"
)

// digestCheck describes one digest value recorded in an RPM header.
type digestCheck struct {
	Tag      int
	Hash     crypto.Hash
	Expected string
	Offset   int64
}

// countingReader keeps the absolute stream offset used in HeaderReport and
// HeaderError. It deliberately does not attempt to seek or otherwise rewind
// the wrapped reader: a failed attempt consumes its generation and the caller
// must provide a fresh stream (or seek) for a retry.
type countingReader struct {
	r io.Reader
	n int64
}

func (reader *countingReader) Read(p []byte) (int, error) {
	n, err := reader.r.Read(p)
	reader.n += int64(n)
	return n, err
}

// headerContext is shared by all header sections belonging to one logical
// read attempt. This is what makes the signature header, general header, and
// payload digest share one generation and one absolute offset.
type headerContext struct {
	generation uint64
	reader     *countingReader
}

func newHeaderContext(stream io.Reader) *headerContext {
	return newHeaderContextWithGeneration(nextHeaderGeneration(), stream)
}

func newHeaderContextWithGeneration(generation uint64, stream io.Reader) *headerContext {
	if stream == nil {
		stream = bytes.NewReader(nil)
	}
	return &headerContext{
		generation: generation,
		reader:     &countingReader{r: stream},
	}
}

func (ctx *headerContext) offset() int64 {
	return ctx.reader.n
}

// readExact reads exactly n bytes and attributes a short read to the supplied
// stage and tag. The reported offset is the first byte that could not be read.
func (ctx *headerContext) readExact(n int, stage HeaderStage, tag int) ([]byte, error) {
	start := ctx.offset()
	buf := make([]byte, n)
	read, err := io.ReadFull(ctx.reader, buf)
	if err != nil {
		return nil, ctx.fail(stage, start+int64(read), tag, err)
	}
	return buf, nil
}

// fail creates a HeaderError unless err already carries header context. The
// generation is never recomputed here, so a retry cannot accidentally reuse a
// lower generation.
func (ctx *headerContext) fail(stage HeaderStage, offset int64, tag int, err error) error {
	if err == nil {
		err = io.ErrUnexpectedEOF
	}
	var existing *HeaderError
	if errors.As(err, &existing) {
		return err
	}
	return &HeaderError{
		Generation: ctx.generation,
		Offset:     offset,
		Tag:        tag,
		Stage:      stage,
		Err:        err,
	}
}

func (ctx *headerContext) complete() HeaderReport {
	return HeaderReport{
		Generation: ctx.generation,
		Offset:     ctx.offset(),
		Tag:        -1,
		Stage:      StageComplete,
	}
}
