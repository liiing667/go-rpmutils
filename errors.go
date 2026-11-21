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

import "fmt"

// HeaderStage identifies the part of an RPM header read that failed.
//
// The type is an alias for string so reports can be compared with plain
// strings as well as with the named constants below.
type HeaderStage = string

const (
	// StageStart is used before any bytes have been consumed.
	StageStart HeaderStage = "start"
	// StageLead covers the 96-byte RPM lead.
	StageLead HeaderStage = "lead"
	// StageSignatureHeader covers the signature header block.
	StageSignatureHeader HeaderStage = "signature-header"
	// StageHeaderIntro covers the 16-byte header intro.
	StageHeaderIntro HeaderStage = "header-intro"
	// StageHeaderIndex covers the tag index table.
	StageHeaderIndex HeaderStage = "header-index"
	// StageHeaderData covers the header data area.
	StageHeaderData HeaderStage = "header-data"
	// StageHeaderEntry covers validation of one tag index entry.
	StageHeaderEntry HeaderStage = "header-entry"
	// StageHeaderString covers validation of one string tag.
	StageHeaderString HeaderStage = "header-string"
	// StageHeaderDigest covers a digest over the general header.
	StageHeaderDigest HeaderStage = "header-digest"
	// StagePayloadRead covers reading the payload while digesting it.
	StagePayloadRead HeaderStage = "payload-read"
	// StagePayloadDigest covers a payload or legacy header+payload digest.
	StagePayloadDigest HeaderStage = "payload-digest"
	// StagePGPSignature covers parsing or validating a PGP signature.
	StagePGPSignature HeaderStage = "pgp-signature"
	// StageComplete means the operation completed and the report is final.
	StageComplete HeaderStage = "complete"
)

// HeaderReport is the durable, machine-readable description of an RPM header
// read attempt. A report is retained for both successful and failed attempts.
//
// Generation is monotonically increasing for every attempt, including
// attempts that fail or are cancelled. Offset is an absolute byte offset from
// the beginning of the stream passed to the reader. Tag is the RPM tag that
// failed, or -1 when the failure is not tied to a particular tag.
type HeaderReport struct {
	Generation uint64
	Offset     int64
	Tag        int
	Stage      HeaderStage
	Err        error
}

// OK reports whether the read completed without an error.
func (report HeaderReport) OK() bool {
	return report.Err == nil
}

// FailedTag returns the tag that failed, or -1 when no tag is applicable.
func (report HeaderReport) FailedTag() int {
	return report.Tag
}

// Error makes a report usable as an error value. It is useful with
// errors.As(err, &report) when callers only need the retained diagnostics.
func (report HeaderReport) Error() string {
	if report.Err == nil {
		return fmt.Sprintf("RPM header read complete (generation=%d offset=%d)",
			report.Generation, report.Offset)
	}
	return (&HeaderError{
		Generation: report.Generation,
		Offset:     report.Offset,
		Tag:        report.Tag,
		Stage:      report.Stage,
		Err:        report.Err,
	}).Error()
}

// Unwrap returns the underlying error, if any.
func (report HeaderReport) Unwrap() error {
	return report.Err
}

// HeaderError describes a failed RPM header read. It retains the generation,
// offset, failed tag, and stage so callers can locate the exact failure even
// after retries or cancellation. The underlying error is available through
// errors.As/errors.Is.
type HeaderError struct {
	Generation uint64
	Offset     int64
	Tag        int
	Stage      HeaderStage
	Err        error
}

func (err *HeaderError) Error() string {
	if err == nil {
		return "<nil>"
	}
	stage := err.Stage
	if stage == "" {
		stage = "unknown"
	}
	if err.Err != nil {
		return fmt.Sprintf("RPM header read failed (generation=%d offset=%d tag=%d stage=%s): %v",
			err.Generation, err.Offset, err.Tag, stage, err.Err)
	}
	return fmt.Sprintf("RPM header read failed (generation=%d offset=%d tag=%d stage=%s)",
		err.Generation, err.Offset, err.Tag, stage)
}

// Unwrap returns the underlying error.
func (err *HeaderError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Err
}

// Report returns the retained report for this failure.
func (err *HeaderError) Report() HeaderReport {
	if err == nil {
		return HeaderReport{Tag: -1, Stage: StageStart}
	}
	return HeaderReport{
		Generation: err.Generation,
		Offset:     err.Offset,
		Tag:        err.Tag,
		Stage:      err.Stage,
		Err:        err.Err,
	}
}

// FailedTag returns the tag that failed, or -1 when no tag is applicable.
func (err *HeaderError) FailedTag() int {
	if err == nil {
		return -1
	}
	return err.Tag
}

// As exposes the retained report as a HeaderReport target.
func (err *HeaderError) As(target interface{}) bool {
	if report, ok := target.(*HeaderReport); ok && err != nil {
		*report = err.Report()
		return true
	}
	return false
}

// NoSuchTagError is returned when a tag does not exist in the header
type NoSuchTagError struct {
	Tag int
}

func (err NoSuchTagError) Error() string {
	return fmt.Sprintf("No such entry %d", err.Tag)
}

// NewNoSuchTagError creates a NoSuchTagError for a given tag
func NewNoSuchTagError(tag int) NoSuchTagError {
	return NoSuchTagError{Tag: tag}
}

// DataTypeError is returned when a header entry uses an unknown or
// unsupported data type.
type DataTypeError struct {
	Tag      int
	DataType int
}

func (err DataTypeError) Error() string {
	return fmt.Sprintf("unsupported data type %d for tag %d", err.DataType, err.Tag)
}

// DuplicateTagError is returned when a malformed header contains the same tag
// more than once. Duplicate tags are ambiguous: different readers can select
// different entries, changing the package identity represented by the header.
type DuplicateTagError struct {
	Tag int
}

func (err DuplicateTagError) Error() string {
	return fmt.Sprintf("duplicate tag %d in RPM header", err.Tag)
}
