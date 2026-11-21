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
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

type gsbHeaderEntry struct {
	tag      int32
	dataType int32
	count    int32
	data     []byte
}

func gsbBuildHeader(entries []gsbHeaderEntry) []byte {
	var table bytes.Buffer
	var data bytes.Buffer
	for _, element := range entries {
		record := make([]byte, headerTagSize)
		binary.BigEndian.PutUint32(record[0:4], uint32(element.tag))
		binary.BigEndian.PutUint32(record[4:8], uint32(element.dataType))
		binary.BigEndian.PutUint32(record[8:12], uint32(data.Len()))
		binary.BigEndian.PutUint32(record[12:16], uint32(element.count))
		table.Write(record)
		data.Write(element.data)
	}
	out := make([]byte, headerIntroSize)
	binary.BigEndian.PutUint32(out[0:4], introMagic)
	binary.BigEndian.PutUint32(out[8:12], uint32(len(entries)))
	binary.BigEndian.PutUint32(out[12:16], uint32(data.Len()))
	out = append(out, table.Bytes()...)
	out = append(out, data.Bytes()...)
	return out
}

func gsbTagRecord(tag, dataType, offset, count int32) []byte {
	record := make([]byte, headerTagSize)
	binary.BigEndian.PutUint32(record[0:4], uint32(tag))
	binary.BigEndian.PutUint32(record[4:8], uint32(dataType))
	binary.BigEndian.PutUint32(record[8:12], uint32(offset))
	binary.BigEndian.PutUint32(record[12:16], uint32(count))
	return record
}

func gsbRawHeader(entries uint32, size uint32, table, data []byte) []byte {
	out := make([]byte, headerIntroSize)
	binary.BigEndian.PutUint32(out[0:4], introMagic)
	binary.BigEndian.PutUint32(out[8:12], entries)
	binary.BigEndian.PutUint32(out[12:16], size)
	out = append(out, table...)
	out = append(out, data...)
	return out
}

// gsbBuildRpm returns a minimal but valid RPM whose headers contain no digest
// tags. ReadHeader is intentionally permissive about unsigned headers.
func gsbBuildRpm() []byte {
	lead := make([]byte, 96)
	binary.BigEndian.PutUint32(lead[0:4], 0xedabeedb)

	signature := gsbBuildHeader([]gsbHeaderEntry{
		{tag: 1000, dataType: RPM_INT32_TYPE, count: 2, data: []byte{0, 0, 0, 1, 0, 0, 0, 2}},
	})
	general := gsbBuildHeader([]gsbHeaderEntry{
		{tag: NAME, dataType: RPM_STRING_TYPE, count: 1, data: []byte("pkg\x00")},
		{tag: VERSION, dataType: RPM_STRING_TYPE, count: 1, data: []byte("1\x00")},
		{tag: RELEASE, dataType: RPM_STRING_TYPE, count: 1, data: []byte("1\x00")},
		{tag: ARCH, dataType: RPM_STRING_TYPE, count: 1, data: []byte("x86_64\x00")},
	})
	out := append([]byte(nil), lead...)
	out = append(out, signature...)
	out = append(out, general...)
	return out
}

type gsbErrorReader struct {
	data      []byte
	failAfter int
	err       error
	offset    int
}

func (reader *gsbErrorReader) Read(p []byte) (int, error) {
	if reader.offset >= reader.failAfter {
		return 0, reader.err
	}
	if reader.offset >= len(reader.data) {
		return 0, io.EOF
	}
	n := len(p)
	if n > reader.failAfter-reader.offset {
		n = reader.failAfter - reader.offset
	}
	if n > len(reader.data)-reader.offset {
		n = len(reader.data) - reader.offset
	}
	copy(p, reader.data[reader.offset:reader.offset+n])
	reader.offset += n
	return n, nil
}

func TestGSBHeaderReaderGenerationMonotonicAcrossRetries(t *testing.T) {
	blob := gsbBuildRpm()
	reader := NewHeaderReader()

	failed, err := reader.ReadHeader(bytes.NewReader(blob[:100]))
	require.Nil(t, failed)
	var first *HeaderError
	require.ErrorAs(t, err, &first)
	require.NotZero(t, first.Generation)
	require.Equal(t, StageHeaderIntro, first.Stage)
	require.Equal(t, int64(100), first.Offset)
	require.Equal(t, -1, first.Tag)
	require.Equal(t, first.Generation, first.Report().Generation)

	ok, err := reader.ReadHeader(bytes.NewReader(blob))
	require.NoError(t, err)
	require.Greater(t, ok.Generation(), first.Generation)
	require.Equal(t, ok.Generation(), reader.Generation())
	require.Equal(t, StageComplete, ok.Report().Stage)
	require.Equal(t, int64(ok.GetRange().End), ok.Report().Offset)

	cancelled, err := reader.ReadHeader(&gsbErrorReader{
		data:      blob,
		failAfter: 100,
		err:       context.Canceled,
	})
	require.Nil(t, cancelled)
	var second *HeaderError
	require.ErrorAs(t, err, &second)
	require.True(t, errors.Is(err, context.Canceled))
	require.Greater(t, second.Generation, ok.Generation())
	require.Equal(t, StageHeaderIntro, second.Stage)
	require.Equal(t, int64(100), second.Offset)

	// A new reader models a component restart. It participates in the same
	// process-wide sequence and must not reuse a generation from the first
	// reader.
	restartedReader := NewHeaderReader()
	restarted, err := restartedReader.ReadHeader(bytes.NewReader(blob))
	require.NoError(t, err)
	require.Greater(t, restarted.Generation(), second.Generation)
}

func TestGSBHeaderErrorRetainsFailedTagOffsetAndStage(t *testing.T) {
	// The tag declares four bytes at offset 4, but the data area is only four
	// bytes long. The failing data starts at absolute offset 16+16+4 = 36.
	header := gsbRawHeader(1, 4,
		gsbTagRecord(1004, RPM_INT32_TYPE, 4, 1),
		[]byte{0, 0, 0, 1})
	_, err := readHeader(bytes.NewReader(header), "", 0, false, false)

	var headerErr *HeaderError
	require.ErrorAs(t, err, &headerErr)
	require.NotZero(t, headerErr.Generation)
	require.Equal(t, int64(36), headerErr.Offset)
	require.Equal(t, 1004, headerErr.Tag)
	require.Equal(t, StageHeaderEntry, headerErr.Stage)

	report := headerErr.Report()
	require.Equal(t, headerErr.Generation, report.Generation)
	require.Equal(t, headerErr.Offset, report.Offset)
	require.Equal(t, headerErr.Tag, report.Tag)
	require.Equal(t, headerErr.Stage, report.Stage)
	var asReport HeaderReport
	require.True(t, errors.As(err, &asReport))
	require.Equal(t, report.Generation, asReport.Generation)

	for _, want := range []string{"generation=", "offset=36", "tag=1004", "stage=header-entry"} {
		require.Contains(t, headerErr.Error(), want)
	}
}

func TestGSBReadHeaderWithReportRetainsFailedStage(t *testing.T) {
	blob := gsbBuildRpm()
	header, report, err := ReadHeaderWithReport(bytes.NewReader(blob[:100]))
	require.Nil(t, header)
	require.Error(t, err)
	require.NotZero(t, report.Generation)
	require.Equal(t, int64(100), report.Offset)
	require.Equal(t, -1, report.Tag)
	require.Equal(t, StageHeaderIntro, report.Stage)
	require.Error(t, report.Err)
}

func TestGSBHeaderReaderRejectsDuplicateTags(t *testing.T) {
	header := gsbRawHeader(2, 8,
		append(gsbTagRecord(1000, RPM_INT32_TYPE, 0, 1),
			gsbTagRecord(1000, RPM_INT32_TYPE, 4, 1)...),
		[]byte{0, 0, 0, 1, 0, 0, 0, 2})
	_, err := readHeader(bytes.NewReader(header), "", 0, false, false)

	var duplicate DuplicateTagError
	require.ErrorAs(t, err, &duplicate)
	require.Equal(t, 1000, duplicate.Tag)
	var headerErr *HeaderError
	require.ErrorAs(t, err, &headerErr)
	require.Equal(t, StageHeaderEntry, headerErr.Stage)
	require.Equal(t, 1000, headerErr.Tag)
}

func TestGSBHeaderReaderRejectsUnknownDataType(t *testing.T) {
	header := gsbRawHeader(1, 4,
		gsbTagRecord(1000, 99, 0, 1),
		[]byte{0, 0, 0, 1})
	_, err := readHeader(bytes.NewReader(header), "", 0, false, false)

	var dataTypeErr DataTypeError
	require.ErrorAs(t, err, &dataTypeErr)
	require.Equal(t, 1000, dataTypeErr.Tag)
	require.Equal(t, 99, dataTypeErr.DataType)
}

func TestGSBMalformedHeaderBounds(t *testing.T) {
	cases := []struct {
		name    string
		entries uint32
		size    uint32
		table   []byte
		data    []byte
		stage   HeaderStage
	}{
		{
			name:    "huge entry count",
			entries: maxHeaderEntries + 1,
			stage:   StageHeaderIntro,
		},
		{
			name:    "huge data size",
			entries: 1,
			size:    maxHeaderSize + 1,
			stage:   StageHeaderIntro,
		},
		{
			name:    "negative offset",
			entries: 1,
			size:    4,
			table:   gsbTagRecord(1000, RPM_INT32_TYPE, -1, 1),
			data:    make([]byte, 4),
			stage:   StageHeaderEntry,
		},
		{
			name:    "count times type size overflows",
			entries: 1,
			size:    4,
			table:   gsbTagRecord(1000, RPM_INT32_TYPE, 0, math.MaxInt32),
			data:    make([]byte, 4),
			stage:   StageHeaderEntry,
		},
		{
			name:    "unterminated string",
			entries: 1,
			size:    4,
			table:   gsbTagRecord(1000, RPM_STRING_TYPE, 0, 1),
			data:    []byte("abcd"),
			stage:   StageHeaderString,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blob := gsbRawHeader(tc.entries, tc.size, tc.table, tc.data)
			_, err := readHeader(bytes.NewReader(blob), "", 0, false, false)
			require.Error(t, err)
			var headerErr *HeaderError
			require.ErrorAs(t, err, &headerErr)
			require.Equal(t, tc.stage, headerErr.Stage)
		})
	}
}
