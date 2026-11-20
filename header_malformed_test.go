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
	"encoding/binary"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// malformedHeader builds a byte stream holding a single RPM header section
// with the given intro fields and raw index/data payloads.
func malformedHeader(t *testing.T, entries, size uint32, table, data []byte) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.BigEndian, &headerIntro{
		Magic:   introMagic,
		Entries: entries,
		Size:    size,
	}))
	buf.Write(table)
	buf.Write(data)
	return &buf
}

func tagRecord(tag, dataType, offset, count int32) []byte {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, &headerTag{
		Tag:      tag,
		DataType: dataType,
		Offset:   offset,
		Count:    count,
	}); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// TestReadHeaderMalformed verifies that malformed headers are rejected with an
// error instead of panicking or attempting unbounded allocations.
func TestReadHeaderMalformed(t *testing.T) {
	validData := make([]byte, 32)
	validTable := tagRecord(1000, RPM_INT32_TYPE, 0, 1)

	tests := []struct {
		name    string
		entries uint32
		size    uint32
		table   []byte
		data    []byte
	}{
		{
			name:    "no entries",
			entries: 0,
			size:    0,
		},
		{
			name:    "entries over limit",
			entries: maxHeaderEntries + 1,
			size:    0,
		},
		{
			name:    "size over limit",
			entries: 1,
			size:    maxHeaderSize + 1,
			table:   validTable,
			data:    validData,
		},
		{
			// Entries*16 overflows a 32-bit allocation size.
			name:    "entries table overflows",
			entries: math.MaxUint32/16 + 1,
			size:    0,
		},
		{
			// count*typeSize overflows uint32.
			name:    "count times type size overflows",
			entries: 1,
			size:    32,
			table:   tagRecord(1000, RPM_INT32_TYPE, 0, math.MaxInt32),
			data:    validData,
		},
		{
			// offset + count*typeSize extends past the declared data size.
			name:    "data extends beyond header",
			entries: 1,
			size:    4,
			table:   tagRecord(1000, RPM_INT32_TYPE, 4, 1),
			data:    make([]byte, 4),
		},
		{
			name:    "negative offset",
			entries: 1,
			size:    32,
			table:   tagRecord(1000, RPM_INT32_TYPE, -1, 1),
			data:    validData,
		},
		{
			name:    "negative count",
			entries: 1,
			size:    32,
			table:   tagRecord(1000, RPM_INT32_TYPE, 0, -1),
			data:    validData,
		},
		{
			name:    "unknown data type",
			entries: 1,
			size:    32,
			table:   tagRecord(1000, 99, 0, 1),
			data:    validData,
		},
		{
			// region tags must be 16-byte BIN entries.
			name:    "bad region tag type",
			entries: 1,
			size:    32,
			table:   tagRecord(RPMTAG_HEADERIMMUTABLE, RPM_INT32_TYPE, 0, 1),
			data:    validData,
		},
		{
			name:    "region tag wrong count",
			entries: 1,
			size:    32,
			table:   tagRecord(RPMTAG_HEADERIMMUTABLE, RPM_BIN_TYPE, 0, 8),
			data:    validData,
		},
		{
			// string tag without any NUL terminator.
			name:    "string tag truncated",
			entries: 1,
			size:    4,
			table:   tagRecord(1000, RPM_STRING_TYPE, 0, 1),
			data:    []byte("abcd"),
		},
		{
			// string array claiming more elements than there are NUL bytes.
			name:    "string array count mismatch",
			entries: 1,
			size:    4,
			table:   tagRecord(1000, RPM_STRING_ARRAY_TYPE, 0, 3),
			data:    []byte("ab\x00\x00"),
		},
		{
			// string tag claiming zero elements.
			name:    "string tag zero count",
			entries: 1,
			size:    4,
			table:   tagRecord(1000, RPM_STRING_TYPE, 0, 0),
			data:    validData,
		},
		{
			// string data runs past the declared header size.
			name:    "string extends beyond header",
			entries: 1,
			size:    2,
			table:   tagRecord(1000, RPM_STRING_TYPE, 0, 1),
			data:    []byte("ab\x00"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stream := malformedHeader(t, tt.entries, tt.size, tt.table, tt.data)
			hdr, err := readHeader(stream, "", 0, false, false)
			require.Error(t, err, "malformed header must be rejected")
			assert.Nil(t, hdr)
			t.Logf("rejected with: %s", err)
		})
	}
}

// TestReadHeaderUnknownDataTypeTyped checks that an unknown data type produces
// the typed DataTypeError.
func TestReadHeaderUnknownDataTypeTyped(t *testing.T) {
	stream := malformedHeader(t, 1, 32,
		tagRecord(1000, 99, 0, 1), make([]byte, 32))
	_, err := readHeader(stream, "", 0, false, false)
	var dtypeErr DataTypeError
	require.ErrorAs(t, err, &dtypeErr)
	assert.Equal(t, 1000, dtypeErr.Tag)
	assert.Equal(t, 99, dtypeErr.DataType)
}

// TestReadHeaderTruncatedStream verifies that a stream ending before the
// declared table or data produces an error rather than a panic.
func TestReadHeaderTruncatedStream(t *testing.T) {
	// Declare a table and data section but supply neither.
	stream := malformedHeader(t, 2, 16, nil, nil)
	hdr, err := readHeader(stream, "", 0, false, false)
	require.Error(t, err)
	assert.Nil(t, hdr)
}

// TestReadHeaderStringCountBounded verifies that GetStrings cannot index past
// the validated contents when a malformed array reaches parsing via a crafted
// but in-bounds entry.
func TestReadHeaderStringCountBounded(t *testing.T) {
	// One NUL-terminated string but a count of two: parsing must reject it
	// before GetStrings can slice beyond the contents.
	stream := malformedHeader(t, 1, 4,
		tagRecord(1000, RPM_STRING_ARRAY_TYPE, 0, 2),
		[]byte("ab\x00cd"))
	_, err := readHeader(stream, "", 0, false, false)
	require.Error(t, err)
}
