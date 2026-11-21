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
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
	"path"
	"strconv"
	"strings"
)

const introMagic = 0x8eade801

const (
	headerIntroSize = 16
	headerTagSize   = 16

	// Hard upper bounds on a single header section. They are large enough for
	// any well-formed RPM while preventing a malformed header from triggering
	// huge allocations or out-of-memory failures.
	maxHeaderEntries = 1 << 20 // at most 1M index entries (~16MiB index)
	maxHeaderSize    = 1 << 28 // at most 256MiB of entry data
)

// stringTypes are null-terminated string data types. A single string entry is
// always followed by a trailing NUL byte, while string arrays hold one NUL
// terminated string per element.
var stringTypes = map[int32]bool{
	RPM_STRING_TYPE:       true,
	RPM_STRING_ARRAY_TYPE: true,
	RPM_I18NSTRING_TYPE:   true,
}

// regionTags delimit RPM header regions. They must hold a 16-byte BIN value
// containing the region trailer.
var regionTags = map[int32]bool{
	RPMTAG_HEADERSIGNATURES: true,
	RPMTAG_HEADERIMMUTABLE:  true,
	RPMTAG_HEADERREGIONS:    true,
}

type entry struct {
	dataType, count int32
	contents        []byte
	// offset is the absolute stream offset of contents, retained for
	// diagnostics. It is not used by the existing accessor APIs.
	offset int64
}

type rpmHeader struct {
	entries    map[int]entry
	isSource   bool
	orig       []byte
	generation uint64
	report     HeaderReport
}

type headerIntro struct {
	Magic, Reserved, Entries, Size uint32
}

type headerTag struct {
	Tag, DataType, Offset, Count int32
}

var typeAlign = map[int32]int{
	RPM_INT16_TYPE: 2,
	RPM_INT32_TYPE: 4,
	RPM_INT64_TYPE: 8,
}

var typeSizes = map[int32]int{
	RPM_NULL_TYPE:  0,
	RPM_CHAR_TYPE:  1,
	RPM_INT8_TYPE:  1,
	RPM_INT16_TYPE: 2,
	RPM_INT32_TYPE: 4,
	RPM_INT64_TYPE: 8,
	RPM_BIN_TYPE:   1,
}

func readExact(f io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(f, buf)
	return buf, err
}

// readHeader is kept as a compatibility wrapper for internal callers and
// tests. New code should share a headerContext across all sections of one
// attempt so the header, payload, and error report share a generation and
// absolute offset.
func readHeader(f io.Reader, hash string, hashType crypto.Hash, isSource bool, sigBlock bool) (*rpmHeader, error) {
	ctx := newHeaderContext(f)
	var checks []digestCheck
	if hash != "" {
		if hashType == 0 || !hashType.Available() {
			return nil, ctx.fail(StageHeaderDigest, 0, -1, fmt.Errorf("digest %q uses unavailable hash %s", hash, hashType))
		}
		checks = append(checks, digestCheck{
			Tag:      headerDigestTag(hashType),
			Hash:     hashType,
			Expected: hash,
		})
	}
	return readHeaderWithContext(ctx, isSource, sigBlock, checks)
}

func headerDigestTag(hashType crypto.Hash) int {
	switch hashType {
	case crypto.SHA256:
		return SIG_SHA256
	case crypto.SHA1:
		return SIG_SHA1
	default:
		return -1
	}
}

// readHeaderWithContext reads one header section using the supplied context.
// The context owns the stream position and generation, so a signature header,
// general header, and payload digest in the same attempt are reported with the
// same generation and absolute offsets.
func readHeaderWithContext(ctx *headerContext, isSource bool, sigBlock bool, checks []digestCheck) (*rpmHeader, error) {
	headerStart := ctx.offset()

	introBuf, err := ctx.readExact(headerIntroSize, StageHeaderIntro, -1)
	if err != nil {
		return nil, err
	}
	intro := headerIntro{
		Magic:    binary.BigEndian.Uint32(introBuf[0:4]),
		Reserved: binary.BigEndian.Uint32(introBuf[4:8]),
		Entries:  binary.BigEndian.Uint32(introBuf[8:12]),
		Size:     binary.BigEndian.Uint32(introBuf[12:16]),
	}
	if intro.Magic != introMagic {
		return nil, ctx.fail(StageHeaderIntro, headerStart, -1, fmt.Errorf("bad magic for header"))
	}
	if intro.Entries == 0 {
		return nil, ctx.fail(StageHeaderIntro, headerStart, -1, fmt.Errorf("RPM header has no entries"))
	}
	if intro.Entries > maxHeaderEntries {
		return nil, ctx.fail(StageHeaderIntro, headerStart, -1,
			fmt.Errorf("RPM header entry count %d exceeds maximum of %d", intro.Entries, maxHeaderEntries))
	}
	if intro.Size > maxHeaderSize {
		return nil, ctx.fail(StageHeaderIntro, headerStart, -1,
			fmt.Errorf("RPM header data size %d exceeds maximum of %d", intro.Size, maxHeaderSize))
	}
	// Entries*16 cannot overflow on 32-bit platforms thanks to the bound
	// above, but guard anyway so a future limit change cannot reintroduce the
	// issue.
	hi, tableLen := bits.Mul64(uint64(intro.Entries), uint64(headerTagSize))
	if hi != 0 || tableLen > math.MaxInt {
		return nil, ctx.fail(StageHeaderIntro, headerStart, -1,
			fmt.Errorf("RPM header table size overflows for %d entries", intro.Entries))
	}

	// Save the exact header bytes. This is both the digest input and the
	// canonical representation returned by the existing header APIs.
	var origBuf bytes.Buffer
	origBuf.Write(introBuf)

	tableStart := ctx.offset()
	entryTable, err := ctx.readExact(int(tableLen), StageHeaderIndex, -1)
	if err != nil {
		return nil, err
	}
	origBuf.Write(entryTable)

	declaredSize := uint64(intro.Size)
	dataSize := declaredSize
	if sigBlock {
		// signature block is padded to 8 byte alignment
		dataSize = (declaredSize + 7) / 8 * 8
		if dataSize > maxHeaderSize+7 {
			return nil, ctx.fail(StageHeaderIntro, headerStart, -1,
				fmt.Errorf("RPM header padded data size %d exceeds maximum", dataSize))
		}
	}
	if dataSize > math.MaxInt {
		return nil, ctx.fail(StageHeaderIntro, headerStart, -1,
			fmt.Errorf("RPM header data size %d overflows int", dataSize))
	}
	dataStart := ctx.offset()
	data, err := ctx.readExact(int(dataSize), StageHeaderData, -1)
	if err != nil {
		return nil, err
	}
	origBuf.Write(data)

	// Verify every digest that is present. Verifying only the preferred tag
	// would allow a malformed header to carry contradictory digest tags and
	// let different readers disagree about the package identity.
	orig := origBuf.Bytes()
	for _, check := range checks {
		offset := check.Offset
		if offset <= 0 {
			offset = headerStart
		}
		if check.Hash == 0 || !check.Hash.Available() {
			return nil, ctx.fail(StageHeaderDigest, offset, check.Tag,
				fmt.Errorf("unknown header digest %s", check.Hash))
		}
		hasher := check.Hash.New()
		hasher.Write(orig)
		calculated := hex.EncodeToString(hasher.Sum(nil))
		if !strings.EqualFold(calculated, check.Expected) {
			return nil, ctx.fail(StageHeaderDigest, offset, check.Tag, &DigestMismatchError{
				Scope:    "header",
				Hash:     check.Hash,
				Expected: check.Expected,
				Actual:   calculated,
			})
		}
	}

	// Parse and validate the tag index. The data slice used for entries is
	// limited to the declared (unpadded) size; signature block padding is not
	// part of any entry.
	dataDeclared := data[:int(declaredSize)]
	ents := make(map[int]entry, int(intro.Entries))
	for i := 0; i < int(intro.Entries); i++ {
		entryStart := tableStart + int64(i*headerTagSize)
		record := entryTable[i*headerTagSize : (i+1)*headerTagSize]
		tag := headerTag{
			Tag:      int32(binary.BigEndian.Uint32(record[0:4])),
			DataType: int32(binary.BigEndian.Uint32(record[4:8])),
			Offset:   int32(binary.BigEndian.Uint32(record[8:12])),
			Count:    int32(binary.BigEndian.Uint32(record[12:16])),
		}
		if tag.Offset < 0 {
			return nil, ctx.fail(StageHeaderEntry, dataStart, int(tag.Tag),
				fmt.Errorf("tag %d has negative offset %d", tag.Tag, tag.Offset))
		}
		if tag.Count < 0 {
			return nil, ctx.fail(StageHeaderEntry, dataStart, int(tag.Tag),
				fmt.Errorf("tag %d has negative count %d", tag.Tag, tag.Count))
		}
		if uint32(tag.Offset) > intro.Size {
			return nil, ctx.fail(StageHeaderEntry, dataStart+int64(tag.Offset), int(tag.Tag),
				fmt.Errorf("tag %d offset %d is outside of header data", tag.Tag, tag.Offset))
		}
		if regionTags[tag.Tag] && (tag.DataType != RPM_BIN_TYPE || tag.Count != 16) {
			return nil, ctx.fail(StageHeaderEntry, dataStart+int64(tag.Offset), int(tag.Tag),
				fmt.Errorf("region tag %d must be a 16-byte BIN entry", tag.Tag))
		}

		var end uint64
		typeSize, fixedType := typeSizes[tag.DataType]
		switch {
		case fixedType:
			hi, dataLen := bits.Mul64(uint64(tag.Count), uint64(typeSize))
			if hi != 0 {
				return nil, ctx.fail(StageHeaderEntry, dataStart+int64(tag.Offset), int(tag.Tag),
					fmt.Errorf("tag %d data length overflows", tag.Tag))
			}
			end64, carry := bits.Add64(uint64(tag.Offset), dataLen, 0)
			if carry != 0 || end64 > declaredSize {
				return nil, ctx.fail(StageHeaderEntry, dataStart+int64(tag.Offset), int(tag.Tag),
					fmt.Errorf("tag %d data extends beyond header data", tag.Tag))
			}
			end = end64
		case stringTypes[tag.DataType]:
			if tag.Count == 0 {
				return nil, ctx.fail(StageHeaderString, dataStart+int64(tag.Offset), int(tag.Tag),
					fmt.Errorf("string tag %d has no elements", tag.Tag))
			}
			// Every string element needs at least one byte (its NUL), so a
			// count larger than the declared data area is necessarily
			// malformed. This also bounds the scanning loop on 32-bit
			// platforms.
			if uint64(tag.Count) > declaredSize {
				return nil, ctx.fail(StageHeaderString, dataStart+int64(tag.Offset), int(tag.Tag),
					fmt.Errorf("string tag %d has %d elements but only %d bytes of data", tag.Tag, tag.Count, declaredSize))
			}
			end = uint64(tag.Offset)
			for element := 0; element < int(tag.Count); element++ {
				if end >= declaredSize {
					return nil, ctx.fail(StageHeaderString, dataStart+int64(end), int(tag.Tag),
						fmt.Errorf("tag %d is truncated", tag.Tag))
				}
				next := bytes.IndexByte(dataDeclared[int(end):], 0)
				if next < 0 {
					return nil, ctx.fail(StageHeaderString, dataStart+int64(end), int(tag.Tag),
						fmt.Errorf("tag %d is truncated", tag.Tag))
				}
				end += uint64(next) + 1
				if end > declaredSize {
					return nil, ctx.fail(StageHeaderString, dataStart+int64(end), int(tag.Tag),
						fmt.Errorf("tag %d string data extends beyond header data", tag.Tag))
				}
			}
		default:
			return nil, ctx.fail(StageHeaderEntry, dataStart+int64(tag.Offset), int(tag.Tag),
				DataTypeError{Tag: int(tag.Tag), DataType: int(tag.DataType)})
		}

		if _, exists := ents[int(tag.Tag)]; exists {
			return nil, ctx.fail(StageHeaderEntry, entryStart, int(tag.Tag),
				DuplicateTagError{Tag: int(tag.Tag)})
		}
		ents[int(tag.Tag)] = entry{
			dataType: tag.DataType,
			count:    tag.Count,
			contents: dataDeclared[int(tag.Offset):int(end)],
			offset:   dataStart + int64(tag.Offset),
		}
	}

	report := ctx.complete()
	return &rpmHeader{
		entries:    ents,
		isSource:   isSource,
		orig:       append([]byte(nil), orig...),
		generation: ctx.generation,
		report:     report,
	}, nil
}

// HasTag returns true if the given tag exists in the header
func (hdr *rpmHeader) HasTag(tag int) bool {
	_, ok := hdr.entries[tag]
	return ok
}

// Get the value of a tag. Returns whichever type most closely represents how
// the tag was stored, or NoSuchTagError if the tag was not found. If tag is
// OLDFILENAMES, special handling is provided to splice together DIRNAMES and
// BASENAMES if it is not present.
func (hdr *rpmHeader) Get(tag int) (interface{}, error) {
	ent, ok := hdr.entries[tag]
	if !ok && tag == OLDFILENAMES {
		return hdr.GetStrings(tag)
	}
	if !ok {
		return nil, NewNoSuchTagError(tag)
	}
	switch ent.dataType {
	case RPM_STRING_TYPE, RPM_STRING_ARRAY_TYPE, RPM_I18NSTRING_TYPE:
		return hdr.GetStrings(tag)
	case RPM_INT8_TYPE, RPM_INT16_TYPE, RPM_INT32_TYPE, RPM_INT64_TYPE, RPM_CHAR_TYPE:
		out, _, err := hdr.getInts(tag)
		return out, err
	case RPM_BIN_TYPE:
		return hdr.GetBytes(tag)
	default:
		return nil, DataTypeError{Tag: tag, DataType: int(ent.dataType)}
	}
}

// GetStrings fetches the given tag holding a string or array of strings. If tag
// is OLDFILENAMES, special handling is provided to splice together DIRNAMES and
// BASENAMES if it is not present.
func (hdr *rpmHeader) GetStrings(tag int) ([]string, error) {
	ent, ok := hdr.entries[tag]
	if tag == OLDFILENAMES && !ok {
		dirs, err := hdr.GetStrings(DIRNAMES)
		if err != nil {
			return nil, err
		}
		dirIdxs, err := hdr.GetUint32s(DIRINDEXES)
		if err != nil {
			return nil, err
		}
		baseNames, err := hdr.GetStrings(BASENAMES)
		if err != nil {
			return nil, err
		}
		if len(dirIdxs) < len(baseNames) {
			return nil, fmt.Errorf("DIRINDEXES has %d entries but BASENAMES has %d", len(dirIdxs), len(baseNames))
		}
		paths := make([]string, 0, len(baseNames))
		for i, base := range baseNames {
			if uint64(dirIdxs[i]) >= uint64(len(dirs)) {
				return nil, fmt.Errorf("DIRINDEXES entry %d refers to missing directory %d", i, dirIdxs[i])
			}
			paths = append(paths, path.Join(dirs[dirIdxs[i]], base))
		}
		return paths, nil
	}

	if !ok {
		return nil, NewNoSuchTagError(tag)
	}
	if ent.dataType != RPM_STRING_TYPE && ent.dataType != RPM_STRING_ARRAY_TYPE && ent.dataType != RPM_I18NSTRING_TYPE {
		return nil, fmt.Errorf("unsupported datatype for string: %d, tag: %d", ent.dataType, tag)
	}
	strs := strings.Split(string(ent.contents), "\x00")
	if len(strs) < int(ent.count) {
		return nil, fmt.Errorf("string tag %d is truncated", tag)
	}
	return strs[:ent.count], nil
}

// get an int array using whatever the appropriate sized type is
func (hdr *rpmHeader) getInts(tag int) (buf interface{}, n int, err error) {
	ent, ok := hdr.entries[tag]
	if !ok {
		return nil, 0, NewNoSuchTagError(tag)
	}
	n = len(ent.contents)
	switch ent.dataType {
	case RPM_INT8_TYPE, RPM_CHAR_TYPE:
		buf = make([]uint8, n)
	case RPM_INT16_TYPE:
		n >>= 1
		buf = make([]uint16, n)
	case RPM_INT32_TYPE:
		n >>= 2
		buf = make([]uint32, n)
	case RPM_INT64_TYPE:
		n >>= 3
		buf = make([]uint64, n)
	default:
		return nil, 0, fmt.Errorf("tag %d isn't an int type", tag)
	}
	if err := binary.Read(bytes.NewReader(ent.contents), binary.BigEndian, buf); err != nil {
		return nil, 0, err
	}
	return
}

// GetInts gets an integer array using the default 'int' type.
//
// DEPRECATED: large int32s and int64s can overflow. Use GetUint32s or GetUint64s instead.
func (hdr *rpmHeader) GetInts(tag int) ([]int, error) {
	buf, n, err := hdr.getInts(tag)
	if err != nil {
		return nil, err
	}
	out := make([]int, n)
	switch bvals := buf.(type) {
	case []uint8:
		for i, v := range bvals {
			out[i] = int(v)
		}
	case []uint16:
		for i, v := range bvals {
			out[i] = int(v)
		}
	case []uint32:
		for i, v := range bvals {
			if v > (1<<31)-1 {
				return nil, fmt.Errorf("value %d out of range for int32 array in tag %d", i, tag)
			}
			out[i] = int(v)
		}
	default:
		return nil, fmt.Errorf("tag %d is too big for int type", tag)
	}
	return out, nil
}

// GetUint32s gets an int array as a uint32 slice. This can accomodate any int
// type other than INT64. Returns an error in case of overflow.
func (hdr *rpmHeader) GetUint32s(tag int) ([]uint32, error) {
	buf, n, err := hdr.getInts(tag)
	if err != nil {
		return nil, err
	}
	if out, ok := buf.([]uint32); ok {
		return out, nil
	}
	out := make([]uint32, n)
	switch bvals := buf.(type) {
	case []uint8:
		for i, v := range bvals {
			out[i] = uint32(v)
		}
	case []uint16:
		for i, v := range bvals {
			out[i] = uint32(v)
		}
	default:
		return nil, fmt.Errorf("tag %d is too big for int type", tag)
	}
	return out, nil
}

// GetUint64s gets an int array as a uint64 slice. This can accomodate all int
// types.
func (hdr *rpmHeader) GetUint64s(tag int) ([]uint64, error) {
	buf, n, err := hdr.getInts(tag)
	if err != nil {
		return nil, err
	}
	if out, ok := buf.([]uint64); ok {
		return out, nil
	}
	out := make([]uint64, n)
	switch bvals := buf.(type) {
	case []uint8:
		for i, v := range bvals {
			out[i] = uint64(v)
		}
	case []uint16:
		for i, v := range bvals {
			out[i] = uint64(v)
		}
	case []uint32:
		for i, v := range bvals {
			out[i] = uint64(v)
		}
	}
	return out, nil
}

// GetUint64Fallback gets longTag if it exists, otherwise intTag, and returns
// the value as an array of uint64s. This can accomodate all int types and is
// normally used when a int32 tag was later replaced with a int64 tag.
func (hdr *rpmHeader) GetUint64Fallback(intTag, longTag int) ([]uint64, error) {
	if _, ok := hdr.entries[longTag]; ok {
		return hdr.GetUint64s(longTag)
	}
	return hdr.GetUint64s(intTag)
}

// GetBytes gets a tag as a byte array.
func (hdr *rpmHeader) GetBytes(tag int) ([]byte, error) {
	ent, ok := hdr.entries[tag]
	if !ok {
		return nil, NewNoSuchTagError(tag)
	}
	if ent.dataType != RPM_BIN_TYPE {
		return nil, fmt.Errorf("unsupported datatype for bytes: %d, tag: %d", ent.dataType, tag)
	}
	return ent.contents, nil
}

// GetNEVRA gets the name, epoch, version, release and arch of the RPM.
func (hdr *rpmHeader) GetNEVRA() (*NEVRA, error) {
	name, err := hdr.GetStrings(NAME)
	if err != nil {
		return nil, err
	}
	if len(name) == 0 {
		return nil, fmt.Errorf("tag %d is empty", NAME)
	}
	epoch, err := hdr.GetUint64s(EPOCH)
	if _, absent := err.(NoSuchTagError); !absent && err != nil {
		return nil, err
	} else if len(epoch) == 0 {
		// no epoch is treated as 0
		epoch = []uint64{0}
	}
	version, err := hdr.GetStrings(VERSION)
	if err != nil {
		return nil, err
	}
	if len(version) == 0 {
		return nil, fmt.Errorf("tag %d is empty", VERSION)
	}
	release, err := hdr.GetStrings(RELEASE)
	if err != nil {
		return nil, err
	}
	if len(release) == 0 {
		return nil, fmt.Errorf("tag %d is empty", RELEASE)
	}
	arch, err := hdr.GetStrings(ARCH)
	if err != nil {
		return nil, err
	}
	if len(arch) == 0 {
		return nil, fmt.Errorf("tag %d is empty", ARCH)
	}
	return &NEVRA{
		Name:    name[0],
		Epoch:   strconv.FormatUint(epoch[0], 10),
		Version: version[0],
		Release: release[0],
		Arch:    arch[0],
	}, nil
}

// GetFiles returns an array of FileInfo objects holding file-related attributes
// held in parallel arrays of tags
//
// If the RPM has no files, GetFiles returns an empty list.
func (hdr *rpmHeader) GetFiles() ([]FileInfo, error) {
	paths, err := hdr.GetStrings(OLDFILENAMES)
	if err != nil {
		if !errors.As(err, &NoSuchTagError{}) {
			return nil, err
		}
		// RPM has no files
		return nil, nil
	}
	fileSizes, err := hdr.GetUint64Fallback(FILESIZES, LONGFILESIZES)
	if err != nil {
		return nil, err
	}
	fileUserName, err := hdr.GetStrings(FILEUSERNAME)
	if err != nil {
		return nil, err
	}
	fileGroupName, err := hdr.GetStrings(FILEGROUPNAME)
	if err != nil {
		return nil, err
	}
	fileFlags, err := hdr.GetUint32s(FILEFLAGS)
	if err != nil {
		return nil, err
	}
	fileMtimes, err := hdr.GetUint32s(FILEMTIMES)
	if err != nil {
		return nil, err
	}
	fileDigests, err := hdr.GetStrings(FILEDIGESTS)
	if err != nil {
		return nil, err
	}
	fileModes, err := hdr.GetUint32s(FILEMODES)
	if err != nil {
		return nil, err
	}
	linkTos, err := hdr.GetStrings(FILELINKTOS)
	if err != nil {
		return nil, err
	}
	devices, err := hdr.GetUint32s(FILEDEVICES)
	if err != nil {
		devices = make([]uint32, len(paths))
	}
	inodes, err := hdr.GetUint32s(FILEINODES)
	if err != nil {
		inodes = make([]uint32, len(paths))
	}
	for _, array := range []struct {
		tag  int
		size int
	}{
		{FILESIZES, len(fileSizes)},
		{FILEUSERNAME, len(fileUserName)},
		{FILEGROUPNAME, len(fileGroupName)},
		{FILEFLAGS, len(fileFlags)},
		{FILEMTIMES, len(fileMtimes)},
		{FILEDIGESTS, len(fileDigests)},
		{FILEMODES, len(fileModes)},
		{FILELINKTOS, len(linkTos)},
		{FILEDEVICES, len(devices)},
		{FILEINODES, len(inodes)},
	} {
		if array.size < len(paths) {
			return nil, fmt.Errorf("tag %d has %d entries but OLDFILENAMES has %d", array.tag, array.size, len(paths))
		}
	}

	files := make([]FileInfo, len(paths))
	for i := 0; i < len(paths); i++ {
		files[i] = &fileInfo{
			name:      paths[i],
			size:      fileSizes[i],
			userName:  fileUserName[i],
			groupName: fileGroupName[i],
			flags:     fileFlags[i],
			mtime:     fileMtimes[i],
			digest:    fileDigests[i],
			mode:      fileModes[i],
			linkName:  linkTos[i],
			device:    devices[i],
			inode:     inodes[i],
		}
	}

	return files, nil
}
