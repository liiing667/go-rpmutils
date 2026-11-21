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

package cpio

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// cpioFile describes one entry of a newc cpio archive built by buildCpio.
type cpioFile struct {
	name    string
	ino     int
	mode    int
	nlink   int
	content []byte
}

// buildCpio serializes the given entries as a newc-style cpio archive.
func buildCpio(t *testing.T, files []cpioFile) []byte {
	t.Helper()
	var out bytes.Buffer
	writeEntry := func(name string, ino, mode, nlink, size int) {
		hdr := fmt.Sprintf("070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
			ino, mode, 0, 0, nlink, 0, size, 0, 0, 0, 0, len(name)+1, 0)
		out.WriteString(hdr)
		out.WriteString(name)
		out.WriteByte(0)
		for out.Len()%4 != 0 {
			out.WriteByte(0)
		}
	}
	for _, f := range files {
		writeEntry(f.name, f.ino, f.mode, f.nlink, len(f.content))
		out.Write(f.content)
		for out.Len()%4 != 0 {
			out.WriteByte(0)
		}
	}
	writeEntry(TRAILER, 0, 0, 1, 0)
	return out.Bytes()
}

// hardlinkArchive returns an archive containing a regular file with two hard
// links. The zero-content link entry precedes the entry carrying the contents,
// as produced by rpm.
func hardlinkArchive(t *testing.T, content []byte) []byte {
	t.Helper()
	return buildCpio(t, []cpioFile{
		{name: "./dir", ino: 1, mode: S_ISDIR | 0755, nlink: 2},
		{name: "./dir/link", ino: 42, mode: S_ISREG | 0644, nlink: 2},
		{name: "./dir/original", ino: 42, mode: S_ISREG | 0644, nlink: 2, content: content},
	})
}

// failingReader returns an error after n bytes have been read.
type failingReader struct {
	r    io.Reader
	left int
	err  error
}

func (fr *failingReader) Read(p []byte) (int, error) {
	if fr.left <= 0 {
		return 0, fr.err
	}
	if len(p) > fr.left {
		p = p[:fr.left]
	}
	n, err := fr.r.Read(p)
	fr.left -= n
	return n, err
}

// TestExtractHardlinks verifies that hard links are created and share the
// same inode as the fully written backing file.
func TestExtractHardlinks(t *testing.T) {
	content := bytes.Repeat([]byte("hardlink-content\n"), 128)
	archive := hardlinkArchive(t, content)

	tmpdir := t.TempDir()
	dest := filepath.Join(tmpdir, "root")
	require.NoError(t, Extract(bytes.NewReader(archive), dest))

	orig, err := os.ReadFile(filepath.Join(dest, "dir", "original"))
	require.NoError(t, err)
	require.Equal(t, content, orig)

	link, err := os.ReadFile(filepath.Join(dest, "dir", "link"))
	require.NoError(t, err)
	require.Equal(t, content, link)

	origInfo, err := os.Stat(filepath.Join(dest, "dir", "original"))
	require.NoError(t, err)
	linkInfo, err := os.Stat(filepath.Join(dest, "dir", "link"))
	require.NoError(t, err)
	require.Equal(t, os.SameFile(origInfo, linkInfo), true,
		"hard link should share an inode with its backing file")
}

// TestExtractSymlink verifies symbolic links are recreated in the staging
// tree and published atomically along with the rest of the entries.
func TestExtractSymlink(t *testing.T) {
	archive := buildCpio(t, []cpioFile{
		{name: "./target", ino: 1, mode: S_ISREG | 0644, nlink: 1, content: []byte("pointed-at")},
		{name: "./link", ino: 2, mode: S_ISLNK | 0777, nlink: 1, content: []byte("target")},
	}
	tmpdir := t.TempDir()
	dest := filepath.Join(tmpdir, "root")

	require.NoError(t, Extract(bytes.NewReader(archive), dest))

	linkTarget, err := os.Readlink(filepath.Join(dest, "link"))
	require.NoError(t, err)
	require.Equal(t, "target", linkTarget)
	got, err := os.ReadFile(filepath.Join(dest, "link"))
	require.NoError(t, err)
	require.Equal(t, []byte("pointed-at"), got)
}

// TestExtractFailureLeavesNoPartialTree is the regression test for a failed
// extraction leaving half-written files (and hard links pointing at them) in
// the destination directory.
func TestExtractFailureLeavesNoPartialTree(t *testing.T) {
	content := bytes.Repeat([]byte("payload\n"), 4096)
	archive := hardlinkArchive(t, content)

	t.Run("fresh destination", func(t *testing.T) {
		tmpdir := t.TempDir()
		dest := filepath.Join(tmpdir, "root")

		// Fail partway through the archive, well after the hard link entry but
		// before the trailer has been consumed.
		failAt := len(archive) / 2
		err := Extract(&failingReader{
			r:    bytes.NewReader(archive),
			left: failAt,
			err:  io.ErrClosedPipe,
		}, dest)
		require.Error(t, err)

		// Nothing must be published: the destination itself must not exist and
		// no staging directories may be left behind.
		_, err = os.Lstat(dest)
		require.True(t, os.IsNotExist(err), "failed extraction must not create the destination")
		entries, err := os.ReadDir(tmpdir)
		require.NoError(t, err)
		require.Empty(t, entries, "staging directory must be cleaned up after failure")
	})

	t.Run("existing destination preserved", func(t *testing.T) {
		tmpdir := t.TempDir()
		dest := filepath.Join(tmpdir, "root")
		require.NoError(t, os.MkdirAll(filepath.Join(dest, "keep"), 0755))
		sentinel := filepath.Join(dest, "keep", "sentinel")
		require.NoError(t, os.WriteFile(sentinel, []byte("previous good tree"), 0644))

		err := Extract(&failingReader{
			r:    bytes.NewReader(archive),
			left: len(archive) / 2,
			err:  io.ErrClosedPipe,
		}, dest)
		require.Error(t, err)

		// The previously published tree must be untouched.
		got, err := os.ReadFile(sentinel)
		require.NoError(t, err)
		require.Equal(t, []byte("previous good tree"), got)

		entries, err := os.ReadDir(tmpdir)
		require.NoError(t, err)
		require.Len(t, entries, 1, "only the preserved destination should remain")
	})
}

// TestExtractRetryAfterFailure verifies that a retry after a failed attempt
// publishes a complete tree and never accumulates stale staging directories.
func TestExtractRetryAfterFailure(t *testing.T) {
	content := bytes.Repeat([]byte("payload\n"), 4096)
	archive := hardlinkArchive(t, content)
	tmpdir := t.TempDir()
	dest := filepath.Join(tmpdir, "root")

	// First attempt fails.
	require.Error(t, Extract(&failingReader{
		r:    bytes.NewReader(archive),
		left: len(archive) / 2,
		err:  io.ErrClosedPipe,
	}, dest))

	// Retry with an intact stream succeeds and publishes the full tree.
	require.NoError(t, Extract(bytes.NewReader(archive), dest))

	link, err := os.ReadFile(filepath.Join(dest, "dir", "link"))
	require.NoError(t, err)
	require.Equal(t, content, link)

	entries, err := os.ReadDir(tmpdir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "no staging or backup directories should remain")
	require.Equal(t, "root", entries[0].Name())
}

// TestExtractOverwrite verifies that successfully re-extracting over an
// existing destination replaces the whole tree.
func TestExtractOverwrite(t *testing.T) {
	tmpdir := t.TempDir()
	dest := filepath.Join(tmpdir, "root")

	first := buildCpio(t, []cpioFile{
		{name: "./old", ino: 1, mode: S_ISREG | 0644, nlink: 1, content: []byte("old contents")},
	})
	require.NoError(t, Extract(bytes.NewReader(first), dest))

	second := buildCpio(t, []cpioFile{
		{name: "./new", ino: 2, mode: S_ISREG | 0644, nlink: 1, content: []byte("new contents")},
	})
	require.NoError(t, Extract(bytes.NewReader(second), dest))

	_, err := os.Lstat(filepath.Join(dest, "old"))
	require.True(t, os.IsNotExist(err), "files from the previous tree must be removed")
	got, err := os.ReadFile(filepath.Join(dest, "new"))
	require.NoError(t, err)
	require.Equal(t, []byte("new contents"), got)

	entries, err := os.ReadDir(tmpdir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
}

// TestExtractToCustomStaging verifies an explicitly supplied staging directory
// is used and cleaned up.
func TestExtractToCustomStaging(t *testing.T) {
	archive := buildCpio(t, []cpioFile{
		{name: "./file", ino: 1, mode: S_ISREG | 0644, nlink: 1, content: []byte("hello")},
	})
	tmpdir := t.TempDir()
	target := filepath.Join(tmpdir, "out", "tree")
	staging := filepath.Join(tmpdir, "staging")

	require.NoError(t, ExtractTo(bytes.NewReader(archive), target, staging))

	_, err := os.Lstat(staging)
	require.True(t, os.IsNotExist(err), "staging directory must be consumed on success")
	got, err := os.ReadFile(filepath.Join(target, "file"))
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), got)

	// A failed attempt with a custom staging directory also cleans up.
	require.Error(t, ExtractTo(&failingReader{
		r:    bytes.NewReader(archive),
		left: 5,
		err:  io.ErrClosedPipe,
	}, target, staging))
	_, err = os.Lstat(staging)
	require.True(t, os.IsNotExist(err))
}

// TestExtractRecoversStaleDirs verifies that a restart recovers from staging
// and backup directories left behind by a process that was killed before it
// could finish or clean up.
func TestExtractRecoversStaleDirs(t *testing.T) {
	archive := buildCpio(t, []cpioFile{
		{name: "./file", ino: 1, mode: S_ISREG | 0644, nlink: 1, content: []byte("complete")},
	})
	tmpdir := t.TempDir()
	dest := filepath.Join(tmpdir, "root")

	// Simulate a previous attempt that died mid-publish leaving both a staging
	// directory and a backup directory behind.
	staging := filepath.Join(tmpdir, stagingName)
	backup := filepath.Join(tmpdir, backupName)
	require.NoError(t, os.MkdirAll(filepath.Join(staging, "partial"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(staging, "partial", "half"),
		[]byte("incomplete"), 0644))
	require.NoError(t, os.MkdirAll(filepath.Join(backup, "old"), 0755))

	require.NoError(t, Extract(bytes.NewReader(archive), dest))

	got, err := os.ReadFile(filepath.Join(dest, "file"))
	require.NoError(t, err)
	require.Equal(t, []byte("complete"), got)

	entries, err := os.ReadDir(tmpdir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "stale staging and backup directories must be reclaimed")
	require.Equal(t, "root", entries[0].Name())
}

// TestExtractRestartAfterKilledPublish simulates the specific hard-link
// regression: a previous run died after publishing a tree whose backing file
// was truncated. A restart must replace it with the complete tree.
func TestExtractRestartAfterKilledPublish(t *testing.T) {
	content := bytes.Repeat([]byte("payload\n"), 4096)
	archive := hardlinkArchive(t, content)
	tmpdir := t.TempDir()
	dest := filepath.Join(tmpdir, "root")

	// Plant a half-written tree similar to what the old, non-atomic extractor
	// could leave behind.
	require.NoError(t, os.MkdirAll(filepath.Join(dest, "dir"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dest, "dir", "original"),
		content[:len(content)/2], 0644))
	require.NoError(t, os.Link(filepath.Join(dest, "dir", "original"),
		filepath.Join(dest, "dir", "link")))

	require.NoError(t, Extract(bytes.NewReader(archive), dest))

	got, err := os.ReadFile(filepath.Join(dest, "dir", "link"))
	require.NoError(t, err)
	require.Equal(t, content, got, "restart must replace the half-written backing file")

	origInfo, err := os.Stat(filepath.Join(dest, "dir", "original"))
	require.NoError(t, err)
	linkInfo, err := os.Stat(filepath.Join(dest, "dir", "link"))
	require.NoError(t, err)
	require.True(t, os.SameFile(origInfo, linkInfo))
}
