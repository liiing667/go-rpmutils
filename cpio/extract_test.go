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
	"testing/iotest"

	"github.com/stretchr/testify/require"
)

func TestExtract(t *testing.T) {
	f, err := os.Open("../testdata/foo.cpio")
	require.NoError(t, err)
	defer f.Close()

	tmpdir := t.TempDir()
	hf := iotest.HalfReader(f)
	require.NoError(t, Extract(hf, tmpdir), "failed to extract cpio")

	// extract again and ensure it overwrites successfully
	_, err = f.Seek(0, io.SeekStart)
	require.NoError(t, err)
	require.NoError(t, Extract(hf, tmpdir), "failed to overwrite extracted cpio")
}

func TestExtractDotdot(t *testing.T) {
	f, err := os.Open("../testdata/dotdot.cpio")
	require.NoError(t, err)
	defer f.Close()

	tmpdir := t.TempDir()
	require.Error(t, Extract(f, tmpdir), "expected paths with ../ to be rejected")

	if _, err := os.Stat(filepath.Join(tmpdir, "aaaaaaaaa")); !os.IsNotExist(err) {
		t.Error("file with ../ must not be extracted into destdir")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(tmpdir), "aaaaaaaaa")); !os.IsNotExist(err) {
		t.Error("file with ../ must not be extracted outside destdir")
	}
}

// testEntry describes a single file in a generated cpio archive.
type testEntry struct {
	name  string
	mode  int
	data  []byte
	ino   int
	nlink int
}

// buildCpio generates an in-memory newc-format cpio archive from entries.
func buildCpio(t *testing.T, entries []testEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	nextIno := 1
	writeEntry := func(e testEntry) {
		if e.ino == 0 {
			e.ino = nextIno
		}
		nextIno = e.ino + 1
		if e.nlink == 0 {
			e.nlink = 1
		}
		namesize := len(e.name) + 1
		fmt.Fprintf(&buf, "070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
			e.ino, e.mode, 0, 0, e.nlink, 0, len(e.data), 0, 0, 0, 0, namesize, 0)
		buf.WriteString(e.name)
		buf.WriteByte(0)
		for pad := (newcHeaderLength + namesize) % 4; pad != 0 && pad < 4; pad++ {
			buf.WriteByte(0)
		}
		buf.Write(e.data)
		for pad := len(e.data) % 4; pad != 0 && pad < 4; pad++ {
			buf.WriteByte(0)
		}
	}
	for _, e := range entries {
		writeEntry(e)
	}
	writeEntry(testEntry{name: TRAILER, mode: 0, nlink: 1})
	return buf.Bytes()
}

func extractEntries(t *testing.T, dest string, entries []testEntry) error {
	t.Helper()
	return Extract(bytes.NewReader(buildCpio(t, entries)), dest)
}

func TestExtractRejectsAbsolutePath(t *testing.T) {
	tmpdir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "evil")
	entries := []testEntry{
		{name: "ok", mode: S_ISREG | 0644, data: []byte("ok")},
		{name: outside, mode: S_ISREG | 0644, data: []byte("evil")},
	}
	require.Error(t, extractEntries(t, tmpdir, entries))

	_, err := os.Stat(outside)
	require.True(t, os.IsNotExist(err), "absolute path entry must not be written")
	_, err = os.Stat(filepath.Join(tmpdir, "ok"))
	require.True(t, os.IsNotExist(err), "partial output must be cleaned up on failure")
}

func TestExtractRejectsDotdotEscape(t *testing.T) {
	parent := t.TempDir()
	tmpdir := filepath.Join(parent, "dest")
	entries := []testEntry{
		{name: "../evil", mode: S_ISREG | 0644, data: []byte("evil")},
	}
	require.Error(t, extractEntries(t, tmpdir, entries))

	_, err := os.Stat(filepath.Join(parent, "evil"))
	require.True(t, os.IsNotExist(err), "path escaping dest must not be written")
	_, err = os.Stat(tmpdir)
	require.True(t, os.IsNotExist(err), "dest created by the failed extraction must be cleaned up")
}

func TestExtractRejectsDeepDotdot(t *testing.T) {
	tmpdir := t.TempDir()
	entries := []testEntry{
		{name: "a/b/../../../../evil", mode: S_ISREG | 0644, data: []byte("evil")},
	}
	require.Error(t, extractEntries(t, tmpdir, entries))
}

func TestExtractRejectsAbsoluteSymlink(t *testing.T) {
	tmpdir := t.TempDir()
	entries := []testEntry{
		{name: "link", mode: S_ISLNK | 0777, data: []byte("/etc/passwd")},
	}
	require.Error(t, extractEntries(t, tmpdir, entries))

	_, err := os.Lstat(filepath.Join(tmpdir, "link"))
	require.True(t, os.IsNotExist(err), "symlink with absolute target must not be created")
}

func TestExtractRejectsEscapingSymlink(t *testing.T) {
	tmpdir := t.TempDir()
	entries := []testEntry{
		{name: "sub", mode: S_ISDIR | 0755},
		{name: "sub/link", mode: S_ISLNK | 0777, data: []byte("../../outside")},
	}
	require.Error(t, extractEntries(t, tmpdir, entries))

	_, err := os.Lstat(filepath.Join(tmpdir, "sub", "link"))
	require.True(t, os.IsNotExist(err), "symlink escaping dest must not be created")
	_, err = os.Stat(filepath.Join(tmpdir, "sub"))
	require.True(t, os.IsNotExist(err), "partial output must be cleaned up on failure")
}

func TestExtractAllowsValidSymlink(t *testing.T) {
	tmpdir := t.TempDir()
	entries := []testEntry{
		{name: "sub", mode: S_ISDIR | 0755},
		{name: "sub/target", mode: S_ISREG | 0644, data: []byte("data")},
		{name: "sub/link", mode: S_ISLNK | 0777, data: []byte("../sub/target")},
		{name: "abslink", mode: S_ISLNK | 0777, data: []byte("sub/target")},
	}
	require.NoError(t, extractEntries(t, tmpdir, entries))

	for _, link := range []string{filepath.Join("sub", "link"), "abslink"} {
		target, err := os.Readlink(filepath.Join(tmpdir, link))
		require.NoError(t, err)
		content, err := os.ReadFile(filepath.Join(tmpdir, link))
		require.NoError(t, err)
		require.Equal(t, "data", string(content), "symlink %q to %q should resolve inside dest", link, target)
	}
}

func TestExtractRejectsSymlinkedParentDir(t *testing.T) {
	tmpdir := t.TempDir()
	outside := t.TempDir()
	// A pre-existing symlink inside dest points outside of it.
	require.NoError(t, os.Symlink(outside, filepath.Join(tmpdir, "alias")))

	entries := []testEntry{
		{name: "alias/evil", mode: S_ISREG | 0644, data: []byte("evil")},
	}
	require.Error(t, extractEntries(t, tmpdir, entries))

	_, err := os.Stat(filepath.Join(outside, "evil"))
	require.True(t, os.IsNotExist(err), "must not write through a symlinked directory outside dest")
}

func TestExtractHardlinks(t *testing.T) {
	tmpdir := t.TempDir()
	entries := []testEntry{
		{name: "link1", mode: S_ISREG | 0644, ino: 42, nlink: 2},
		{name: "dir", mode: S_ISDIR | 0755},
		{name: "dir/link2", mode: S_ISREG | 0644, ino: 42, nlink: 2},
		{name: "content", mode: S_ISREG | 0644, ino: 42, nlink: 2, data: []byte("shared")},
	}
	require.NoError(t, extractEntries(t, tmpdir, entries))

	for _, name := range []string{"link1", filepath.Join("dir", "link2"), "content"} {
		content, err := os.ReadFile(filepath.Join(tmpdir, name))
		require.NoError(t, err)
		require.Equal(t, "shared", string(content))
	}
}

func TestExtractRejectsEscapingHardlink(t *testing.T) {
	parent := t.TempDir()
	tmpdir := filepath.Join(parent, "dest")
	entries := []testEntry{
		{name: "../evil", mode: S_ISREG | 0644, ino: 42, nlink: 2},
		{name: "content", mode: S_ISREG | 0644, ino: 42, nlink: 2, data: []byte("shared")},
	}
	require.Error(t, extractEntries(t, tmpdir, entries))

	_, err := os.Stat(filepath.Join(parent, "evil"))
	require.True(t, os.IsNotExist(err), "hardlink escaping dest must not be created")
}

func TestExtractPermissions(t *testing.T) {
	tmpdir := t.TempDir()
	entries := []testEntry{
		{name: "dir", mode: S_ISDIR | 0750},
		{name: "dir/file", mode: S_ISREG | 0640, data: []byte("data")},
		{name: "script", mode: S_ISREG | 0755, data: []byte("#!/bin/sh\n")},
	}
	require.NoError(t, extractEntries(t, tmpdir, entries))

	for name, want := range map[string]os.FileMode{
		"dir":      0750,
		"dir/file": 0640,
		"script":   0755,
	} {
		info, err := os.Stat(filepath.Join(tmpdir, name))
		require.NoError(t, err)
		require.Equal(t, want, info.Mode().Perm(), "wrong permissions for %s", name)
	}
}

func TestExtractCleanupOnFailure(t *testing.T) {
	parent := t.TempDir()
	tmpdir := filepath.Join(parent, "dest")
	entries := []testEntry{
		{name: "sub", mode: S_ISDIR | 0755},
		{name: "sub/ok", mode: S_ISREG | 0644, data: []byte("ok")},
		{name: "sub/link", mode: S_ISLNK | 0777, data: []byte("ok")},
		{name: "/etc/evil", mode: S_ISREG | 0644, data: []byte("evil")},
	}
	require.Error(t, extractEntries(t, tmpdir, entries))

	_, err := os.Lstat(tmpdir)
	require.True(t, os.IsNotExist(err), "failed extraction must remove all partial output")
}
