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
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/sassoftware/go-rpmutils/fileutil"
)

// Standard set of permission bit masks.
const (
	S_ISUID  = 04000   // Set uid
	S_ISGID  = 02000   // Set gid
	S_ISVTX  = 01000   // Save text (sticky bit)
	S_ISDIR  = 040000  // Directory
	S_ISFIFO = 010000  // FIFO
	S_ISREG  = 0100000 // Regular file
	S_ISLNK  = 0120000 // Symbolic link
	S_ISBLK  = 060000  // Block special file
	S_ISCHR  = 020000  // Character special file
	S_ISSOCK = 0140000 // Socket
)

// stagingPrefix is the prefix used for the temporary staging directories that
// hold an in-progress extraction before it is published atomically.
const (
	stagingPrefix = ".cpio-extract-"
	stagingName   = stagingPrefix + "staging"
	backupName    = stagingPrefix + "backup"
)

// Extract the contents of a cpio stream from r to the destination directory
// dest. The archive is unpacked into a hidden staging directory next to dest
// and moved into place only after the entire archive has been read and
// validated, so a failed, cancelled or interrupted extraction can never leave
// dest containing a partial directory tree. A failed attempt can safely be
// retried: any staging directory left behind is replaced.
func Extract(rs io.Reader, dest string) error {
	dest = filepath.Clean(filepath.FromSlash(dest))
	return ExtractTo(rs, dest, filepath.Join(filepath.Dir(dest), stagingName))
}

// ExtractTo extracts the contents of a cpio stream from rs into the directory
// target, using stagingDir as a temporary working area. The contents of target
// are only replaced once the whole archive has been unpacked successfully, so
// failures, cancellation and restarts can never publish a partial directory
// tree (for example hard links whose backing file was only half written).
//
// stagingDir should reside on the same filesystem as target so that the final
// publish is an atomic rename. Any staging directory left behind by a previous
// attempt is removed before extraction starts. Concurrent extractions into the
// same target are not supported.
func ExtractTo(rs io.Reader, target, stagingDir string) error {
	target = filepath.Clean(filepath.FromSlash(target))
	stagingDir = filepath.Clean(filepath.FromSlash(stagingDir))

	// Reuse the staging area left behind by a failed or interrupted attempt
	// so that retries do not accumulate stale directories.
	if err := os.RemoveAll(stagingDir); err != nil {
		return err
	}
	if err := os.MkdirAll(stagingDir, 0755); err != nil {
		return err
	}

	// Remove the staging area on any failure. A successful extraction moves it
	// into place instead.
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(stagingDir)
		}
	}()

	if err := extractStream(rs, stagingDir, target); err != nil {
		return err
	}

	if err := publish(stagingDir, target); err != nil {
		return err
	}
	committed = true
	return nil
}

// publish atomically replaces target with the fully extracted stagingDir.
func publish(stagingDir, target string) error {
	parent := filepath.Dir(target)
	if err := os.MkdirAll(parent, 0755); err != nil {
		return err
	}

	// Use a fixed backup path in the same directory to move any existing
	// target out of the way. Both renames are atomic, so observers either see
	// the old tree or the complete new tree, never a partially extracted one.
	backup := filepath.Join(parent, backupName)
	haveOld := false
	if _, err := os.Lstat(target); err == nil {
		haveOld = true
		// A backup left behind by an interrupted publish is stale: the target
		// that still exists is the live tree and must be preserved.
		if err := os.RemoveAll(backup); err != nil {
			return err
		}
		if err := os.Rename(target, backup); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	} else if _, err := os.Lstat(backup); err == nil {
		// No live target but a stale backup from a killed process: drop it so
		// the rename below has a free slot.
		if err := os.RemoveAll(backup); err != nil {
			return err
		}
	}
	if err := os.Rename(stagingDir, target); err != nil {
		// Best-effort rollback so the original destination is preserved when
		// publishing fails.
		if haveOld {
			_ = os.Rename(backup, target)
		}
		return err
	}
	if haveOld {
		return os.RemoveAll(backup)
	}
	return nil
}

// extractStream unpacks a single cpio stream into stagingDir. relBase is the
// final destination path used when validating sanitized archive paths.
func extractStream(rs io.Reader, stagingDir, relBase string) error {
	linkMap := make(map[int][]string)

	stream := NewCpioStream(rs)

	for {
		entry, err := stream.ReadNextEntry()
		if err != nil {
			return err
		}

		if entry.Header.filename == TRAILER {
			break
		}

		// sanitize path
		name := path.Clean(entry.Header.filename)
		for strings.HasPrefix(name, "../") {
			name = name[3:]
		}
		finalPath := filepath.Join(relBase, filepath.FromSlash(name))
		if !strings.HasPrefix(finalPath, relBase+string(filepath.Separator)) && relBase != finalPath {
			// this shouldn't happen due to the sanitization above but always check
			return fmt.Errorf("invalid cpio path %q", entry.Header.filename)
		}
		target := filepath.Join(stagingDir, filepath.FromSlash(name))
		// Create the parent directory if it doesn't exist.
		parent := filepath.Dir(target)
		if err := os.MkdirAll(parent, 0755); err != nil {
			return err
		}
		// FIXME: Need a makedev implementation in go.

		switch entry.Header.Mode() &^ 07777 {
		case S_ISCHR:
			// FIXME: skipping due to lack of makedev.
			continue
		case S_ISBLK:
			// FIXME: skipping due to lack of makedev.
			continue
		case S_ISDIR:
			m := os.FileMode(entry.Header.Mode()).Perm()
			if err := os.Mkdir(target, m); err != nil && !os.IsExist(err) {
				return err
			}
		case S_ISFIFO:
			if err := fileutil.Mkfifo(target, uint32(entry.Header.Mode())); err != nil {
				return err
			}
		case S_ISLNK:
			buf := make([]byte, entry.Header.filesize)
			if _, err := io.ReadFull(entry.payload, buf); err != nil {
				return err
			}
			if err := os.Symlink(string(buf), target); err != nil {
				return err
			}
		case S_ISREG:
			// save hardlinks until after the target is written
			if entry.Header.nlink > 1 && entry.Header.filesize == 0 {
				linkMap[entry.Header.ino] = append(linkMap[entry.Header.ino], target)
				continue
			}

			// FIXME: Set permissions on files when creating.
			f, err := os.Create(target)
			if err != nil {
				return err
			}
			written, copyErr := io.Copy(f, entry.payload)
			closeErr := f.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
			if written != int64(entry.Header.filesize) {
				return errors.New("short write")
			}

			// Create hardlinks only after the file content has been written in
			// full, so no link can ever point at a half-written file.
			if entry.Header.nlink > 1 && entry.Header.filesize > 0 {
				l, ok := linkMap[entry.Header.ino]
				if !ok {
					return fmt.Errorf("hardlinks missing")
				}

				for _, t := range l {
					if err := os.Link(target, t); err != nil {
						return err
					}
				}
			}
		default:
			return fmt.Errorf("unknown file mode 0%o for %s",
				entry.Header.mode, entry.Header.filename)
		}
	}

	return nil
}
