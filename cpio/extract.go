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

// Extract the contents of a cpio stream from r to the destination directory dest
func Extract(rs io.Reader, dest string) error {
	dest = filepath.Clean(filepath.FromSlash(dest))
	e := &extractor{
		dest:    dest,
		linkMap: make(map[int][]string),
	}
	if err := e.run(rs); err != nil {
		e.cleanup()
		return err
	}
	return nil
}

// extractor tracks the state of a single extraction so that partially
// written output can be removed if the extraction fails.
type extractor struct {
	dest     string
	realDest string
	created  []string
	linkMap  map[int][]string
}

func (e *extractor) run(rs io.Reader) error {
	// Record whether the destination already exists so that cleanup can
	// remove it if it was created here.
	if _, err := os.Stat(e.dest); os.IsNotExist(err) {
		if err := os.MkdirAll(e.dest, 0755); err != nil {
			return err
		}
		e.created = append(e.created, e.dest)
	} else if err != nil {
		return err
	}
	realDest, err := filepath.EvalSymlinks(e.dest)
	if err != nil {
		return fmt.Errorf("unable to resolve destination %q: %w", e.dest, err)
	}
	e.realDest = realDest

	stream := NewCpioStream(rs)

	for {
		entry, err := stream.ReadNextEntry()
		if err != nil {
			return err
		}

		if entry.Header.filename == TRAILER {
			break
		}

		// Reject absolute paths and relative paths that escape dest.
		target, err := e.resolvePath(entry.Header.filename)
		if err != nil {
			return err
		}
		// Create the parent directory if it doesn't exist.
		if err := e.makeParent(target); err != nil {
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
			m := fileMode(entry.Header.Mode())
			err := os.Mkdir(target, m.Perm())
			if err == nil {
				e.created = append(e.created, target)
			} else if !os.IsExist(err) {
				return err
			}
			// Apply the declared permissions even if the directory
			// already exists (e.g. created as a parent above).
			if err := os.Chmod(target, m); err != nil {
				return err
			}
		case S_ISFIFO:
			removeIfExists(target)
			if err := fileutil.Mkfifo(target, uint32(entry.Header.Mode())); err != nil {
				return err
			}
			e.created = append(e.created, target)
		case S_ISLNK:
			buf := make([]byte, entry.Header.filesize)
			if _, err := entry.payload.Read(buf); err != nil {
				return err
			}
			linkname := string(buf)
			if err := e.checkSymlinkTarget(target, linkname); err != nil {
				return err
			}
			removeIfExists(target)
			if err := os.Symlink(linkname, target); err != nil {
				return err
			}
			e.created = append(e.created, target)
		case S_ISREG:
			// save hardlinks until after the taget is written
			if entry.Header.nlink > 1 && entry.Header.filesize == 0 {
				l, ok := e.linkMap[entry.Header.ino]
				if !ok {
					l = make([]string, 0)
				}
				l = append(l, target)
				e.linkMap[entry.Header.ino] = l
				continue
			}

			m := fileMode(entry.Header.Mode())
			f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, m.Perm())
			if err != nil {
				return err
			}
			e.created = append(e.created, target)
			written, err := io.Copy(f, entry.payload)
			if err != nil {
				f.Close()
				return err
			}
			if written != int64(entry.Header.filesize) {
				f.Close()
				return fmt.Errorf("short write")
			}
			// Apply the declared permissions exactly, including any
			// setuid/setgid/sticky bits, since the create mode is
			// subject to the process umask.
			if err := f.Chmod(m); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}

			// Create hardlinks after the file content is written.
			if entry.Header.nlink > 1 && entry.Header.filesize > 0 {
				l, ok := e.linkMap[entry.Header.ino]
				if !ok {
					return fmt.Errorf("hardlinks missing")
				}

				for _, t := range l {
					removeIfExists(t)
					if err := os.Link(target, t); err != nil {
						return err
					}
					e.created = append(e.created, t)
				}
			}
		default:
			return fmt.Errorf("unknown file mode 0%o for %s",
				entry.Header.mode, entry.Header.filename)
		}
	}

	return nil
}

// resolvePath validates an entry name and returns its target path within the
// destination directory. Absolute paths and relative paths that would escape
// the destination are rejected.
func (e *extractor) resolvePath(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("invalid cpio path: empty filename")
	}
	if path.IsAbs(name) || filepath.IsAbs(name) {
		return "", fmt.Errorf("invalid cpio path %q: absolute paths are not allowed", name)
	}
	clean := filepath.Clean(filepath.FromSlash(name))
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid cpio path %q: path escapes the destination directory", name)
	}
	return filepath.Join(e.dest, clean), nil
}

// makeParent creates the parent directory of target, tracking newly created
// directories for cleanup, and verifies that the resolved parent directory
// is inside the destination. The check defends against symbolic links,
// whether pre-existing or created by earlier archive entries, that point
// outside of the destination.
func (e *extractor) makeParent(target string) error {
	parent := filepath.Dir(target)

	// Determine which directories need to be created, from the top down.
	var missing []string
	for dir := parent; ; dir = filepath.Dir(dir) {
		if _, err := os.Lstat(dir); err == nil {
			break
		} else if !os.IsNotExist(err) {
			return err
		}
		missing = append(missing, dir)
		if filepath.Dir(dir) == dir {
			break
		}
	}
	if len(missing) > 0 {
		if err := os.MkdirAll(parent, 0755); err != nil {
			return err
		}
		for i := len(missing) - 1; i >= 0; i-- {
			e.created = append(e.created, missing[i])
		}
	}

	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return fmt.Errorf("unable to resolve directory for %q: %w", target, err)
	}
	if resolved != e.realDest && !strings.HasPrefix(resolved, e.realDest+string(filepath.Separator)) {
		return fmt.Errorf("invalid cpio path %q: directory escapes the destination directory", target)
	}
	return nil
}

// checkSymlinkTarget verifies that a symbolic link created at linkPath with
// the given target cannot point outside of the destination directory.
func (e *extractor) checkSymlinkTarget(linkPath, linkname string) error {
	if linkname == "" {
		return fmt.Errorf("invalid symlink %q: empty target", linkPath)
	}
	if path.IsAbs(linkname) || filepath.IsAbs(linkname) {
		return fmt.Errorf("invalid symlink %q: target %q is an absolute path", linkPath, linkname)
	}
	resolved := filepath.Clean(filepath.Join(filepath.Dir(linkPath), filepath.FromSlash(linkname)))
	if resolved != e.dest && !strings.HasPrefix(resolved, e.dest+string(filepath.Separator)) {
		return fmt.Errorf("invalid symlink %q: target %q escapes the destination directory", linkPath, linkname)
	}
	return nil
}

// cleanup removes any files, links, and directories created during a failed
// extraction, in reverse order of creation.
func (e *extractor) cleanup() {
	// Make created directories writable again so their contents can be
	// removed even if a restrictive mode was applied.
	for _, p := range e.created {
		if info, err := os.Lstat(p); err == nil && info.IsDir() {
			os.Chmod(p, 0755)
		}
	}
	for i := len(e.created) - 1; i >= 0; i-- {
		os.Remove(e.created[i])
	}
}

// removeIfExists removes an existing file, symlink, or fifo at path so that
// it can be replaced. Directories and missing entries are left alone.
func removeIfExists(path string) {
	if info, err := os.Lstat(path); err == nil && !info.IsDir() {
		os.Remove(path)
	}
}

// fileMode converts the permission bits of a cpio mode field into an
// os.FileMode, preserving setuid, setgid, and sticky bits.
func fileMode(mode int) os.FileMode {
	m := os.FileMode(mode & 0777)
	if mode&S_ISUID != 0 {
		m |= os.ModeSetuid
	}
	if mode&S_ISGID != 0 {
		m |= os.ModeSetgid
	}
	if mode&S_ISVTX != 0 {
		m |= os.ModeSticky
	}
	return m
}
