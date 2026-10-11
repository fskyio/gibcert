// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 FSKY <development@fsky.io>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package deploy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

type stagedFile struct {
	kind, dst    string
	data         []byte
	defaultMode  fs.FileMode
	temp, backup string
	// backupFile keeps an owner-only copy of a replaced regular file open
	// until rollback gives it the original attributes through the descriptor.
	backupFile             *os.File
	restoreMode            fs.FileMode
	restoreUID, restoreGID int
	// link records that a symbolic link was replaced, and linkTarget its
	// target; rollback recreates the link instead of restoring a backup.
	link       bool
	linkTarget string
	installed  bool
	keepBackup bool
}

type stagedDeploy struct {
	files  [6]stagedFile
	result Result
	// refuseSymlinks makes a symbolic link at a destination an error rather
	// than something to replace. Receivers set it so that a destination
	// planted by another user is never followed.
	refuseSymlinks bool
	// dryRun reads the destinations and probes permissions without creating
	// directories or writing material.
	dryRun bool
}

func (s *stagedDeploy) prepare(req Request, out io.Writer) error {
	uid, gid, err := deployOwnership(req.Owner, req.Group)
	if err != nil {
		return err
	}
	s.result.Target = req.Target
	for i, k := range fileKinds {
		f := req.file(k.name)
		s.files[i] = stagedFile{kind: k.name, dst: f.Path, data: f.Data, defaultMode: k.defaultMode}
	}
	for i := range s.files {
		file := &s.files[i]
		if file.dst == "" || len(file.data) == 0 {
			continue
		}
		changed, err := file.prepare(req.Mode, uid, gid, s.refuseSymlinks, s.dryRun, out)
		if err != nil {
			return fmt.Errorf("%s: %w", file.kind, err)
		}
		if changed {
			s.result.Changed = append(s.result.Changed, file.kind)
		}
	}
	return nil
}

func (f *stagedFile) prepare(explicitMode *fs.FileMode, uid, gid int, refuseSymlinks, dryRun bool, out io.Writer) (bool, error) {
	dir := filepath.Dir(f.dst)
	if dryRun {
		var err error
		if dir, err = existingDir(dir); err != nil {
			return false, err
		}
	} else if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, err
	}
	existing, previous, err := readDestination(f.dst, refuseSymlinks)
	if err != nil {
		return false, err
	}
	var link os.FileInfo
	if existing != nil && existing.Mode()&fs.ModeSymlink != 0 {
		// A link is never read through and nothing is inherited from it:
		// it is replaced by a regular file and kept only for rollback.
		link, existing = existing, nil
	}
	oldUID, oldGID := -1, -1
	if existing != nil {
		oldUID, oldGID = fileOwnership(existing)
	}
	// Only root can give a new key to another user, so with an explicit mode
	// an unprivileged process has nothing at stake in the existing owner.
	inherit, untrusted := existing, false
	if existing != nil && privateKind(f.kind) &&
		(explicitMode == nil || (os.Geteuid() == 0 && (uid == -1 || gid == -1))) {
		trusted, err := InheritTrusted(f.dst, existing)
		if err != nil {
			return false, err
		}
		if !trusted {
			inherit, untrusted = nil, true
		}
	}
	mode, err := desiredMode(f.defaultMode, inherit, explicitMode)
	if err != nil {
		return false, err
	}
	if inherit != nil {
		if uid == -1 {
			uid = oldUID
		}
		if gid == -1 {
			gid = oldGID
		}
	}
	changed := existing == nil || !bytes.Equal(previous, f.data)
	attrsChanged := existing != nil && (ModeDiffers(existing.Mode().Perm(), mode) ||
		(uid != -1 && uid != oldUID) || (gid != -1 && gid != oldGID))
	if !changed && !attrsChanged {
		return false, nil
	}
	switch {
	case link != nil:
		fmt.Fprintf(out, "warning: %s: replacing symbolic link with a regular file\n", f.dst)
	case untrusted:
		fmt.Fprintf(out, "warning: %s: not inheriting owner, group, or mode from the existing private key, which another user could have placed there (directory writable by group or other, or file owned by uid %d); set deploy owner, group, and mode explicitly\n", f.dst, oldUID)
	case inherit != nil && explicitMode == nil && privateKind(f.kind) && ModeDiffers(inherit.Mode().Perm(), mode):
		fmt.Fprintf(out, "warning: %s: narrowing private-key mode %#o to %#o (set deploy.mode to choose it explicitly)\n", f.dst, inherit.Mode().Perm(), mode)
	}
	if existing == nil && explicitMode == nil {
		fmt.Fprintf(out, "warning: %s: creating with default mode %#o (set deploy.mode to silence)\n", f.dst, mode)
	}
	if dryRun {
		return changed, probeStage(dir, mode, uid, gid)
	}
	f.temp, err = stageFile(dir, ".gibcert-new-*", f.data, mode, uid, gid)
	if err != nil {
		return false, err
	}
	switch {
	case link != nil:
		f.linkTarget, err = os.Readlink(f.dst)
		f.link = err == nil
	case existing != nil:
		f.restoreMode = existing.Mode().Perm()
		if privateKind(f.kind) {
			// Restored keys obey the private-key policy too.
			f.restoreMode &^= 0o117
		}
		f.restoreUID, f.restoreGID = oldUID, oldGID
		f.backupFile, err = createBackup(dir, previous)
		if err == nil {
			f.backup = f.backupFile.Name()
		}
	}
	if err != nil {
		return false, fmt.Errorf("backup: %w", err)
	}
	return changed, nil
}

// existingDir returns dir or, when it does not exist yet, its nearest
// existing ancestor, which must be a directory.
func existingDir(dir string) (string, error) {
	for {
		info, err := os.Stat(dir)
		if err == nil {
			if !info.IsDir() {
				return "", fmt.Errorf("%s is not a directory", dir)
			}
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if !errors.Is(err, os.ErrNotExist) || parent == dir {
			return "", err
		}
		dir = parent
	}
}

// readDestination returns what is at dst without following a symbolic link
// there: nothing, the link's own info, or a regular file's info and content
// read through one descriptor. With refuseSymlinks a link is an error; any
// other file type always is.
func readDestination(dst string, refuseSymlinks bool) (os.FileInfo, []byte, error) {
	info, err := os.Lstat(dst)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		if refuseSymlinks {
			return nil, nil, fmt.Errorf("destination %s is a symbolic link", dst)
		}
		return info, nil, nil
	}
	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("destination %s is not a regular file", dst)
	}
	file, err := openDestination(dst)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	if info, err = file.Stat(); err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("destination %s is not a regular file", dst)
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, nil, err
	}
	return info, data, nil
}

func stageFile(dir, pattern string, data []byte, mode fs.FileMode, uid, gid int) (string, error) {
	file, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", err
	}
	name := file.Name()
	_, err = file.Write(data)
	if err == nil {
		err = setAttrs(file, mode, uid, gid)
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		_ = os.Remove(name)
		return "", err
	}
	return name, nil
}

// probeStage checks that a file with the given attributes can be created in
// dir, without writing any material.
func probeStage(dir string, mode fs.FileMode, uid, gid int) error {
	name, err := stageFile(dir, ".gibcert-probe-*", nil, mode, uid, gid)
	if err != nil {
		return err
	}
	return os.Remove(name)
}

// setAttrs gives file the wanted owner, group, and mode. Components the file
// already has are skipped: an unprivileged user may not chown at all, yet
// already owns the file and may sit in a setgid directory that gave it the
// wanted group.
func setAttrs(file *os.File, mode fs.FileMode, uid, gid int) error {
	if uid != -1 || gid != -1 {
		curUID, curGID := -1, -1
		if info, err := file.Stat(); err == nil {
			curUID, curGID = fileOwnership(info)
		}
		if uid == curUID {
			uid = -1
		}
		if gid == curGID {
			gid = -1
		}
		if uid != -1 || gid != -1 {
			if err := file.Chown(uid, gid); err != nil {
				if os.Geteuid() != 0 {
					return fmt.Errorf("chown requires privileges (running as non-root): %w", err)
				}
				return err
			}
		}
	}
	return file.Chmod(mode)
}

// createBackup copies the content of a file about to be replaced into a new
// owner-only file in dir. The original attributes are applied only when
// rollback restores it.
func createBackup(dir string, data []byte) (*os.File, error) {
	file, err := os.CreateTemp(dir, ".gibcert-backup-*")
	if err != nil {
		return nil, err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return nil, err
	}
	return file, nil
}

// restoreLink puts back a replaced symbolic link: a new link to target is
// created under a temporary name in dir and renamed over dst.
func restoreLink(dir, dst, target string) error {
	// The temporary file only reserves a unique name. Should another user
	// take the name meanwhile, Symlink fails rather than follow anything.
	file, err := os.CreateTemp(dir, ".gibcert-link-*")
	if err != nil {
		return err
	}
	name := file.Name()
	if err := errors.Join(file.Close(), os.Remove(name)); err != nil {
		return err
	}
	if err := os.Symlink(target, name); err != nil {
		return err
	}
	if err := os.Rename(name, dst); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}

func deployOwnership(owner, group string) (int, int, error) {
	uid, gid := -1, -1
	if owner != "" {
		u, err := user.Lookup(owner)
		if err != nil {
			return -1, -1, fmt.Errorf("owner %q: %w", owner, err)
		}
		uid, err = strconv.Atoi(u.Uid)
		if err != nil {
			return -1, -1, fmt.Errorf("owner %q uid %q: %w", owner, u.Uid, err)
		}
	}
	if group != "" {
		g, err := user.LookupGroup(group)
		if err != nil {
			return -1, -1, fmt.Errorf("group %q: %w", group, err)
		}
		gid, err = strconv.Atoi(g.Gid)
		if err != nil {
			return -1, -1, fmt.Errorf("group %q gid %q: %w", group, g.Gid, err)
		}
	}
	return uid, gid, nil
}

func (s *stagedDeploy) install() error {
	for i := range s.files {
		file := &s.files[i]
		if file.temp == "" {
			continue
		}
		if err := os.Rename(file.temp, file.dst); err != nil {
			return fmt.Errorf("install %s: %w", file.kind, err)
		}
		file.temp = ""
		file.installed = true
	}
	return nil
}

func (s *stagedDeploy) rollback() error {
	var errs []error
	for i := len(s.files) - 1; i >= 0; i-- {
		file := &s.files[i]
		if !file.installed {
			continue
		}
		var err error
		switch {
		case file.link:
			err = restoreLink(filepath.Dir(file.dst), file.dst, file.linkTarget)
			if err != nil {
				err = fmt.Errorf("%w; it was a symbolic link to %q", err, file.linkTarget)
			}
		case file.backup == "":
			err = os.Remove(file.dst)
			if errors.Is(err, os.ErrNotExist) {
				err = nil
			}
		default:
			err = file.restoreBackup()
			if err == nil {
				file.backup = ""
			} else {
				file.keepBackup = true
				err = fmt.Errorf("%w; previous material retained at %s", err, file.backup)
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("rollback %s: %w", file.dst, err))
		}
	}
	return errors.Join(errs...)
}

// restoreBackup gives a regular-file backup the attributes of the file it
// copied, then renames it back to the destination.
func (f *stagedFile) restoreBackup() error {
	if f.backupFile != nil {
		err := setAttrs(f.backupFile, f.restoreMode, f.restoreUID, f.restoreGID)
		err = errors.Join(err, f.backupFile.Close())
		f.backupFile = nil
		if err != nil {
			return err
		}
	}
	return os.Rename(f.backup, f.dst)
}

func (s *stagedDeploy) cleanup() {
	for i := range s.files {
		file := &s.files[i]
		if file.temp != "" {
			_ = os.Remove(file.temp)
		}
		if file.backupFile != nil {
			_ = file.backupFile.Close()
			file.backupFile = nil
		}
		if file.backup != "" && !file.keepBackup {
			_ = os.Remove(file.backup)
		}
	}
}
