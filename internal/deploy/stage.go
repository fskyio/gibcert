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
	installed    bool
	keepBackup   bool
}

type stagedDeploy struct {
	files  [6]stagedFile
	result Result
	// refuseSymlinks makes a symbolic link at a destination an error rather
	// than something to replace. Receivers set it so that a destination
	// planted by another user is never followed.
	refuseSymlinks bool
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
		changed, err := file.prepare(req.Mode, uid, gid, s.refuseSymlinks, out)
		if err != nil {
			return fmt.Errorf("%s: %w", file.kind, err)
		}
		if changed {
			s.result.Changed = append(s.result.Changed, file.kind)
		}
	}
	return nil
}

func (f *stagedFile) prepare(explicitMode *fs.FileMode, uid, gid int, refuseSymlinks bool, out io.Writer) (bool, error) {
	if err := os.MkdirAll(filepath.Dir(f.dst), 0o755); err != nil {
		return false, err
	}
	existing, err := statDestination(f.dst, refuseSymlinks)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	var previous []byte
	oldUID, oldGID := -1, -1
	if existing != nil {
		if !existing.Mode().IsRegular() {
			return false, fmt.Errorf("destination %s is not a regular file", f.dst)
		}
		previous, err = os.ReadFile(f.dst)
		if err != nil {
			return false, err
		}
		oldUID, oldGID = fileOwnership(existing)
	}
	mode, err := desiredMode(f.defaultMode, existing, explicitMode)
	if err != nil {
		return false, err
	}
	if uid == -1 {
		uid = oldUID
	}
	if gid == -1 {
		gid = oldGID
	}
	changed := existing == nil || !bytes.Equal(previous, f.data)
	attrsChanged := existing != nil && (existing.Mode().Perm() != mode ||
		(uid != -1 && uid != oldUID) || (gid != -1 && gid != oldGID))
	if !changed && !attrsChanged {
		return false, nil
	}
	if existing == nil && explicitMode == nil {
		fmt.Fprintf(out, "warning: %s: creating with default mode %#o (set deploy.mode to silence)\n", f.dst, mode)
	}
	f.temp, err = stageFile(f.dst, ".gibcert-new-*", f.data, mode, uid, gid)
	if err != nil {
		return false, err
	}
	if existing != nil {
		restoreMode := existing.Mode().Perm()
		if f.defaultMode == 0o600 {
			// Backups and restored keys must obey the private-key policy too.
			restoreMode &= 0o600 | (mode & 0o060)
		}
		f.backup, err = stageFile(f.dst, ".gibcert-backup-*", previous, restoreMode, oldUID, oldGID)
		if err != nil {
			return false, fmt.Errorf("backup: %w", err)
		}
	}
	return changed, nil
}

func stageFile(dst, pattern string, data []byte, mode fs.FileMode, uid, gid int) (string, error) {
	file, err := os.CreateTemp(filepath.Dir(dst), pattern)
	if err != nil {
		return "", err
	}
	name := file.Name()
	_, err = file.Write(data)
	if err == nil && (uid != -1 || gid != -1) {
		// Skip components the file already has: an unprivileged user may not
		// chown at all, yet already owns the file and may sit in a setgid
		// directory that gave it the wanted group.
		curUID, curGID := -1, -1
		if info, serr := file.Stat(); serr == nil {
			curUID, curGID = fileOwnership(info)
		}
		if uid == curUID {
			uid = -1
		}
		if gid == curGID {
			gid = -1
		}
		if uid != -1 || gid != -1 {
			err = file.Chown(uid, gid)
			if err != nil && os.Geteuid() != 0 {
				err = fmt.Errorf("chown requires privileges (running as non-root): %w", err)
			}
		}
	}
	if err == nil {
		err = file.Chmod(mode)
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		_ = os.Remove(name)
		return "", err
	}
	return name, nil
}

// statDestination stats dst. With refuseSymlinks a symbolic link is an error
// instead of being followed.
func statDestination(dst string, refuseSymlinks bool) (os.FileInfo, error) {
	if !refuseSymlinks {
		return os.Stat(dst)
	}
	info, err := os.Lstat(dst)
	if err == nil && info.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("destination %s is a symbolic link", dst)
	}
	return info, err
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
		if file.backup == "" {
			err = os.Remove(file.dst)
			if errors.Is(err, os.ErrNotExist) {
				err = nil
			}
		} else {
			err = os.Rename(file.backup, file.dst)
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

func (s *stagedDeploy) cleanup() {
	for i := range s.files {
		file := &s.files[i]
		if file.temp != "" {
			_ = os.Remove(file.temp)
		}
		if file.backup != "" && !file.keepBackup {
			_ = os.Remove(file.backup)
		}
	}
}
