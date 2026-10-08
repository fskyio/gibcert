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

	"gitfield.org/fsky/gibcert/internal/config"
	"gitfield.org/fsky/gibcert/internal/storage"
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
	files   [6]stagedFile
	result  Result
	records []storage.CertDeployMeta
}

func (s *stagedDeploy) prepare(d *config.Deploy, srcCert, srcChain, srcFullchain, srcKey []byte, out io.Writer) error {
	derCert, derKey, err := derVariants(d, srcCert, srcKey)
	if err != nil {
		return err
	}
	uid, gid, err := deployOwnership(d)
	if err != nil {
		return err
	}
	s.result.Target = d.Name
	s.files = [6]stagedFile{
		{kind: "cert", dst: d.Cert, data: srcCert, defaultMode: 0o644},
		{kind: "chain", dst: d.Chain, data: srcChain, defaultMode: 0o644},
		{kind: "fullchain", dst: d.Fullchain, data: srcFullchain, defaultMode: 0o644},
		{kind: "key", dst: d.Key, data: srcKey, defaultMode: 0o600},
		{kind: "cert-der", dst: d.CertDER, data: derCert, defaultMode: 0o644},
		{kind: "key-der", dst: d.KeyDER, data: derKey, defaultMode: 0o600},
	}
	s.records = make([]storage.CertDeployMeta, 0, len(s.files))
	now := timeNow()
	for i := range s.files {
		file := &s.files[i]
		if file.dst == "" || len(file.data) == 0 {
			continue
		}
		changed, err := file.prepare(d, uid, gid, out)
		if err != nil {
			return fmt.Errorf("%s: %w", file.kind, err)
		}
		if changed {
			s.result.Changed = append(s.result.Changed, file.kind)
		}
		s.records = append(s.records, storage.CertDeployMeta{
			Target: d.Name, Kind: file.kind, Path: file.dst,
			SHA256: storage.SHA256Hex(file.data), At: now,
		})
	}
	return nil
}

func (f *stagedFile) prepare(d *config.Deploy, uid, gid int, out io.Writer) (bool, error) {
	if err := os.MkdirAll(filepath.Dir(f.dst), 0o755); err != nil {
		return false, err
	}
	existing, err := os.Stat(f.dst)
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
	mode, err := DesiredMode(f.defaultMode, existing, d)
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
	if existing == nil && d.Mode == nil {
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
		err = file.Chown(uid, gid)
		if err != nil && os.Geteuid() != 0 {
			err = fmt.Errorf("chown requires privileges (running as non-root): %w", err)
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

func deployOwnership(d *config.Deploy) (int, int, error) {
	uid, gid := -1, -1
	if d.Owner != "" {
		owner, err := user.Lookup(d.Owner)
		if err != nil {
			return -1, -1, fmt.Errorf("owner %q: %w", d.Owner, err)
		}
		uid, err = strconv.Atoi(owner.Uid)
		if err != nil {
			return -1, -1, fmt.Errorf("owner %q uid %q: %w", d.Owner, owner.Uid, err)
		}
	}
	if d.Group != "" {
		group, err := user.LookupGroup(d.Group)
		if err != nil {
			return -1, -1, fmt.Errorf("group %q: %w", d.Group, err)
		}
		gid, err = strconv.Atoi(group.Gid)
		if err != nil {
			return -1, -1, fmt.Errorf("group %q gid %q: %w", d.Group, group.Gid, err)
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
