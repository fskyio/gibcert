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

//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package deploy

import (
	"os"
	"path/filepath"
	"syscall"
)

// openDestination opens dst for reading without following a symbolic link,
// and without blocking should it have been replaced by a FIFO since it was
// checked.
func openDestination(dst string) (*os.File, error) {
	return os.OpenFile(dst, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

// InheritTrusted reports whether a private key deployed to dst may inherit
// the owner, group, and mode of existing, the file currently there. It may
// only when no other user could have placed that file: the directory is not
// writable by group or other, and the file belongs to this user or to the
// directory's owner.
func InheritTrusted(dst string, existing os.FileInfo) (bool, error) {
	dir, err := os.Stat(filepath.Dir(dst))
	if err != nil {
		return false, err
	}
	return trustedToInherit(dir, existing, os.Geteuid()), nil
}

func trustedToInherit(dir, existing os.FileInfo, euid int) bool {
	if dir.Mode().Perm()&0o022 != 0 {
		return false
	}
	dirUID, _ := fileOwnership(dir)
	uid, _ := fileOwnership(existing)
	return uid != -1 && (uid == euid || uid == dirUID)
}
