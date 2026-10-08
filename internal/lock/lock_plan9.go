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

//go:build plan9

package lock

import (
	"errors"
	"os"
	"syscall"
)

const (
	plan9ORCLOSE = 0x40
	// The versioned path bypasses legacy .held markers that may be stale.
	plan9LockSuffix = ".held.v2"
)

func lockFile(path string, _ *os.File) (func() error, error) {
	lockPath := path + plan9LockSuffix
	// ORCLOSE removes the marker when this fid closes, including on process exit.
	fd, err := syscall.Create(lockPath, syscall.O_RDWR|syscall.O_EXCL|syscall.O_CLOEXEC|plan9ORCLOSE, 0o644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, errLockBusy
		}
		return nil, err
	}
	marker := os.NewFile(uintptr(fd), lockPath)
	return marker.Close, nil
}
