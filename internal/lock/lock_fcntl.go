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

//go:build aix || (solaris && !illumos)

package lock

import (
	"errors"
	"os"
	"syscall"
)

func lockFile(_ string, f *os.File) (func() error, error) {
	lk := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: 0, Start: 0, Len: 0}
	if err := syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, &lk); err != nil {
		if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EAGAIN) {
			return nil, errLockBusy
		}
		return nil, err
	}
	return func() error {
		lk := syscall.Flock_t{Type: syscall.F_UNLCK, Whence: 0, Start: 0, Len: 0}
		return syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, &lk)
	}, nil
}
