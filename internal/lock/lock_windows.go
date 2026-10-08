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

//go:build windows

package lock

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var (
	lockFileExProc   = syscall.NewLazyDLL("kernel32.dll").NewProc("LockFileEx")
	unlockFileExProc = syscall.NewLazyDLL("kernel32.dll").NewProc("UnlockFileEx")
)

const (
	lockFileExclusiveLock                   = 0x2
	lockFileFailImmediately                 = 0x1
	windowsErrorLockViolation syscall.Errno = 33
	// Keep the locked range at 4 GiB so the PID record remains readable on contention.
	lockFileOffsetHigh = 1
)

func lockFile(_ string, f *os.File) (func() error, error) {
	overlapped := syscall.Overlapped{OffsetHigh: lockFileOffsetHigh}
	r1, _, err := lockFileExProc.Call(
		f.Fd(),
		uintptr(lockFileExclusiveLock|lockFileFailImmediately),
		0,
		1,
		0,
		uintptr(unsafe.Pointer(&overlapped)),
	)
	if r1 == 0 {
		if errors.Is(err, windowsErrorLockViolation) {
			return nil, errLockBusy
		}
		return nil, fmt.Errorf("LockFileEx: %w", err)
	}

	return func() error {
		r1, _, err := unlockFileExProc.Call(
			f.Fd(),
			0,
			1,
			0,
			uintptr(unsafe.Pointer(&overlapped)),
		)
		if r1 == 0 {
			return fmt.Errorf("UnlockFileEx: %w", err)
		}
		return nil
	}, nil
}
