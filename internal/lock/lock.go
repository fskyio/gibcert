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

package lock

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Lock struct {
	f      *os.File
	path   string
	unlock func() error
}

var errLockBusy = errors.New("lock busy")

func Acquire(path string, timeout time.Duration) (*Lock, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}

	deadline := time.Now().Add(timeout)
	var unlock func() error
	for {
		unlock, err = lockFile(path, f)
		if err == nil {
			break
		}
		if !errors.Is(err, errLockBusy) {
			f.Close()
			return nil, fmt.Errorf("lock %s: %w", path, err)
		}
		if time.Now().After(deadline) {
			pid := readPID(path)
			f.Close()
			if pid > 0 {
				return nil, fmt.Errorf("lock %s held by pid %d", path, pid)
			}
			return nil, fmt.Errorf("lock %s busy", path)
		}
		time.Sleep(100 * time.Millisecond)
	}

	if err := f.Truncate(0); err != nil {
		_ = unlock()
		f.Close()
		return nil, err
	}
	if _, err := f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0); err != nil {
		_ = unlock()
		f.Close()
		return nil, err
	}
	return &Lock{f: f, path: path, unlock: unlock}, nil
}

func (l *Lock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	_ = l.f.Truncate(0)
	var unlockErr error
	if l.unlock != nil {
		unlockErr = l.unlock()
	}
	closeErr := l.f.Close()
	l.f = nil
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}

func readPID(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0
	}
	return n
}
