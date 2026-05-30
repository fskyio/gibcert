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

//go:build windows || plan9

package lock

import (
	"errors"
	"os"
)

func lockFile(path string, _ *os.File) (func() error, error) {
	lockPath := path + ".held"
	f, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, errLockBusy
		}
		return nil, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(lockPath)
		return nil, err
	}
	return func() error {
		return os.Remove(lockPath)
	}, nil
}
