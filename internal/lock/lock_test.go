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
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestAcquireRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.lock")
	l, err := Acquire(path, time.Second)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if err := l.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	l2, err := Acquire(path, time.Second)
	if err != nil {
		t.Fatalf("re-acquire: %v", err)
	}
	if err := l2.Release(); err != nil {
		t.Fatalf("re-release: %v", err)
	}
}

func TestContentionReportsPID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.lock")
	l, err := Acquire(path, time.Second)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	t.Cleanup(func() { l.Release() })

	_, err = Acquire(path, 200*time.Millisecond)
	if err == nil {
		t.Fatal("expected contention error, got nil")
	}
	if pid := readPID(path); pid <= 0 {
		t.Errorf("PID not recorded in lock file (got %q)", strconv.Itoa(pid))
	}
}
