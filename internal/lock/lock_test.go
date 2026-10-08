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
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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

const lockHelperPathEnv = "GIBCERT_LOCK_HELPER_PATH"

func TestLockProcessHelper(t *testing.T) {
	path := os.Getenv(lockHelperPathEnv)
	if path == "" {
		t.Skip("used only as a lock-holder subprocess")
	}

	l, err := Acquire(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()
	if _, err := fmt.Fprintln(os.Stdout, "lock-ready"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Hour)
}

func TestProcessTerminationReleasesLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.lock")
	// Simulate a stale marker written by the previous Windows and Plan 9 backends.
	if err := os.WriteFile(path+".held", nil, 0o600); err != nil {
		t.Fatalf("create stale marker: %v", err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestLockProcessHelper$")
	cmd.Env = append(os.Environ(), lockHelperPathEnv+"="+path)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("helper stdout: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start lock helper: %v", err)
	}
	childRunning := true
	defer func() {
		if childRunning {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	ready := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if scanner.Text() == "lock-ready" {
				ready <- nil
				return
			}
		}
		if err := scanner.Err(); err != nil {
			ready <- err
			return
		}
		ready <- errors.New("lock helper exited before acquiring the lock")
	}()

	select {
	case err := <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for lock helper")
	}
	if pid := readPID(path); pid != cmd.Process.Pid {
		t.Fatalf("lock owner PID = %d, want helper PID %d", pid, cmd.Process.Pid)
	}

	l, err := Acquire(path, 250*time.Millisecond)
	if err == nil {
		if releaseErr := l.Release(); releaseErr != nil {
			t.Errorf("release unexpectedly acquired lock: %v", releaseErr)
		}
		t.Fatal("second process acquired lock while helper held it")
	}
	if want := fmt.Sprintf("held by pid %d", cmd.Process.Pid); !strings.Contains(err.Error(), want) {
		t.Fatalf("contention error = %q, want %q", err, want)
	}

	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill lock helper: %v", err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("lock helper exited without termination")
	}
	childRunning = false

	l, err = Acquire(path, 5*time.Second)
	if err != nil {
		t.Fatalf("acquire after helper termination: %v", err)
	}
	if err := l.Release(); err != nil {
		t.Fatalf("release after helper termination: %v", err)
	}
}
