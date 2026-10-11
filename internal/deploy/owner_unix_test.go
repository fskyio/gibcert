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
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"gitfield.org/fsky/gibcert/internal/config"
	"gitfield.org/fsky/gibcert/internal/storage"
)

func TestDeployPreservesOwnershipOnReplacement(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing destination UID/GID requires root")
	}
	owner, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	group, err := user.LookupGroupId(strconv.Itoa(os.Getegid()))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, owner, group string
		uid, gid           int
	}{
		{"omitted", "", "", 12345, 12346},
		{"owner only", owner.Username, "", os.Geteuid(), 12346},
		{"group only", "", group.Name, 12345, os.Getegid()},
		{"explicit both", owner.Username, group.Name, os.Geteuid(), os.Getegid()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			// The previous files belong to the directory's owner, so a key
			// may inherit their ownership.
			if err := os.Chown(root, 12345, 12346); err != nil {
				t.Fatal(err)
			}
			store := storage.New(filepath.Join(root, "state"))
			writeCanonical(t, store, "service")
			mode := os.FileMode(0o640)
			d := &config.Deploy{Name: "local", Fullchain: filepath.Join(root, "fullchain"), Key: filepath.Join(root, "key"), Mode: &mode, Owner: tc.owner, Group: tc.group}
			for _, dst := range []string{d.Fullchain, d.Key} {
				if err := os.WriteFile(dst, []byte("previous generation"), mode); err != nil {
					t.Fatal(err)
				}
				if err := os.Chown(dst, 12345, 12346); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := Deploy(&config.Certificate{Name: "service", Deploys: []*config.Deploy{d}}, store, io.Discard); err != nil {
				t.Fatal(err)
			}
			for _, output := range []struct{ path, data string }{{d.Fullchain, "fullchain"}, {d.Key, "key"}} {
				data, err := os.ReadFile(output.path)
				if err != nil || string(data) != output.data {
					t.Fatalf("replacement content = %q, error %v", data, err)
				}
				info, err := os.Stat(output.path)
				if err != nil {
					t.Fatal(err)
				}
				uid, gid := fileOwnership(info)
				if uid != tc.uid || gid != tc.gid {
					t.Fatalf("%s ownership = %d:%d, want %d:%d", output.path, uid, gid, tc.uid, tc.gid)
				}
			}
		})
	}
}

type ownedInfo struct {
	mode fs.FileMode
	uid  uint32
}

func (i ownedInfo) Name() string       { return "owned" }
func (i ownedInfo) Size() int64        { return 0 }
func (i ownedInfo) Mode() fs.FileMode  { return i.mode }
func (i ownedInfo) ModTime() time.Time { return time.Time{} }
func (i ownedInfo) IsDir() bool        { return i.mode.IsDir() }
func (i ownedInfo) Sys() any           { return &syscall.Stat_t{Uid: i.uid} }

func TestTrustedToInheritRejectsPlantedKeys(t *testing.T) {
	const euid, other = 0, 1000
	for _, tc := range []struct {
		name    string
		dirMode fs.FileMode
		dirUID  uint32
		fileUID uint32
		trusted bool
	}{
		{"own file in private directory", 0o755, euid, euid, true},
		{"directory owner's file", 0o750, other, other, true},
		{"another user's file", 0o755, euid, other, false},
		{"group-writable directory", 0o775, euid, euid, false},
		{"sticky world-writable directory", fs.ModeSticky | 0o777, euid, euid, false},
	} {
		dir := ownedInfo{mode: fs.ModeDir | tc.dirMode, uid: tc.dirUID}
		file := ownedInfo{mode: 0o640, uid: tc.fileUID}
		if got := trustedToInherit(dir, file, euid); got != tc.trusted {
			t.Errorf("%s: trusted = %v, want %v", tc.name, got, tc.trusted)
		}
	}
}
