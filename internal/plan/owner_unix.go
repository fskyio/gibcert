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

package plan

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"

	"foundry.fsky.io/fsky/gibcert/internal/config"
)

func plannedOwnerGroupChangesForOS(info os.FileInfo, name string, d *config.Deploy) ([]string, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, nil
	}

	var changes []string
	if d.Owner != "" {
		u, err := user.Lookup(d.Owner)
		if err != nil {
			return nil, fmt.Errorf("owner %q: %w", d.Owner, err)
		}
		uid, err := strconv.ParseUint(u.Uid, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("owner %q uid %q: %w", d.Owner, u.Uid, err)
		}
		if stat.Uid != uint32(uid) {
			changes = append(changes, name+" chown "+d.Owner)
		}
	}
	if d.Group != "" {
		g, err := user.LookupGroup(d.Group)
		if err != nil {
			return nil, fmt.Errorf("group %q: %w", d.Group, err)
		}
		gid, err := strconv.ParseUint(g.Gid, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("group %q gid %q: %w", d.Group, g.Gid, err)
		}
		if stat.Gid != uint32(gid) {
			changes = append(changes, name+" chgrp "+d.Group)
		}
	}
	return changes, nil
}
