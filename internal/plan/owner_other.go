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

//go:build !(aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris)

package plan

import (
	"fmt"
	"os"
	"runtime"

	"foundry.fsky.io/fsky/gibcert/internal/config"
)

func plannedOwnerGroupChangesForOS(_ os.FileInfo, _ string, d *config.Deploy) ([]string, error) {
	if d.Owner == "" && d.Group == "" {
		return nil, nil
	}
	return nil, fmt.Errorf("owner/group planning is not supported on %s", runtime.GOOS)
}
