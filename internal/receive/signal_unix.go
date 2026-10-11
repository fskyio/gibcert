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

//go:build !windows && !plan9

package receive

import (
	"os"
	"syscall"
)

// holdSignals keeps a dropped SSH connection, or a request to stop, from
// killing the receiver in the middle of an installation: once a request is
// read the receiver finishes or rolls it back, including the hooks that
// restart a service its before hook stopped. The signals are caught rather
// than ignored, so hooks still start with the default dispositions, and a
// write to a closed connection fails instead of killing the receiver. Only
// SIGKILL or a power loss can still interrupt it. The returned function
// restores the default behavior.
func holdSignals() (release func()) {
	return catchSignals(os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGPIPE)
}
