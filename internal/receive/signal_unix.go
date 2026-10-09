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
	"os/signal"
	"syscall"
)

// ignoreHangup keeps a dropped SSH connection from killing the receiver in the
// middle of an installation. Once a request is read the receiver finishes it,
// including the hooks that restart a service its before hook stopped, and
// reports to a connection that may be gone.
func ignoreHangup() {
	signal.Ignore(syscall.SIGHUP, syscall.SIGPIPE)
}
