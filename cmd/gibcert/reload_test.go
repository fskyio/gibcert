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

package main

import (
	"strings"
	"testing"

	"foundry.fsky.io/fsky/gibcert/internal/config"
	"foundry.fsky.io/fsky/gibcert/internal/deploy"
)

func reloadCert(name string, cmds ...string) *config.Certificate {
	return &config.Certificate{Name: name, Reloads: cmds}
}

func TestReloadQueueDedupesAcrossCerts(t *testing.T) {
	q := newReloadQueue()
	q.add(reloadCert("a", "reload nginx"))
	q.add(reloadCert("b", "reload nginx"))
	q.add(reloadCert("c", "reload nginx", "reload haproxy"))

	if got, want := strings.Join(q.order, "|"), "reload nginx|reload haproxy"; got != want {
		t.Fatalf("order: got %q, want %q", got, want)
	}
	// nginx was contributed by all three, in order.
	if got, want := strings.Join(q.certs["reload nginx"], ","), "a,b,c"; got != want {
		t.Errorf("nginx contributors: got %q, want %q", got, want)
	}
	if got, want := strings.Join(q.certs["reload haproxy"], ","), "c"; got != want {
		t.Errorf("haproxy contributors: got %q, want %q", got, want)
	}
}

func TestAnyChangedReportsRotation(t *testing.T) {
	if anyChanged([]deploy.Result{{Target: "a"}, {Target: "b"}}) {
		t.Errorf("no Changed entries should report false")
	}
	if !anyChanged([]deploy.Result{{Target: "a"}, {Target: "b", Changed: []string{"fullchain"}}}) {
		t.Errorf("a changed deploy should report true")
	}
}

// Only certs whose deploys changed enqueue their reload, mirroring how the run
// loops gate enqueue on anyChanged(results).
func TestReloadOnlyEnqueuedOnChange(t *testing.T) {
	q := newReloadQueue()
	type step struct {
		cert    *config.Certificate
		results []deploy.Result
	}
	steps := []step{
		{reloadCert("changed", "reload nginx"), []deploy.Result{{Target: "d", Changed: []string{"fullchain"}}}},
		{reloadCert("unchanged", "reload nginx"), []deploy.Result{{Target: "d"}}},
	}
	for _, s := range steps {
		if anyChanged(s.results) {
			q.add(s.cert)
		}
	}
	if got, want := strings.Join(q.certs["reload nginx"], ","), "changed"; got != want {
		t.Errorf("contributors: got %q, want %q (unchanged cert must not enqueue)", got, want)
	}
}
