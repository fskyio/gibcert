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
)

// simulateRun walks certs in dependency order, calling process for each cert
// that is not gated by gateReason, and returns the per-cert outcomes. It mirrors
// how cmdApply/cmdRenew drive a run, so the ordering + gating interaction can be
// tested without ACME or deploy side effects.
func simulateRun(t *testing.T, certs []*config.Certificate, process func(*config.Certificate) runOutcome) map[string]runOutcome {
	t.Helper()
	ordered, err := config.OrderCertificates(certs)
	if err != nil {
		t.Fatalf("OrderCertificates: %v", err)
	}
	outcomes := map[string]runOutcome{}
	for _, c := range ordered {
		if reason := gateReason(c, outcomes); reason != "" {
			outcomes[c.Name] = runSkipped
			continue
		}
		outcomes[c.Name] = process(c)
	}
	return outcomes
}

func dep(name string, requires ...string) *config.Certificate {
	return &config.Certificate{Name: name, Requires: requires}
}

func TestGateSkipsDependentsOfFailure(t *testing.T) {
	// b requires a, c requires b, d is independent. a fails.
	certs := []*config.Certificate{dep("a"), dep("b", "a"), dep("c", "b"), dep("d")}
	var processed []string
	outcomes := simulateRun(t, certs, func(c *config.Certificate) runOutcome {
		processed = append(processed, c.Name)
		if c.Name == "a" {
			return runFailed
		}
		return runOK
	})

	// b and c are skipped transitively; d still runs.
	if outcomes["b"] != runSkipped || outcomes["c"] != runSkipped {
		t.Errorf("want b and c skipped, got %v", outcomes)
	}
	if outcomes["d"] != runOK {
		t.Errorf("want d ok, got %v", outcomes["d"])
	}
	if strings.Contains(strings.Join(processed, ","), "b") || strings.Contains(strings.Join(processed, ","), "c") {
		t.Errorf("gated certs should not be processed, processed %v", processed)
	}
}

func TestGateAllowsWhenRequirementSucceeds(t *testing.T) {
	certs := []*config.Certificate{dep("a"), dep("b", "a")}
	outcomes := simulateRun(t, certs, func(c *config.Certificate) runOutcome { return runOK })
	if outcomes["b"] != runOK {
		t.Errorf("want b ok, got %v", outcomes["b"])
	}
}

func TestGateAbsentRequirementSatisfied(t *testing.T) {
	// b requires a, but a is not part of this run (e.g. not due in renew).
	// gateReason treats an absent outcome as satisfied.
	if reason := gateReason(dep("b", "a"), map[string]runOutcome{}); reason != "" {
		t.Errorf("absent requirement should not gate, got %q", reason)
	}
}

func TestGateWantsDoesNotGate(t *testing.T) {
	// A wants-only dependency that failed must not skip the dependent.
	c := &config.Certificate{Name: "b", Wants: []string{"a"}}
	if reason := gateReason(c, map[string]runOutcome{"a": runFailed}); reason != "" {
		t.Errorf("wants must not gate, got %q", reason)
	}
}
