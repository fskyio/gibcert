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

package config

import "fmt"

// OrderCertificates returns the certificates sorted so that each one appears
// after every certificate it requires or wants. Among certificates with no
// ordering constraint between them, the original order is preserved (a stable
// topological sort). It returns an error if the requires/wants edges contain a
// cycle. Unknown dependency names are ignored here; Validate reports them.
func OrderCertificates(certs []*Certificate) ([]*Certificate, error) {
	index := make(map[string]int, len(certs))
	for i, c := range certs {
		index[c.Name] = i
	}

	// adj[j] lists the certificates that depend on certs[j]; indeg[i] counts how
	// many dependencies certs[i] is still waiting on.
	adj := make([][]int, len(certs))
	indeg := make([]int, len(certs))
	for i, c := range certs {
		seen := map[int]bool{}
		for _, dep := range append(append([]string{}, c.Requires...), c.Wants...) {
			j, ok := index[dep]
			if !ok || j == i || seen[j] {
				continue
			}
			seen[j] = true
			adj[j] = append(adj[j], i)
			indeg[i]++
		}
	}

	// Kahn's algorithm, always taking the lowest available index so the result
	// is deterministic and preserves input order among independent certs.
	done := make([]bool, len(certs))
	order := make([]*Certificate, 0, len(certs))
	for len(order) < len(certs) {
		next := -1
		for i := range certs {
			if !done[i] && indeg[i] == 0 {
				next = i
				break
			}
		}
		if next == -1 {
			return nil, fmt.Errorf("certificate dependency cycle detected")
		}
		done[next] = true
		order = append(order, certs[next])
		for _, dep := range adj[next] {
			indeg[dep]--
		}
	}
	return order, nil
}

// validateDependencies checks requires/wants references for unknown targets,
// self-references, duplicates, contradictory listings, and cycles.
func validateDependencies(certs []*Certificate) []error {
	var errs []error
	names := make(map[string]bool, len(certs))
	for _, c := range certs {
		names[c.Name] = true
	}
	for _, c := range certs {
		check := func(kind string, list []string) map[string]bool {
			seen := map[string]bool{}
			for _, dep := range list {
				switch {
				case dep == c.Name:
					errs = append(errs, fmt.Errorf("certificate %q: %s list includes itself", c.Name, kind))
				case !names[dep]:
					errs = append(errs, fmt.Errorf("certificate %q: %s unknown certificate %q", c.Name, kind, dep))
				case seen[dep]:
					errs = append(errs, fmt.Errorf("certificate %q: duplicate %s %q", c.Name, kind, dep))
				}
				seen[dep] = true
			}
			return seen
		}
		req := check("requires", c.Requires)
		for dep := range check("wants", c.Wants) {
			if req[dep] {
				errs = append(errs, fmt.Errorf("certificate %q: %q listed in both requires and wants", c.Name, dep))
			}
		}
	}
	if _, err := OrderCertificates(certs); err != nil {
		errs = append(errs, err)
	}
	return errs
}
