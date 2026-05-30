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

import (
	"strings"
	"testing"
)

func certs(specs ...[3]string) []*Certificate {
	// each spec is {name, requires-csv, wants-csv}
	out := make([]*Certificate, 0, len(specs))
	for _, s := range specs {
		c := &Certificate{Name: s[0]}
		if s[1] != "" {
			c.Requires = strings.Split(s[1], ",")
		}
		if s[2] != "" {
			c.Wants = strings.Split(s[2], ",")
		}
		out = append(out, c)
	}
	return out
}

func orderNames(t *testing.T, cs []*Certificate) []string {
	t.Helper()
	ordered, err := OrderCertificates(cs)
	if err != nil {
		t.Fatalf("OrderCertificates: %v", err)
	}
	names := make([]string, len(ordered))
	for i, c := range ordered {
		names[i] = c.Name
	}
	return names
}

func before(t *testing.T, names []string, a, b string) {
	t.Helper()
	ai, bi := -1, -1
	for i, n := range names {
		if n == a {
			ai = i
		}
		if n == b {
			bi = i
		}
	}
	if ai == -1 || bi == -1 {
		t.Fatalf("missing %q or %q in %v", a, b, names)
	}
	if ai > bi {
		t.Errorf("expected %q before %q, got %v", a, b, names)
	}
}

func TestOrderStablePreservesInput(t *testing.T) {
	names := orderNames(t, certs([3]string{"a", "", ""}, [3]string{"b", "", ""}, [3]string{"c", "", ""}))
	if got, want := strings.Join(names, ","), "a,b,c"; got != want {
		t.Errorf("order: got %q, want %q", got, want)
	}
}

func TestOrderRequiresAndWantsRunFirst(t *testing.T) {
	// b requires a; c wants b. Expect a before b before c.
	names := orderNames(t, certs(
		[3]string{"c", "", "b"},
		[3]string{"b", "a", ""},
		[3]string{"a", "", ""},
	))
	before(t, names, "a", "b")
	before(t, names, "b", "c")
}

func TestOrderCycleDetected(t *testing.T) {
	_, err := OrderCertificates(certs([3]string{"a", "b", ""}, [3]string{"b", "a", ""}))
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("want cycle error, got %v", err)
	}
}

func TestOrderUnknownDepIgnored(t *testing.T) {
	// OrderCertificates ignores unknown names (Validate reports them).
	names := orderNames(t, certs([3]string{"a", "ghost", ""}))
	if len(names) != 1 || names[0] != "a" {
		t.Errorf("got %v", names)
	}
}

func TestValidateDependencyErrors(t *testing.T) {
	base := `
account letsencrypt {
  ca letsencrypt
}
`
	cert := func(name, deps string) string {
		return base + `
certificate ` + name + ` {
  account letsencrypt
  names ` + name + `.example.com
  challenge http-01 {
    listen :80
  }
  ` + deps + `
}
`
	}
	cases := []struct {
		name, src, want string
	}{
		{"unknown", cert("a", "requires nope"), `unknown certificate "nope"`},
		{"self", cert("a", "wants a"), "list includes itself"},
		{"cycle", base + `
certificate a {
  account letsencrypt
  names a.example.com
  challenge http-01 {
    listen :80
  }
  requires b
}
certificate b {
  account letsencrypt
  names b.example.com
  challenge http-01 {
    listen :80
  }
  requires a
}
`, "cycle"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Read(strings.NewReader(tc.src))
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			err = cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate error: got %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestValidateBothRequiresAndWants(t *testing.T) {
	src := `
account letsencrypt {
  ca letsencrypt
}
certificate a {
  account letsencrypt
  names a.example.com
  challenge http-01 {
    listen :80
  }
}
certificate b {
  account letsencrypt
  names b.example.com
  challenge http-01 {
    listen :80
  }
  requires a
  wants a
}
`
	cfg, err := Read(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	err = cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "both requires and wants") {
		t.Fatalf("Validate error: got %v, want 'both requires and wants'", err)
	}
}
