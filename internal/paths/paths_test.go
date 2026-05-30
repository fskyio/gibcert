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

package paths

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestResolveRegularUserDefaults(t *testing.T) {
	if isRoot() {
		t.Skip("regular-user path defaults are not used as root")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("XDG_CACHE_HOME", "")

	p, err := Resolve(Overrides{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	switch runtime.GOOS {
	case "darwin":
		wantRoot := filepath.Join(home, "Library", "Application Support", "gibcert")
		if p.Config != filepath.Join(wantRoot, "gibcert.scfg") {
			t.Fatalf("Config = %q, want %q", p.Config, filepath.Join(wantRoot, "gibcert.scfg"))
		}
		if p.State != filepath.Join(wantRoot, "state") {
			t.Fatalf("State = %q, want %q", p.State, filepath.Join(wantRoot, "state"))
		}
	case "windows":
		t.Skip("Windows defaults depend on AppData and LocalAppData")
	case "plan9":
		t.Skip("Plan 9 defaults depend on $home")
	default:
		if p.Config != filepath.Join(home, ".config", "gibcert", "gibcert.scfg") {
			t.Fatalf("Config = %q", p.Config)
		}
		if p.State != filepath.Join(home, ".local", "state", "gibcert") {
			t.Fatalf("State = %q", p.State)
		}
		if p.Runtime != p.State {
			t.Fatalf("Runtime = %q, want state dir %q", p.Runtime, p.State)
		}
		if p.Cache != filepath.Join(home, ".cache", "gibcert") {
			t.Fatalf("Cache = %q", p.Cache)
		}
	}
}

func TestResolveOverrides(t *testing.T) {
	p, err := Resolve(Overrides{
		Config:  filepath.Join("tmp", "config.scfg"),
		State:   filepath.Join("tmp", "state"),
		Runtime: filepath.Join("tmp", "run"),
		Cache:   filepath.Join("tmp", "cache"),
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if p.Config != filepath.Join("tmp", "config.scfg") ||
		p.State != filepath.Join("tmp", "state") ||
		p.Runtime != filepath.Join("tmp", "run") ||
		p.Cache != filepath.Join("tmp", "cache") {
		t.Fatalf("overrides not applied: %+v", p)
	}
}

func TestResolveEnvironmentOverrides(t *testing.T) {
	t.Setenv("GIBCERT_CONFIG", "config.scfg")
	t.Setenv("GIBCERT_STATE_DIR", "state")
	t.Setenv("GIBCERT_RUNTIME_DIR", "run")
	t.Setenv("GIBCERT_CACHE_DIR", "cache")

	p, err := Resolve(Overrides{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if p.Config != "config.scfg" ||
		p.State != "state" ||
		p.Runtime != "run" ||
		p.Cache != "cache" {
		t.Fatalf("environment overrides not applied: %+v", p)
	}
}
