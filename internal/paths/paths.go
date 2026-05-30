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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

type Paths struct {
	Config  string
	State   string
	Runtime string
	Cache   string
	Root    bool
}

type Overrides struct {
	Config  string
	State   string
	Runtime string
	Cache   string
}

func Resolve(o Overrides) (*Paths, error) {
	p, err := defaultPaths()
	if err != nil {
		return nil, err
	}

	if v := os.Getenv("GIBCERT_CONFIG"); v != "" {
		p.Config = v
	}
	if v := os.Getenv("GIBCERT_STATE_DIR"); v != "" {
		p.State = v
	}
	if v := os.Getenv("GIBCERT_RUNTIME_DIR"); v != "" {
		p.Runtime = v
	}
	if v := os.Getenv("GIBCERT_CACHE_DIR"); v != "" {
		p.Cache = v
	}

	if o.Config != "" {
		p.Config = o.Config
	}
	if o.State != "" {
		p.State = o.State
	}
	if o.Runtime != "" {
		p.Runtime = o.Runtime
	}
	if o.Cache != "" {
		p.Cache = o.Cache
	}

	return p, nil
}

func defaultPaths() (*Paths, error) {
	root := isRoot()
	p := &Paths{Root: root}

	if root {
		switch runtime.GOOS {
		case "darwin":
			p.Config = filepath.Join("/Library/Application Support", "gibcert", "gibcert.scfg")
			p.State = filepath.Join("/Library/Application Support", "gibcert", "state")
			p.Runtime = filepath.Join("/var/run", "gibcert")
			p.Cache = filepath.Join("/Library/Caches", "gibcert")
		default:
			p.Config = "/etc/gibcert/gibcert.scfg"
			p.State = "/var/lib/gibcert"
			p.Runtime = "/run/gibcert"
			p.Cache = "/var/cache/gibcert"
		}
		return p, nil
	}

	configRoot, err := userConfigRoot()
	if err != nil {
		return nil, fmt.Errorf("resolve config path: %w", err)
	}
	cacheRoot, err := userCacheRoot()
	if err != nil {
		return nil, fmt.Errorf("resolve cache path: %w", err)
	}

	p.Config = filepath.Join(configRoot, "gibcert", "gibcert.scfg")
	p.Cache = filepath.Join(cacheRoot, "gibcert")

	switch runtime.GOOS {
	case "darwin":
		appRoot := filepath.Join(configRoot, "gibcert")
		p.State = filepath.Join(appRoot, "state")
		p.Runtime = filepath.Join(os.TempDir(), "gibcert")
	case "windows":
		localRoot := filepath.Join(cacheRoot, "gibcert")
		p.State = filepath.Join(localRoot, "state")
		p.Runtime = filepath.Join(localRoot, "run")
	case "plan9":
		root := filepath.Join(configRoot, "gibcert")
		p.State = filepath.Join(root, "state")
		p.Runtime = p.State
	default:
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("resolve state path: %w", err)
		}
		p.State = filepath.Join(xdg("XDG_STATE_HOME", filepath.Join(home, ".local", "state")), "gibcert")
		if rd := os.Getenv("XDG_RUNTIME_DIR"); rd != "" {
			p.Runtime = filepath.Join(rd, "gibcert")
		} else {
			p.Runtime = p.State
		}
	}

	return p, nil
}

func userConfigRoot() (string, error) {
	if dir, err := os.UserConfigDir(); err == nil {
		return dir, nil
	}
	return userFallbackRoot("config")
}

func userCacheRoot() (string, error) {
	if dir, err := os.UserCacheDir(); err == nil {
		return dir, nil
	}
	return userFallbackRoot("cache")
}

func userFallbackRoot(kind string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	switch runtime.GOOS {
	case "darwin":
		if kind == "cache" {
			return filepath.Join(home, "Library", "Caches"), nil
		}
		return filepath.Join(home, "Library", "Application Support"), nil
	case "windows":
		if kind == "cache" {
			return filepath.Join(home, "AppData", "Local"), nil
		}
		return filepath.Join(home, "AppData", "Roaming"), nil
	case "plan9":
		if kind == "cache" {
			return filepath.Join(home, "lib", "cache"), nil
		}
		return filepath.Join(home, "lib"), nil
	default:
		if kind == "cache" {
			return filepath.Join(home, ".cache"), nil
		}
		return filepath.Join(home, ".config"), nil
	}
}

func isRoot() bool {
	switch runtime.GOOS {
	case "windows", "plan9":
		return false
	default:
		return os.Geteuid() == 0
	}
}

func xdg(env, fallback string) string {
	if v := os.Getenv(env); v != "" {
		return v
	}
	return fallback
}
