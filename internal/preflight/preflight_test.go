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

package preflight

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"foundry.fsky.io/fsky/gibcert/internal/config"
)

func TestCheckHTTP01Webroot(t *testing.T) {
	cfg := &config.Config{
		Accounts: []*config.Account{{Name: "a", Directory: "https://example.invalid/directory"}},
		Certificates: []*config.Certificate{{
			Name:    "example.com",
			Account: "a",
			Names:   []string{"example.com"},
			Challenge: config.ChallengeSpec{
				Type:    "http-01",
				Webroot: t.TempDir(),
			},
			Deploys: []*config.Deploy{{Name: "d", Cert: "/tmp/cert.pem"}},
		}},
	}
	if err := Check(cfg); err != nil {
		t.Fatalf("Check: %v", err)
	}
}

func TestCheckRejectsMissingHTTP01Webroot(t *testing.T) {
	cfg := &config.Config{
		Accounts: []*config.Account{{Name: "a", Directory: "https://example.invalid/directory"}},
		Certificates: []*config.Certificate{{
			Name:    "example.com",
			Account: "a",
			Names:   []string{"example.com"},
			Challenge: config.ChallengeSpec{
				Type:    "http-01",
				Webroot: "/definitely/not/a/real/gibcert/webroot",
			},
			Deploys: []*config.Deploy{{Name: "d", Cert: "/tmp/cert.pem"}},
		}},
	}
	err := Check(cfg)
	if err == nil {
		t.Fatal("Check succeeded, want error")
	}
	if !strings.Contains(err.Error(), "webroot") {
		t.Fatalf("error %q does not mention webroot", err)
	}
}

func TestCheckUsesGlobalHTTP01WebrootAndSkipsLocalCA(t *testing.T) {
	webroot := t.TempDir()
	cfg := &config.Config{
		CAs: []*config.CA{{Name: "local", Type: "local"}},
		GlobalChallenge: &config.GlobalChallenge{
			Type:    "http-01",
			Webroot: webroot,
		},
		Certificates: []*config.Certificate{
			{
				Name:    "example.com",
				Account: "a",
				Names:   []string{"example.com"},
			},
			{
				Name:  "local.example",
				CA:    "local",
				Names: []string{"local.example"},
				Challenge: config.ChallengeSpec{
					Type:    "http-01",
					Webroot: "/definitely/missing",
				},
			},
		},
	}
	if err := Check(cfg); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if _, err := os.Stat(filepath.Join(webroot, ".well-known", "acme-challenge")); err != nil {
		t.Fatalf("challenge dir not created: %v", err)
	}
}

func TestCheckListenValidation(t *testing.T) {
	cfg := &config.Config{
		Certificates: []*config.Certificate{{
			Name:    "example.com",
			Account: "a",
			Names:   []string{"example.com"},
			Challenge: config.ChallengeSpec{
				Type:   "tls-alpn-01",
				Listen: "not-a-host-port",
			},
		}},
	}
	err := Check(cfg)
	if err == nil || !strings.Contains(err.Error(), "tls-alpn-01 listen") {
		t.Fatalf("Check got %v, want listen error", err)
	}
	if err := checkListen("example.com", "http-01", "127.0.0.1:0"); err != nil {
		t.Fatalf("checkListen valid: %v", err)
	}
	if got := challengeType(&config.Config{GlobalChallenge: &config.GlobalChallenge{Type: "dns-01"}}, &config.Certificate{}); got != "dns-01" {
		t.Fatalf("challengeType global got %q", got)
	}
}

func TestCheckWebrootRejectsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-dir")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := checkWebroot("example.com", path)
	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("checkWebroot got %v, want file error", err)
	}
}
