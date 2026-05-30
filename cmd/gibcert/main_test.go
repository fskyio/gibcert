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
	"os"
	"path/filepath"
	"testing"
	"time"

	"foundry.fsky.io/fsky/gibcert/internal/config"
	"foundry.fsky.io/fsky/gibcert/internal/paths"
	"foundry.fsky.io/fsky/gibcert/internal/storage"
)

func TestShouldJitterBeforeRenewal(t *testing.T) {
	cfg := &config.Config{
		CAs: []*config.CA{{
			Name: "internal",
			Type: "local",
		}},
	}

	tests := []struct {
		name      string
		cert      *config.Certificate
		noJitter  bool
		maxJitter time.Duration
		want      bool
		wantErr   bool
	}{
		{
			name:      "disabled",
			cert:      &config.Certificate{Name: "example.com", Account: "letsencrypt"},
			noJitter:  true,
			maxJitter: time.Minute,
			want:      false,
		},
		{
			name:      "zero max",
			cert:      &config.Certificate{Name: "example.com", Account: "letsencrypt"},
			maxJitter: 0,
			want:      false,
		},
		{
			name:      "acme account",
			cert:      &config.Certificate{Name: "example.com", Account: "letsencrypt"},
			maxJitter: time.Minute,
			want:      true,
		},
		{
			name:      "builtin acme ca",
			cert:      &config.Certificate{Name: "example.com", CA: "letsencrypt"},
			maxJitter: time.Minute,
			want:      true,
		},
		{
			name:      "local ca",
			cert:      &config.Certificate{Name: "service.internal", CA: "internal"},
			maxJitter: time.Minute,
			want:      false,
		},
		{
			name:      "unknown ca",
			cert:      &config.Certificate{Name: "broken", CA: "missing"},
			maxJitter: time.Minute,
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := shouldJitterBeforeRenewal(cfg, tc.cert, tc.noJitter, tc.maxJitter)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err got %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDeploySummaryReportsCurrentState(t *testing.T) {
	store := storage.New(t.TempDir())
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	cert := &config.Certificate{
		Name: "example.com",
		Deploys: []*config.Deploy{{
			Name: "web",
			Cert: filepath.Join(t.TempDir(), "cert.pem"),
			Key:  filepath.Join(t.TempDir(), "privkey.pem"),
		}},
	}
	paths := store.CertPaths(cert.Name)
	if err := os.MkdirAll(paths.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.Cert, []byte("cert"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.Key, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cert.Deploys[0].Cert, []byte("cert"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cert.Deploys[0].Key, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}

	if got := deploySummary(cert, store); got != "ok" {
		t.Fatalf("deploySummary got %q, want ok", got)
	}
	if err := os.WriteFile(cert.Deploys[0].Key, []byte("old-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := deploySummary(cert, store); got != "partial" {
		t.Fatalf("deploySummary got %q, want partial", got)
	}
}

func TestDeploySummaryDistinguishesNeverAndMissing(t *testing.T) {
	store := storage.New(t.TempDir())
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	targetDir := t.TempDir()
	cert := &config.Certificate{
		Name: "example.com",
		Deploys: []*config.Deploy{{
			Name: "web",
			Cert: filepath.Join(targetDir, "cert.pem"),
		}},
	}
	paths := store.CertPaths(cert.Name)
	if err := os.MkdirAll(paths.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.Cert, []byte("cert"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := deploySummary(cert, store); got != "never" {
		t.Fatalf("deploySummary got %q, want never", got)
	}

	at := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	if err := store.SaveCertMeta(cert.Name, storage.CertMeta{
		Name: cert.Name,
		Deploys: []storage.CertDeployMeta{{
			Target: "web",
			Kind:   "cert",
			Path:   cert.Deploys[0].Cert,
			SHA256: storage.SHA256Hex([]byte("cert")),
			At:     at,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if got := deploySummary(cert, store); got != "missing" {
		t.Fatalf("deploySummary got %q, want missing", got)
	}
}

func TestImportPEMUsageErrors(t *testing.T) {
	p := &paths.Paths{State: t.TempDir()}
	tests := [][]string{
		{"--key", "privkey.pem", "--fullchain", "fullchain.pem"},
		{"--name", "example.com", "--fullchain", "fullchain.pem"},
		{"--name", "example.com", "--key", "privkey.pem"},
		{"--name", "example.com", "--key", "privkey.pem", "--cert", "cert.pem", "--fullchain", "fullchain.pem"},
		{"--name", "example.com", "--key", "privkey.pem", "--chain", "chain.pem", "--fullchain", "fullchain.pem"},
	}
	for _, args := range tests {
		if got := cmdImportPEM(p, args); got != 2 {
			t.Fatalf("cmdImportPEM(%v) got %d, want 2", args, got)
		}
	}
}

func TestRenameRejectsUnsafeNames(t *testing.T) {
	p := &paths.Paths{State: t.TempDir()}
	if got := cmdRename(p, []string{"example.com", "../../outside"}); got != 2 {
		t.Fatalf("cmdRename got %d, want 2", got)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(p.State), "outside")); !os.IsNotExist(err) {
		t.Fatalf("outside path err=%v, want missing", err)
	}
}

func TestDeleteRejectsUnsafeName(t *testing.T) {
	p := &paths.Paths{State: t.TempDir()}
	if got := cmdDelete(p, []string{"--yes", "../../outside"}); got != 2 {
		t.Fatalf("cmdDelete got %d, want 2", got)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(p.State), "outside")); !os.IsNotExist(err) {
		t.Fatalf("outside path err=%v, want missing", err)
	}
}
