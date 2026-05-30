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

package plan

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"foundry.fsky.io/fsky/gibcert/internal/config"
	"foundry.fsky.io/fsky/gibcert/internal/storage"
)

func TestComputePlansMissingState(t *testing.T) {
	store := storage.New(t.TempDir())
	cfg := testConfig(t.TempDir())

	pl, err := Compute(cfg, store, time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	got := renderActions(pl.Actions)
	for _, want := range []string{
		"account letsencrypt:register:account metadata missing",
		"certificate example.com:issue:certificate missing or unreadable",
		"deploy example.com/local:pending:certificate material not stored yet",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("actions:\n%s\nmissing %q", got, want)
		}
	}
}

func TestComputeNoChanges(t *testing.T) {
	root := t.TempDir()
	store := storage.New(filepath.Join(root, "state"))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(root)
	if err := store.SaveAccountMeta("letsencrypt", storage.AccountMeta{
		URL:       "https://example.invalid/acct/1",
		Email:     "admin@example.com",
		Directory: "https://example.invalid/directory",
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	certPEM := makeCertPEM(t, time.Now().Add(-time.Hour), time.Now().Add(45*24*time.Hour))
	paths := store.CertPaths("example.com")
	if err := os.MkdirAll(paths.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{paths.Cert, certPEM, 0o644},
		{paths.Fullchain, certPEM, 0o644},
		{paths.Key, []byte("key"), 0o600},
		{cfg.Certificates[0].Deploys[0].Fullchain, certPEM, 0o600},
		{cfg.Certificates[0].Deploys[0].Key, []byte("key"), 0o600},
	} {
		if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f.path, f.data, f.mode); err != nil {
			t.Fatal(err)
		}
	}

	pl, err := Compute(cfg, store, time.Now())
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if !pl.Empty() {
		t.Fatalf("got actions:\n%s", renderActions(pl.Actions))
	}
}

func TestComputePlansBeforeAndAfterDeployHooks(t *testing.T) {
	root := t.TempDir()
	store := storage.New(filepath.Join(root, "state"))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(root)
	cfg.Certificates[0].Deploys[0].Before = "systemctl stop service"
	cfg.Certificates[0].Deploys[0].After = "systemctl reload service"
	if err := store.SaveAccountMeta("letsencrypt", storage.AccountMeta{
		URL:       "https://example.invalid/acct/1",
		Email:     "admin@example.com",
		Directory: "https://example.invalid/directory",
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	certPEM := makeCertPEM(t, time.Now().Add(-time.Hour), time.Now().Add(45*24*time.Hour))
	paths := store.CertPaths("example.com")
	for _, f := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{paths.Cert, certPEM, 0o644},
		{paths.Fullchain, certPEM, 0o644},
		{paths.Key, []byte("key"), 0o600},
		{cfg.Certificates[0].Deploys[0].Fullchain, []byte("old"), 0o600},
		{cfg.Certificates[0].Deploys[0].Key, []byte("key"), 0o600},
	} {
		if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f.path, f.data, f.mode); err != nil {
			t.Fatal(err)
		}
	}

	pl, err := Compute(cfg, store, time.Now())
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	got := renderActions(pl.Actions)
	for _, want := range []string{
		"hook example.com/local:run:before deploy",
		"deploy example.com/local:update:fullchain update",
		"hook example.com/local:run:after deploy",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("actions:\n%s\nmissing %q", got, want)
		}
	}
}

func TestComputeReportsOrphanCertificateState(t *testing.T) {
	root := t.TempDir()
	store := storage.New(filepath.Join(root, "state"))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(store.CertDir("old.example.com"), 0o755); err != nil {
		t.Fatal(err)
	}

	pl, err := Compute(testConfig(root), store, time.Now())
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	got := renderActions(pl.Actions)
	want := "orphan certificate old.example.com:review:local state exists but certificate is not configured"
	if !strings.Contains(got, want) {
		t.Fatalf("actions:\n%s\nmissing %q", got, want)
	}
}

func TestComputePlansImplicitACMEAccount(t *testing.T) {
	store := storage.New(t.TempDir())
	cfg := &config.Config{
		Certificates: []*config.Certificate{{
			Name:  "example.com",
			CA:    "letsencrypt",
			Names: []string{"example.com"},
			Deploys: []*config.Deploy{{
				Name: "local",
				Cert: "/tmp/example.com.pem",
			}},
		}},
	}

	pl, err := Compute(cfg, store, time.Now())
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	got := renderActions(pl.Actions)
	for _, want := range []string{
		"account letsencrypt:register:implicit ACME account metadata missing",
		"certificate example.com:issue:certificate missing or unreadable",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("actions:\n%s\nmissing %q", got, want)
		}
	}
}

func TestComputePlansLocalCAAndSigning(t *testing.T) {
	store := storage.New(t.TempDir())
	cfg := &config.Config{
		CAs: []*config.CA{{
			Name: "dev",
			Type: "local",
		}},
		Certificates: []*config.Certificate{{
			Name:  "localhost",
			CA:    "dev",
			Names: []string{"localhost"},
			Deploys: []*config.Deploy{{
				Name: "local",
				Cert: "/tmp/localhost.pem",
			}},
		}},
	}

	pl, err := Compute(cfg, store, time.Now())
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	got := renderActions(pl.Actions)
	for _, want := range []string{
		"ca dev:create:local CA certificate missing or unreadable",
		"certificate localhost:sign:certificate missing or unreadable",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("actions:\n%s\nmissing %q", got, want)
		}
	}
}

func testConfig(root string) *config.Config {
	return &config.Config{
		Accounts: []*config.Account{{
			Name:      "letsencrypt",
			Directory: "https://example.invalid/directory",
			Email:     "admin@example.com",
		}},
		Certificates: []*config.Certificate{{
			Name:    "example.com",
			Account: "letsencrypt",
			Names:   []string{"example.com"},
			Renew:   config.RenewSpec{BeforeExpiry: 30 * 24 * time.Hour},
			Deploys: []*config.Deploy{{
				Name:      "local",
				Fullchain: filepath.Join(root, "deploy", "fullchain.pem"),
				Key:       filepath.Join(root, "deploy", "privkey.pem"),
				Mode:      modePtr(0o600),
			}},
		}},
	}
}

func modePtr(mode os.FileMode) *os.FileMode {
	return &mode
}

func makeCertPEM(t *testing.T, notBefore, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: bigOne(),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func bigOne() *big.Int {
	return big.NewInt(1)
}

func renderActions(actions []Action) string {
	var b strings.Builder
	for _, a := range actions {
		b.WriteString(a.Subject)
		b.WriteByte(':')
		b.WriteString(a.Verb)
		b.WriteByte(':')
		b.WriteString(a.Detail)
		b.WriteByte('\n')
	}
	return b.String()
}
