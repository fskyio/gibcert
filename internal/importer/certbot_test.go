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

package importer

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"foundry.fsky.io/fsky/gibcert/internal/storage"
)

func writeCertbotDir(t *testing.T, root, certName string, fc fakeCert, conf string) {
	t.Helper()
	liveDir := filepath.Join(root, "live", certName)
	archiveDir := filepath.Join(root, "archive", certName)
	if err := os.MkdirAll(liveDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(archiveDir, 0o755); err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(archiveDir, "cert1.pem")
	keyFile := filepath.Join(archiveDir, "privkey1.pem")
	chainFile := filepath.Join(archiveDir, "chain1.pem")
	if err := os.WriteFile(certFile, fc.leafPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, fc.keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(chainFile, fc.leafPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "..", "archive", certName, "cert1.pem"), filepath.Join(liveDir, "cert.pem")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "..", "archive", certName, "privkey1.pem"), filepath.Join(liveDir, "privkey.pem")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "..", "archive", certName, "chain1.pem"), filepath.Join(liveDir, "chain.pem")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "..", "archive", certName, "cert1.pem"), filepath.Join(liveDir, "fullchain.pem")); err != nil {
		t.Fatal(err)
	}
	if conf != "" {
		renewalDir := filepath.Join(root, "renewal")
		if err := os.MkdirAll(renewalDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(renewalDir, certName+".conf"), []byte(conf), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestImportCertbotHappyPath(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	notAfter := time.Now().Add(60 * 24 * time.Hour)
	fc := makeCert(t, false, []string{"example.com", "www.example.com"}, notAfter)
	writeCertbotDir(t, src, "example.com", fc,
		"server = https://acme-v02.api.letsencrypt.org/directory\n[renewalparams]\nserver = https://acme-v02.api.letsencrypt.org/directory\n")

	results, err := ImportCertbot(store, CertbotOptions{Path: src, Now: time.Now()})
	if err != nil {
		t.Fatalf("ImportCertbot: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results=%d, want 1", len(results))
	}
	r := results[0]
	if r.Status != StatusImported {
		t.Fatalf("status=%q detail=%q, want imported", r.Status, r.Detail)
	}
	if r.Name != "example.com" {
		t.Fatalf("name=%q, want example.com", r.Name)
	}

	meta, err := store.LoadCertMeta("example.com")
	if err != nil {
		t.Fatalf("LoadCertMeta: %v", err)
	}
	if meta.Directory != "https://acme-v02.api.letsencrypt.org/directory" {
		t.Fatalf("directory=%q, want LE prod URL", meta.Directory)
	}

	paths := store.CertPaths("example.com")
	for _, p := range []string{paths.Cert, paths.Chain, paths.Fullchain, paths.Key, paths.Meta} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("missing %s: %v", p, err)
		}
	}
}

func TestImportCertbotSkipExisting(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	fc := makeCert(t, false, []string{"example.com"}, time.Now().Add(60*24*time.Hour))
	writeCertbotDir(t, src, "example.com", fc, "")

	if _, err := ImportCertbot(store, CertbotOptions{Path: src, Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	results, err := ImportCertbot(store, CertbotOptions{Path: src, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Status != StatusSkipped {
		t.Fatalf("status=%q, want skipped", results[0].Status)
	}

	results, err = ImportCertbot(store, CertbotOptions{Path: src, Force: true, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Status != StatusImported {
		t.Fatalf("force status=%q detail=%q", results[0].Status, results[0].Detail)
	}
}

func TestImportCertbotDryRun(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	fc := makeCert(t, false, []string{"example.com"}, time.Now().Add(60*24*time.Hour))
	writeCertbotDir(t, src, "example.com", fc, "")

	results, err := ImportCertbot(store, CertbotOptions{Path: src, DryRun: true, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Status != StatusPlanned {
		t.Fatalf("status=%q, want planned", results[0].Status)
	}
	if _, err := os.Stat(store.CertPaths("example.com").Meta); !os.IsNotExist(err) {
		t.Fatalf("dry run wrote meta")
	}
}

func TestImportCertbotKeyMismatch(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	cert := makeCert(t, false, []string{"example.com"}, time.Now().Add(60*24*time.Hour))
	other := makeCert(t, false, []string{"example.com"}, time.Now().Add(60*24*time.Hour))
	cert.keyPEM = other.keyPEM
	writeCertbotDir(t, src, "example.com", cert, "")

	results, err := ImportCertbot(store, CertbotOptions{Path: src, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Status != StatusFailed {
		t.Fatalf("status=%q, want failed", results[0].Status)
	}
}

func TestImportCertbotExpired(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	expired := makeCert(t, false, []string{"example.com"}, time.Now().Add(-24*time.Hour))
	writeCertbotDir(t, src, "example.com", expired, "")

	results, err := ImportCertbot(store, CertbotOptions{Path: src, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Status != StatusImported {
		t.Fatalf("expired cert: status=%q, want imported", results[0].Status)
	}
	if !contains(results[0].Detail, "EXPIRED") {
		t.Fatalf("detail=%q, want EXPIRED tag", results[0].Detail)
	}
}

func TestImportCertbotOnlyFilter(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	a := makeCert(t, false, []string{"a.example"}, time.Now().Add(60*24*time.Hour))
	b := makeCert(t, false, []string{"b.example"}, time.Now().Add(60*24*time.Hour))
	writeCertbotDir(t, src, "a.example", a, "")
	writeCertbotDir(t, src, "b.example", b, "")

	results, err := ImportCertbot(store, CertbotOptions{Path: src, Only: []string{"a.example"}, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Name != "a.example" {
		t.Fatalf("results=%+v, want only a.example", results)
	}
}

func TestImportCertbotNameOverride(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	fc := makeCert(t, true, []string{"example.com"}, time.Now().Add(60*24*time.Hour))
	writeCertbotDir(t, src, "example.com", fc, "")

	results, err := ImportCertbot(store, CertbotOptions{
		Path: src,
		Only: []string{"example.com"},
		Name: "my-cert",
		Now:  time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Source != "example.com" || results[0].Name != "my-cert" {
		t.Fatalf("results=%+v, want source example.com target my-cert", results)
	}
	if _, err := store.LoadCertMeta("my-cert"); err != nil {
		t.Fatalf("LoadCertMeta override target: %v", err)
	}
}

func TestImportCertbotNameOverrideRequiresSingle(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	a := makeCert(t, false, []string{"a.example"}, time.Now().Add(60*24*time.Hour))
	b := makeCert(t, false, []string{"b.example"}, time.Now().Add(60*24*time.Hour))
	writeCertbotDir(t, src, "a.example", a, "")
	writeCertbotDir(t, src, "b.example", b, "")

	if _, err := ImportCertbot(store, CertbotOptions{Path: src, Name: "example.com", Now: time.Now()}); err == nil {
		t.Fatal("ImportCertbot with --name and multiple candidates succeeded, want error")
	}
}

func TestImportCertbotNoLiveDir(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	_, err := ImportCertbot(store, CertbotOptions{Path: src, Now: time.Now()})
	if err == nil {
		t.Fatal("expected error when no live/ directory exists")
	}
}

func TestImportCertbotSkipsNonDirEntries(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	if err := os.MkdirAll(filepath.Join(src, "live"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "live", "README"), []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}
	results, err := ImportCertbot(store, CertbotOptions{Path: src, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("results=%+v, want empty", results)
	}
}

func TestImportCertbotServerFromRenewalConf(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	notAfter := time.Now().Add(60 * 24 * time.Hour)
	fc := makeCert(t, false, []string{"example.com"}, notAfter)
	conf := `# renew before expiry, Mon Jan 01 00:00:00 UTC 2024
cert = /etc/letsencrypt/live/example.com/cert.pem
privkey = /etc/letsencrypt/live/example.com/privkey.pem
chain = /etc/letsencrypt/live/example.com/chain.pem
fullchain = /etc/letsencrypt/live/example.com/fullchain.pem

[renewalparams]
account = abcdef1234567890
authenticator = standalone
server = https://acme-staging-v02.api.letsencrypt.org/directory
`
	writeCertbotDir(t, src, "example.com", fc, conf)

	results, err := ImportCertbot(store, CertbotOptions{Path: src, Now: time.Now()})
	if err != nil {
		t.Fatalf("ImportCertbot: %v", err)
	}
	if results[0].Status != StatusImported {
		t.Fatalf("status=%q detail=%q", results[0].Status, results[0].Detail)
	}
	meta, err := store.LoadCertMeta("example.com")
	if err != nil {
		t.Fatalf("LoadCertMeta: %v", err)
	}
	if meta.Directory != "https://acme-staging-v02.api.letsencrypt.org/directory" {
		t.Fatalf("directory=%q, want staging URL", meta.Directory)
	}
}

func TestImportCertbotNoChain(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	notAfter := time.Now().Add(60 * 24 * time.Hour)
	fc := makeCert(t, false, []string{"example.com"}, notAfter)

	liveDir := filepath.Join(src, "live", "example.com")
	archiveDir := filepath.Join(src, "archive", "example.com")
	if err := os.MkdirAll(liveDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(archiveDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(archiveDir, "cert1.pem"), fc.leafPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(archiveDir, "privkey1.pem"), fc.keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "..", "archive", "example.com", "cert1.pem"), filepath.Join(liveDir, "cert.pem")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "..", "archive", "example.com", "privkey1.pem"), filepath.Join(liveDir, "privkey.pem")); err != nil {
		t.Fatal(err)
	}

	results, err := ImportCertbot(store, CertbotOptions{Path: src, Now: time.Now()})
	if err != nil {
		t.Fatalf("ImportCertbot: %v", err)
	}
	if results[0].Status != StatusImported {
		t.Fatalf("status=%q detail=%q, want imported", results[0].Status, results[0].Detail)
	}
}
