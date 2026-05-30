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

func writeLegoDir(t *testing.T, certsDir, baseName string, fc fakeCert, withIssuer bool) {
	t.Helper()
	if err := os.MkdirAll(certsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	chainPEM := fc.leafPEM
	if err := os.WriteFile(filepath.Join(certsDir, baseName+".crt"), chainPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certsDir, baseName+".key"), fc.keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if withIssuer {
		if err := os.WriteFile(filepath.Join(certsDir, baseName+".issuer.crt"), fc.leafPEM, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func writeLegoDirWithIssuer(t *testing.T, certsDir, baseName string, fc fakeCert, issuerPEM []byte) {
	t.Helper()
	if err := os.MkdirAll(certsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certsDir, baseName+".crt"), fc.leafPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certsDir, baseName+".key"), fc.keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certsDir, baseName+".issuer.crt"), issuerPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestImportLegoHappyPath(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	notAfter := time.Now().Add(60 * 24 * time.Hour)
	fc := makeCert(t, false, []string{"example.com", "www.example.com"}, notAfter)
	writeLegoDir(t, filepath.Join(src, "certificates"), "example.com", fc, false)

	results, err := ImportLego(store, LegoOptions{Path: src, Now: time.Now()})
	if err != nil {
		t.Fatalf("ImportLego: %v", err)
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
	if meta.IssuerType != "imported" {
		t.Fatalf("issuer_type=%q, want imported", meta.IssuerType)
	}
	if len(meta.Names) != 2 || meta.Names[0] != "example.com" {
		t.Fatalf("names=%v", meta.Names)
	}
}

func TestImportLegoWithIssuer(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	notAfter := time.Now().Add(60 * 24 * time.Hour)
	fc := makeCert(t, false, []string{"example.com"}, notAfter)
	writeLegoDirWithIssuer(t, filepath.Join(src, "certificates"), "example.com", fc, fc.leafPEM)

	results, err := ImportLego(store, LegoOptions{Path: src, Now: time.Now()})
	if err != nil {
		t.Fatalf("ImportLego: %v", err)
	}
	if results[0].Status != StatusImported {
		t.Fatalf("status=%q detail=%q, want imported", results[0].Status, results[0].Detail)
	}
	paths := store.CertPaths("example.com")
	if _, err := os.Stat(paths.Chain); err != nil {
		t.Fatalf("missing chain file: %v", err)
	}
}

func TestImportLegoSkipExisting(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	fc := makeCert(t, false, []string{"example.com"}, time.Now().Add(60*24*time.Hour))
	writeLegoDir(t, filepath.Join(src, "certificates"), "example.com", fc, false)

	if _, err := ImportLego(store, LegoOptions{Path: src, Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	results, err := ImportLego(store, LegoOptions{Path: src, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Status != StatusSkipped {
		t.Fatalf("status=%q, want skipped", results[0].Status)
	}

	results, err = ImportLego(store, LegoOptions{Path: src, Force: true, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Status != StatusImported {
		t.Fatalf("force status=%q detail=%q", results[0].Status, results[0].Detail)
	}
}

func TestImportLegoDryRun(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	fc := makeCert(t, false, []string{"example.com"}, time.Now().Add(60*24*time.Hour))
	writeLegoDir(t, filepath.Join(src, "certificates"), "example.com", fc, false)

	results, err := ImportLego(store, LegoOptions{Path: src, DryRun: true, Now: time.Now()})
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

func TestImportLegoKeyMismatch(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	cert := makeCert(t, false, []string{"example.com"}, time.Now().Add(60*24*time.Hour))
	other := makeCert(t, false, []string{"example.com"}, time.Now().Add(60*24*time.Hour))
	cert.keyPEM = other.keyPEM
	writeLegoDir(t, filepath.Join(src, "certificates"), "example.com", cert, false)

	results, err := ImportLego(store, LegoOptions{Path: src, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Status != StatusFailed {
		t.Fatalf("status=%q, want failed", results[0].Status)
	}
}

func TestImportLegoExpired(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	expired := makeCert(t, false, []string{"example.com"}, time.Now().Add(-24*time.Hour))
	writeLegoDir(t, filepath.Join(src, "certificates"), "example.com", expired, false)

	results, err := ImportLego(store, LegoOptions{Path: src, Now: time.Now()})
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

func TestImportLegoOnlyFilter(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	a := makeCert(t, false, []string{"a.example"}, time.Now().Add(60*24*time.Hour))
	b := makeCert(t, false, []string{"b.example"}, time.Now().Add(60*24*time.Hour))
	writeLegoDir(t, filepath.Join(src, "certificates"), "a.example", a, false)
	writeLegoDir(t, filepath.Join(src, "certificates"), "b.example", b, false)

	results, err := ImportLego(store, LegoOptions{Path: src, Only: []string{"a.example"}, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Name != "a.example" {
		t.Fatalf("results=%+v, want only a.example", results)
	}
}

func TestImportLegoNameOverride(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	fc := makeCert(t, true, []string{"example.com"}, time.Now().Add(60*24*time.Hour))
	writeLegoDir(t, filepath.Join(src, "certificates"), "example.com", fc, false)

	results, err := ImportLego(store, LegoOptions{
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

func TestImportLegoNameOverrideRequiresSingle(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	a := makeCert(t, false, []string{"a.example"}, time.Now().Add(60*24*time.Hour))
	b := makeCert(t, false, []string{"b.example"}, time.Now().Add(60*24*time.Hour))
	writeLegoDir(t, filepath.Join(src, "certificates"), "a.example", a, false)
	writeLegoDir(t, filepath.Join(src, "certificates"), "b.example", b, false)

	if _, err := ImportLego(store, LegoOptions{Path: src, Name: "my-cert", Now: time.Now()}); err == nil {
		t.Fatal("ImportLego with --name and multiple candidates succeeded, want error")
	}
}

func TestImportLegoNoCertsDir(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	_, err := ImportLego(store, LegoOptions{Path: src, Now: time.Now()})
	if err == nil {
		t.Fatal("expected error when no certificates/ directory exists")
	}
}

func TestImportLegoWildcard(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	notAfter := time.Now().Add(60 * 24 * time.Hour)
	fc := makeCert(t, true, []string{"*.example.com"}, notAfter)
	writeLegoDir(t, filepath.Join(src, "certificates"), "_.example.com", fc, false)

	results, err := ImportLego(store, LegoOptions{Path: src, Now: time.Now()})
	if err != nil {
		t.Fatalf("ImportLego: %v", err)
	}
	if results[0].Status != StatusImported {
		t.Fatalf("status=%q detail=%q, want imported", results[0].Status, results[0].Detail)
	}
	if results[0].Name != "_.example.com" {
		t.Fatalf("name=%q, want _.example.com", results[0].Name)
	}
}
