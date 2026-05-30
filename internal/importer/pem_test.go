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

func TestImportPEMFullchain(t *testing.T) {
	stateDir := t.TempDir()
	store := storage.New(stateDir)
	src := t.TempDir()

	leaf := makeCert(t, false, []string{"example.com", "www.example.com"}, time.Now().Add(60*24*time.Hour))
	issuer := makeCert(t, false, []string{"issuer.example"}, time.Now().Add(365*24*time.Hour))
	fullchainPath := filepath.Join(src, "fullchain.pem")
	keyPath := filepath.Join(src, "privkey.pem")
	fullchainPEM := append(append([]byte{}, leaf.leafPEM...), issuer.leafPEM...)
	if err := os.WriteFile(fullchainPath, fullchainPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, leaf.keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	results, err := ImportPEM(store, PEMOptions{
		Name:          "example.com",
		FullchainPath: fullchainPath,
		KeyPath:       keyPath,
		Now:           time.Now(),
	})
	if err != nil {
		t.Fatalf("ImportPEM: %v", err)
	}
	if len(results) != 1 || results[0].Status != StatusImported {
		t.Fatalf("results=%+v, want imported", results)
	}
	meta, err := store.LoadCertMeta("example.com")
	if err != nil {
		t.Fatalf("LoadCertMeta: %v", err)
	}
	if meta.IssuerType != "imported" {
		t.Fatalf("issuer_type=%q, want imported", meta.IssuerType)
	}
	if len(meta.Names) != 2 || meta.Names[0] != "example.com" {
		t.Fatalf("names=%v, want DNS SANs", meta.Names)
	}
	paths := store.CertPaths("example.com")
	if b, err := os.ReadFile(paths.Cert); err != nil || string(b) != string(leaf.leafPEM) {
		t.Fatalf("cert file got %d bytes err=%v, want leaf", len(b), err)
	}
	if b, err := os.ReadFile(paths.Chain); err != nil || string(b) != string(issuer.leafPEM) {
		t.Fatalf("chain file got %d bytes err=%v, want issuer", len(b), err)
	}
}

func TestImportPEMCertAndChain(t *testing.T) {
	stateDir := t.TempDir()
	store := storage.New(stateDir)
	src := t.TempDir()

	leaf := makeCert(t, false, []string{"example.com"}, time.Now().Add(60*24*time.Hour))
	issuer := makeCert(t, false, []string{"issuer.example"}, time.Now().Add(365*24*time.Hour))
	certPath := filepath.Join(src, "cert.pem")
	chainPath := filepath.Join(src, "chain.pem")
	keyPath := filepath.Join(src, "privkey.pem")
	for path, data := range map[string][]byte{
		certPath:  leaf.leafPEM,
		chainPath: issuer.leafPEM,
		keyPath:   leaf.keyPEM,
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	results, err := ImportPEM(store, PEMOptions{
		Name:      "example.com",
		CertPath:  certPath,
		ChainPath: chainPath,
		KeyPath:   keyPath,
		Now:       time.Now(),
	})
	if err != nil {
		t.Fatalf("ImportPEM: %v", err)
	}
	if len(results) != 1 || results[0].Status != StatusImported {
		t.Fatalf("results=%+v, want imported", results)
	}
}

func TestImportPEMRequiresValidInputSelection(t *testing.T) {
	store := storage.New(t.TempDir())
	_, err := ImportPEM(store, PEMOptions{Name: "example.com", KeyPath: "key.pem"})
	if err == nil {
		t.Fatal("ImportPEM without cert/fullchain succeeded, want error")
	}
	_, err = ImportPEM(store, PEMOptions{Name: "example.com", KeyPath: "key.pem", CertPath: "cert.pem", FullchainPath: "fullchain.pem"})
	if err == nil {
		t.Fatal("ImportPEM with cert and fullchain succeeded, want error")
	}
	_, err = ImportPEM(store, PEMOptions{Name: "example.com", KeyPath: "key.pem", ChainPath: "chain.pem", FullchainPath: "fullchain.pem"})
	if err == nil {
		t.Fatal("ImportPEM with chain and fullchain succeeded, want error")
	}
}

func TestImportPEMRejectsUnsafeName(t *testing.T) {
	store := storage.New(t.TempDir())
	src := t.TempDir()

	leaf := makeCert(t, false, []string{"example.com"}, time.Now().Add(60*24*time.Hour))
	certPath := filepath.Join(src, "cert.pem")
	keyPath := filepath.Join(src, "privkey.pem")
	if err := os.WriteFile(certPath, leaf.leafPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, leaf.keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	results, err := ImportPEM(store, PEMOptions{
		Name:     "../../outside",
		CertPath: certPath,
		KeyPath:  keyPath,
		Now:      time.Now(),
	})
	if err != nil {
		t.Fatalf("ImportPEM: %v", err)
	}
	if len(results) != 1 || results[0].Status != StatusFailed {
		t.Fatalf("results=%+v, want failed", results)
	}
	if want := "invalid name: must not contain path separators"; results[0].Detail != want {
		t.Fatalf("detail=%q, want %q", results[0].Detail, want)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(store.Root), "outside")); !os.IsNotExist(err) {
		t.Fatalf("outside state path err=%v, want missing", err)
	}
}

func TestImportPEMPreservesDeployAndTLSAMetadataOnForce(t *testing.T) {
	stateDir := t.TempDir()
	store := storage.New(stateDir)
	src := t.TempDir()

	old := makeCert(t, false, []string{"example.com"}, time.Now().Add(30*24*time.Hour))
	newCert := makeCert(t, true, []string{"example.com"}, time.Now().Add(60*24*time.Hour))
	certPath := filepath.Join(src, "cert.pem")
	keyPath := filepath.Join(src, "privkey.pem")
	if err := importCertFixture(store, "example.com", old); err != nil {
		t.Fatal(err)
	}
	paths := store.CertPaths("example.com")
	if err := store.SaveCertMeta("example.com", storage.CertMeta{
		Name:       "example.com",
		IssuerType: "imported",
		Deploys: []storage.CertDeployMeta{{
			Target: "web",
			Kind:   "cert",
			Path:   "/srv/cert.pem",
		}},
		TLSA: &storage.CertTLSAMeta{TTL: 3600},
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, newCert.leafPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, newCert.keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	results, err := ImportPEM(store, PEMOptions{
		Name:     "example.com",
		CertPath: certPath,
		KeyPath:  keyPath,
		Force:    true,
		Now:      time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Status != StatusImported {
		t.Fatalf("status=%q detail=%q, want imported", results[0].Status, results[0].Detail)
	}
	meta, err := store.LoadCertMeta("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.Deploys) != 1 || meta.Deploys[0].Target != "web" {
		t.Fatalf("deploy metadata not preserved: %+v", meta.Deploys)
	}
	if meta.TLSA == nil || meta.TLSA.TTL != 3600 {
		t.Fatalf("TLSA metadata not preserved: %+v", meta.TLSA)
	}
	if _, err := os.Stat(paths.Chain); !os.IsNotExist(err) {
		t.Fatalf("chain path after no-chain force import err=%v, want missing", err)
	}
}

func importCertFixture(store *storage.Store, name string, fc fakeCert) error {
	paths := store.CertPaths(name)
	if err := os.MkdirAll(paths.Dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(paths.Cert, fc.leafPEM, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(paths.Key, fc.keyPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(paths.Chain, fc.leafPEM, 0o644); err != nil {
		return err
	}
	return nil
}
