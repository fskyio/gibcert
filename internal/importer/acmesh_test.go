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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"foundry.fsky.io/fsky/gibcert/internal/storage"
)

type fakeCert struct {
	dnsNames []string
	cn       string
	notAfter time.Time
	priv     any
	leafPEM  []byte
	keyPEM   []byte
}

func makeCert(t *testing.T, ecc bool, dnsNames []string, notAfter time.Time) fakeCert {
	t.Helper()
	var priv any
	var pub any
	if ecc {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		priv = k
		pub = &k.PublicKey
	} else {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		priv = k
		pub = &k.PublicKey
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		DNSNames:     dnsNames,
		NotBefore:    notAfter.Add(-90 * 24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	return fakeCert{
		dnsNames: dnsNames,
		cn:       dnsNames[0],
		notAfter: notAfter,
		priv:     priv,
		leafPEM:  leafPEM,
		keyPEM:   keyPEM,
	}
}

func writeACMEShDir(t *testing.T, root, dirName, baseName string, fc fakeCert, conf string) {
	t.Helper()
	d := filepath.Join(root, dirName)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, baseName+".cer"), fc.leafPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, baseName+".key"), fc.keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	// chain: re-use the leaf as a stand-in intermediate; we only verify it parses.
	if err := os.WriteFile(filepath.Join(d, "ca.cer"), fc.leafPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if conf != "" {
		if err := os.WriteFile(filepath.Join(d, baseName+".conf"), []byte(conf), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestImportACMEShHappyPath(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	notAfter := time.Now().Add(60 * 24 * time.Hour)
	fc := makeCert(t, false, []string{"example.com", "www.example.com"}, notAfter)
	writeACMEShDir(t, src, "example.com", "example.com", fc,
		"Le_API='https://acme-v02.api.letsencrypt.org/directory'\n")

	results, err := ImportACMESh(store, ACMEShOptions{Path: src, Now: time.Now()})
	if err != nil {
		t.Fatalf("ImportACMESh: %v", err)
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
	if meta.Directory != "https://acme-v02.api.letsencrypt.org/directory" {
		t.Fatalf("directory=%q, want LE prod URL", meta.Directory)
	}
	if len(meta.Names) != 2 || meta.Names[0] != "example.com" {
		t.Fatalf("names=%v", meta.Names)
	}

	paths := store.CertPaths("example.com")
	for _, p := range []string{paths.Cert, paths.Chain, paths.Fullchain, paths.Key, paths.Meta} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("missing %s: %v", p, err)
		}
	}
}

func TestImportACMEShECCRenaming(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	notAfter := time.Now().Add(60 * 24 * time.Hour)
	rsaCert := makeCert(t, false, []string{"example.com"}, notAfter)
	eccCert := makeCert(t, true, []string{"example.com"}, notAfter)
	writeACMEShDir(t, src, "example.com", "example.com", rsaCert, "")
	writeACMEShDir(t, src, "example.com_ecc", "example.com", eccCert, "")

	results, err := ImportACMESh(store, ACMEShOptions{Path: src, Now: time.Now()})
	if err != nil {
		t.Fatalf("ImportACMESh: %v", err)
	}
	names := map[string]string{}
	for _, r := range results {
		names[r.Name] = r.Status
	}
	if names["example.com"] != StatusImported || names["example.com-ecc"] != StatusImported {
		t.Fatalf("results=%v, want both imported", names)
	}
	if _, err := store.LoadCertMeta("example.com"); err != nil {
		t.Fatalf("RSA cert not stored: %v", err)
	}
	if _, err := store.LoadCertMeta("example.com-ecc"); err != nil {
		t.Fatalf("ECC cert not stored: %v", err)
	}
}

func TestImportACMEShSkipExisting(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	fc := makeCert(t, false, []string{"example.com"}, time.Now().Add(60*24*time.Hour))
	writeACMEShDir(t, src, "example.com", "example.com", fc, "")

	if _, err := ImportACMESh(store, ACMEShOptions{Path: src, Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	results, err := ImportACMESh(store, ACMEShOptions{Path: src, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Status != StatusSkipped {
		t.Fatalf("status=%q, want skipped", results[0].Status)
	}

	// --force overwrites and archives the old key.
	results, err = ImportACMESh(store, ACMEShOptions{Path: src, Force: true, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Status != StatusImported {
		t.Fatalf("force status=%q detail=%q", results[0].Status, results[0].Detail)
	}
	entries, err := os.ReadDir(store.CertPaths("example.com").Dir)
	if err != nil {
		t.Fatal(err)
	}
	archived := false
	for _, e := range entries {
		if len(e.Name()) > len("privkey-") && e.Name()[:len("privkey-")] == "privkey-" && e.Name() != "privkey.pem" {
			archived = true
		}
	}
	if !archived {
		t.Fatalf("expected archived privkey, got %v", entries)
	}
}

func TestImportACMEShDryRun(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	fc := makeCert(t, false, []string{"example.com"}, time.Now().Add(60*24*time.Hour))
	writeACMEShDir(t, src, "example.com", "example.com", fc, "")

	results, err := ImportACMESh(store, ACMEShOptions{Path: src, DryRun: true, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Status != StatusPlanned {
		t.Fatalf("status=%q, want planned", results[0].Status)
	}
	if _, err := os.Stat(store.CertPaths("example.com").Meta); !os.IsNotExist(err) {
		t.Fatalf("dry run wrote meta: %v", err)
	}
}

func TestImportACMEShKeyMismatch(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	cert := makeCert(t, false, []string{"example.com"}, time.Now().Add(60*24*time.Hour))
	other := makeCert(t, false, []string{"example.com"}, time.Now().Add(60*24*time.Hour))
	// Swap in a non-matching key.
	cert.keyPEM = other.keyPEM
	writeACMEShDir(t, src, "example.com", "example.com", cert, "")

	results, err := ImportACMESh(store, ACMEShOptions{Path: src, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Status != StatusFailed {
		t.Fatalf("status=%q, want failed", results[0].Status)
	}
}

func TestImportACMEShExpired(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	expired := makeCert(t, false, []string{"example.com"}, time.Now().Add(-24*time.Hour))
	writeACMEShDir(t, src, "example.com", "example.com", expired, "")

	results, err := ImportACMESh(store, ACMEShOptions{Path: src, Now: time.Now()})
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

func TestImportACMEShOnlyFilter(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	a := makeCert(t, false, []string{"a.example"}, time.Now().Add(60*24*time.Hour))
	b := makeCert(t, false, []string{"b.example"}, time.Now().Add(60*24*time.Hour))
	writeACMEShDir(t, src, "a.example", "a.example", a, "")
	writeACMEShDir(t, src, "b.example", "b.example", b, "")

	results, err := ImportACMESh(store, ACMEShOptions{Path: src, Only: []string{"a.example"}, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Name != "a.example" {
		t.Fatalf("results=%+v, want only a.example", results)
	}
}

func TestImportACMEShOnlyFilterMatchesECCTargetName(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	ecc := makeCert(t, true, []string{"example.com"}, time.Now().Add(60*24*time.Hour))
	writeACMEShDir(t, src, "example.com_ecc", "example.com", ecc, "")

	results, err := ImportACMESh(store, ACMEShOptions{Path: src, Only: []string{"example.com-ecc"}, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Name != "example.com-ecc" {
		t.Fatalf("results=%+v, want target example.com-ecc", results)
	}
}

func TestImportACMEShNameOverride(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	ecc := makeCert(t, true, []string{"example.com"}, time.Now().Add(60*24*time.Hour))
	writeACMEShDir(t, src, "example.com_ecc", "example.com", ecc, "")

	results, err := ImportACMESh(store, ACMEShOptions{
		Path: src,
		Only: []string{
			"example.com_ecc",
		},
		Name: "example.com",
		Now:  time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Source != "example.com_ecc" || results[0].Name != "example.com" {
		t.Fatalf("results=%+v, want source example.com_ecc target example.com", results)
	}
	if _, err := store.LoadCertMeta("example.com"); err != nil {
		t.Fatalf("LoadCertMeta override target: %v", err)
	}
}

func TestImportACMEShNameOverrideRequiresSingleCandidate(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	a := makeCert(t, false, []string{"a.example"}, time.Now().Add(60*24*time.Hour))
	b := makeCert(t, false, []string{"b.example"}, time.Now().Add(60*24*time.Hour))
	writeACMEShDir(t, src, "a.example", "a.example", a, "")
	writeACMEShDir(t, src, "b.example", "b.example", b, "")

	if _, err := ImportACMESh(store, ACMEShOptions{Path: src, Name: "example.com", Now: time.Now()}); err == nil {
		t.Fatal("ImportACMESh with --name and multiple candidates succeeded, want error")
	}
}

func TestImportACMEShSkipsCADir(t *testing.T) {
	src := t.TempDir()
	stateDir := t.TempDir()
	store := storage.New(stateDir)

	// acme.sh has a top-level "ca/" directory; importer must ignore it.
	if err := os.MkdirAll(filepath.Join(src, "ca", "acme-v02.api.letsencrypt.org"), 0o755); err != nil {
		t.Fatal(err)
	}
	results, err := ImportACMESh(store, ACMEShOptions{Path: src, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("results=%+v, want empty", results)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
