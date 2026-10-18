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

package prune

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gitfield.org/fsky/gibcert/internal/config"
	"gitfield.org/fsky/gibcert/internal/storage"
)

var now = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

// baseConfig has an explicit account with an implicit failover account, and a
// certificate signed by a local CA.
func baseConfig() *config.Config {
	return &config.Config{
		CAs: []*config.CA{{Name: "dev", Type: "local"}},
		Accounts: []*config.Account{{
			Name:      "main",
			CA:        "letsencrypt",
			Directory: "https://acme-v02.api.letsencrypt.org/directory",
		}},
		Certificates: []*config.Certificate{
			{Name: "live.example", Account: "main", Failover: []config.Issuer{{CA: "zerossl"}}},
			{Name: "internal.example", CA: "dev"},
		},
	}
}

func newStore(t *testing.T) *storage.Store {
	t.Helper()
	store := storage.New(t.TempDir())
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	return store
}

func saveCert(t *testing.T, store *storage.Store, name string, meta storage.CertMeta) {
	t.Helper()
	meta.Name = name
	if err := store.SaveCertMeta(name, meta); err != nil {
		t.Fatal(err)
	}
}

func saveAccount(t *testing.T, store *storage.Store, name string) {
	t.Helper()
	if err := store.SaveAccountMeta(name, storage.AccountMeta{Directory: "https://ca.example/" + name}); err != nil {
		t.Fatal(err)
	}
	writeFile(t, store.AccountKeyPath(name), "key")
}

func saveCA(t *testing.T, store *storage.Store, name string) {
	t.Helper()
	writeFile(t, store.CAPaths(name).Key, "key")
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func scan(t *testing.T, cfg *config.Config, store *storage.Store, opts Options) Report {
	t.Helper()
	report, err := Scan(cfg, store, now, opts)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return report
}

// wantItems requires the report to hold exactly the given IDs with the given
// removal state.
func wantItems(t *testing.T, report Report, want map[string]bool) {
	t.Helper()
	got := map[string]bool{}
	for _, it := range report.Items {
		got[it.ID()] = it.Remove
	}
	for id, remove := range want {
		g, ok := got[id]
		if !ok {
			t.Errorf("%s: missing from report", id)
		} else if g != remove {
			t.Errorf("%s: Remove = %v, want %v", id, g, remove)
		}
	}
	for id := range got {
		if _, ok := want[id]; !ok {
			t.Errorf("%s: unexpected item in report", id)
		}
	}
}

func findItem(t *testing.T, report Report, id string) Item {
	t.Helper()
	for _, it := range report.Items {
		if it.ID() == id {
			return it
		}
	}
	t.Fatalf("%s: not in report", id)
	return Item{}
}

func TestScanClassifiesOrphanCerts(t *testing.T) {
	store := newStore(t)
	cfg := baseConfig()
	valid := now.Add(24 * time.Hour)
	revokedAt := now.Add(-time.Hour)
	saveCert(t, store, "live.example", storage.CertMeta{NotAfter: now.Add(-24 * time.Hour)})
	saveCert(t, store, "expired.example", storage.CertMeta{NotAfter: now.Add(-48 * time.Hour)})
	saveCert(t, store, "revoked.example", storage.CertMeta{NotAfter: valid, RevokedAt: &revokedAt})
	saveCert(t, store, "valid.example", storage.CertMeta{NotAfter: valid})
	saveCert(t, store, "noexpiry.example", storage.CertMeta{})
	if err := os.MkdirAll(store.CertDir("nometa.example"), 0o755); err != nil {
		t.Fatal(err)
	}

	report := scan(t, cfg, store, Options{Certs: true})
	wantItems(t, report, map[string]bool{
		"cert/expired.example":  true,
		"cert/revoked.example":  true,
		"cert/valid.example":    false,
		"cert/noexpiry.example": true,
		"cert/nometa.example":   true,
	})
	if got := findItem(t, report, "cert/valid.example").Reason; !strings.Contains(got, "--include-valid") {
		t.Errorf("valid orphan reason = %q, want a hint about --include-valid", got)
	}

	report = scan(t, cfg, store, Options{Certs: true, IncludeValid: true})
	if !findItem(t, report, "cert/valid.example").Remove {
		t.Error("valid orphan kept despite IncludeValid")
	}
}

func TestScanDependenciesFollowSurvivors(t *testing.T) {
	store := newStore(t)
	cfg := baseConfig()
	for _, name := range []string{"main", "ca:zerossl", "ca:google", "ca:buypass", "old"} {
		saveAccount(t, store, name)
	}
	for _, name := range []string{"dev", "gone", "held"} {
		saveCA(t, store, name)
	}
	// A configured certificate keeps the account it was issued with, even
	// after the config moved on to another issuer.
	saveCert(t, store, "live.example", storage.CertMeta{Account: "old", NotAfter: now.Add(time.Hour)})
	saveCert(t, store, "orphan.example", storage.CertMeta{Account: "ca:buypass", CA: "held", NotAfter: now.Add(time.Hour)})

	// Orphan certs are not selected, so they survive and keep their issuers.
	report := scan(t, cfg, store, Options{Accounts: true, CAs: true})
	wantItems(t, report, map[string]bool{
		"account/main":       false, // declared in config
		"account/ca:zerossl": false, // failover issuer of a configured cert
		"account/old":        false, // recorded by a configured cert
		"account/ca:buypass": false, // recorded by a surviving orphan
		"account/ca:google":  true,
		"ca/dev":             false,
		"ca/held":            false,
		"ca/gone":            true,
	})
	if got := findItem(t, report, "account/ca:buypass").Reason; !strings.Contains(got, "cert/orphan.example") {
		t.Errorf("kept account reason = %q, want it to name the certificate that needs it", got)
	}

	// Once the orphan goes, what only it needed becomes removable.
	all := Options{Certs: true, Accounts: true, CAs: true, IncludeValid: true}
	report = scan(t, cfg, store, all)
	wantItems(t, report, map[string]bool{
		"cert/orphan.example": true,
		"account/main":        false,
		"account/ca:zerossl":  false,
		"account/old":         false,
		"account/ca:buypass":  true,
		"account/ca:google":   true,
		"ca/dev":              false,
		"ca/held":             true,
		"ca/gone":             true,
	})

	// Excepting the orphan keeps it, and with it what it needs.
	all.Except = []string{"cert/orphan.example"}
	report = scan(t, cfg, store, all)
	wantItems(t, report, map[string]bool{
		"cert/orphan.example": false,
		"account/main":        false,
		"account/ca:zerossl":  false,
		"account/old":         false,
		"account/ca:buypass":  false,
		"account/ca:google":   true,
		"ca/dev":              false,
		"ca/held":             false,
		"ca/gone":             true,
	})
}

func TestScanImplicitAccountNeedsAConfiguredCertificate(t *testing.T) {
	store := newStore(t)
	cfg := baseConfig()
	cfg.Certificates = append(cfg.Certificates, &config.Certificate{Name: "viaca.example", CA: "letsencrypt"})
	saveAccount(t, store, "ca:letsencrypt")
	saveAccount(t, store, "ca:google")

	report := scan(t, cfg, store, Options{Accounts: true})
	wantItems(t, report, map[string]bool{
		"account/ca:letsencrypt": false,
		"account/ca:google":      true,
	})
}

func TestScanAccountKeyArchives(t *testing.T) {
	store := newStore(t)
	cfg := baseConfig()
	saveAccount(t, store, "main")
	saveAccount(t, store, "ca:google")
	archives := []string{"account-20260101T000000Z.key", "account-20260201T000000Z.key", "account-20260301T000000Z.key"}
	for _, a := range []string{"main", "ca:google"} {
		for _, f := range archives {
			writeFile(t, filepath.Join(store.AccountDir(a), f), "old")
		}
	}
	writeFile(t, store.AccountKeyNextPath("main"), "staged")
	writeFile(t, filepath.Join(store.AccountDir("main"), "account-notes.key"), "not an archive")

	report := scan(t, cfg, store, Options{AccountKeys: true})
	wantItems(t, report, map[string]bool{
		"account-key/main/account-20260101T000000Z.key":      true,
		"account-key/main/account-20260201T000000Z.key":      true,
		"account-key/ca:google/account-20260101T000000Z.key": true,
		"account-key/ca:google/account-20260201T000000Z.key": true,
	})

	// An account that is removed takes its archives with it.
	report = scan(t, cfg, store, Options{Accounts: true, AccountKeys: true})
	for _, it := range report.Items {
		if it.Kind == KindAccountKey && strings.HasPrefix(it.Name, "ca:google/") {
			t.Errorf("%s listed although its account is removed", it.ID())
		}
	}

	report = scan(t, cfg, store, Options{AccountKeys: true})
	for _, r := range Apply(report, store) {
		if r.Err != nil {
			t.Fatalf("Apply %s: %v", r.Item.ID(), r.Err)
		}
	}
	for _, a := range []string{"main", "ca:google"} {
		if !exists(filepath.Join(store.AccountDir(a), archives[2])) {
			t.Errorf("%s: newest archive removed", a)
		}
		for _, f := range archives[:2] {
			if exists(filepath.Join(store.AccountDir(a), f)) {
				t.Errorf("%s: %s survived", a, f)
			}
		}
		if !exists(store.AccountKeyPath(a)) {
			t.Errorf("%s: live account key removed", a)
		}
	}
	for _, p := range []string{store.AccountKeyNextPath("main"), filepath.Join(store.AccountDir("main"), "account-notes.key")} {
		if !exists(p) {
			t.Errorf("%s removed", p)
		}
	}
}

func TestScanExceptMustMatchACandidate(t *testing.T) {
	store := newStore(t)
	cfg := baseConfig()
	saveAccount(t, store, "main")
	saveCert(t, store, "expired.example", storage.CertMeta{NotAfter: now.Add(-time.Hour)})

	_, err := Scan(cfg, store, now, Options{Certs: true, Except: []string{"cert/expierd.example"}})
	if err == nil || !strings.Contains(err.Error(), "cert/expierd.example") {
		t.Fatalf("typo in --except: err = %v, want it to name the unknown ID", err)
	}

	// IDs of items outside the selected categories and of kept items are valid.
	report := scan(t, cfg, store, Options{Certs: true, Except: []string{"account/main", "cert/expired.example"}})
	wantItems(t, report, map[string]bool{"cert/expired.example": false})
	if got := findItem(t, report, "cert/expired.example").Reason; !strings.HasPrefix(got, "kept by --except") {
		t.Errorf("excepted reason = %q", got)
	}
}

func TestScanRefusesConfigWithoutCertificates(t *testing.T) {
	store := newStore(t)
	saveCert(t, store, "expired.example", storage.CertMeta{NotAfter: now.Add(-time.Hour)})
	_, err := Scan(&config.Config{}, store, now, Options{Certs: true})
	if !errors.Is(err, ErrNoCertificates) {
		t.Fatalf("err = %v, want ErrNoCertificates", err)
	}
}

func TestScanWarnsAboutArtifactsThatOutliveRemoval(t *testing.T) {
	store := newStore(t)
	saveCert(t, store, "expired.example", storage.CertMeta{
		NotAfter: now.Add(-time.Hour),
		TLSA:     &storage.CertTLSAMeta{Published: []storage.TLSARecord{{Owner: "_443._tcp.expired.example.", RData: "3 1 1 aa"}}},
		Deploys: []storage.CertDeployMeta{
			{Target: "web", Kind: "fullchain", Path: "/etc/ssl/expired.pem"},
			{Target: "web", Kind: "key", Path: "/etc/ssl/expired.key"},
			{Target: "web", Host: "edge1", Kind: "key", Path: "/etc/ssl/expired.key"},
		},
	})
	saveCert(t, store, "valid.example", storage.CertMeta{NotAfter: now.Add(time.Hour), IssuerType: "acme"})

	report := scan(t, baseConfig(), store, Options{Certs: true, IncludeValid: true})
	joined := strings.Join(findItem(t, report, "cert/expired.example").Warnings, "\n")
	for _, want := range []string{"1 published TLSA record", "2 deployed local file", "remote host(s): edge1"} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings %q missing %q", joined, want)
		}
	}
	if joined := strings.Join(findItem(t, report, "cert/valid.example").Warnings, "\n"); !strings.Contains(joined, "not revoked") {
		t.Errorf("valid orphan warnings %q, want one about missing revocation", joined)
	}
}

func TestApplyRemovesOnlyMarkedItems(t *testing.T) {
	store := newStore(t)
	cfg := baseConfig()
	saveCert(t, store, "live.example", storage.CertMeta{NotAfter: now.Add(time.Hour)})
	saveCert(t, store, "expired.example", storage.CertMeta{NotAfter: now.Add(-time.Hour)})
	saveCert(t, store, "valid.example", storage.CertMeta{NotAfter: now.Add(time.Hour)})
	saveAccount(t, store, "main")
	saveAccount(t, store, "ca:google")
	writeFile(t, store.AccountKeyNextPath("ca:google"), "staged")
	saveCA(t, store, "dev")
	saveCA(t, store, "gone")
	writeFile(t, store.CertPaths("expired.example").KeyNext, "staged")

	report := scan(t, cfg, store, Options{Certs: true, Accounts: true, CAs: true})
	results := Apply(report, store)
	if len(results) != 3 {
		t.Fatalf("Apply returned %d results, want 3: %+v", len(results), results)
	}
	for _, r := range results {
		if r.Err != nil {
			t.Errorf("%s: %v", r.Item.ID(), r.Err)
		}
	}
	for _, gone := range []string{store.CertDir("expired.example"), store.AccountDir("ca:google"), store.CADir("gone")} {
		if exists(gone) {
			t.Errorf("%s survived", gone)
		}
	}
	for _, kept := range []string{store.CertDir("live.example"), store.CertDir("valid.example"), store.AccountDir("main"), store.CADir("dev")} {
		if !exists(kept) {
			t.Errorf("%s removed", kept)
		}
	}
}

func TestScanNeverFollowsSymlinks(t *testing.T) {
	store := newStore(t)
	outside := t.TempDir()
	for _, sub := range []string{"certs", "accounts", "cas"} {
		if err := os.Symlink(outside, filepath.Join(store.Root, sub, "link")); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	saveAccount(t, store, "main")
	if err := os.Symlink(store.AccountKeyPath("main"), filepath.Join(store.AccountDir("main"), "account-20260101T000000Z.key")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	writeFile(t, filepath.Join(store.AccountDir("main"), "account-20260201T000000Z.key"), "old")

	report := scan(t, baseConfig(), store, Options{Certs: true, Accounts: true, CAs: true, AccountKeys: true})
	if len(report.Items) != 1 || report.Items[0].ID() != "account/main" {
		t.Fatalf("report = %+v, want only account/main", report.Items)
	}
	// With the symlinked archive ignored only one real archive remains, so
	// there is nothing superseded to list.
}
