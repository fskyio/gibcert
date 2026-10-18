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
	"strings"
	"testing"
	"time"

	"gitfield.org/fsky/gibcert/internal/paths"
	"gitfield.org/fsky/gibcert/internal/storage"
)

// pruneFixture is a config declaring account "custom" and local CA "dev",
// with state holding orphans of every kind next to the declared items.
func pruneFixture(t *testing.T) (*paths.Paths, *storage.Store) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gibcert.scfg")
	cfg := `
challenge http-01 {
  webroot ` + dir + `
}
ca dev {
  type local
}
account custom {
  ca letsencrypt
  email admin@example.com
}
certificate configured.example {
  account custom
  names configured.example
}`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	p := &paths.Paths{Config: cfgPath, State: filepath.Join(dir, "state")}
	store := storage.New(p.State)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	save := func(name string, meta storage.CertMeta) {
		t.Helper()
		meta.Name = name
		if err := store.SaveCertMeta(name, meta); err != nil {
			t.Fatal(err)
		}
	}
	save("configured.example", storage.CertMeta{Account: "custom", NotAfter: time.Now().Add(time.Hour)})
	save("old.example", storage.CertMeta{Account: "ca:zerossl", NotAfter: time.Now().Add(-time.Hour)})
	save("valid.example", storage.CertMeta{Account: "ca:buypass", NotAfter: time.Now().Add(time.Hour)})
	for _, name := range []string{"custom", "ca:zerossl", "ca:buypass", "ca:google"} {
		if err := store.SaveAccountMeta(name, storage.AccountMeta{Directory: "https://ca.example/" + name}); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"dev", "gone"} {
		if err := os.MkdirAll(store.CADir(name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return p, store
}

func assertPruneState(t *testing.T, store *storage.Store, want map[string]bool) {
	t.Helper()
	dirs := map[string]string{
		"cert/configured.example": store.CertDir("configured.example"),
		"cert/old.example":        store.CertDir("old.example"),
		"cert/valid.example":      store.CertDir("valid.example"),
		"account/custom":          store.AccountDir("custom"),
		"account/ca:zerossl":      store.AccountDir("ca:zerossl"),
		"account/ca:buypass":      store.AccountDir("ca:buypass"),
		"account/ca:google":       store.AccountDir("ca:google"),
		"ca/dev":                  store.CADir("dev"),
		"ca/gone":                 store.CADir("gone"),
	}
	for id, dir := range dirs {
		_, err := os.Stat(dir)
		present := err == nil
		if wantPresent, ok := want[id]; ok && present != wantPresent {
			t.Errorf("%s: present = %v, want %v", id, present, wantPresent)
		}
	}
}

func TestPruneDryRunReviewsEverythingAndRemovesNothing(t *testing.T) {
	p, store := pruneFixture(t)
	out, errOut, code := captureCommand(t, func() int { return cmdPrune(p, []string{"--dry-run"}) })
	if code != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	for _, want := range []string{
		"remove  cert/old.example",
		"keep    cert/valid.example",
		"remove  account/ca:google",
		"keep    account/custom",
		"remove  ca/gone",
		"keep    ca/dev",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	// ca:buypass is needed by the valid orphan that stays.
	if !strings.Contains(out, "keep    account/ca:buypass") || !strings.Contains(out, "needed by cert/valid.example") {
		t.Errorf("dependency not reported:\n%s", out)
	}
	assertPruneState(t, store, map[string]bool{
		"cert/old.example": true, "account/ca:google": true, "ca/gone": true,
	})
}

func TestPruneYesNeedsASelection(t *testing.T) {
	p, store := pruneFixture(t)
	_, errOut, code := captureCommand(t, func() int { return cmdPrune(p, []string{"--yes"}) })
	if code != 2 || !strings.Contains(errOut, "--yes requires naming what to prune") {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
	_, errOut, code = captureCommand(t, func() int { return cmdPrune(p, []string{"--accounts", "--include-valid", "--yes"}) })
	if code != 2 || !strings.Contains(errOut, "--include-valid requires --certs") {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
	assertPruneState(t, store, map[string]bool{
		"cert/old.example": true, "account/ca:google": true, "ca/gone": true,
	})
}

func TestPruneRemovesOnlySelectedKindsAndHonorsExcept(t *testing.T) {
	p, store := pruneFixture(t)
	out, errOut, code := captureCommand(t, func() int {
		return cmdPrune(p, []string{"--certs", "--accounts", "--except", "account/ca:zerossl", "--yes"})
	})
	if code != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	assertPruneState(t, store, map[string]bool{
		"cert/configured.example": true,
		"cert/old.example":        false, // expired orphan
		"cert/valid.example":      true,  // valid orphans need --include-valid
		"account/custom":          true,
		"account/ca:zerossl":      true, // excepted although its only certificate is gone
		"account/ca:buypass":      true, // the valid orphan still needs it
		"account/ca:google":       false,
		"ca/dev":                  true,
		"ca/gone":                 true, // --cas was not selected
	})
	if !strings.Contains(out, "removed cert/old.example") || !strings.Contains(out, "removed account/ca:google") {
		t.Errorf("output missing removals:\n%s", out)
	}
}

func TestPruneIncludeValidReleasesWhatTheCertNeeded(t *testing.T) {
	p, store := pruneFixture(t)
	_, errOut, code := captureCommand(t, func() int {
		return cmdPrune(p, []string{"--certs", "--accounts", "--cas", "--include-valid", "--yes"})
	})
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
	assertPruneState(t, store, map[string]bool{
		"cert/configured.example": true,
		"cert/old.example":        false,
		"cert/valid.example":      false,
		"account/custom":          true,
		"account/ca:zerossl":      false,
		"account/ca:buypass":      false,
		"account/ca:google":       false,
		"ca/dev":                  true,
		"ca/gone":                 false,
	})
}

func TestPruneRefusesUnknownExceptAndBrokenConfig(t *testing.T) {
	p, store := pruneFixture(t)
	_, errOut, code := captureCommand(t, func() int {
		return cmdPrune(p, []string{"--certs", "--except", "cert/old.exmaple", "--yes"})
	})
	if code != 1 || !strings.Contains(errOut, "cert/old.exmaple") {
		t.Fatalf("typo in --except: code=%d stderr=%q", code, errOut)
	}

	if err := os.Remove(p.Config); err != nil {
		t.Fatal(err)
	}
	_, errOut, code = captureCommand(t, func() int { return cmdPrune(p, []string{"--certs", "--yes"}) })
	if code != 1 || errOut == "" {
		t.Fatalf("missing config: code=%d stderr=%q", code, errOut)
	}

	empty := filepath.Join(t.TempDir(), "empty.scfg")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	p.Config = empty
	_, errOut, code = captureCommand(t, func() int { return cmdPrune(p, []string{"--certs", "--yes"}) })
	if code != 1 || !strings.Contains(errOut, "declares no certificates") {
		t.Fatalf("empty config: code=%d stderr=%q", code, errOut)
	}
	assertPruneState(t, store, map[string]bool{"cert/old.example": true, "account/ca:google": true, "ca/gone": true})
}

func TestPruneWithoutConfirmationRemovesNothing(t *testing.T) {
	p, store := pruneFixture(t)
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	oldStdin := os.Stdin
	os.Stdin = devNull
	defer func() { os.Stdin = oldStdin }()

	_, _, code := captureCommand(t, func() int { return cmdPrune(p, []string{"--certs"}) })
	if code != 1 {
		t.Fatalf("code=%d, want 1 without confirmation", code)
	}
	assertPruneState(t, store, map[string]bool{"cert/old.example": true})
}
