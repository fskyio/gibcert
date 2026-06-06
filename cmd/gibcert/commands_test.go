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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"foundry.fsky.io/fsky/gibcert/internal/config"
	"foundry.fsky.io/fsky/gibcert/internal/importer"
	"foundry.fsky.io/fsky/gibcert/internal/logging"
	"foundry.fsky.io/fsky/gibcert/internal/paths"
	"foundry.fsky.io/fsky/gibcert/internal/plan"
	"foundry.fsky.io/fsky/gibcert/internal/renew"
	"foundry.fsky.io/fsky/gibcert/internal/storage"
)

func TestHelpVersionAndSubcommandUsage(t *testing.T) {
	out, errOut, code := captureCommand(t, func() int { return cmdHelp(nil) })
	if code != 0 || !strings.Contains(out, "usage: gibcert") {
		t.Fatalf("cmdHelp got code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	out, errOut, code = captureCommand(t, func() int { return cmdHelp([]string{"show"}) })
	if code != 0 || !strings.Contains(out, "usage: gibcert show <certificate>") {
		t.Fatalf("cmdHelp show got code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	_, errOut, code = captureCommand(t, func() int { return cmdHelp([]string{"missing"}) })
	if code != 2 || !strings.Contains(errOut, "unknown command") {
		t.Fatalf("cmdHelp missing got code=%d stderr=%q", code, errOut)
	}
	out, errOut, code = captureCommand(t, func() int { return cmdVersion(nil) })
	if code != 0 || !strings.Contains(out, "gibcert") {
		t.Fatalf("cmdVersion got code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	_, errOut, code = captureCommand(t, func() int { return cmdVersion([]string{"extra"}) })
	if code != 2 || !strings.Contains(errOut, "usage: gibcert version") {
		t.Fatalf("cmdVersion extra got code=%d stderr=%q", code, errOut)
	}
}

func TestCheckPlanListShowAndCACommands(t *testing.T) {
	p := localConfigPaths(t)

	out, errOut, code := captureCommand(t, func() int { return cmdCheck(p) })
	if code != 0 || !strings.Contains(out, "ok:") || !strings.Contains(out, "1 certificate") {
		t.Fatalf("cmdCheck got code=%d stdout=%q stderr=%q", code, out, errOut)
	}

	out, errOut, code = captureCommand(t, func() int { return cmdPlan(p, nil) })
	if code != 0 || !strings.Contains(out, "planned changes:") || !strings.Contains(out, "certificate example.com") {
		t.Fatalf("cmdPlan got code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	_, errOut, code = captureCommand(t, func() int { return cmdPlan(p, []string{"extra"}) })
	if code != 2 || !strings.Contains(errOut, "usage: gibcert plan") {
		t.Fatalf("cmdPlan extra got code=%d stderr=%q", code, errOut)
	}

	out, errOut, code = captureCommand(t, func() int { return cmdList(p, nil) })
	if code != 0 || !strings.Contains(out, "example.com") || !strings.Contains(out, "local:dev") {
		t.Fatalf("cmdList got code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	_, errOut, code = captureCommand(t, func() int { return cmdList(p, []string{"extra"}) })
	if code != 2 || !strings.Contains(errOut, "usage: gibcert list") {
		t.Fatalf("cmdList extra got code=%d stderr=%q", code, errOut)
	}

	out, errOut, code = captureCommand(t, func() int { return cmdShow(p, []string{"example.com"}) })
	if code != 0 || !strings.Contains(out, "certificate: example.com") || !strings.Contains(out, "issuer:") {
		t.Fatalf("cmdShow got code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	_, errOut, code = captureCommand(t, func() int { return cmdShow(p, nil) })
	if code != 2 || !strings.Contains(errOut, "usage: gibcert show") {
		t.Fatalf("cmdShow usage got code=%d stderr=%q", code, errOut)
	}

	out, errOut, code = captureCommand(t, func() int { return cmdCA(p, []string{"list"}) })
	if code != 0 || !strings.Contains(out, "dev") || !strings.Contains(out, "local") {
		t.Fatalf("cmdCA list got code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	out, errOut, code = captureCommand(t, func() int { return cmdCA(p, []string{"show", "dev"}) })
	if code != 0 || !strings.Contains(out, "ca:") || !strings.Contains(out, "common name") {
		t.Fatalf("cmdCA show got code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	_, errOut, code = captureCommand(t, func() int { return cmdCA(p, []string{"bogus"}) })
	if code != 2 || !strings.Contains(errOut, "unknown ca command") {
		t.Fatalf("cmdCA bogus got code=%d stderr=%q", code, errOut)
	}
}

func TestStorageOnlyListShowRenameDeleteCommands(t *testing.T) {
	p := &paths.Paths{
		Config: filepath.Join(t.TempDir(), "missing.scfg"),
		State:  t.TempDir(),
	}
	store := storage.New(p.State)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	notAfter := time.Now().Add(24 * time.Hour).UTC()
	if err := store.SaveCertMeta("orphan.example", storage.CertMeta{
		Name:       "orphan.example",
		Account:    "letsencrypt",
		IssuerType: "acme",
		Directory:  "https://ca.example/directory",
		Names:      []string{"orphan.example"},
		NotAfter:   notAfter,
	}); err != nil {
		t.Fatal(err)
	}

	out, errOut, code := captureCommand(t, func() int { return cmdList(p, nil) })
	if code != 1 || !strings.Contains(errOut, "config unavailable") || !strings.Contains(out, "orphan.example") {
		t.Fatalf("storage-only list got code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	out, errOut, code = captureCommand(t, func() int { return cmdShow(p, []string{"orphan.example"}) })
	if code != 0 || !strings.Contains(out, "not in config") || !strings.Contains(out, "orphan.example") {
		t.Fatalf("orphan show got code=%d stdout=%q stderr=%q", code, out, errOut)
	}

	out, errOut, code = captureCommand(t, func() int { return cmdRename(p, []string{"orphan.example", "renamed.example"}) })
	if code != 0 || !strings.Contains(out, "renamed to renamed.example") {
		t.Fatalf("cmdRename got code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	if _, err := os.Stat(store.CertDir("orphan.example")); !os.IsNotExist(err) {
		t.Fatalf("old cert dir still exists: %v", err)
	}
	if meta, err := store.LoadCertMeta("renamed.example"); err != nil || meta.Name != "renamed.example" {
		t.Fatalf("renamed metadata got meta=%#v err=%v", meta, err)
	}

	out, errOut, code = captureCommand(t, func() int { return cmdDelete(p, []string{"--yes", "renamed.example"}) })
	if code != 0 || !strings.Contains(out, "local state deleted") {
		t.Fatalf("cmdDelete got code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	if _, err := os.Stat(store.CertDir("renamed.example")); !os.IsNotExist(err) {
		t.Fatalf("deleted cert dir still exists: %v", err)
	}
	_, errOut, code = captureCommand(t, func() int { return cmdDelete(p, []string{"--yes", "--reason", "nonsense", "renamed.example"}) })
	if code != 2 || !strings.Contains(errOut, "unknown revocation reason") {
		t.Fatalf("cmdDelete bad reason got code=%d stderr=%q", code, errOut)
	}
}

func TestImportDispatchAndRunImportOutput(t *testing.T) {
	p := &paths.Paths{State: t.TempDir()}
	_, errOut, code := captureCommand(t, func() int { return cmdImport(p, nil) })
	if code != 2 || !strings.Contains(errOut, "usage: gibcert import") {
		t.Fatalf("cmdImport empty got code=%d stderr=%q", code, errOut)
	}
	_, errOut, code = captureCommand(t, func() int { return cmdImport(p, []string{"unknown"}) })
	if code != 2 || !strings.Contains(errOut, "unknown import source") {
		t.Fatalf("cmdImport unknown got code=%d stderr=%q", code, errOut)
	}
	_, errOut, code = captureCommand(t, func() int { return cmdImportACMESh(p, nil) })
	if code != 2 || !strings.Contains(errOut, "usage: gibcert import") {
		t.Fatalf("cmdImportACMESh usage got code=%d stderr=%q", code, errOut)
	}
	var only stringList
	if only.String() != "" {
		t.Fatalf("empty stringList got %q", only.String())
	}
	if err := only.Set("example.com"); err != nil {
		t.Fatal(err)
	}
	if only.String() != "example.com" {
		t.Fatalf("stringList got %q", only.String())
	}

	out, errOut, code := captureCommand(t, func() int {
		return runImport(p, true, func(*storage.Store) ([]importer.Result, error) {
			return []importer.Result{
				{Source: "example.com", Name: "stored.example", Status: importer.StatusPlanned, Detail: "dry run"},
				{Source: "skip.example", Status: importer.StatusSkipped},
			}, nil
		})
	})
	if code != 0 || !strings.Contains(out, "example.com -> stored.example") || !strings.Contains(out, "dry-run: 1 planned") {
		t.Fatalf("runImport dry run got code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	_, errOut, code = captureCommand(t, func() int {
		return runImport(p, false, func(*storage.Store) ([]importer.Result, error) {
			return nil, errors.New("boom")
		})
	})
	if code != 1 || !strings.Contains(errOut, "boom") {
		t.Fatalf("runImport error got code=%d stderr=%q", code, errOut)
	}
}

func TestCompletionCommands(t *testing.T) {
	out, errOut, code := captureCommand(t, func() int { return cmdCompletion([]string{"bash"}) })
	if code != 0 || !strings.Contains(out, "complete -F _gibcert gibcert") {
		t.Fatalf("bash completion got code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	out, errOut, code = captureCommand(t, func() int { return cmdCompletion([]string{"fish"}) })
	if code != 0 || !strings.Contains(out, "complete -c gibcert") {
		t.Fatalf("fish completion got code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	_, errOut, code = captureCommand(t, func() int { return cmdCompletion(nil) })
	if code != 2 || !strings.Contains(errOut, "usage: gibcert completion") {
		t.Fatalf("completion usage got code=%d stderr=%q", code, errOut)
	}
	_, errOut, code = captureCommand(t, func() int { return cmdCompletion([]string{"powershell"}) })
	if code != 2 || !strings.Contains(errOut, "unknown shell") {
		t.Fatalf("completion unknown got code=%d stderr=%q", code, errOut)
	}

	p := completionConfigPaths(t)
	store := storage.New(p.State)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(store.CertDir("stored.example"), 0o755); err != nil {
		t.Fatal(err)
	}
	out, _, code = captureCommand(t, func() int { return cmdInternalComplete(p, []string{"certs"}) })
	if code != 0 || !strings.Contains(out, "configured.example") || !strings.Contains(out, "stored.example") {
		t.Fatalf("__complete certs got code=%d stdout=%q", code, out)
	}
	out, _, code = captureCommand(t, func() int { return cmdInternalComplete(p, []string{"cas"}) })
	if code != 0 || !strings.Contains(out, "letsencrypt") {
		t.Fatalf("__complete cas got code=%d stdout=%q", code, out)
	}
	out, _, code = captureCommand(t, func() int { return cmdInternalComplete(p, []string{"accounts"}) })
	if code != 0 || !strings.Contains(out, "custom") || !strings.Contains(out, "ca:letsencrypt") {
		t.Fatalf("__complete accounts got code=%d stdout=%q", code, out)
	}
}

func TestCommandUsageAndIdentityHelpers(t *testing.T) {
	p := localConfigPaths(t)
	_, errOut, code := captureCommand(t, func() int { return cmdAccount(p, nil) })
	if code != 2 || !strings.Contains(errOut, "usage: gibcert account") {
		t.Fatalf("cmdAccount usage got code=%d stderr=%q", code, errOut)
	}
	_, errOut, code = captureCommand(t, func() int { return cmdAccount(p, []string{"bogus"}) })
	if code != 2 || !strings.Contains(errOut, "unknown account command") {
		t.Fatalf("cmdAccount bogus got code=%d stderr=%q", code, errOut)
	}
	_, errOut, code = captureCommand(t, func() int { return cmdAccountRotateKey(p, "../bad") })
	if code != 2 || !strings.Contains(errOut, "invalid account name") {
		t.Fatalf("cmdAccountRotateKey invalid got code=%d stderr=%q", code, errOut)
	}
	_, errOut, code = captureCommand(t, func() int { return cmdIssue(p, nil) })
	if code != 2 || !strings.Contains(errOut, "usage: gibcert issue") {
		t.Fatalf("cmdIssue usage got code=%d stderr=%q", code, errOut)
	}
	_, errOut, code = captureCommand(t, func() int { return cmdRenew(p, []string{"--max-jitter", "-1s"}) })
	if code != 2 || !strings.Contains(errOut, "--max-jitter must be >= 0") {
		t.Fatalf("cmdRenew bad jitter got code=%d stderr=%q", code, errOut)
	}
	_, errOut, code = captureCommand(t, func() int { return cmdRevoke(p, []string{"--reason", "mystery", "--yes", "example.com"}) })
	if code != 2 || !strings.Contains(errOut, "unknown revocation reason") {
		t.Fatalf("cmdRevoke bad reason got code=%d stderr=%q", code, errOut)
	}
	_, errOut, code = captureCommand(t, func() int { return cmdApply(p, []string{"extra"}) })
	if code != 2 || !strings.Contains(errOut, "usage: gibcert apply") {
		t.Fatalf("cmdApply usage got code=%d stderr=%q", code, errOut)
	}

	cfg := &config.Config{
		CAs: []*config.CA{
			{Name: "letsencrypt", Type: "acme", Directory: "https://ca.example/directory"},
			{Name: "dev", Type: "local"},
		},
		Accounts:  []*config.Account{{Name: "custom", CA: "letsencrypt", Directory: "https://ca.example/directory"}},
		Providers: []*config.Provider{{Name: "manual", Driver: "manual"}},
	}
	account, err := findACMEAccount(cfg, "ca:letsencrypt")
	if err != nil || account.Name != "ca:letsencrypt" {
		t.Fatalf("findACMEAccount implicit got account=%#v err=%v", account, err)
	}
	if _, err := findACMEAccount(cfg, "ca:dev"); err == nil {
		t.Fatal("findACMEAccount accepted local CA")
	}
	account, err = acmeAccountForCert(cfg, &config.Certificate{Name: "example.com", CA: "letsencrypt"})
	if err != nil || account.Name != "ca:letsencrypt" {
		t.Fatalf("acmeAccountForCert got account=%#v err=%v", account, err)
	}
	if usesManualDNS(cfg, &config.Certificate{Challenge: config.ChallengeSpec{Type: "dns-01", Provider: "manual"}}) != true {
		t.Fatal("usesManualDNS did not detect manual provider")
	}

	opts := acmeAccountOptions(&config.Account{
		Name:      "custom",
		Directory: "https://ca.example/directory",
		Email:     "admin@example.com",
		EAB: &config.EABSpec{
			KID: "kid",
			HMACKey: config.SecretValue{
				Value: "secret",
			},
		},
	})
	if opts.Name != "custom" || opts.EAB == nil || opts.EAB.HMACKeyValue != "secret" {
		t.Fatalf("acmeAccountOptions got %#v", opts)
	}
}

func TestCommandStatusHelpers(t *testing.T) {
	now := time.Now().UTC()
	if got := certificateStatusLabel(renew.Decision{}, nil, errors.New("bad meta")); got != "meta-error" {
		t.Fatalf("meta-error status got %q", got)
	}
	revokedAt := now
	if got := certificateStatusLabel(renew.Decision{NotAfter: now.Add(time.Hour)}, &storage.CertMeta{RevokedAt: &revokedAt}, nil); got != "revoked" {
		t.Fatalf("revoked status got %q", got)
	}
	if got := certificateStatusLabel(renew.Decision{}, nil, nil); got != "missing" {
		t.Fatalf("missing status got %q", got)
	}
	if got := certificateStatusLabel(renew.Decision{Due: true, Reason: "certificate expired", NotAfter: now.Add(-time.Hour)}, nil, nil); got != "expired" {
		t.Fatalf("expired status got %q", got)
	}
	if got := certificateStatusLabel(renew.Decision{Due: true, Reason: "inside renewal window", NotAfter: now.Add(time.Hour)}, nil, nil); got != "due" {
		t.Fatalf("due status got %q", got)
	}
	if got := certificateStatusLabel(renew.Decision{NotAfter: now.Add(time.Hour)}, nil, nil); got != "valid" {
		t.Fatalf("valid status got %q", got)
	}

	if got := orphanedCertStatus(nil); got != "missing" {
		t.Fatalf("orphaned nil got %q", got)
	}
	if got := orphanedCertStatus(&storage.CertMeta{RevokedAt: &revokedAt, NotAfter: now.Add(time.Hour)}); got != "revoked" {
		t.Fatalf("orphaned revoked got %q", got)
	}
	if got := orphanedCertStatus(&storage.CertMeta{NotAfter: now.Add(-time.Hour)}); got != "expired" {
		t.Fatalf("orphaned expired got %q", got)
	}
	if got := orphanedCertStatus(&storage.CertMeta{NotAfter: now.Add(time.Hour)}); got != "valid" {
		t.Fatalf("orphaned valid got %q", got)
	}

	cfg := &config.Config{CAs: []*config.CA{{Name: "dev", Type: "local"}}}
	if got := issuerSummary(cfg, &config.Certificate{Name: "local", CA: "dev"}, nil); got != "local:dev" {
		t.Fatalf("local issuer got %q", got)
	}
	if got := orphanedIssuerSummary(&storage.CertMeta{IssuerType: "imported"}); got != "imported" {
		t.Fatalf("imported orphan issuer got %q", got)
	}
	if got := formatInstant(time.Time{}); got != "-" {
		t.Fatalf("zero instant got %q", got)
	}
	if got := formatRenewAt(renew.Decision{}, time.Hour); got != "now" {
		t.Fatalf("zero renew-at got %q", got)
	}
	if got, err := randomJitter(0); err != nil || got != 0 {
		t.Fatalf("zero randomJitter got %s err=%v", got, err)
	}
	if got, err := randomJitter(time.Millisecond); err != nil || got < 0 || got > time.Millisecond {
		t.Fatalf("randomJitter got %s err=%v", got, err)
	}
	serial := "1234"
	retryAfter := now.Add(time.Hour)
	if !ariFresh(&storage.CertARI{Serial: serial, RetryAfter: &retryAfter}, serial, now) {
		t.Fatal("ariFresh returned false for fresh matching ARI")
	}
	if ariFresh(&storage.CertARI{Serial: "other", RetryAfter: &retryAfter}, serial, now) {
		t.Fatal("ariFresh returned true for mismatched serial")
	}
	if d := issueDecision(cfg, storage.New(t.TempDir()), &config.Certificate{Name: "local", CA: "dev"}, now); !d.Due || d.Reason == "" {
		t.Fatalf("local issueDecision got %#v", d)
	}

	pl := plan.Plan{Actions: []plan.Action{{Subject: "certificate example.com", Verb: "issue"}}}
	if !planNeedsConfirmation(pl) {
		t.Fatal("certificate issue plan should need confirmation")
	}
	if planNeedsConfirmation(plan.Plan{Actions: []plan.Action{{Subject: "deploy web", Verb: "update"}}}) {
		t.Fatal("deploy-only plan should not need confirmation")
	}
}

func TestConfirmationRejectsNonTTY(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ok, err := confirmYesNo(f, io.Discard, "confirm? ")
	if err == nil || ok {
		t.Fatalf("confirmYesNo got ok=%v err=%v, want non-tty error", ok, err)
	}
	ok, err = confirmApply(f, io.Discard)
	if err == nil || ok {
		t.Fatalf("confirmApply got ok=%v err=%v, want non-tty error", ok, err)
	}
}

func localConfigPaths(t *testing.T) *paths.Paths {
	t.Helper()
	dir := t.TempDir()
	deployDir := filepath.Join(dir, "deploy")
	if err := os.MkdirAll(deployDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "gibcert.scfg")
	cfg := fmt.Sprintf(`
ca dev {
  type local
  common-name "gibcert dev CA"
}
certificate example.com {
  ca dev
  names example.com www.example.com
  deploy local {
    fullchain %s
    key %s
  }
}`, filepath.Join(deployDir, "fullchain.pem"), filepath.Join(deployDir, "privkey.pem"))
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	return &paths.Paths{Config: cfgPath, State: filepath.Join(dir, "state")}
}

func completionConfigPaths(t *testing.T) *paths.Paths {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gibcert.scfg")
	cfg := `
ca letsencrypt {
  type acme
  directory https://ca.example/directory
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
	return &paths.Paths{Config: cfgPath, State: filepath.Join(dir, "state")}
}

func captureCommand(t *testing.T, fn func() int) (stdout, stderr string, code int) {
	t.Helper()
	oldStdout, oldStderr := os.Stdout, os.Stderr
	oldLog := cliLog
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = outW, errW
	logger, err := logging.New(logging.Options{Format: "text", Stderr: os.Stderr})
	if err != nil {
		t.Fatal(err)
	}
	cliLog = logger
	defer func() {
		cliLog = oldLog
		os.Stdout, os.Stderr = oldStdout, oldStderr
	}()

	code = fn()
	_ = logger.Close()
	_ = outW.Close()
	_ = errW.Close()
	outBytes, err := io.ReadAll(outR)
	if err != nil {
		t.Fatal(err)
	}
	errBytes, err := io.ReadAll(errR)
	if err != nil {
		t.Fatal(err)
	}
	_ = outR.Close()
	_ = errR.Close()
	return string(outBytes), string(errBytes), code
}
