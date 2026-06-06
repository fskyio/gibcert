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

package deploy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"foundry.fsky.io/fsky/gibcert/internal/config"
	"foundry.fsky.io/fsky/gibcert/internal/storage"
)

func TestDeployWritesFilesRunsHookAndShortCircuits(t *testing.T) {
	root := t.TempDir()
	store := storage.New(filepath.Join(root, "state"))
	writeCanonical(t, store, "example.com")
	hookPath := filepath.Join(root, "hook.log")
	mode := os.FileMode(0o600)
	cert := &config.Certificate{
		Name: "example.com",
		Deploys: []*config.Deploy{{
			Name:      "local",
			Fullchain: filepath.Join(root, "deploy", "fullchain.pem"),
			Key:       filepath.Join(root, "deploy", "privkey.pem"),
			Mode:      &mode,
			After:     "printf '%s|%s|%s' \"$GIBCERT_CHANGED\" \"$GIBCERT_FULLCHAIN_PATH\" \"$GIBCERT_KEY_PATH\" > " + hookPath,
		}},
	}

	results, err := Deploy(cert, store, os.Stdout)
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if got := strings.Join(results[0].Changed, ","); got != "fullchain,key" {
		t.Fatalf("changed got %q, want fullchain,key", got)
	}
	assertMode(t, cert.Deploys[0].Fullchain, 0o600)
	assertMode(t, cert.Deploys[0].Key, 0o600)
	hook, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(hook); got != "fullchain,key|"+cert.Deploys[0].Fullchain+"|"+cert.Deploys[0].Key {
		t.Fatalf("hook got %q", got)
	}

	if err := os.WriteFile(hookPath, []byte("unchanged"), 0o644); err != nil {
		t.Fatal(err)
	}
	results, err = Deploy(cert, store, os.Stdout)
	if err != nil {
		t.Fatalf("Deploy second time: %v", err)
	}
	if len(results[0].Changed) != 0 {
		t.Fatalf("second deploy changed %v, want none", results[0].Changed)
	}
	hook, err = os.ReadFile(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(hook) != "unchanged" {
		t.Fatalf("hook reran on no-op deploy: %q", hook)
	}
	meta, err := store.LoadCertMeta("example.com")
	if err != nil {
		t.Fatalf("LoadCertMeta: %v", err)
	}
	if len(meta.Deploys) != 2 {
		t.Fatalf("deploy metadata entries got %d, want 2", len(meta.Deploys))
	}
}

func TestDeployRunsBeforeHookBeforeWriting(t *testing.T) {
	root := t.TempDir()
	store := storage.New(filepath.Join(root, "state"))
	writeCanonical(t, store, "example.com")
	dst := filepath.Join(root, "deploy", "fullchain.pem")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(root, "before.log")
	t.Setenv("GIBCERT_TEST_HOOK_LOG", logPath)
	cert := &config.Certificate{
		Name: "example.com",
		Deploys: []*config.Deploy{{
			Name:      "local",
			Fullchain: dst,
			Before:    `printf '%s|%s|' "$GIBCERT_EVENT" "$GIBCERT_CHANGED" > "$GIBCERT_TEST_HOOK_LOG"; cat "$GIBCERT_FULLCHAIN_PATH" >> "$GIBCERT_TEST_HOOK_LOG"`,
		}},
	}

	if _, err := Deploy(cert, store, os.Stdout); err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	hook, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(hook); got != "before-deploy|fullchain|old" {
		t.Fatalf("before hook got %q", got)
	}
	deployed, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(deployed); got != "fullchain" {
		t.Fatalf("deployed content got %q, want fullchain", got)
	}

	if err := os.WriteFile(logPath, []byte("unchanged"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Deploy(cert, store, os.Stdout); err != nil {
		t.Fatalf("Deploy second time: %v", err)
	}
	hook, err = os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(hook) != "unchanged" {
		t.Fatalf("before hook reran on no-op deploy: %q", hook)
	}
}

func TestDeployBeforeHookFailureShortCircuitsWrites(t *testing.T) {
	root := t.TempDir()
	store := storage.New(filepath.Join(root, "state"))
	writeCanonical(t, store, "example.com")
	dst := filepath.Join(root, "deploy", "fullchain.pem")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	cert := &config.Certificate{
		Name: "example.com",
		Deploys: []*config.Deploy{{
			Name:      "local",
			Fullchain: dst,
			Before:    "exit 23",
		}},
	}

	if _, err := Deploy(cert, store, os.Stdout); err == nil {
		t.Fatal("Deploy got nil error, want before hook failure")
	}
	deployed, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(deployed); got != "old" {
		t.Fatalf("deployed content got %q, want old", got)
	}
	if _, err := store.LoadCertMeta("example.com"); !os.IsNotExist(err) {
		t.Fatalf("metadata after failed before hook error = %v, want not exist", err)
	}
}

func TestDeployRetriesHookWhenPreviousHookFailed(t *testing.T) {
	root := t.TempDir()
	store := storage.New(filepath.Join(root, "state"))
	writeCanonical(t, store, "example.com")
	flagPath := filepath.Join(root, "hook.failed")
	logPath := filepath.Join(root, "hook.log")
	t.Setenv("GIBCERT_TEST_HOOK_FLAG", flagPath)
	t.Setenv("GIBCERT_TEST_HOOK_LOG", logPath)
	cert := &config.Certificate{
		Name: "example.com",
		Deploys: []*config.Deploy{{
			Name:      "local",
			Fullchain: filepath.Join(root, "deploy", "fullchain.pem"),
			Key:       filepath.Join(root, "deploy", "privkey.pem"),
			After:     `if [ ! -f "$GIBCERT_TEST_HOOK_FLAG" ]; then touch "$GIBCERT_TEST_HOOK_FLAG"; exit 23; fi; printf '%s' "$GIBCERT_CHANGED" > "$GIBCERT_TEST_HOOK_LOG"`,
		}},
	}

	if _, err := Deploy(cert, store, os.Stdout); err == nil {
		t.Fatal("first Deploy got nil error, want hook failure")
	}
	if _, err := store.LoadCertMeta("example.com"); !os.IsNotExist(err) {
		t.Fatalf("metadata after failed hook error = %v, want not exist", err)
	}

	results, err := Deploy(cert, store, os.Stdout)
	if err != nil {
		t.Fatalf("retry Deploy: %v", err)
	}
	if len(results[0].Changed) != 0 {
		t.Fatalf("retry changed %v, want none", results[0].Changed)
	}
	hook, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(hook); got != "fullchain,key" {
		t.Fatalf("retry hook changed got %q, want fullchain,key", got)
	}
	meta, err := store.LoadCertMeta("example.com")
	if err != nil {
		t.Fatalf("LoadCertMeta: %v", err)
	}
	if len(meta.Deploys) != 2 {
		t.Fatalf("deploy metadata entries got %d, want 2", len(meta.Deploys))
	}
}

func TestDeployPreservesExistingModeWhenModeUnset(t *testing.T) {
	root := t.TempDir()
	store := storage.New(filepath.Join(root, "state"))
	writeCanonical(t, store, "example.com")
	dst := filepath.Join(root, "deploy", "fullchain.pem")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("old"), 0o640); err != nil {
		t.Fatal(err)
	}
	cert := &config.Certificate{
		Name: "example.com",
		Deploys: []*config.Deploy{{
			Name:      "local",
			Fullchain: dst,
		}},
	}
	if _, err := Deploy(cert, store, os.Stdout); err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	assertMode(t, dst, 0o640)
}

func TestDeployAppliesModeToUnchangedContent(t *testing.T) {
	root := t.TempDir()
	store := storage.New(filepath.Join(root, "state"))
	writeCanonical(t, store, "example.com")
	dst := filepath.Join(root, "deploy", "fullchain.pem")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("fullchain"), 0o644); err != nil {
		t.Fatal(err)
	}
	mode := os.FileMode(0o600)
	cert := &config.Certificate{
		Name: "example.com",
		Deploys: []*config.Deploy{{
			Name:      "local",
			Fullchain: dst,
			Mode:      &mode,
		}},
	}

	results, err := Deploy(cert, store, os.Stdout)
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if len(results[0].Changed) != 0 {
		t.Fatalf("changed got %v, want none for content-identical file", results[0].Changed)
	}
	assertMode(t, dst, 0o600)
}

func TestDeployMissingCanonicalMaterialFailsEarly(t *testing.T) {
	root := t.TempDir()
	store := storage.New(filepath.Join(root, "state"))
	cert := &config.Certificate{
		Name: "missing.example",
		Deploys: []*config.Deploy{{
			Name:      "local",
			Fullchain: filepath.Join(root, "deploy", "fullchain.pem"),
		}},
	}

	if _, err := Deploy(cert, store, os.Stdout); err == nil || !strings.Contains(err.Error(), "read canonical cert") {
		t.Fatalf("Deploy error = %v, want canonical cert read error", err)
	}
}

func TestRunReloadExportsEnvironment(t *testing.T) {
	root := t.TempDir()
	logPath := filepath.Join(root, "reload.log")
	t.Setenv("GIBCERT_TEST_RELOAD_LOG", logPath)
	err := RunReload(`printf '%s|%s|%s' "$GIBCERT_HOOK_API" "$GIBCERT_EVENT" "$GIBCERT_CHANGED_CERTS" > "$GIBCERT_TEST_RELOAD_LOG"`, []string{"a.example", "b.example"})
	if err != nil {
		t.Fatalf("RunReload: %v", err)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(raw); got != "1|reload|a.example,b.example" {
		t.Fatalf("reload env got %q", got)
	}
	if err := RunReload("", []string{"ignored.example"}); err != nil {
		t.Fatalf("empty RunReload: %v", err)
	}
}

func TestUndeployOnlyRemovesMatchingFiles(t *testing.T) {
	root := t.TempDir()
	store := storage.New(filepath.Join(root, "state"))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	removePath := filepath.Join(root, "deploy", "fullchain.pem")
	keepPath := filepath.Join(root, "deploy", "privkey.pem")
	if err := os.MkdirAll(filepath.Dir(removePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(removePath, []byte("known"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keepPath, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveCertMeta("example.com", storage.CertMeta{
		Name: "example.com",
		Deploys: []storage.CertDeployMeta{
			{Target: "local", Kind: "fullchain", Path: removePath, SHA256: storage.SHA256Hex([]byte("known"))},
			{Target: "local", Kind: "key", Path: keepPath, SHA256: storage.SHA256Hex([]byte("old-key"))},
		},
	}); err != nil {
		t.Fatal(err)
	}

	results, err := Undeploy("example.com", store)
	if err != nil {
		t.Fatalf("Undeploy: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("results got %d, want 2", len(results))
	}
	if _, err := os.Stat(removePath); !os.IsNotExist(err) {
		t.Fatalf("matching deploy file still exists: %v", err)
	}
	if _, err := os.Stat(keepPath); err != nil {
		t.Fatalf("changed deploy file should remain: %v", err)
	}
}

func writeCanonical(t *testing.T, store *storage.Store, name string) {
	t.Helper()
	paths := store.CertPaths(name)
	if err := os.MkdirAll(paths.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		paths.Cert:      []byte("cert"),
		paths.Chain:     []byte("chain"),
		paths.Fullchain: []byte("fullchain"),
		paths.Key:       []byte("key"),
	}
	for path, data := range files {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode got %#o, want %#o", path, got, want)
	}
}
