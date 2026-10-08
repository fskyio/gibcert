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

//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package deploy

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gitfield.org/fsky/gibcert/internal/config"
	"gitfield.org/fsky/gibcert/internal/localca"
	"gitfield.org/fsky/gibcert/internal/storage"
)

func TestDeployStagesSetBeforeHooks(t *testing.T) {
	root := t.TempDir()
	store, cert, previous := seedDeployGenerations(t, root)
	d := cert.Deploys[0]
	marker := filepath.Join(root, "hook")
	t.Setenv("GIBCERT_TEST_DEPLOY_MARKER", marker)
	d.Before = `printf stopped > "$GIBCERT_TEST_DEPLOY_MARKER"`
	d.After = `printf recovered > "$GIBCERT_TEST_DEPLOY_MARKER"`
	d.Key = filepath.Join(root, "invalid-key")
	if err := os.Mkdir(d.Key, 0o755); err != nil {
		t.Fatal(err)
	}
	metaBefore, err := os.ReadFile(store.CertPaths(cert.Name).Meta)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Deploy(cert, store, io.Discard); err == nil {
		t.Fatal("directory key target was accepted")
	}
	assertDeployBytes(t, d.Fullchain, previous[0])
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("hook ran before complete staging: %v", err)
	}
	assertDeployBytes(t, store.CertPaths(cert.Name).Meta, metaBefore)
	assertNoDeployStages(t, filepath.Dir(d.Fullchain))
}

func TestDeployRollsBackLaterWriteFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permission failures")
	}
	root := t.TempDir()
	store, cert, previous := seedDeployGenerations(t, root)
	d := cert.Deploys[0]
	keyDir := filepath.Dir(d.Key)
	t.Cleanup(func() { _ = os.Chmod(keyDir, 0o755) })
	marker := filepath.Join(root, "service-state")
	log := filepath.Join(root, "recovery-event")
	t.Setenv("GIBCERT_TEST_KEY_DIRECTORY", keyDir)
	t.Setenv("GIBCERT_TEST_DEPLOY_MARKER", marker)
	t.Setenv("GIBCERT_TEST_DEPLOY_EVENT", log)
	d.Before = `printf stopped > "$GIBCERT_TEST_DEPLOY_MARKER"; chmod 0555 "$GIBCERT_TEST_KEY_DIRECTORY"`
	d.After = `chmod 0755 "$GIBCERT_TEST_KEY_DIRECTORY"; printf running > "$GIBCERT_TEST_DEPLOY_MARKER"; printf '%s' "$GIBCERT_EVENT" > "$GIBCERT_TEST_DEPLOY_EVENT"`
	metaBefore, err := os.ReadFile(store.CertPaths(cert.Name).Meta)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Deploy(cert, store, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "install key") {
		t.Fatalf("Deploy = %v, want later key installation failure", err)
	}
	assertDeployBytes(t, d.Fullchain, previous[0])
	assertDeployBytes(t, d.Key, previous[1])
	assertDeployBytes(t, store.CertPaths(cert.Name).Meta, metaBefore)
	assertDeployBytes(t, marker, []byte("running"))
	assertDeployBytes(t, log, []byte("rollback-deploy"))
	assertMode(t, d.Fullchain, 0o640)
	assertMode(t, d.Key, 0o640)
	assertNoDeployStages(t, filepath.Dir(d.Fullchain), keyDir)
}

func TestDeployRollbackRetainsBackupOnRestoreFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permission failures")
	}
	root := t.TempDir()
	store, cert, previous := seedDeployGenerations(t, root)
	d := cert.Deploys[0]
	paths := store.CertPaths(cert.Name)
	fullchain, err := os.ReadFile(paths.Fullchain)
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(paths.Key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := os.ReadFile(paths.Cert)
	if err != nil {
		t.Fatal(err)
	}
	var staged stagedDeploy
	defer staged.cleanup()
	if err := staged.prepare(d, leaf, nil, fullchain, key, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := staged.install(); err != nil {
		t.Fatal(err)
	}
	keyDir := filepath.Dir(d.Key)
	if err := os.Chmod(keyDir, 0o555); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(keyDir, 0o755)
	backup := staged.files[3].backup
	err = staged.rollback()
	if err == nil || !strings.Contains(err.Error(), backup) {
		t.Fatalf("rollback = %v, want retained backup path %s", err, backup)
	}
	staged.cleanup()
	assertDeployBytes(t, backup, previous[1])
	assertDeployBytes(t, d.Key, key)
	assertDeployBytes(t, d.Fullchain, previous[0])
	if err := os.Chmod(keyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(backup, d.Key); err != nil {
		t.Fatal(err)
	}
	assertDeployBytes(t, d.Key, previous[1])
}

func seedDeployGenerations(t *testing.T, root string) (*storage.Store, *config.Certificate, [2][]byte) {
	t.Helper()
	store := storage.New(filepath.Join(root, "state"))
	mode := os.FileMode(0o640)
	d := &config.Deploy{Name: "local", Fullchain: filepath.Join(root, "public", "fullchain.pem"), Key: filepath.Join(root, "private", "key.pem"), Mode: &mode}
	ca := &config.CA{Name: "dev", Type: "local"}
	cert := &config.Certificate{Name: "service", CA: ca.Name, Names: []string{"service.example"}, Deploys: []*config.Deploy{d}}
	cfg := &config.Config{CAs: []*config.CA{ca}, Certificates: []*config.Certificate{cert}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	if err := localca.Issue(cert, ca, store, localca.IssueOptions{Out: io.Discard, Now: now}); err != nil {
		t.Fatal(err)
	}
	paths := store.CertPaths(cert.Name)
	var previous [2][]byte
	for i, file := range []struct{ src, dst, kind string }{{paths.Fullchain, d.Fullchain, "fullchain"}, {paths.Key, d.Key, "key"}} {
		data, err := os.ReadFile(file.src)
		if err != nil {
			t.Fatal(err)
		}
		previous[i] = data
		if err := os.MkdirAll(filepath.Dir(file.dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file.dst, data, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(file.dst, mode); err != nil {
			t.Fatal(err)
		}
	}
	meta, err := store.LoadCertMeta(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	meta.Deploys = []storage.CertDeployMeta{
		{Target: d.Name, Kind: "fullchain", Path: d.Fullchain, SHA256: storage.SHA256Hex(previous[0]), At: now},
		{Target: d.Name, Kind: "key", Path: d.Key, SHA256: storage.SHA256Hex(previous[1]), At: now},
	}
	if err := store.SaveCertMeta(cert.Name, *meta); err != nil {
		t.Fatal(err)
	}
	if err := localca.Issue(cert, ca, store, localca.IssueOptions{Out: io.Discard, NewKey: true, Now: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	return store, cert, previous
}

func assertDeployBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("%s does not retain expected material: %v", path, err)
	}
}
func assertNoDeployStages(t *testing.T, dirs ...string) {
	t.Helper()
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".gibcert-") {
				t.Fatalf("staged material left behind: %s", filepath.Join(dir, entry.Name()))
			}
		}
	}
}
