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
//go:build !windows && !plan9

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitfield.org/fsky/gibcert/internal/config"
	"gitfield.org/fsky/gibcert/internal/paths"
	"gitfield.org/fsky/gibcert/internal/receive"
	"gitfield.org/fsky/gibcert/internal/storage"
)

// TestReceiveHelper is not a test: the fake ssh re-executes the test binary to
// act as "gibcert receive" on the "remote" host.
func TestReceiveHelper(t *testing.T) {
	if os.Getenv("GIBCERT_TEST_RECEIVE_HELPER") != "1" {
		t.Skip("helper process")
	}
	os.Exit(receive.Serve(os.Stdin, os.Stdout, os.Stderr))
}

// useFakeSSH puts an ssh stand-in first on PATH. It behaves like a remote
// receiver, except that connecting to an address containing "down.example"
// fails the way an unreachable host does.
func useFakeSSH(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\n" +
		"case \"$*\" in *down.example*) echo 'ssh: connect to host down.example: Connection refused' >&2; exit 255;; esac\n" +
		"exec \"" + os.Args[0] + "\" -test.run=TestReceiveHelper\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIBCERT_TEST_RECEIVE_HELPER", "1")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// remoteFixture writes a config with hosts web1 (reachable) and web2
// (unreachable) and one certificate whose deploy target installs on the given
// hosts into destDir, and issues the certificate.
func remoteFixture(t *testing.T, hosts, destDir string) (*paths.Paths, *storage.Store) {
	t.Helper()
	useFakeSSH(t)
	dir := t.TempDir()
	cfg := fmt.Sprintf(`
ca dev {
  type local
}
host web1 {
  address web1.example
  user gibdeploy
}
host web2 {
  address down.example
  user gibdeploy
}
certificate example.com {
  ca dev
  names example.com
  deploy nginx {
    host %s
    fullchain %s/fullchain.pem
    key %s/privkey.pem
    mode 0640
  }
}
`, hosts, destDir, destDir)
	cfgPath := filepath.Join(dir, "gibcert.scfg")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	p := &paths.Paths{Config: cfgPath, State: filepath.Join(dir, "state")}
	if out, errOut, code := captureCommand(t, func() int { return cmdIssue(p, []string{"example.com"}) }); code != 0 {
		t.Fatalf("issue: code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	return p, storage.New(p.State)
}

func TestDeployHostInstallsOverSSH(t *testing.T) {
	dest := t.TempDir()
	p, store := remoteFixture(t, "web1", dest)

	out, errOut, code := captureCommand(t, func() int { return cmdDeploy(p, []string{"--host", "web1", "example.com"}) })
	if code != 0 || !strings.Contains(out, "nginx@web1: updated") {
		t.Fatalf("deploy: code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	want, err := os.ReadFile(store.CertPaths("example.com").Fullchain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "fullchain.pem"))
	if err != nil || string(got) != string(want) {
		t.Fatalf("installed fullchain differs from canonical: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(dest, "privkey.pem")); err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("privkey stat = %v, %v", fi, err)
	}
	meta, err := store.LoadCertMeta("example.com")
	if err != nil || len(meta.Deploys) == 0 {
		t.Fatalf("meta = %+v, %v", meta, err)
	}
	for _, rec := range meta.Deploys {
		if rec.Host != "web1" {
			t.Fatalf("deploy record without host: %+v", rec)
		}
	}

	out, errOut, code = captureCommand(t, func() int { return cmdDeploy(p, []string{"--host", "web1", "example.com"}) })
	if code != 0 || !strings.Contains(out, "nginx@web1: up to date") {
		t.Fatalf("second deploy: code=%d stdout=%q stderr=%q", code, out, errOut)
	}

	if _, _, code = captureCommand(t, func() int { return cmdDeploy(p, []string{"--host", "nope", "example.com"}) }); code != 1 {
		t.Fatalf("deploy --host unknown: code=%d, want 1", code)
	}
	if _, _, code = captureCommand(t, func() int { return cmdDeploy(p, []string{"--host", "web2", "example.com"}) }); code != 1 {
		t.Fatalf("deploy --host without target on it: code=%d, want 1", code)
	}

	out, _, code = captureCommand(t, func() int { return cmdShow(p, []string{"example.com"}) })
	if code != 0 || !strings.Contains(out, "nginx@web1") || strings.Contains(out, "FAILED") {
		t.Fatalf("show: code=%d stdout=%q", code, out)
	}
}

func TestHostTestReportsPermissionProblems(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dest := t.TempDir()
	p, _ := remoteFixture(t, "web1", dest)

	out, errOut, code := captureCommand(t, func() int { return cmdHost(p, []string{"test", "web1"}) })
	if code != 0 || !strings.Contains(out, "web1: ok") || !strings.Contains(out, "example.com/nginx: ok") {
		t.Fatalf("host test: code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	if _, err := os.Stat(filepath.Join(dest, "fullchain.pem")); err == nil {
		t.Fatal("host test installed a file")
	}

	if err := os.Chmod(dest, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dest, 0o755) })
	out, errOut, code = captureCommand(t, func() int { return cmdHost(p, []string{"test"}) })
	if code != 1 || !strings.Contains(out, "example.com/nginx: FAIL") || !strings.Contains(out, "setfacl") || !strings.Contains(out, dest) {
		t.Fatalf("host test on read-only dir: code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	if !strings.Contains(out, "web2: FAIL") {
		t.Fatalf("host test did not report the unreachable host: %q", out)
	}

	if _, _, code = captureCommand(t, func() int { return cmdHost(p, []string{"test", "nope"}) }); code != 2 {
		t.Fatalf("host test unknown host: code=%d, want 2", code)
	}
}

func TestDeployFailureOnOneHostDoesNotStopOthers(t *testing.T) {
	dest := t.TempDir()
	p, store := remoteFixture(t, "web2 web1", dest)

	out, errOut, code := captureCommand(t, func() int { return cmdDeploy(p, []string{"example.com"}) })
	if code != 1 || !strings.Contains(out, "nginx@web1: updated") || !strings.Contains(errOut, "web2") {
		t.Fatalf("deploy: code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	if _, err := os.Stat(filepath.Join(dest, "fullchain.pem")); err != nil {
		t.Fatalf("good host was not installed: %v", err)
	}
	meta, err := store.LoadCertMeta("example.com")
	if err != nil || len(meta.DeployFailures) != 1 || meta.DeployFailures[0].Host != "web2" {
		t.Fatalf("failures = %+v, %v", meta.DeployFailures, err)
	}

	out, _, code = captureCommand(t, func() int { return cmdShow(p, []string{"example.com"}) })
	if code != 0 || !strings.Contains(out, "nginx@web2") || !strings.Contains(out, "FAILED since") {
		t.Fatalf("show: code=%d stdout=%q", code, out)
	}
	if got := deploySummary(cfgCert(t, p, "example.com"), store); got != "failed" {
		t.Fatalf("deploySummary = %q, want failed", got)
	}
}

func cfgCert(t *testing.T, p *paths.Paths, name string) *config.Certificate {
	t.Helper()
	cfg, err := loadCfg(p)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := findCert(cfg, name)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
