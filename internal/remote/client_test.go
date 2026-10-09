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

package remote

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"gitfield.org/fsky/gibcert/internal/config"
	"gitfield.org/fsky/gibcert/internal/deploy"
	"gitfield.org/fsky/gibcert/internal/receive"
)

// TestReceiveHelper is not a test: the fake ssh re-executes the test binary to
// act as "gibcert receive" on the "remote" host.
func TestReceiveHelper(t *testing.T) {
	if os.Getenv("GIBCERT_TEST_RECEIVE_HELPER") != "1" {
		t.Skip("helper process")
	}
	os.Exit(receive.Serve(os.Stdin, os.Stdout, os.Stderr))
}

// fakeSSH writes an ssh stand-in that records its arguments and then behaves
// like a remote receiver. The returned path is passed as Client.SSH.
func fakeSSH(t *testing.T, body string) (program, argsFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	program = filepath.Join(dir, "ssh")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argsFile + "\n" + body + "\n"
	if err := os.WriteFile(program, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIBCERT_TEST_RECEIVE_HELPER", "1")
	return program, argsFile
}

func receiverSSH(t *testing.T) (string, string) {
	t.Helper()
	return fakeSSH(t, `exec "`+os.Args[0]+`" -test.run=TestReceiveHelper`)
}

func testHost() *config.Host {
	return &config.Host{
		Name: "web1", Address: "web1.example.net", User: "gibdeploy", Port: 2222,
		IdentityFile: "/etc/gibcert/id", KnownHosts: "/etc/gibcert/known hosts",
		Timeout: 20 * time.Second, RemoteCommand: "/usr/local/bin/gibcert",
	}
}

func testRequest(dir string) deploy.Request {
	mode := fs.FileMode(0o640)
	return deploy.Request{
		Cert: "example.com", Target: "web", Mode: &mode,
		Files: []deploy.File{
			{Kind: "fullchain", Path: filepath.Join(dir, "fullchain.pem"), Data: []byte("fullchain")},
			{Kind: "key", Path: filepath.Join(dir, "privkey.pem"), Data: []byte("key")},
		},
	}
}

func TestSSHArgsAreStrictAndUnattended(t *testing.T) {
	args, err := sshArgs(testHost())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"BatchMode=yes", "StrictHostKeyChecking=yes", "ConnectTimeout=20", "IdentitiesOnly=yes",
		`UserKnownHostsFile="/etc/gibcert/known hosts"`,
	} {
		if !slices.Contains(args, want) {
			t.Errorf("args lack %q: %q", want, args)
		}
	}
	// The address must come after "--" so a host name can never be an option.
	tail := args[len(args)-3:]
	if !slices.Equal(tail, []string{"--", "web1.example.net", "/usr/local/bin/gibcert receive"}) {
		t.Errorf("tail = %q", tail)
	}
	for i, a := range args {
		if a == "-l" && args[i+1] != "gibdeploy" || a == "-p" && args[i+1] != "2222" || a == "-i" && args[i+1] != "/etc/gibcert/id" {
			t.Errorf("bad value after %s: %q", a, args[i+1])
		}
	}
	for _, a := range args {
		if strings.Contains(a, "StrictHostKeyChecking=no") || strings.Contains(a, "accept-new") {
			t.Errorf("args weaken host key checking: %q", a)
		}
	}
}

func TestSSHArgsRejectUnquotablePath(t *testing.T) {
	h := testHost()
	h.KnownHosts = `/etc/"quoted"`
	if _, err := sshArgs(h); err == nil {
		t.Fatal("sshArgs accepted a path it cannot quote")
	}
}

func TestParseResponseSkipsLoginNoise(t *testing.T) {
	out := []byte("Welcome to web1\nlast login: never\n{\"protocol\":1,\"ok\":true,\"changed\":[\"key\"]}\n")
	resp := parseResponse(out)
	if resp == nil || !resp.OK || len(resp.Changed) != 1 {
		t.Fatalf("parseResponse = %+v", resp)
	}
	if parseResponse([]byte("no json here\n")) != nil {
		t.Fatal("parseResponse found a response in noise")
	}
}

func TestApplyInstallsOnTheRemoteSide(t *testing.T) {
	ssh, argsFile := receiverSSH(t)
	dir := t.TempDir()
	req := testRequest(dir)
	req.After = "echo reloaded; echo stdout-noise"
	c := &Client{SSH: ssh}
	var out bytes.Buffer

	res, err := c.Apply(testHost(), req, false, &out)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Host != "web1" || res.Target != "web" || strings.Join(res.Changed, ",") != "fullchain,key" {
		t.Fatalf("result = %+v", res)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "privkey.pem")); string(got) != "key" {
		t.Fatalf("key = %q", got)
	}
	if !strings.Contains(out.String(), "web1: reloaded\n") {
		t.Fatalf("hook output not forwarded with host prefix: %q", out.String())
	}
	if args, _ := os.ReadFile(argsFile); !strings.Contains(string(args), "/usr/local/bin/gibcert receive") {
		t.Fatalf("ssh args = %q", args)
	}

	res, err = c.Apply(testHost(), req, false, &out)
	if err != nil || len(res.Changed) != 0 {
		t.Fatalf("second Apply = %+v, %v; want nothing changed", res, err)
	}
}

func TestApplyDryRunChangesNothing(t *testing.T) {
	ssh, _ := receiverSSH(t)
	dir := t.TempDir()
	res, err := (&Client{SSH: ssh}).Apply(testHost(), testRequest(dir), true, nil)
	if err != nil || len(res.Changed) != 2 {
		t.Fatalf("dry run = %+v, %v; want two kinds that would change", res, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("dry run left files: %v", entries)
	}
}

func TestApplyReportsReceiverFailureWithItsCode(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	ssh, _ := receiverSSH(t)
	locked := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(locked, 0o555); err != nil {
		t.Fatal(err)
	}
	_, err := (&Client{SSH: ssh}).Apply(testHost(), testRequest(locked), true, nil)
	var re *Error
	if !errors.As(err, &re) || re.Code != receive.CodePermission || re.Host != "web1" {
		t.Fatalf("err = %v, want a permission *Error for web1", err)
	}
}

func TestApplyExplainsUnreachableHosts(t *testing.T) {
	for name, tc := range map[string]struct {
		script string
		want   string
	}{
		"ssh failure": {"echo 'Permission denied (publickey).' >&2; exit 255", "Permission denied (publickey)"},
		"no gibcert":  {"echo 'sh: gibcert: not found' >&2; exit 127", "was not found on the host"},
		"old gibcert": {"echo 'unknown command receive' >&2; exit 2", "too old"},
	} {
		t.Run(name, func(t *testing.T) {
			ssh, _ := fakeSSH(t, tc.script)
			_, err := (&Client{SSH: ssh}).Apply(testHost(), testRequest(t.TempDir()), false, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), `"web1"`) {
				t.Fatalf("err = %v, want mention of %q and the host", err, tc.want)
			}
		})
	}
}

func TestHello(t *testing.T) {
	ssh, _ := receiverSSH(t)
	h, err := (&Client{SSH: ssh}).Hello(testHost())
	if err != nil || h.UID != os.Geteuid() {
		t.Fatalf("Hello = %+v, %v", h, err)
	}
}

func TestMissingSSHClient(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	_, err := (&Client{}).Hello(testHost())
	if err == nil || !strings.Contains(err.Error(), "OpenSSH client") {
		t.Fatalf("err = %v, want missing ssh client explanation", err)
	}
}
