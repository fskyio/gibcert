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

package receive

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitfield.org/fsky/gibcert/internal/deploy"
)

func envelope(t *testing.T, env Envelope) *bytes.Reader {
	t.Helper()
	if env.Protocol == 0 {
		env.Protocol = ProtocolVersion
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(b)
}

func request(dir string) deploy.Request {
	mode := fs.FileMode(0o640)
	return deploy.Request{
		Cert:   "example.com",
		Target: "web",
		Files: []deploy.File{
			{Kind: "fullchain", Path: filepath.Join(dir, "fullchain.pem"), Data: []byte("fullchain")},
			{Kind: "key", Path: filepath.Join(dir, "privkey.pem"), Data: []byte("key")},
		},
		Mode: &mode,
	}
}

func decode(t *testing.T, stdout string) Response {
	t.Helper()
	var resp Response
	dec := json.NewDecoder(strings.NewReader(stdout))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("stdout is not one response: %v: %q", err, stdout)
	}
	if dec.More() {
		t.Fatalf("stdout holds more than one JSON value: %q", stdout)
	}
	return resp
}

func TestServeApplyKeepsStdoutToTheResponse(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "hook.log")
	req := request(dir)
	req.After = `echo hook-chatter; echo "$GIBCERT_EVENT:$GIBCERT_CHANGED" > ` + log

	var stdout, stderr bytes.Buffer
	code := Serve(envelope(t, Envelope{Op: OpApply, Request: &req}), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Serve = %d, stdout %q stderr %q", code, stdout.String(), stderr.String())
	}
	resp := decode(t, stdout.String())
	if !resp.OK || strings.Join(resp.Changed, ",") != "fullchain,key" {
		t.Fatalf("response = %+v, want ok with fullchain,key changed", resp)
	}
	if !strings.Contains(stderr.String(), "hook-chatter") {
		t.Fatalf("hook output missing from stderr: %q", stderr.String())
	}
	if got, _ := os.ReadFile(log); string(got) != "after-deploy:fullchain,key\n" {
		t.Fatalf("hook saw %q", got)
	}
	info, err := os.Stat(filepath.Join(dir, "privkey.pem"))
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("key = %v, %v; want mode 0640", info, err)
	}
}

func TestServeCheckStagesWithoutInstalling(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "hook.log")
	req := request(dir)
	req.After = "touch " + log

	var stdout, stderr bytes.Buffer
	if code := Serve(envelope(t, Envelope{Op: OpCheck, Request: &req}), &stdout, &stderr); code != 0 {
		t.Fatalf("Serve = %d, stdout %q stderr %q", code, stdout.String(), stderr.String())
	}
	resp := decode(t, stdout.String())
	if !resp.OK || len(resp.Changed) != 2 {
		t.Fatalf("response = %+v, want two changed kinds", resp)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("check left files behind: %v", entries)
	}
}

func TestServeRejectsUntrustedRequests(t *testing.T) {
	dir := t.TempDir()
	good := func() deploy.Request { return request(dir) }
	loose := fs.FileMode(0o644)
	for name, tc := range map[string]struct {
		env  func() Envelope
		code string
	}{
		"relative path": {func() Envelope {
			r := good()
			r.Files[0].Path = "fullchain.pem"
			return Envelope{Op: OpApply, Request: &r}
		}, CodeInvalid},
		"world readable key": {func() Envelope {
			r := good()
			r.Mode = &loose
			return Envelope{Op: OpApply, Request: &r}
		}, CodeInvalid},
		"before without after": {func() Envelope {
			r := good()
			r.Before = "true"
			return Envelope{Op: OpApply, Request: &r}
		}, CodeInvalid},
		"duplicate destination": {func() Envelope {
			r := good()
			r.Files[1].Path = r.Files[0].Path
			return Envelope{Op: OpApply, Request: &r}
		}, CodeInvalid},
		"missing request": {func() Envelope { return Envelope{Op: OpApply} }, CodeInvalid},
		"unknown op":      {func() Envelope { return Envelope{Op: "shell"} }, CodeInvalid},
		"newer protocol": {func() Envelope {
			return Envelope{Protocol: ProtocolVersion + 1, Op: OpHello}
		}, CodeProtocol},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Serve(envelope(t, tc.env()), &stdout, &stderr); code == 0 {
				t.Fatal("Serve accepted the request")
			}
			resp := decode(t, stdout.String())
			if resp.OK || resp.Error == nil || resp.Error.Code != tc.code {
				t.Fatalf("response = %+v, want error code %q", resp, tc.code)
			}
			if entries, _ := os.ReadDir(dir); len(entries) != 0 {
				t.Fatalf("rejected request touched the filesystem: %v", entries)
			}
		})
	}
}

func TestServeRejectsMalformedInput(t *testing.T) {
	for name, in := range map[string]string{
		"not json":      "hello",
		"unknown field": `{"protocol":1,"op":"hello","sudo":true}`,
		"empty":         "",
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Serve(strings.NewReader(in), &stdout, &stderr); code == 0 {
				t.Fatal("Serve accepted malformed input")
			}
			if resp := decode(t, stdout.String()); resp.Error == nil || resp.Error.Code != CodeInvalid {
				t.Fatalf("response = %+v, want invalid", resp)
			}
		})
	}
}

func TestRefuseEscalation(t *testing.T) {
	env := func(pairs ...string) func(string) string {
		m := map[string]string{}
		for i := 0; i < len(pairs); i += 2 {
			m[pairs[i]] = pairs[i+1]
		}
		return func(k string) string { return m[k] }
	}
	for name, tc := range map[string]struct {
		euid    int
		getenv  func(string) string
		refused bool
	}{
		"root through sudo":     {0, env("SUDO_USER", "deploy"), true},
		"root through doas":     {0, env("DOAS_USER", "deploy"), true},
		"root login":            {0, env(), false},
		"unprivileged":          {1001, env(), false},
		"stray variable":        {1001, env("SUDO_USER", "deploy"), false},
		"windows style euid":    {-1, env("SUDO_USER", "deploy"), false},
		"root with empty value": {0, env("SUDO_USER", ""), false},
	} {
		t.Run(name, func(t *testing.T) {
			if err := refuseEscalation(tc.euid, tc.getenv); (err != nil) != tc.refused {
				t.Fatalf("refuseEscalation = %v, refused %v", err, tc.refused)
			}
		})
	}
	resp := handle(strings.NewReader(""), &bytes.Buffer{}, 0, env("SUDO_USER", "deploy"))
	if resp.OK || resp.Error.Code != CodeDenied {
		t.Fatalf("handle under sudo = %+v, want denied", resp)
	}
}

func TestServeNeverFollowsDestinationSymlinks(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("root only"), 0o600); err != nil {
		t.Fatal(err)
	}
	req := request(dir)
	if err := os.Symlink(secret, req.Files[0].Path); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Serve(envelope(t, Envelope{Op: OpApply, Request: &req}), &stdout, &stderr); code == 0 {
		t.Fatal("Serve replaced a symlink destination")
	}
	if resp := decode(t, stdout.String()); resp.Error == nil || !strings.Contains(resp.Error.Message, "symbolic link") {
		t.Fatalf("response = %+v, want symbolic link refusal", resp)
	}
	if got, _ := os.ReadFile(secret); string(got) != "root only" {
		t.Fatalf("symlink target changed: %q", got)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".gibcert-") {
			t.Fatalf("staging file left behind: %s", e.Name())
		}
	}
}

func TestServeClassifiesPermissionFailures(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o555); err != nil {
		t.Fatal(err)
	}
	req := request(locked)
	var stdout, stderr bytes.Buffer
	if code := Serve(envelope(t, Envelope{Op: OpCheck, Request: &req}), &stdout, &stderr); code == 0 {
		t.Fatal("Serve wrote into a read-only directory")
	}
	resp := decode(t, stdout.String())
	if resp.Error == nil || resp.Error.Code != CodePermission || !strings.Contains(resp.Error.Message, "runs as uid") {
		t.Fatalf("response = %+v, want permission error naming the uid", resp)
	}
}

func TestServeHello(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Serve(envelope(t, Envelope{Op: OpHello}), &stdout, &stderr); code != 0 {
		t.Fatalf("Serve = %d: %s", code, stdout.String())
	}
	resp := decode(t, stdout.String())
	if !resp.OK || resp.Hello == nil || resp.Hello.UID != os.Geteuid() || resp.Hello.OS == "" {
		t.Fatalf("hello = %+v", resp)
	}
}
