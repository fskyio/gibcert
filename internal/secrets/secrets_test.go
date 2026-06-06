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

package secrets

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveFileTrimsWhitespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(" secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := (Source{File: path}).Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if want := "secret"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestResolveEnv(t *testing.T) {
	t.Setenv("GIBCERT_TEST_SECRET", "from-env")
	got, err := (Source{Env: "GIBCERT_TEST_SECRET"}).Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if want := "from-env"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestResolveCommandTrimsTrailingNewline(t *testing.T) {
	got, err := (Source{Command: []string{"sh", "-c", "printf 'from-command\\n'"}}).Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if want := "from-command"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestResolveSystemdCredential(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "api-key")
	if err := os.WriteFile(path, []byte("from-credential\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)

	got, err := (Source{SystemdCredential: "api-key"}).Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if want := "from-credential"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestResolveErrors(t *testing.T) {
	if _, err := (Source{}).Resolve(context.Background()); err == nil {
		t.Fatal("empty source resolved")
	}
	if _, err := (Source{Env: "GIBCERT_MISSING_SECRET"}).Resolve(context.Background()); err == nil {
		t.Fatal("missing env resolved")
	}
	if _, err := (Source{File: filepath.Join(t.TempDir(), "missing")}).Resolve(context.Background()); err == nil {
		t.Fatal("missing file resolved")
	}
	if _, err := (Source{Command: []string{"sh", "-c", "exit 7"}}).Resolve(context.Background()); err == nil {
		t.Fatal("failing command resolved")
	}
}

func TestSystemdCredentialPathRejectsUnsafeNames(t *testing.T) {
	if _, err := (Source{}).SystemdCredentialPath(); err == nil {
		t.Fatal("empty credential path succeeded")
	}
	t.Setenv("CREDENTIALS_DIRECTORY", t.TempDir())
	if _, err := (Source{SystemdCredential: "../secret"}).SystemdCredentialPath(); err == nil {
		t.Fatal("path-like credential name succeeded")
	}
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if _, err := (Source{SystemdCredential: "api-key"}).SystemdCredentialPath(); err == nil {
		t.Fatal("credential path without directory succeeded")
	}
}

func TestRunSecretCommandNilContextAndOutputLimit(t *testing.T) {
	got, err := runSecretCommand(nil, []string{"sh", "-c", "printf secret"})
	if err != nil {
		t.Fatalf("runSecretCommand nil context: %v", err)
	}
	if got != "secret" {
		t.Fatalf("got %q, want secret", got)
	}
	if _, err := runSecretCommand(context.Background(), nil); err == nil {
		t.Fatal("empty command succeeded")
	}
	if _, err := runSecretCommand(context.Background(), []string{"sh", "-c", "yes x | head -c 70000"}); err == nil || !strings.Contains(err.Error(), "output exceeds") {
		t.Fatalf("large output error got %v", err)
	}
}

func TestLimitedBufferAndDiscard(t *testing.T) {
	var b limitedBuffer
	if n, err := b.Write([]byte("ignored")); err != nil || n != len("ignored") || b.buf.Len() != 0 {
		t.Fatalf("zero-limit Write got n=%d err=%v len=%d", n, err, b.buf.Len())
	}
	b.Limit = 3
	if n, err := b.Write([]byte("hello")); err != nil || n != 5 {
		t.Fatalf("limited Write got n=%d err=%v", n, err)
	}
	if !b.Truncated || b.buf.String() != "hel" {
		t.Fatalf("limited buffer got truncated=%v buf=%q", b.Truncated, b.buf.String())
	}
	discard := ioDiscard{}
	if n, err := discard.Write([]byte("x")); err != nil || n != 1 {
		t.Fatalf("ioDiscard Write got n=%d err=%v", n, err)
	}
}
