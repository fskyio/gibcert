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
