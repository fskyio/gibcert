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

package acmeclient

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"foundry.fsky.io/fsky/gibcert/internal/storage"
)

// eabFor encodes the resolved HMAC secret as a base64url MACKey that internal/acme
// decodes back to the original bytes before signing. These tests assert both
// the KID passthrough and that round-trip for each secret source.
func TestEABForValue(t *testing.T) {
	eab, err := eabFor(context.Background(), &EABOptions{
		KID:          "kid-1",
		HMACKeyValue: "secret",
	})
	if err != nil {
		t.Fatalf("eabFor: %v", err)
	}
	if got, want := eab.KeyID, "kid-1"; got != want {
		t.Errorf("KeyID got %q, want %q", got, want)
	}
	assertMACKeyDecodes(t, eab.MACKey, "secret")
}

func TestEABForFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eab.key")
	if err := os.WriteFile(path, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	eab, err := eabFor(context.Background(), &EABOptions{
		KID:         "kid-1",
		HMACKeyFile: path,
	})
	if err != nil {
		t.Fatalf("eabFor: %v", err)
	}
	assertMACKeyDecodes(t, eab.MACKey, "secret")
}

func TestEABForEnv(t *testing.T) {
	t.Setenv("GIBCERT_EAB_KEY", "env-secret")

	eab, err := eabFor(context.Background(), &EABOptions{
		KID:        "kid-1",
		HMACKeyEnv: "GIBCERT_EAB_KEY",
	})
	if err != nil {
		t.Fatalf("eabFor: %v", err)
	}
	assertMACKeyDecodes(t, eab.MACKey, "env-secret")
}

func assertMACKeyDecodes(t *testing.T, macKey, want string) {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(macKey)
	if err != nil {
		t.Fatalf("MACKey is not base64url: %v", err)
	}
	if got := string(decoded); got != want {
		t.Errorf("decoded MAC key got %q, want %q", got, want)
	}
}

func TestRotateAccountKey(t *testing.T) {
	var keyChangeCalls int
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/directory":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"newNonce":"`+srv.URL+`/nonce","newAccount":"`+srv.URL+`/new-account","newOrder":"`+srv.URL+`/new-order","keyChange":"`+srv.URL+`/key-change"}`)
		case "/nonce":
			w.Header().Set("Replay-Nonce", "nonce-value")
			w.WriteHeader(http.StatusOK)
		case "/new-account":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Replay-Nonce", "nonce-value")
			w.Header().Set("Location", srv.URL+"/acct/1")
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, `{"status":"valid"}`)
		case "/key-change":
			keyChangeCalls++
			w.Header().Set("Replay-Nonce", "nonce-value")
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, `{}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	store := storage.New(t.TempDir())
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	oldKey, err := storage.GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(store.AccountDir("default"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := storage.WriteKey(store.AccountKeyPath("default"), oldKey); err != nil {
		t.Fatal(err)
	}

	var out strings.Builder
	if err := RotateAccountKey(context.Background(), store, "default", srv.URL+"/directory", nil, &out); err != nil {
		t.Fatalf("RotateAccountKey: %v", err)
	}
	if keyChangeCalls != 1 {
		t.Fatalf("key-change calls got %d, want 1", keyChangeCalls)
	}
	if _, err := storage.ReadKey(store.AccountKeyPath("default")); err != nil {
		t.Fatalf("read rotated key: %v", err)
	}
	if _, err := os.Stat(store.AccountKeyNextPath("default")); !os.IsNotExist(err) {
		t.Fatalf("staged key still exists: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(store.AccountDir("default"), "account-*.key"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("account key archives got %v, want one archive", matches)
	}
	if !strings.Contains(out.String(), "rotated account key for default") {
		t.Fatalf("output %q does not mention rotation", out.String())
	}
}
