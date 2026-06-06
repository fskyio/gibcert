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
	"encoding/json"
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

func TestLoadOrRegisterRegistersAndCachesAccount(t *testing.T) {
	var newAccountCalls int
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce-value")
		switch r.URL.Path {
		case "/directory":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"newNonce":   srv.URL + "/nonce",
				"newAccount": srv.URL + "/new-account",
				"newOrder":   srv.URL + "/new-order",
				"revokeCert": srv.URL + "/revoke",
				"keyChange":  srv.URL + "/key-change",
			})
		case "/nonce":
			w.WriteHeader(http.StatusOK)
		case "/new-account":
			newAccountCalls++
			if r.Method != http.MethodPost {
				t.Fatalf("new-account method got %s", r.Method)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Location", srv.URL+"/acct/1")
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"status":"valid"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	store := storage.New(t.TempDir())
	client, err := LoadOrRegister(context.Background(), store, AccountOptions{
		Name:         "default",
		DirectoryURL: srv.URL + "/directory",
		Email:        "admin@example.com",
	})
	if err != nil {
		t.Fatalf("LoadOrRegister: %v", err)
	}
	if client.DirectoryURL() != srv.URL+"/directory" {
		t.Fatalf("DirectoryURL got %q", client.DirectoryURL())
	}
	if client.AccountURL() != srv.URL+"/acct/1" {
		t.Fatalf("AccountURL got %q", client.AccountURL())
	}
	if newAccountCalls != 1 {
		t.Fatalf("new-account calls got %d, want 1", newAccountCalls)
	}
	meta, err := store.LoadAccountMeta("default")
	if err != nil {
		t.Fatalf("LoadAccountMeta: %v", err)
	}
	if meta.URL != srv.URL+"/acct/1" || meta.Email != "admin@example.com" || meta.Directory != srv.URL+"/directory" {
		t.Fatalf("account metadata got %#v", meta)
	}

	cached, err := LoadOrRegister(context.Background(), store, AccountOptions{
		Name:         "default",
		DirectoryURL: srv.URL + "/directory",
		Email:        "admin@example.com",
	})
	if err != nil {
		t.Fatalf("cached LoadOrRegister: %v", err)
	}
	if cached.AccountURL() != srv.URL+"/acct/1" {
		t.Fatalf("cached AccountURL got %q", cached.AccountURL())
	}
	if newAccountCalls != 1 {
		t.Fatalf("cached LoadOrRegister called new-account again: %d", newAccountCalls)
	}
}

func TestLoadOrRegisterUpdatesChangedEmail(t *testing.T) {
	var updateCalls int
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce-value")
		switch r.URL.Path {
		case "/directory":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"newNonce":   srv.URL + "/nonce",
				"newAccount": srv.URL + "/new-account",
				"newOrder":   srv.URL + "/new-order",
				"revokeCert": srv.URL + "/revoke",
				"keyChange":  srv.URL + "/key-change",
			})
		case "/nonce":
			w.WriteHeader(http.StatusOK)
		case "/acct/1":
			updateCalls++
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Location", srv.URL+"/acct/1")
			_, _ = io.WriteString(w, `{"status":"valid","contact":["mailto:new@example.com"]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	store := storage.New(t.TempDir())
	if err := os.MkdirAll(store.AccountDir("default"), 0o700); err != nil {
		t.Fatal(err)
	}
	key, err := storage.GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.WriteKey(store.AccountKeyPath("default"), key); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAccountMeta("default", storage.AccountMeta{
		URL:       srv.URL + "/acct/1",
		Email:     "old@example.com",
		Directory: srv.URL + "/directory",
	}); err != nil {
		t.Fatal(err)
	}

	client, err := LoadOrRegister(context.Background(), store, AccountOptions{
		Name:         "default",
		DirectoryURL: srv.URL + "/directory",
		Email:        "new@example.com",
	})
	if err != nil {
		t.Fatalf("LoadOrRegister update: %v", err)
	}
	if updateCalls != 1 {
		t.Fatalf("update calls got %d, want 1", updateCalls)
	}
	if client.AccountURL() != srv.URL+"/acct/1" {
		t.Fatalf("AccountURL got %q", client.AccountURL())
	}
	meta, err := store.LoadAccountMeta("default")
	if err != nil {
		t.Fatalf("LoadAccountMeta: %v", err)
	}
	if meta.Email != "new@example.com" {
		t.Fatalf("updated email got %q", meta.Email)
	}
}

func TestLoadExistingUsesStoredMetadata(t *testing.T) {
	store := storage.New(t.TempDir())
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	key, err := storage.GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(store.AccountDir("default"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := storage.WriteKey(store.AccountKeyPath("default"), key); err != nil {
		t.Fatal(err)
	}
	if err := saveAccountMeta(store, "default", "https://ca.example/acct/1", "admin@example.com", "https://ca.example/directory"); err != nil {
		t.Fatalf("saveAccountMeta: %v", err)
	}
	client, err := LoadExisting(context.Background(), store, "default", "https://ca.example/directory")
	if err != nil {
		t.Fatalf("LoadExisting: %v", err)
	}
	if client.AccountURL() != "https://ca.example/acct/1" {
		t.Fatalf("AccountURL got %q", client.AccountURL())
	}
}

func TestLoadOrCreateAccountKey(t *testing.T) {
	store := storage.New(t.TempDir())
	if err := os.MkdirAll(store.AccountDir("default"), 0o700); err != nil {
		t.Fatal(err)
	}
	first, err := loadOrCreateAccountKey(store, "default")
	if err != nil {
		t.Fatalf("loadOrCreateAccountKey create: %v", err)
	}
	second, err := loadOrCreateAccountKey(store, "default")
	if err != nil {
		t.Fatalf("loadOrCreateAccountKey load: %v", err)
	}
	if first.Public() == nil || second.Public() == nil {
		t.Fatal("account keys missing public key")
	}
	if _, err := os.Stat(store.AccountKeyPath("default")); err != nil {
		t.Fatalf("account key not written: %v", err)
	}
}

func TestFetchDirectoryMeta(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/directory" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"newNonce":    srv.URL + "/nonce",
			"newAccount":  srv.URL + "/new-account",
			"newOrder":    srv.URL + "/new-order",
			"revokeCert":  srv.URL + "/revoke",
			"keyChange":   srv.URL + "/key-change",
			"renewalInfo": srv.URL + "/ari",
			"meta": map[string]any{
				"termsOfService":          "https://ca.example/terms",
				"website":                 "https://ca.example",
				"caaIdentities":           []string{"ca.example"},
				"externalAccountRequired": true,
				"profiles":                map[string]string{"short": "short-lived"},
			},
		})
	}))
	defer srv.Close()
	meta, err := FetchDirectoryMeta(context.Background(), srv.URL+"/directory")
	if err != nil {
		t.Fatalf("FetchDirectoryMeta: %v", err)
	}
	if meta.RenewalInfo != srv.URL+"/ari" || meta.Terms != "https://ca.example/terms" || !meta.ExternalAccountRequired {
		t.Fatalf("directory metadata got %#v", meta)
	}
	if len(meta.CAAIdentities) != 1 || meta.CAAIdentities[0] != "ca.example" || meta.Profiles["short"] != "short-lived" {
		t.Fatalf("directory metadata lists got %#v", meta)
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
