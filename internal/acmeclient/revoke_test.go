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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"foundry.fsky.io/fsky/gibcert/internal/acme"
	"foundry.fsky.io/fsky/gibcert/internal/storage"
)

func TestRevocationReasonAndKnownReason(t *testing.T) {
	tests := []struct {
		reason string
		code   int
		known  bool
	}{
		{"unspecified", acme.ReasonUnspecified, true},
		{"key-compromise", acme.ReasonKeyCompromise, true},
		{"ca-compromise", acme.ReasonCACompromise, true},
		{"affiliation-changed", acme.ReasonAffiliationChanged, true},
		{"superseded", acme.ReasonSuperseded, true},
		{"cessation-of-operation", acme.ReasonCessationOfOperation, true},
		{"certificate-hold", acme.ReasonCertificateHold, true},
		{"privilege-withdrawn", acme.ReasonPrivilegeWithdrawn, true},
		{"aa-compromise", acme.ReasonAACompromise, true},
		{"mystery", acme.ReasonUnspecified, false},
	}
	for _, tt := range tests {
		t.Run(tt.reason, func(t *testing.T) {
			if got := RevocationReason(tt.reason); got != tt.code {
				t.Fatalf("RevocationReason got %d, want %d", got, tt.code)
			}
			if got := KnownRevocationReason(tt.reason); got != tt.known {
				t.Fatalf("KnownRevocationReason got %v, want %v", got, tt.known)
			}
		})
	}
}

func TestReadLeafCert(t *testing.T) {
	dir := t.TempDir()
	certPath := dir + "/cert.pem"
	cert := testCertDER(t, "example.com", nil, nil)
	if err := storage.WriteSingleCertDER(certPath, cert.der, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readLeafCert(certPath)
	if err != nil {
		t.Fatalf("readLeafCert: %v", err)
	}
	if got.SerialNumber.Cmp(cert.cert.SerialNumber) != 0 {
		t.Fatalf("serial got %s, want %s", got.SerialNumber, cert.cert.SerialNumber)
	}

	badPath := dir + "/bad.pem"
	if err := os.WriteFile(badPath, []byte("not pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readLeafCert(badPath); err == nil {
		t.Fatal("readLeafCert accepted non-PEM input")
	}
	if _, err := readLeafCert(dir + "/missing.pem"); err == nil {
		t.Fatal("readLeafCert accepted missing file")
	}
}

func TestRevokeUpdatesMetadata(t *testing.T) {
	var revokeCalls int
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
		case "/revoke":
			revokeCalls++
			if r.Method != http.MethodPost {
				t.Fatalf("revoke method got %s", r.Method)
			}
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{}"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

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
	if err := store.SaveAccountMeta("default", storage.AccountMeta{
		URL:       srv.URL + "/acct/1",
		Email:     "admin@example.com",
		Directory: srv.URL + "/directory",
	}); err != nil {
		t.Fatal(err)
	}

	cert := testCertDER(t, "example.com", nil, nil)
	paths := store.CertPaths("example.com")
	if err := os.MkdirAll(paths.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := storage.WriteSingleCertDER(paths.Cert, cert.der, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Revoke(context.Background(), store, "example.com", "default", srv.URL+"/directory", "key-compromise"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if revokeCalls != 1 {
		t.Fatalf("revoke calls got %d, want 1", revokeCalls)
	}
	meta, err := store.LoadCertMeta("example.com")
	if err != nil {
		t.Fatalf("LoadCertMeta: %v", err)
	}
	if meta.RevokedAt == nil || meta.RevocationReason != "key-compromise" {
		t.Fatalf("revocation metadata got %#v", meta)
	}
	if meta.Account != "default" || meta.Directory != srv.URL+"/directory" {
		t.Fatalf("fallback metadata got %#v", meta)
	}
}
