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
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"foundry.fsky.io/fsky/gibcert/internal/acme"
)

func TestRenewalInfo(t *testing.T) {
	ca := testCertDER(t, "Test CA", nil, nil)
	leafFixture := testCertDER(t, "example.com", ca.cert, ca.key)
	leaf := leafFixture.cert
	certID, err := acme.ARIUniqueIdentifier(leaf)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	end := start.Add(2 * time.Hour)

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/directory":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"newNonce":    srv.URL + "/nonce",
				"newAccount":  srv.URL + "/new-account",
				"newOrder":    srv.URL + "/new-order",
				"revokeCert":  srv.URL + "/revoke",
				"keyChange":   srv.URL + "/key-change",
				"renewalInfo": srv.URL + "/ari",
			})
		case r.URL.Path == "/ari/"+certID:
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "60")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"suggestedWindow": map[string]time.Time{
					"start": start,
					"end":   end,
				},
				"explanationURL": "https://ca.example/why",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := &Client{acme: newACMEClient(srv.URL+"/directory", srv.Client())}
	ari, err := client.RenewalInfo(context.Background(), leaf)
	if err != nil {
		t.Fatalf("RenewalInfo: %v", err)
	}
	if !ari.WindowStart.Equal(start) || !ari.WindowEnd.Equal(end) || ari.ExplanationURL != "https://ca.example/why" {
		t.Fatalf("ARI got %#v", ari)
	}
	if ari.RetryAfter == nil || time.Until(*ari.RetryAfter) <= 0 {
		t.Fatalf("RetryAfter got %#v", ari.RetryAfter)
	}
	if ari.SelectedTime.Before(start) || !ari.SelectedTime.Before(end) {
		t.Fatalf("SelectedTime %v outside [%v,%v)", ari.SelectedTime, start, end)
	}
}

func TestRenewalInfoUnsupported(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/directory" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   srv.URL + "/nonce",
			"newAccount": srv.URL + "/new-account",
			"newOrder":   srv.URL + "/new-order",
			"revokeCert": srv.URL + "/revoke",
			"keyChange":  srv.URL + "/key-change",
		})
	}))
	defer srv.Close()
	client := &Client{acme: newACMEClient(srv.URL+"/directory", srv.Client())}
	_, err := client.RenewalInfo(context.Background(), testCertDER(t, "example.com", nil, nil).cert)
	if !errors.Is(err, ErrARIUnsupported) {
		t.Fatalf("RenewalInfo error got %v, want ErrARIUnsupported", err)
	}
	if err != nil && !strings.Contains(err.Error(), "renewal information") {
		t.Fatalf("RenewalInfo unsupported error text got %v", err)
	}
}
