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

package challenge

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"foundry.fsky.io/fsky/gibcert/internal/config"
)

type fakePowerDNS struct {
	mu     sync.Mutex
	rrsets map[string][]powerDNSRecord
	apiKey string
	calls  []string
}

func newFakePowerDNS(apiKey string) *fakePowerDNS {
	return &fakePowerDNS{
		rrsets: map[string][]powerDNSRecord{},
		apiKey: apiKey,
	}
}

func (f *fakePowerDNS) handler(t *testing.T) http.Handler {
	const (
		listPath = "/api/v1/servers/localhost/zones"
		zonePath = "/api/v1/servers/localhost/zones/example.com."
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-API-Key"); got != f.apiKey {
			t.Errorf("X-API-Key: got %q, want %q", got, f.apiKey)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path == listPath && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]map[string]string{
				{"name": "other.example."},
				{"name": "example.com."},
			})
			return
		}
		if r.URL.Path != zonePath {
			t.Errorf("path: got %q, want %q", r.URL.Path, zonePath)
			http.NotFound(w, r)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, r.Method)
		switch r.Method {
		case http.MethodGet:
			type rr struct {
				Name    string           `json:"name"`
				Type    string           `json:"type"`
				Records []powerDNSRecord `json:"records"`
			}
			var out struct {
				RRsets []rr `json:"rrsets"`
			}
			for name, recs := range f.rrsets {
				out.RRsets = append(out.RRsets, rr{Name: name, Type: "TXT", Records: recs})
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(out)
		case http.MethodPatch:
			var body struct {
				RRsets []powerDNSRRset `json:"rrsets"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			for _, s := range body.RRsets {
				switch s.ChangeType {
				case "REPLACE":
					f.rrsets[s.Name] = s.Records
				case "DELETE":
					delete(f.rrsets, s.Name)
				default:
					http.Error(w, "bad changetype", http.StatusBadRequest)
					return
				}
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

func providerForFake(url string) *config.Provider {
	return &config.Provider{
		Name:   "powerdns-test",
		Type:   "dns",
		Driver: "powerdns",
		Fields: map[string][]string{
			"api-url": {url},
		},
		Secrets: []*config.Secret{{Name: "api-key", Value: "topsecret"}},
	}
}

func TestDNSPowerDNSPresentAndCleanup(t *testing.T) {
	fake := newFakePowerDNS("topsecret")
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()

	d := &DNSPowerDNS{Provider: providerForFake(srv.URL), Out: io.Discard}
	cleanup, err := d.Present(context.Background(), Request{FQDN: "_acme-challenge.example.com", Value: "token-1"})
	if err != nil {
		t.Fatalf("Present: %v", err)
	}

	fake.mu.Lock()
	recs := fake.rrsets["_acme-challenge.example.com."]
	fake.mu.Unlock()
	if len(recs) != 1 || recs[0].Content != `"token-1"` {
		t.Fatalf("after present: got %+v, want single \"token-1\"", recs)
	}

	cleanup()
	fake.mu.Lock()
	_, present := fake.rrsets["_acme-challenge.example.com."]
	fake.mu.Unlock()
	if present {
		t.Fatalf("after cleanup: rrset should be deleted")
	}
}

func TestDNSPowerDNSMergesExistingTXT(t *testing.T) {
	fake := newFakePowerDNS("topsecret")
	fake.rrsets["_acme-challenge.example.com."] = []powerDNSRecord{{Content: `"existing"`}}
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()

	d := &DNSPowerDNS{Provider: providerForFake(srv.URL), Out: io.Discard}
	cleanup, err := d.Present(context.Background(), Request{FQDN: "_acme-challenge.example.com", Value: "token-2"})
	if err != nil {
		t.Fatalf("Present: %v", err)
	}

	fake.mu.Lock()
	recs := fake.rrsets["_acme-challenge.example.com."]
	fake.mu.Unlock()
	if len(recs) != 2 {
		t.Fatalf("after present: got %d records, want 2: %+v", len(recs), recs)
	}
	if !containsRecord(recs, `"existing"`) || !containsRecord(recs, `"token-2"`) {
		t.Fatalf("after present: missing expected records: %+v", recs)
	}

	cleanup()
	fake.mu.Lock()
	recs = fake.rrsets["_acme-challenge.example.com."]
	fake.mu.Unlock()
	if len(recs) != 1 || recs[0].Content != `"existing"` {
		t.Fatalf("after cleanup: got %+v, want only \"existing\"", recs)
	}
}

func TestDNSPowerDNSReadsSecretFromEnv(t *testing.T) {
	t.Setenv("POWERDNS_TEST_API_KEY", "from-env")
	fake := newFakePowerDNS("from-env")
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()

	p := providerForFake(srv.URL)
	p.Secrets = []*config.Secret{{Name: "api-key", Env: "POWERDNS_TEST_API_KEY"}}
	d := &DNSPowerDNS{Provider: p, Out: io.Discard}
	cleanup, err := d.Present(context.Background(), Request{FQDN: "_acme-challenge.example.com", Value: "token-env"})
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	cleanup()
}

func TestDNSPowerDNSAuthFailureSurfaced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
	}))
	defer srv.Close()

	d := &DNSPowerDNS{Provider: providerForFake(srv.URL), Out: io.Discard}
	_, err := d.Present(context.Background(), Request{FQDN: "_acme-challenge.example.com", Value: "v"})
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("Present: want 401 error, got %v", err)
	}
}
