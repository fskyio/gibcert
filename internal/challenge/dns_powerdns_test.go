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
	"slices"
	"strings"
	"sync"
	"testing"

	"gitfield.org/fsky/gibcert/internal/config"
)

type fakePowerDNSPatch struct {
	zone   string
	rrsets []powerDNSRRset
}

// fakePowerDNS holds RRsets for every zone it lists, keyed by "name|TYPE".
type fakePowerDNS struct {
	mu      sync.Mutex
	rrsets  map[string][]powerDNSRecord
	apiKey  string
	calls   []string
	patches []fakePowerDNSPatch
}

func newFakePowerDNS(apiKey string) *fakePowerDNS {
	return &fakePowerDNS{
		rrsets: map[string][]powerDNSRecord{},
		apiKey: apiKey,
	}
}

func (f *fakePowerDNS) handler(t *testing.T) http.Handler {
	const (
		listPath   = "/api/v1/servers/localhost/zones"
		zonePrefix = listPath + "/"
	)
	zones := []string{"other.example.", "example.com."}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-API-Key"); got != f.apiKey {
			t.Errorf("X-API-Key: got %q, want %q", got, f.apiKey)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path == listPath && r.Method == http.MethodGet {
			var out []map[string]string
			for _, z := range zones {
				out = append(out, map[string]string{"name": z})
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(out)
			return
		}
		zone := strings.TrimPrefix(r.URL.Path, zonePrefix)
		if zone == r.URL.Path || !slices.Contains(zones, zone) {
			t.Errorf("unexpected path %q", r.URL.Path)
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
			for key, recs := range f.rrsets {
				name, typ, _ := strings.Cut(key, "|")
				if name == zone || strings.HasSuffix(name, "."+zone) {
					out.RRsets = append(out.RRsets, rr{Name: name, Type: typ, Records: recs})
				}
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
			f.patches = append(f.patches, fakePowerDNSPatch{zone: zone, rrsets: body.RRsets})
			for _, s := range body.RRsets {
				key := s.Name + "|" + s.Type
				switch s.ChangeType {
				case "REPLACE":
					f.rrsets[key] = s.Records
				case "DELETE":
					delete(f.rrsets, key)
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
	recs := fake.rrsets["_acme-challenge.example.com.|TXT"]
	fake.mu.Unlock()
	if len(recs) != 1 || recs[0].Content != `"token-1"` {
		t.Fatalf("after present: got %+v, want single \"token-1\"", recs)
	}

	cleanup()
	fake.mu.Lock()
	_, present := fake.rrsets["_acme-challenge.example.com.|TXT"]
	fake.mu.Unlock()
	if present {
		t.Fatalf("after cleanup: rrset should be deleted")
	}
}

func TestDNSPowerDNSMergesExistingTXT(t *testing.T) {
	fake := newFakePowerDNS("topsecret")
	fake.rrsets["_acme-challenge.example.com.|TXT"] = []powerDNSRecord{{Content: `"existing"`}}
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()

	d := &DNSPowerDNS{Provider: providerForFake(srv.URL), Out: io.Discard}
	cleanup, err := d.Present(context.Background(), Request{FQDN: "_acme-challenge.example.com", Value: "token-2"})
	if err != nil {
		t.Fatalf("Present: %v", err)
	}

	fake.mu.Lock()
	recs := fake.rrsets["_acme-challenge.example.com.|TXT"]
	fake.mu.Unlock()
	if len(recs) != 2 {
		t.Fatalf("after present: got %d records, want 2: %+v", len(recs), recs)
	}
	if !containsRecord(recs, `"existing"`) || !containsRecord(recs, `"token-2"`) {
		t.Fatalf("after present: missing expected records: %+v", recs)
	}

	cleanup()
	fake.mu.Lock()
	recs = fake.rrsets["_acme-challenge.example.com.|TXT"]
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

func TestDNSPowerDNSAddAndRemoveRecord(t *testing.T) {
	fake := newFakePowerDNS("topsecret")
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()

	d := &DNSPowerDNS{Provider: providerForFake(srv.URL), Out: io.Discard}
	req := EditRequest{
		Owner:      "_443._tcp.example.com",
		RecordType: "TXT",
		RData:      `"tlsa-value"`,
		TTL:        300,
	}
	if err := d.AddRecord(context.Background(), req); err != nil {
		t.Fatalf("AddRecord: %v", err)
	}
	fake.mu.Lock()
	recs := fake.rrsets["_443._tcp.example.com.|TXT"]
	fake.mu.Unlock()
	if len(recs) != 1 || recs[0].Content != `"tlsa-value"` {
		t.Fatalf("after add: got %+v, want single record", recs)
	}

	if err := d.RemoveRecord(context.Background(), req); err != nil {
		t.Fatalf("RemoveRecord: %v", err)
	}
	fake.mu.Lock()
	_, present := fake.rrsets["_443._tcp.example.com.|TXT"]
	fake.mu.Unlock()
	if present {
		t.Fatal("after remove: rrset should be deleted")
	}
}

func TestDNSPowerDNSConfigErrors(t *testing.T) {
	if _, err := (&DNSPowerDNS{}).Present(context.Background(), Request{}); err == nil || !strings.Contains(err.Error(), "missing provider") {
		t.Fatalf("missing provider error = %v", err)
	}
	provider := &config.Provider{Name: "powerdns-test", Fields: map[string][]string{}}
	if _, err := (&DNSPowerDNS{Provider: provider}).Present(context.Background(), Request{}); err == nil || !strings.Contains(err.Error(), "api-url is required") {
		t.Fatalf("missing api-url error = %v", err)
	}
	provider = &config.Provider{
		Name:   "powerdns-test",
		Fields: map[string][]string{"api-url": {"http://127.0.0.1:1"}, "ttl": {"nope"}},
		Secrets: []*config.Secret{
			{Name: "api-key", Value: "topsecret"},
		},
	}
	if _, err := (&DNSPowerDNS{Provider: provider}).Present(context.Background(), Request{}); err == nil || !strings.Contains(err.Error(), "invalid ttl") {
		t.Fatalf("invalid ttl error = %v", err)
	}
	provider = &config.Provider{
		Name:   "powerdns-test",
		Fields: map[string][]string{"api-url": {"http://127.0.0.1:1"}},
	}
	if _, err := (&DNSPowerDNS{Provider: provider}).Present(context.Background(), Request{}); err == nil || !strings.Contains(err.Error(), `secret "api-key" is required`) {
		t.Fatalf("missing api-key error = %v", err)
	}
}

func TestDNSPowerDNSNoMatchingZone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/servers/localhost/zones" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]string{{"name": "unrelated.example."}})
	}))
	defer srv.Close()

	d := &DNSPowerDNS{Provider: providerForFake(srv.URL), Out: io.Discard}
	_, err := d.Present(context.Background(), Request{FQDN: "_acme-challenge.example.com", Value: "token"})
	if err == nil || !strings.Contains(err.Error(), "no zone") {
		t.Fatalf("Present error = %v, want no zone", err)
	}
}

func TestPowerDNSPickZoneChoosesLongestMatch(t *testing.T) {
	zones := []string{"example.com.", "sub.example.com.", "com."}
	if got := powerDNSPickZone(zones, "_acme-challenge.sub.example.com."); got != "sub.example.com." {
		t.Fatalf("powerDNSPickZone got %q, want sub.example.com.", got)
	}
	if got := powerDNSPickZone(zones, "elsewhere.invalid."); got != "" {
		t.Fatalf("powerDNSPickZone got %q, want no match", got)
	}
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

func powerDNSContents(recs []powerDNSRecord) []string {
	out := make([]string, len(recs))
	for i, r := range recs {
		out[i] = r.Content
	}
	return out
}

func TestDNSPowerDNSApplyEditsMergesRRsetsIntoOnePatch(t *testing.T) {
	fake := newFakePowerDNS("topsecret")
	fake.rrsets["_443._tcp.example.com.|TLSA"] = []powerDNSRecord{{Content: "3 1 1 old"}}
	fake.rrsets["_443._tcp.example.com.|TXT"] = []powerDNSRecord{{Content: `"keep"`}}
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()

	edit := func(owner, rdata string) EditRequest {
		return EditRequest{Owner: owner, RecordType: "TLSA", RData: rdata, TTL: 300}
	}
	ops := []EditOp{
		{EditRequest: edit("_443._tcp.example.com", "3 1 1 new1")},
		{EditRequest: edit("_25._tcp.example.com", "3 1 1 new1")},
		{EditRequest: edit("_443._TCP.example.com", "3 1 1 new2")},
		{Remove: true, EditRequest: edit("_443._tcp.example.com", "3 1 1 old")},
	}
	d := &DNSPowerDNS{Provider: providerForFake(srv.URL), Out: io.Discard}
	if err := ApplyEdits(context.Background(), d, ops); err != nil {
		t.Fatalf("ApplyEdits: %v", err)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if want := []string{http.MethodGet, http.MethodPatch}; !slices.Equal(fake.calls, want) {
		t.Fatalf("zone requests = %v, want %v", fake.calls, want)
	}
	if len(fake.patches) != 1 || fake.patches[0].zone != "example.com." || len(fake.patches[0].rrsets) != 2 {
		t.Fatalf("patches = %+v, want one patch of two RRsets on example.com.", fake.patches)
	}
	for _, rrset := range fake.patches[0].rrsets {
		if rrset.Type != "TLSA" || rrset.TTL != 300 || rrset.ChangeType != "REPLACE" {
			t.Fatalf("rrset = %+v, want TLSA REPLACE with ttl 300", rrset)
		}
	}
	if got, want := powerDNSContents(fake.rrsets["_443._tcp.example.com.|TLSA"]), []string{"3 1 1 new1", "3 1 1 new2"}; !slices.Equal(got, want) {
		t.Fatalf("_443 TLSA = %v, want %v", got, want)
	}
	if got, want := powerDNSContents(fake.rrsets["_25._tcp.example.com.|TLSA"]), []string{"3 1 1 new1"}; !slices.Equal(got, want) {
		t.Fatalf("_25 TLSA = %v, want %v", got, want)
	}
	if got, want := powerDNSContents(fake.rrsets["_443._tcp.example.com.|TXT"]), []string{`"keep"`}; !slices.Equal(got, want) {
		t.Fatalf("TXT at the same owner = %v, want it untouched: %v", got, want)
	}
}

func TestDNSPowerDNSApplyEditsAppliesOpsInOrder(t *testing.T) {
	fake := newFakePowerDNS("topsecret")
	fake.rrsets["_443._tcp.example.com.|TLSA"] = []powerDNSRecord{{Content: "3 1 1 x"}}
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()

	req := func(owner, rdata string) EditRequest {
		return EditRequest{Owner: owner, RecordType: "TLSA", RData: rdata}
	}
	ops := []EditOp{
		{Remove: true, EditRequest: req("_443._tcp.example.com", "3 1 1 x")},
		{EditRequest: req("_443._tcp.example.com", "3 1 1 x")},
		{EditRequest: req("_25._tcp.example.com", "3 1 1 y")},
		{Remove: true, EditRequest: req("_25._tcp.example.com", "3 1 1 y")},
	}
	d := &DNSPowerDNS{Provider: providerForFake(srv.URL), Out: io.Discard}
	if err := d.ApplyEdits(context.Background(), ops); err != nil {
		t.Fatalf("ApplyEdits: %v", err)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if got, want := powerDNSContents(fake.rrsets["_443._tcp.example.com.|TLSA"]), []string{"3 1 1 x"}; !slices.Equal(got, want) {
		t.Fatalf("remove then add = %v, want the record kept: %v", got, want)
	}
	if recs, ok := fake.rrsets["_25._tcp.example.com.|TLSA"]; ok {
		t.Fatalf("add then remove left %+v, want the RRset deleted", recs)
	}
}

func TestDNSPowerDNSApplyEditsSendsOnePatchPerZone(t *testing.T) {
	fake := newFakePowerDNS("topsecret")
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()

	req := func(owner string) EditOp {
		return EditOp{EditRequest: EditRequest{Owner: owner, RecordType: "TLSA", RData: "3 1 1 z"}}
	}
	ops := []EditOp{req("_443._tcp.example.com"), req("_443._tcp.www.other.example"), req("_25._tcp.example.com")}
	d := &DNSPowerDNS{Provider: providerForFake(srv.URL), Out: io.Discard}
	if err := d.ApplyEdits(context.Background(), ops); err != nil {
		t.Fatalf("ApplyEdits: %v", err)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.patches) != 2 {
		t.Fatalf("patches = %+v, want one per zone", fake.patches)
	}
	if p := fake.patches[0]; p.zone != "example.com." || len(p.rrsets) != 2 {
		t.Fatalf("first patch = %+v, want two RRsets on example.com.", p)
	}
	if p := fake.patches[1]; p.zone != "other.example." || len(p.rrsets) != 1 {
		t.Fatalf("second patch = %+v, want one RRset on other.example.", p)
	}
}

func TestDNSPowerDNSApplyEditsChangesNothingWhenAnOpHasNoZone(t *testing.T) {
	fake := newFakePowerDNS("topsecret")
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()

	ops := []EditOp{
		{EditRequest: EditRequest{Owner: "_443._tcp.example.com", RecordType: "TLSA", RData: "3 1 1 z"}},
		{EditRequest: EditRequest{Owner: "_443._tcp.unrelated.test", RecordType: "TLSA", RData: "3 1 1 z"}},
	}
	d := &DNSPowerDNS{Provider: providerForFake(srv.URL), Out: io.Discard}
	err := d.ApplyEdits(context.Background(), ops)
	if err == nil || !strings.Contains(err.Error(), "unrelated.test") {
		t.Fatalf("ApplyEdits error = %v, want no zone for unrelated.test", err)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.patches) != 0 || len(fake.rrsets) != 0 {
		t.Fatalf("DNS changed despite the failed batch: patches=%+v rrsets=%+v", fake.patches, fake.rrsets)
	}
}
