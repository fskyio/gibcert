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

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"gitfield.org/fsky/gibcert/internal/paths"
	"gitfield.org/fsky/gibcert/internal/storage"
)

func TestApplyAndRenewReconcileLocalCATLSA(t *testing.T) {
	dns := newFakePowerDNS(t)
	dir := t.TempDir()
	p := &paths.Paths{Config: filepath.Join(dir, "gibcert.scfg"), State: filepath.Join(dir, "state")}
	writeConfig := func(tlsaNames string) {
		t.Helper()
		cfg := fmt.Sprintf(`
ca dev {
  type local
}
provider pdns {
  type dns
  driver powerdns
  api-url %s
  server-id localhost
  secret api-key {
    value topsecret
  }
}
certificate example.com {
  ca dev
  names example.com www.example.com
  tlsa {
    provider pdns
    port 25
    ttl 60
    %s
  }
}
`, dns.URL, tlsaNames)
		if err := os.WriteFile(p.Config, []byte(cfg), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	apply := func() {
		t.Helper()
		if out, errOut, code := captureCommand(t, func() int { return cmdApply(p, []string{"--yes"}) }); code != 0 {
			t.Fatalf("apply got code=%d stdout=%q stderr=%q", code, out, errOut)
		}
	}

	// Signing from a local CA publishes the certificate's TLSA records.
	writeConfig("")
	apply()
	dns.wantOwners(t, "_25._tcp.example.com.", "_25._tcp.www.example.com.")
	certPath := storage.New(p.State).CertPaths("example.com").Cert
	signed, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}

	// Changing tlsa names on a current certificate is planned and applied
	// without reissuance, and the result converges.
	writeConfig("names mail.example.com")
	out, errOut, code := captureCommand(t, func() int { return cmdPlan(p, nil) })
	if code != 0 || !strings.Contains(out, "tlsa example.com: reconcile (published TLSA owners differ from configuration)") {
		t.Fatalf("plan after names change got code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	if strings.Contains(out, "certificate example.com") {
		t.Fatalf("names change planned certificate reissuance: %q", out)
	}
	apply()
	dns.wantOwners(t, "_25._tcp.mail.example.com.")
	if after, err := os.ReadFile(certPath); err != nil || !bytes.Equal(after, signed) {
		t.Fatalf("certificate changed during TLSA reconcile (err=%v)", err)
	}
	out, errOut, code = captureCommand(t, func() int { return cmdPlan(p, nil) })
	if code != 0 || strings.TrimSpace(out) != "no changes" {
		t.Fatalf("plan after reconcile got code=%d stdout=%q stderr=%q", code, out, errOut)
	}

	// Scheduled renewal converges too, even for a certificate without deploys.
	writeConfig("names mx.example.com")
	if out, errOut, code := captureCommand(t, func() int { return cmdRenew(p, []string{"--no-jitter"}) }); code != 0 {
		t.Fatalf("renew got code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	dns.wantOwners(t, "_25._tcp.mx.example.com.")
}

// fakePowerDNS serves the subset of the PowerDNS API used for TLSA edits on a
// single example.com. zone.
type fakePowerDNS struct {
	*httptest.Server
	mu      sync.Mutex
	records map[string][]fakePowerDNSRecord // TLSA records by owner
}

type fakePowerDNSRecord struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

type fakePowerDNSRRset struct {
	Name       string               `json:"name"`
	Type       string               `json:"type"`
	ChangeType string               `json:"changetype,omitempty"`
	Records    []fakePowerDNSRecord `json:"records"`
}

func newFakePowerDNS(t *testing.T) *fakePowerDNS {
	t.Helper()
	f := &fakePowerDNS{records: map[string][]fakePowerDNSRecord{}}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func (f *fakePowerDNS) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-API-Key") != "topsecret" {
		http.Error(w, "bad api key", http.StatusForbidden)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/servers/localhost/zones":
		_ = json.NewEncoder(w).Encode([]map[string]string{{"name": "example.com."}})
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/servers/localhost/zones/example.com.":
		var rrsets []fakePowerDNSRRset
		for owner, records := range f.records {
			rrsets = append(rrsets, fakePowerDNSRRset{Name: owner, Type: "TLSA", Records: records})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"rrsets": rrsets})
	case r.Method == http.MethodPatch && r.URL.Path == "/api/v1/servers/localhost/zones/example.com.":
		var body struct {
			RRsets []fakePowerDNSRRset `json:"rrsets"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for _, rrset := range body.RRsets {
			switch rrset.ChangeType {
			case "REPLACE":
				f.records[rrset.Name] = rrset.Records
			case "DELETE":
				delete(f.records, rrset.Name)
			default:
				http.Error(w, "bad changetype", http.StatusBadRequest)
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

// wantOwners checks that TLSA records exist under exactly the given owners,
// with the current and staged next-key record under each.
func (f *fakePowerDNS) wantOwners(t *testing.T, want ...string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	var got []string
	for owner, records := range f.records {
		if len(records) != 2 {
			t.Fatalf("owner %s has %d TLSA records, want 2", owner, len(records))
		}
		got = append(got, owner)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("TLSA owners got %v, want %v", got, want)
	}
}
