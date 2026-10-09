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

// tlsaFixtureCert describes one certificate in a tlsa reconcile test config.
// An empty provider means the certificate has no tlsa block.
type tlsaFixtureCert struct {
	name     string
	provider string
}

type tlsaFixture struct {
	t     *testing.T
	p     *paths.Paths
	pdns  *tlsaFakePowerDNS
	good  string
	bad   string
	token string
}

// newTLSAFixture starts a working PowerDNS fake ("good" provider) and one that
// fails every request ("bad" provider).
func newTLSAFixture(t *testing.T) *tlsaFixture {
	t.Helper()
	dir := t.TempDir()
	pdns := &tlsaFakePowerDNS{apiKey: "topsecret", records: map[string][]string{}}
	goodSrv := httptest.NewServer(pdns)
	t.Cleanup(goodSrv.Close)
	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "provider down", http.StatusInternalServerError)
	}))
	t.Cleanup(badSrv.Close)
	token := filepath.Join(dir, "api-key")
	if err := os.WriteFile(token, []byte("topsecret"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &tlsaFixture{
		t:     t,
		p:     &paths.Paths{Config: filepath.Join(dir, "gibcert.scfg"), State: filepath.Join(dir, "state")},
		pdns:  pdns,
		good:  goodSrv.URL,
		bad:   badSrv.URL,
		token: token,
	}
}

func (f *tlsaFixture) writeConfig(certs ...tlsaFixtureCert) {
	f.t.Helper()
	var b strings.Builder
	b.WriteString("ca dev {\n  type local\n  common-name \"gibcert dev CA\"\n}\n")
	for name, url := range map[string]string{"good": f.good, "bad": f.bad} {
		fmt.Fprintf(&b, "provider %s {\n  type dns\n  driver powerdns\n  api-url %s\n  server-id localhost\n  secret api-key {\n    file %s\n  }\n}\n", name, url, f.token)
	}
	for _, c := range certs {
		fmt.Fprintf(&b, "certificate %s {\n  ca dev\n  names %s\n", c.name, c.name)
		if c.provider != "" {
			fmt.Fprintf(&b, "  tlsa {\n    provider %s\n    port 443\n    ttl 60\n  }\n", c.provider)
		}
		b.WriteString("}\n")
	}
	if err := os.WriteFile(f.p.Config, []byte(b.String()), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

// issue stores material for the configured certificates through apply.
func (f *tlsaFixture) issue() {
	f.t.Helper()
	if out, errOut, code := captureCommand(f.t, func() int { return cmdApply(f.p, []string{"--yes"}) }); code != 0 {
		f.t.Fatalf("apply code=%d stdout=%q stderr=%q", code, out, errOut)
	}
}

func (f *tlsaFixture) reconcile(args ...string) (stdout, stderr string, code int) {
	f.t.Helper()
	cfg, err := loadCfg(f.p)
	if err != nil {
		f.t.Fatal(err)
	}
	store := storage.New(f.p.State)
	if err := store.Init(); err != nil {
		f.t.Fatal(err)
	}
	return captureCommand(f.t, func() int { return cmdTLSAReconcile(cfg, store, args) })
}

// published returns how many TLSA records exist for the certificate name.
func (f *tlsaFixture) published(name string) int {
	return f.pdns.count("_443._tcp." + name + ".")
}

func TestTLSAReconcileAllSkipsCertificatesWithoutTLSAOrStoredMaterial(t *testing.T) {
	f := newTLSAFixture(t)
	f.writeConfig(
		tlsaFixtureCert{name: "a.example.com"},
		tlsaFixtureCert{name: "b.example.com"},
		tlsaFixtureCert{name: "plain.example.com"},
	)
	f.issue()
	f.writeConfig(
		tlsaFixtureCert{name: "a.example.com", provider: "good"},
		tlsaFixtureCert{name: "b.example.com", provider: "good"},
		tlsaFixtureCert{name: "new.example.com", provider: "good"},
		tlsaFixtureCert{name: "plain.example.com"},
	)

	out, errOut, code := f.reconcile("--all")
	if code != 0 {
		t.Fatalf("reconcile --all code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	for _, want := range []string{
		"tlsa reconciled: a.example.com",
		"tlsa reconciled: b.example.com",
		"tlsa skipped: new.example.com (no stored certificate)",
		"tlsa reconcile: 2 reconciled, 1 skipped, 0 failed",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "plain.example.com") {
		t.Fatalf("certificate without tlsa block was reported:\n%s", out)
	}
	for name, want := range map[string]int{
		"a.example.com":     2,
		"b.example.com":     2,
		"new.example.com":   0,
		"plain.example.com": 0,
	} {
		if got := f.published(name); got != want {
			t.Fatalf("published TLSA records for %s got %d, want %d", name, got, want)
		}
	}
}

func TestTLSAReconcileContinuesAfterFailure(t *testing.T) {
	f := newTLSAFixture(t)
	f.writeConfig(
		tlsaFixtureCert{name: "a.example.com"},
		tlsaFixtureCert{name: "b.example.com"},
		tlsaFixtureCert{name: "c.example.com"},
	)
	f.issue()
	f.writeConfig(
		tlsaFixtureCert{name: "a.example.com", provider: "good"},
		tlsaFixtureCert{name: "b.example.com", provider: "bad"},
		tlsaFixtureCert{name: "c.example.com", provider: "good"},
		tlsaFixtureCert{name: "new.example.com", provider: "good"},
	)

	// b fails at its provider and new has no stored material; a and c, which
	// come after the first failure, must still be reconciled. A certificate
	// named explicitly is never skipped, so new counts as failed.
	out, errOut, code := f.reconcile("b.example.com", "a.example.com", "new.example.com", "c.example.com")
	if code != 1 {
		t.Fatalf("reconcile code=%d, want 1; stdout=%q stderr=%q", code, out, errOut)
	}
	if !strings.Contains(out, "tlsa reconcile: 2 reconciled, 0 skipped, 2 failed") {
		t.Fatalf("summary missing from stdout:\n%s", out)
	}
	for _, name := range []string{"b.example.com", "new.example.com"} {
		if !strings.Contains(errOut, name) {
			t.Fatalf("stderr does not name failed certificate %s:\n%s", name, errOut)
		}
	}
	for name, want := range map[string]int{
		"a.example.com":   2,
		"b.example.com":   0,
		"c.example.com":   2,
		"new.example.com": 0,
	} {
		if got := f.published(name); got != want {
			t.Fatalf("published TLSA records for %s got %d, want %d", name, got, want)
		}
	}
}

func TestTLSAReconcileArguments(t *testing.T) {
	f := newTLSAFixture(t)
	f.writeConfig(tlsaFixtureCert{name: "a.example.com"}, tlsaFixtureCert{name: "plain.example.com"})
	f.issue()
	f.writeConfig(
		tlsaFixtureCert{name: "a.example.com", provider: "good"},
		tlsaFixtureCert{name: "plain.example.com"},
	)

	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"no selection", nil, 2},
		{"all with names", []string{"--all", "a.example.com"}, 2},
		{"unknown flag", []string{"--bogus"}, 2},
		{"invalid name", []string{"a/b"}, 2},
		{"unknown certificate", []string{"missing.example.com"}, 1},
		{"certificate without tlsa block", []string{"plain.example.com"}, 1},
		// The valid first name must not be reconciled when a later one is bad.
		{"bad name after good one", []string{"a.example.com", "missing.example.com"}, 1},
		{"no tlsa name after good one", []string{"a.example.com", "plain.example.com"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, errOut, code := f.reconcile(tc.args...)
			if code != tc.want {
				t.Fatalf("code=%d, want %d; stdout=%q stderr=%q", code, tc.want, out, errOut)
			}
			if got := f.published("a.example.com"); got != 0 {
				t.Fatalf("rejected selection published %d records", got)
			}
		})
	}

	t.Run("duplicate names reconcile once", func(t *testing.T) {
		out, errOut, code := f.reconcile("a.example.com", "a.example.com")
		if code != 0 {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errOut)
		}
		if got := strings.Count(out, "tlsa reconciled: a.example.com"); got != 1 {
			t.Fatalf("reconciled %d times, want 1:\n%s", got, out)
		}
	})
}

func TestTLSAReconcileAllWithoutTLSABlocksSucceeds(t *testing.T) {
	f := newTLSAFixture(t)
	f.writeConfig(tlsaFixtureCert{name: "plain.example.com"})

	out, errOut, code := f.reconcile("--all")
	if code != 0 || !strings.Contains(out, "no certificates with a tlsa block") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errOut)
	}
}

func TestApplyAndRenewReconcileLocalCATLSA(t *testing.T) {
	pdns := &tlsaFakePowerDNS{apiKey: "topsecret", records: map[string][]string{}}
	srv := httptest.NewServer(pdns)
	t.Cleanup(srv.Close)
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
`, srv.URL, tlsaNames)
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
	pdns.wantOwners(t, "_25._tcp.example.com.", "_25._tcp.www.example.com.")
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
	pdns.wantOwners(t, "_25._tcp.mail.example.com.")
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
	pdns.wantOwners(t, "_25._tcp.mx.example.com.")
}

// tlsaFakePowerDNS implements the PowerDNS API calls the TLSA editor makes for
// the single zone example.com.
type tlsaFakePowerDNS struct {
	mu      sync.Mutex
	apiKey  string
	records map[string][]string
}

func (p *tlsaFakePowerDNS) count(owner string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.records[owner+"|TLSA"])
}

// wantOwners checks that TLSA records exist under exactly the given owners,
// with the current and staged next-key record under each.
func (p *tlsaFakePowerDNS) wantOwners(t *testing.T, want ...string) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	var got []string
	for key, records := range p.records {
		owner, _, _ := strings.Cut(key, "|")
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

func (p *tlsaFakePowerDNS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if r.Header.Get("X-API-Key") != p.apiKey {
		http.Error(w, "bad api key", http.StatusForbidden)
		return
	}
	type rrset struct {
		Name       string `json:"name"`
		Type       string `json:"type"`
		TTL        int    `json:"ttl,omitempty"`
		ChangeType string `json:"changetype"`
		Records    []struct {
			Content  string `json:"content"`
			Disabled bool   `json:"disabled"`
		} `json:"records,omitempty"`
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/servers/localhost/zones":
		_ = json.NewEncoder(w).Encode([]map[string]string{{"name": "example.com."}})
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/servers/localhost/zones/example.com.":
		var sets []rrset
		for key, contents := range p.records {
			name, typ, _ := strings.Cut(key, "|")
			set := rrset{Name: name, Type: typ}
			for _, c := range contents {
				set.Records = append(set.Records, struct {
					Content  string `json:"content"`
					Disabled bool   `json:"disabled"`
				}{Content: c})
			}
			sets = append(sets, set)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"rrsets": sets})
	case r.Method == http.MethodPatch && r.URL.Path == "/api/v1/servers/localhost/zones/example.com.":
		var body struct {
			RRsets []rrset `json:"rrsets"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for _, set := range body.RRsets {
			key := set.Name + "|" + set.Type
			switch set.ChangeType {
			case "REPLACE":
				var contents []string
				for _, rec := range set.Records {
					contents = append(contents, rec.Content)
				}
				p.records[key] = contents
			case "DELETE":
				delete(p.records, key)
			default:
				http.Error(w, "unexpected changetype "+set.ChangeType, http.StatusBadRequest)
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}
