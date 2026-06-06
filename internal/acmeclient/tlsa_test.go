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
	"strings"
	"testing"
	"time"

	"foundry.fsky.io/fsky/gibcert/internal/config"
	"foundry.fsky.io/fsky/gibcert/internal/storage"
)

func TestReconcileTLSAUsesStoredMaterialAndCreatesMetadata(t *testing.T) {
	store := storage.New(t.TempDir())
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	certFixture := testCertDER(t, "example.com", nil, nil)
	paths := store.CertPaths("example.com")
	if err := os.MkdirAll(paths.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := storage.WriteKey(paths.Key, certFixture.key); err != nil {
		t.Fatal(err)
	}
	if err := storage.WriteSingleCertDER(paths.Cert, certFixture.der, 0o644); err != nil {
		t.Fatal(err)
	}

	pdns := newTLSATestPowerDNS(t, "topsecret")
	srv := httptest.NewServer(pdns)
	t.Cleanup(srv.Close)

	cfg := &config.Config{
		Providers: []*config.Provider{{
			Name:   "powerdns",
			Type:   "dns",
			Driver: "powerdns",
			Fields: map[string][]string{
				"api-url":   {srv.URL},
				"server-id": {"localhost"},
			},
			Secrets: []*config.Secret{{Name: "api-key", Value: "topsecret"}},
		}},
	}
	cert := &config.Certificate{
		Name:  "example.com",
		Names: []string{"example.com"},
		Key:   config.KeySpec{Type: "ecdsa", Curve: "p256"},
		TLSA: &config.TLSASpec{
			Provider:     "powerdns",
			Ports:        []config.TLSAPort{{Port: 443, Protocol: "tcp"}},
			TTL:          60,
			Usage:        3,
			Selector:     1,
			MatchingType: 1,
		},
	}
	cfg.Certificates = []*config.Certificate{cert}

	err := ReconcileTLSA(context.Background(), store, cfg, cert, TLSAReconcileOptions{
		Out: io.Discard,
		Meta: storage.CertMeta{
			Name:       cert.Name,
			Account:    "ca:letsencrypt",
			CA:         "letsencrypt",
			IssuerType: "acme",
			Directory:  "https://acme-v02.api.letsencrypt.org/directory",
		},
	})
	if err != nil {
		t.Fatalf("ReconcileTLSA: %v", err)
	}

	meta, err := store.LoadCertMeta(cert.Name)
	if err != nil {
		t.Fatalf("LoadCertMeta: %v", err)
	}
	if meta.TLSA == nil {
		t.Fatal("TLSA metadata was not saved")
	}
	if got := len(meta.TLSA.Published); got != 2 {
		t.Fatalf("published records got %d, want 2", got)
	}
	if meta.SerialNumber != certFixture.cert.SerialNumber.String() {
		t.Fatalf("serial got %q, want %q", meta.SerialNumber, certFixture.cert.SerialNumber.String())
	}
	if _, err := os.Stat(paths.KeyNext); err != nil {
		t.Fatalf("staged next key was not written: %v", err)
	}

	recs := pdns.records["_443._tcp.example.com.|TLSA"]
	if got := len(recs); got != 2 {
		t.Fatalf("PowerDNS records got %d, want 2", got)
	}
	for _, r := range recs {
		if !strings.HasPrefix(r.Content, "3 1 1 ") {
			t.Fatalf("record content got %q, want TLSA 3 1 1", r.Content)
		}
	}
}

func TestTLSAHelperBranches(t *testing.T) {
	meta := storage.CertMeta{}
	fillTLSAMetaDefaults(&meta, storage.CertMeta{
		Account:    "account",
		CA:         "ca",
		IssuerType: "acme",
		Directory:  "https://ca.example/directory",
	})
	if meta.Account != "account" || meta.CA != "ca" || meta.IssuerType != "acme" || meta.Directory != "https://ca.example/directory" {
		t.Fatalf("fillTLSAMetaDefaults got %#v", meta)
	}
	meta.Account = "kept"
	fillTLSAMetaDefaults(&meta, storage.CertMeta{Account: "default"})
	if meta.Account != "kept" {
		t.Fatalf("fillTLSAMetaDefaults overwrote account: %#v", meta)
	}

	rec := storage.TLSARecord{Owner: "_443._tcp.example.com.", RData: "3 1 1 abc"}
	if !containsTLSA([]storage.TLSARecord{rec}, rec) {
		t.Fatal("containsTLSA did not find existing record")
	}
	if containsTLSA([]storage.TLSARecord{rec}, storage.TLSARecord{Owner: rec.Owner, RData: "3 1 1 def"}) {
		t.Fatal("containsTLSA matched different record data")
	}
	if _, err := newDNSEditor(&config.Provider{Name: "bad", Driver: "manual"}, io.Discard); err == nil {
		t.Fatal("newDNSEditor accepted unsupported driver")
	}
	if err := ReconcileTLSA(context.Background(), storage.New(t.TempDir()), &config.Config{}, &config.Certificate{Name: "no-tlsa"}, TLSAReconcileOptions{}); err == nil {
		t.Fatal("ReconcileTLSA accepted certificate without TLSA block")
	}
}

func TestPickTLSAKey(t *testing.T) {
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	cert := &config.Certificate{
		Name: "example.com",
		Key:  config.KeySpec{Type: "ecdsa"},
		TLSA: &config.TLSASpec{TTL: 60},
	}

	store := storage.New(t.TempDir())
	paths := store.CertPaths(cert.Name)
	if err := os.MkdirAll(paths.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	current := testCertDER(t, "current", nil, nil)
	next := testCertDER(t, "next", nil, nil)
	if err := storage.WriteKey(paths.Key, current.key); err != nil {
		t.Fatal(err)
	}
	if err := storage.WriteKey(paths.KeyNext, next.key); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveCertMeta(cert.Name, storage.CertMeta{
		Name: cert.Name,
		TLSA: &storage.CertTLSAMeta{
			TTL:             60,
			NextPublishedAt: now.Add(-2 * time.Minute),
		},
	}); err != nil {
		t.Fatal(err)
	}
	decision, err := pickTLSAKey(cert, store, now)
	if err != nil {
		t.Fatalf("pickTLSAKey mature staged: %v", err)
	}
	if !decision.StagedKey || decision.ReusedKey || decision.Bootstrap {
		t.Fatalf("mature staged decision got %#v", decision)
	}

	if err := store.SaveCertMeta(cert.Name, storage.CertMeta{
		Name: cert.Name,
		TLSA: &storage.CertTLSAMeta{
			TTL:             60,
			NextPublishedAt: now.Add(-30 * time.Second),
		},
	}); err != nil {
		t.Fatal(err)
	}
	decision, err = pickTLSAKey(cert, store, now)
	if err != nil {
		t.Fatalf("pickTLSAKey immature staged: %v", err)
	}
	if !decision.ReusedKey || !decision.NextNotYet || decision.StagedKey {
		t.Fatalf("immature staged decision got %#v", decision)
	}

	if err := os.Remove(paths.KeyNext); err != nil {
		t.Fatal(err)
	}
	decision, err = pickTLSAKey(cert, store, now)
	if err != nil {
		t.Fatalf("pickTLSAKey missing staged: %v", err)
	}
	if !decision.ReusedKey || !decision.NextMissing {
		t.Fatalf("missing staged decision got %#v", decision)
	}

	bootstrapStore := storage.New(t.TempDir())
	decision, err = pickTLSAKey(&config.Certificate{Name: "new", Key: config.KeySpec{Type: "ecdsa"}, TLSA: &config.TLSASpec{TTL: 60}}, bootstrapStore, now)
	if err != nil {
		t.Fatalf("pickTLSAKey bootstrap: %v", err)
	}
	if !decision.Bootstrap || decision.Key == nil {
		t.Fatalf("bootstrap decision got %#v", decision)
	}
}

func TestReadStoredLeafRejectsInvalidPEM(t *testing.T) {
	path := t.TempDir() + "/cert.pem"
	if err := os.WriteFile(path, []byte("not pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readStoredLeaf(path); err == nil {
		t.Fatal("readStoredLeaf accepted invalid PEM")
	}
}

type tlsaTestPowerDNS struct {
	t       *testing.T
	apiKey  string
	records map[string][]tlsaTestPowerDNSRecord
}

func newTLSATestPowerDNS(t *testing.T, apiKey string) *tlsaTestPowerDNS {
	t.Helper()
	return &tlsaTestPowerDNS{
		t:       t,
		apiKey:  apiKey,
		records: map[string][]tlsaTestPowerDNSRecord{},
	}
}

func (p *tlsaTestPowerDNS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-API-Key") != p.apiKey {
		http.Error(w, "bad api key", http.StatusForbidden)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/servers/localhost/zones":
		_ = json.NewEncoder(w).Encode([]map[string]string{{"name": "example.com."}})
	case r.URL.Path == "/api/v1/servers/localhost/zones/example.com.":
		p.serveZone(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (p *tlsaTestPowerDNS) serveZone(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		var rrsets []tlsaTestPowerDNSRRset
		for key, records := range p.records {
			parts := strings.Split(key, "|")
			rrsets = append(rrsets, tlsaTestPowerDNSRRset{
				Name:    parts[0],
				Type:    parts[1],
				Records: records,
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"rrsets": rrsets})
	case http.MethodPatch:
		var body struct {
			RRsets []tlsaTestPowerDNSRRset `json:"rrsets"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for _, rrset := range body.RRsets {
			key := rrset.Name + "|" + rrset.Type
			switch rrset.ChangeType {
			case "REPLACE":
				p.records[key] = rrset.Records
			case "DELETE":
				delete(p.records, key)
			default:
				p.t.Fatalf("unexpected changetype %q", rrset.ChangeType)
			}
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

type tlsaTestPowerDNSRRset struct {
	Name       string                   `json:"name"`
	Type       string                   `json:"type"`
	TTL        int                      `json:"ttl,omitempty"`
	ChangeType string                   `json:"changetype"`
	Records    []tlsaTestPowerDNSRecord `json:"records,omitempty"`
}

type tlsaTestPowerDNSRecord struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}
