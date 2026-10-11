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

package renew

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"gitfield.org/fsky/gibcert/internal/challenge"
	"gitfield.org/fsky/gibcert/internal/config"
	"gitfield.org/fsky/gibcert/internal/localca"
	"gitfield.org/fsky/gibcert/internal/storage"
)

func TestShouldRenew(t *testing.T) {
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name         string
		notBefore    time.Time
		notAfter     time.Time
		beforeExpiry time.Duration
		wantDue      bool
	}{
		{
			name:     "missing certificate is due",
			wantDue:  true,
			notAfter: time.Time{},
		},
		{
			name:      "outside capped default renewal window",
			notBefore: now.Add(-45 * 24 * time.Hour),
			notAfter:  now.Add(45 * 24 * time.Hour),
			wantDue:   false,
		},
		{
			name:      "inside capped default renewal window",
			notBefore: now.Add(-70 * 24 * time.Hour),
			notAfter:  now.Add(20 * 24 * time.Hour),
			wantDue:   true,
		},
		{
			name:      "outside dynamic short certificate renewal window",
			notBefore: now.Add(-3 * 24 * time.Hour),
			notAfter:  now.Add(3 * 24 * time.Hour),
			wantDue:   false,
		},
		{
			name:      "inside dynamic short certificate renewal window",
			notBefore: now.Add(-5 * 24 * time.Hour),
			notAfter:  now.Add(24 * time.Hour),
			wantDue:   true,
		},
		{
			name:         "outside configured renewal window",
			notBefore:    now.Add(-70 * 24 * time.Hour),
			notAfter:     now.Add(20 * 24 * time.Hour),
			beforeExpiry: 10 * 24 * time.Hour,
			wantDue:      false,
		},
		{
			name:         "inside configured renewal window",
			notBefore:    now.Add(-70 * 24 * time.Hour),
			notAfter:     now.Add(20 * 24 * time.Hour),
			beforeExpiry: 30 * 24 * time.Hour,
			wantDue:      true,
		},
		{
			name:      "expired certificate",
			notBefore: now.Add(-70 * 24 * time.Hour),
			notAfter:  now.Add(-time.Hour),
			wantDue:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := storage.New(t.TempDir())
			cert := &config.Certificate{
				Name:  "example.com",
				Names: []string{"example.com"},
				Renew: config.RenewSpec{BeforeExpiry: tc.beforeExpiry},
			}
			if !tc.notAfter.IsZero() {
				writeTestCert(t, store, cert.Name, tc.notBefore, tc.notAfter)
			}

			got := ShouldRenew(&config.Config{}, cert, store, now)
			if got.Due != tc.wantDue {
				t.Fatalf("Due: got %v, want %v (reason: %s)", got.Due, tc.wantDue, got.Reason)
			}
			if !tc.notAfter.IsZero() && !got.NotAfter.Equal(tc.notAfter) {
				t.Fatalf("NotAfter: got %s, want %s", got.NotAfter, tc.notAfter)
			}
		})
	}
}

func TestRenewalWindow(t *testing.T) {
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	cert := &config.Certificate{Name: "example.com"}

	if got, want := RenewalWindow(cert, now.Add(-45*24*time.Hour), now.Add(45*24*time.Hour)), DefaultBeforeExpiry; got != want {
		t.Fatalf("90 day cert window: got %s, want %s", got, want)
	}
	if got, want := RenewalWindow(cert, now, now.Add(6*24*time.Hour)), 2*24*time.Hour; got != want {
		t.Fatalf("6 day cert window: got %s, want %s", got, want)
	}

	cert.Renew.BeforeExpiry = 12 * time.Hour
	if got, want := RenewalWindow(cert, now, now.Add(6*24*time.Hour)), 12*time.Hour; got != want {
		t.Fatalf("configured window: got %s, want %s", got, want)
	}
}

func TestApplyARI(t *testing.T) {
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	notDue := Decision{Due: false, Reason: "certificate still valid", NotAfter: now.Add(45 * 24 * time.Hour)}
	due := Decision{Due: true, Reason: "certificate inside renewal window"}

	tests := []struct {
		name    string
		base    Decision
		ari     *storage.CertARI
		serial  string
		wantDue bool
	}{
		{name: "no ari leaves base", base: notDue, ari: nil, serial: "1", wantDue: false},
		{name: "base already due unchanged", base: due, ari: &storage.CertARI{Serial: "1", SelectedTime: now.Add(-time.Hour)}, serial: "1", wantDue: true},
		{name: "selected time passed makes due", base: notDue, ari: &storage.CertARI{Serial: "1", SelectedTime: now.Add(-time.Hour)}, serial: "1", wantDue: true},
		{name: "selected time in future stays", base: notDue, ari: &storage.CertARI{Serial: "1", SelectedTime: now.Add(time.Hour)}, serial: "1", wantDue: false},
		{name: "serial mismatch ignored", base: notDue, ari: &storage.CertARI{Serial: "2", SelectedTime: now.Add(-time.Hour)}, serial: "1", wantDue: false},
		{name: "no window ignored", base: notDue, ari: &storage.CertARI{Serial: "1"}, serial: "1", wantDue: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ApplyARI(tc.base, tc.ari, tc.serial, now)
			if got.Due != tc.wantDue {
				t.Fatalf("Due: got %v, want %v (reason %q)", got.Due, tc.wantDue, got.Reason)
			}
			if got.NotAfter != tc.base.NotAfter {
				t.Errorf("NotAfter changed: got %s, want %s", got.NotAfter, tc.base.NotAfter)
			}
		})
	}
}

func TestShouldRenewWithCachedARI(t *testing.T) {
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	store := storage.New(t.TempDir())
	cert := &config.Certificate{Name: "example.com", Names: []string{"example.com"}}
	// Outside the expiry-based window, so only ARI can make it due. Serial "1"
	// matches writeTestCert.
	writeTestCert(t, store, cert.Name, now.Add(-time.Hour), now.Add(45*24*time.Hour))

	if d := ShouldRenew(&config.Config{}, cert, store, now); d.Due {
		t.Fatalf("expected not due without ARI, got due (%s)", d.Reason)
	}

	if err := store.SaveCertMeta(cert.Name, storage.CertMeta{
		Name: cert.Name,
		ARI:  &storage.CertARI{Serial: "1", SelectedTime: now.Add(-time.Hour)},
	}); err != nil {
		t.Fatal(err)
	}
	d := ShouldRenew(&config.Config{}, cert, store, now)
	if !d.Due {
		t.Fatalf("expected due from cached ARI, got not due (%s)", d.Reason)
	}
	if !d.NotAfter.Equal(now.Add(45 * 24 * time.Hour)) {
		t.Errorf("NotAfter: got %s", d.NotAfter)
	}
}

func writeTestCert(t *testing.T, store *storage.Store, name string, notBefore, notAfter time.Time) {
	t.Helper()
	writeTestLeaf(t, store, name, []string{name}, notBefore, notAfter)
}

// writeTestLeaf stores a self-signed leaf with serial 1 and the given DNS and
// IP SANs.
func writeTestLeaf(t *testing.T, store *storage.Store, name string, sans []string, notBefore, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	for _, san := range sans {
		if ip := net.ParseIP(san); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, san)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	paths := store.CertPaths(name)
	if err := os.MkdirAll(paths.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := storage.WriteSingleCertDER(paths.Cert, der, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestShouldRenewSANSet(t *testing.T) {
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	ca := &config.CA{Name: "dev", Type: "local"}
	cfg := &config.Config{CAs: []*config.CA{ca}}
	store := storage.New(t.TempDir())
	cert := &config.Certificate{
		Name: "example.com", CA: ca.Name,
		Names: []string{"example.com", "*.example.com", "192.0.2.1", "2001:db8::1"},
	}
	if err := localca.Issue(cert, ca, store, localca.IssueOptions{Out: io.Discard, Now: now}); err != nil {
		t.Fatal(err)
	}
	issued, err := store.LoadCertMeta(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	stale := *issued
	stale.Names, stale.SerialNumber = []string{"stale-metadata.example"}, "stale"
	tests := []struct {
		name    string
		names   []string
		wantDue bool
	}{
		{"unchanged", cert.Names, false},
		{"reordered normalized", []string{"2001:0db8:0:0:0:0:0:1", "192.0.2.1", "*.EXAMPLE.COM", "EXAMPLE.COM"}, false},
		{"duplicate set member", []string{"example.com", "example.com", "*.example.com", "192.0.2.1", "2001:db8::1"}, false},
		{"added DNS", []string{"example.com", "*.example.com", "192.0.2.1", "2001:db8::1", "www.example.com"}, true},
		{"removed DNS", []string{"*.example.com", "192.0.2.1", "2001:db8::1"}, true},
		{"wildcard is exact", []string{"example.com", "www.example.com", "192.0.2.1", "2001:db8::1"}, true},
		{"changed IP", []string{"example.com", "*.example.com", "192.0.2.2", "2001:db8::1"}, true},
		{"removed IP", []string{"example.com", "*.example.com", "2001:db8::1"}, true},
	}
	// The same set rules apply whether the requested names recorded for this
	// leaf or, without such a record, the leaf SANs are compared.
	for _, record := range []struct {
		name string
		meta *storage.CertMeta
	}{{"requested names", issued}, {"stale metadata", &stale}, {"missing metadata", nil}} {
		path := store.CertPaths(cert.Name).Meta
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if record.meta != nil {
			if err := store.SaveCertMeta(cert.Name, *record.meta); err != nil {
				t.Fatal(err)
			}
		}
		for _, tc := range tests {
			t.Run(record.name+"/"+tc.name, func(t *testing.T) {
				desired := *cert
				desired.Names = tc.names
				d := ShouldRenew(cfg, &desired, store, now)
				if d.Due != tc.wantDue {
					t.Fatalf("Due=%v, want %v (%s)", d.Due, tc.wantDue, d.Reason)
				}
			})
		}
	}
	imported := *issued
	imported.IssuerType = "imported"
	if err := store.SaveCertMeta(cert.Name, imported); err != nil {
		t.Fatal(err)
	}
	desired := *cert
	desired.Names = []string{"replacement.example"}
	if d := ShouldRenew(cfg, &desired, store, now); !d.Due {
		t.Fatal("imported leaf with changed SANs was treated as current")
	}
	if err := os.Remove(store.CAPaths(ca.Name).Key); err != nil {
		t.Fatal(err)
	}
	if d := ShouldRenew(cfg, cert, store, now); !d.Due {
		t.Fatal("unready local CA left matching leaf current")
	}
}

// A CA may add SANs it was not asked for (www bundling, private CA
// templates). The requested names recorded for the leaf keep such a leaf
// current, while configuration changes still make it due.
func TestShouldRenewToleratesCAAddedSANs(t *testing.T) {
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	store := storage.New(t.TempDir())
	writeTestLeaf(t, store, "example.com",
		[]string{"example.com", "api.example.com", "www.example.com", "*.example.com", "192.0.2.1"},
		now.Add(-time.Hour), now.Add(90*24*time.Hour))
	tests := []struct {
		name      string
		requested []string
		serial    string
		names     []string
		wantDue   bool
	}{
		{name: "extra SAN tolerated", requested: []string{"example.com", "api.example.com"},
			names: []string{"API.example.com", "example.com"}},
		{name: "extra wildcard and IP tolerated", requested: []string{"example.com"}, names: []string{"example.com"}},
		{name: "added name", requested: []string{"example.com", "api.example.com"},
			names: []string{"example.com", "api.example.com", "mail.example.com"}, wantDue: true},
		{name: "added name the CA already bundled", requested: []string{"example.com", "api.example.com"},
			names: []string{"example.com", "api.example.com", "www.example.com"}, wantDue: true},
		{name: "removed name", requested: []string{"example.com", "api.example.com"},
			names: []string{"example.com"}, wantDue: true},
		{name: "recorded name missing from leaf", requested: []string{"example.com", "mail.example.com"},
			names: []string{"example.com", "mail.example.com"}, wantDue: true},
		{name: "wildcard SAN does not stand in for host", requested: []string{"mail.example.com"},
			names: []string{"mail.example.com"}, wantDue: true},
		{name: "record for another leaf ignored", requested: []string{"example.com"}, serial: "2",
			names: []string{"example.com"}, wantDue: true},
		{name: "exact SAN set without record", serial: "2",
			names: []string{"example.com", "api.example.com", "www.example.com", "*.example.com", "192.0.2.1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			serial := tc.serial
			if serial == "" {
				serial = "1"
			}
			meta := storage.CertMeta{Name: "example.com", IssuerType: "acme", Names: tc.requested, SerialNumber: serial}
			if err := store.SaveCertMeta("example.com", meta); err != nil {
				t.Fatal(err)
			}
			cert := &config.Certificate{Name: "example.com", Names: tc.names}
			d := ShouldRenew(&config.Config{}, cert, store, now)
			if d.Due != tc.wantDue {
				t.Fatalf("Due=%v, want %v (%s)", d.Due, tc.wantDue, d.Reason)
			}
		})
	}
}

func TestShouldRenewIssuerIdentity(t *testing.T) {
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	cfg := &config.Config{
		CAs: []*config.CA{
			{Name: "dev", Type: "local"}, {Name: "other", Type: "local"},
			{Name: "primary", Type: "acme", Directory: "https://primary.invalid/directory"},
			{Name: "backup", Type: "acme", Directory: "https://backup.invalid/directory"},
		},
		Accounts: []*config.Account{
			{Name: "primary-account", CA: "primary", Directory: "https://primary.invalid/directory"},
			{Name: "other-account", CA: "primary", Directory: "https://primary.invalid/directory"},
			{Name: "backup-account", CA: "backup", Directory: "https://backup.invalid/directory"},
		},
	}
	store := storage.New(t.TempDir())
	for _, ca := range cfg.CAs[:2] {
		if err := localca.Issue(&config.Certificate{Name: "seed", Names: []string{"seed"}, CA: ca.Name},
			ca, store, localca.IssueOptions{Out: io.Discard, Now: now}); err != nil {
			t.Fatal(err)
		}
	}
	writeTestCert(t, store, "example.com", now.Add(-time.Hour), now.Add(90*24*time.Hour))
	local := storage.CertMeta{IssuerType: "local", CA: "dev", Directory: "local:dev"}
	acme := storage.CertMeta{IssuerType: "acme", Account: "primary-account", CA: "primary", Directory: "https://primary.invalid/directory"}
	backup := storage.CertMeta{IssuerType: "acme", Account: "backup-account", CA: "backup", Directory: "https://backup.invalid/directory"}
	tests := []struct {
		name     string
		ca       string
		account  string
		failover []config.Issuer
		meta     *storage.CertMeta
		wantDue  bool
	}{
		{name: "same local", ca: "dev", meta: &local},
		{name: "changed local CA", ca: "other", meta: &local, wantDue: true},
		{name: "local to ACME", account: "primary-account", meta: &local, wantDue: true},
		{name: "ACME to local", ca: "dev", meta: &acme, wantDue: true},
		{name: "same ACME", account: "primary-account", meta: &acme},
		{name: "changed account", account: "other-account", meta: &acme, wantDue: true},
		{name: "changed directory", account: "primary-account",
			meta: &storage.CertMeta{IssuerType: "acme", Account: "primary-account", CA: "primary", Directory: "https://old.invalid/directory"}, wantDue: true},
		{name: "changed CA", account: "primary-account",
			meta: &storage.CertMeta{IssuerType: "acme", Account: "primary-account", CA: "old", Directory: acme.Directory}, wantDue: true},
		{name: "implicit account", ca: "primary",
			meta: &storage.CertMeta{IssuerType: "acme", Account: "ca:primary", CA: "primary", Directory: acme.Directory}},
		{name: "explicit failover accepted", account: "primary-account", meta: &backup,
			failover: []config.Issuer{{Account: "backup-account"}}},
		{name: "implicit failover accepted", account: "primary-account",
			meta:     &storage.CertMeta{IssuerType: "acme", Account: "ca:backup", CA: "backup", Directory: backup.Directory},
			failover: []config.Issuer{{CA: "backup"}}},
		{name: "removed failover", account: "primary-account", meta: &backup, wantDue: true},
		{name: "changed failover directory", account: "primary-account", failover: []config.Issuer{{Account: "backup-account"}},
			meta: &storage.CertMeta{IssuerType: "acme", Account: "backup-account", CA: "backup", Directory: "https://old.invalid/directory"}, wantDue: true},
		{name: "imported identity not claimed", account: "primary-account",
			meta: &storage.CertMeta{IssuerType: "imported", Account: "foreign", Directory: "https://foreign.invalid"}},
		{name: "missing metadata", account: "primary-account"},
		{name: "empty legacy metadata", account: "primary-account", meta: &storage.CertMeta{}},
		{name: "incomplete ACME identity", ca: "dev", meta: &storage.CertMeta{IssuerType: "acme", Account: "foreign"}},
		// v0.1.0 and v0.2.0 recorded the primary account name for failover
		// issuance, with the failover's CA and directory.
		{name: "legacy failover record accepted", account: "primary-account", failover: []config.Issuer{{Account: "backup-account"}},
			meta: &storage.CertMeta{IssuerType: "acme", Account: "primary-account", CA: "backup", Directory: backup.Directory}},
		{name: "legacy implicit failover record accepted", account: "primary-account", failover: []config.Issuer{{CA: "backup"}},
			meta: &storage.CertMeta{IssuerType: "acme", Account: "primary-account", CA: "backup", Directory: backup.Directory}},
		{name: "legacy failover record without CA accepted", account: "primary-account", failover: []config.Issuer{{Account: "backup-account"}},
			meta: &storage.CertMeta{Account: "primary-account", Directory: backup.Directory}},
		{name: "legacy failover record after failover removed", account: "primary-account",
			meta: &storage.CertMeta{IssuerType: "acme", Account: "primary-account", CA: "backup", Directory: backup.Directory}, wantDue: true},
		{name: "legacy failover record with other CA", account: "primary-account", failover: []config.Issuer{{Account: "backup-account"}},
			meta: &storage.CertMeta{IssuerType: "acme", Account: "primary-account", CA: "old", Directory: backup.Directory}, wantDue: true},
		{name: "legacy failover record after primary changed", account: "other-account", failover: []config.Issuer{{Account: "backup-account"}},
			meta: &storage.CertMeta{IssuerType: "acme", Account: "primary-account", CA: "backup", Directory: backup.Directory}, wantDue: true},
		{name: "legacy ACME same", account: "primary-account",
			meta: &storage.CertMeta{Account: "primary-account", Directory: acme.Directory}},
		{name: "legacy ACME changed", account: "other-account",
			meta: &storage.CertMeta{Account: "primary-account", Directory: acme.Directory}, wantDue: true},
		{name: "legacy local same", ca: "dev", meta: &storage.CertMeta{Directory: "local:dev"}},
		{name: "legacy local changed", ca: "other", meta: &storage.CertMeta{Directory: "local:dev"}, wantDue: true},
		{name: "stale metadata ignored", account: "primary-account",
			meta: &storage.CertMeta{IssuerType: "local", CA: "dev", Directory: "local:dev", SerialNumber: "2"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := store.CertPaths("example.com").Meta
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if tc.meta != nil {
				if err := store.SaveCertMeta("example.com", *tc.meta); err != nil {
					t.Fatal(err)
				}
			}
			cert := &config.Certificate{Name: "example.com", Names: []string{"example.com"},
				CA: tc.ca, Account: tc.account, Failover: tc.failover}
			d := ShouldRenew(cfg, cert, store, now)
			if d.Due != tc.wantDue {
				t.Fatalf("Due=%v, want %v (%s)", d.Due, tc.wantDue, d.Reason)
			}
		})
	}
}

func TestTLSAReconcileReason(t *testing.T) {
	store := storage.New(t.TempDir())
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	metaPath := store.CertPaths("example.com").Meta
	if err := os.MkdirAll(store.CertPaths("example.com").Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	published := func(owners ...string) *storage.CertMeta {
		meta := &storage.CertMeta{Name: "example.com", TLSA: &storage.CertTLSAMeta{}}
		for _, owner := range owners {
			meta.TLSA.Published = append(meta.TLSA.Published,
				storage.TLSARecord{Owner: owner, RData: "3 1 1 aa"},
				storage.TLSARecord{Owner: owner, RData: "3 1 1 bb"})
		}
		return meta
	}
	const (
		notPublished = "TLSA records not published"
		drift        = "published TLSA owners differ from configuration"
	)
	smtp := []config.TLSAPort{{Port: 25, Protocol: "tcp"}}
	tests := []struct {
		name  string
		names []string
		ports []config.TLSAPort
		meta  *storage.CertMeta
		raw   string
		want  string
	}{
		{name: "missing metadata", want: notPublished},
		{name: "metadata without tlsa", meta: &storage.CertMeta{Name: "example.com"}, want: notPublished},
		{name: "unreadable metadata", raw: "{", want: "certificate metadata unreadable"},
		{name: "default owners current", meta: published("_25._tcp.example.com.", "_25._tcp.www.example.com.")},
		{name: "owner case ignored", meta: published("_25._TCP.Example.COM.", "_25._tcp.WWW.example.com.")},
		{name: "names changed", names: []string{"mail.example.com"},
			meta: published("_25._tcp.example.com.", "_25._tcp.www.example.com."), want: drift},
		{name: "names current", names: []string{"mail.example.com"}, meta: published("_25._tcp.mail.example.com.")},
		{name: "stale owner retained", names: []string{"mail.example.com"},
			meta: published("_25._tcp.mail.example.com.", "_25._tcp.example.com."), want: drift},
		{name: "port added", ports: append(smtp, config.TLSAPort{Port: 465, Protocol: "tcp"}),
			meta: published("_25._tcp.example.com.", "_25._tcp.www.example.com."), want: drift},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.Remove(metaPath); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if tc.meta != nil {
				if err := store.SaveCertMeta("example.com", *tc.meta); err != nil {
					t.Fatal(err)
				}
			}
			if tc.raw != "" {
				if err := os.WriteFile(metaPath, []byte(tc.raw), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			ports := tc.ports
			if ports == nil {
				ports = smtp
			}
			cert := &config.Certificate{
				Name:  "example.com",
				Names: []string{"example.com", "www.example.com"},
				TLSA:  &config.TLSASpec{Ports: ports, Names: tc.names},
			}
			if got := TLSAReconcileReason(cert, store); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
	if got := TLSAReconcileReason(&config.Certificate{Name: "example.com"}, store); got != "" {
		t.Fatalf("certificate without tlsa block got %q", got)
	}
}

func TestTLSAReconcileReasonStoredKey(t *testing.T) {
	store := storage.New(t.TempDir())
	paths := store.CertPaths("example.com")
	if err := os.MkdirAll(paths.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	key, err := storage.GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.WriteKey(paths.Key, key); err != nil {
		t.Fatal(err)
	}
	hash, err := challenge.SPKIHash(key.Public(), 1)
	if err != nil {
		t.Fatal(err)
	}
	stored := challenge.TLSARData(3, 1, 1, hash)
	published := func(rdata ...string) *storage.CertMeta {
		meta := &storage.CertMeta{Name: "example.com", TLSA: &storage.CertTLSAMeta{Usage: 3, Selector: 1, MatchingType: 1}}
		for _, value := range rdata {
			meta.TLSA.Published = append(meta.TLSA.Published, storage.TLSARecord{Owner: "_25._tcp.example.com.", RData: value})
		}
		return meta
	}
	const unpublished = "stored key TLSA not published"
	tests := []struct {
		name            string
		meta            *storage.CertMeta
		want            string
		wantUnpublished bool
	}{
		{name: "stored key published", meta: published(stored)},
		{name: "stored and next key published", meta: published("3 1 1 aa", stored)},
		{name: "only another key published", meta: published("3 1 1 aa"), want: unpublished, wantUnpublished: true},
		{name: "no TLSA metadata", meta: &storage.CertMeta{Name: "example.com"}, want: "TLSA records not published"},
		{name: "no metadata", want: "TLSA records not published"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.Remove(paths.Meta); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if tc.meta != nil {
				if err := store.SaveCertMeta("example.com", *tc.meta); err != nil {
					t.Fatal(err)
				}
			}
			cert := &config.Certificate{
				Name:  "example.com",
				Names: []string{"example.com"},
				TLSA:  &config.TLSASpec{Ports: []config.TLSAPort{{Port: 25, Protocol: "tcp"}}},
			}
			if got := TLSAReconcileReason(cert, store); got != tc.want {
				t.Fatalf("TLSAReconcileReason = %q, want %q", got, tc.want)
			}
			if got := StoredKeyTLSAUnpublished(cert, store); got != tc.wantUnpublished {
				t.Fatalf("StoredKeyTLSAUnpublished = %v, want %v", got, tc.wantUnpublished)
			}
		})
	}
}
