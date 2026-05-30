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
	"math/big"
	"os"
	"testing"
	"time"

	"foundry.fsky.io/fsky/gibcert/internal/config"
	"foundry.fsky.io/fsky/gibcert/internal/storage"
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
				Renew: config.RenewSpec{BeforeExpiry: tc.beforeExpiry},
			}
			if !tc.notAfter.IsZero() {
				writeTestCert(t, store, cert.Name, tc.notBefore, tc.notAfter)
			}

			got := ShouldRenew(cert, store, now)
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
	cert := &config.Certificate{Name: "example.com"}
	// Outside the expiry-based window, so only ARI can make it due. Serial "1"
	// matches writeTestCert.
	writeTestCert(t, store, cert.Name, now.Add(-time.Hour), now.Add(45*24*time.Hour))

	if d := ShouldRenew(cert, store, now); d.Due {
		t.Fatalf("expected not due without ARI, got due (%s)", d.Reason)
	}

	if err := store.SaveCertMeta(cert.Name, storage.CertMeta{
		Name: cert.Name,
		ARI:  &storage.CertARI{Serial: "1", SelectedTime: now.Add(-time.Hour)},
	}); err != nil {
		t.Fatal(err)
	}
	d := ShouldRenew(cert, store, now)
	if !d.Due {
		t.Fatalf("expected due from cached ARI, got not due (%s)", d.Reason)
	}
	if !d.NotAfter.Equal(now.Add(45 * 24 * time.Hour)) {
		t.Errorf("NotAfter: got %s", d.NotAfter)
	}
}

func writeTestCert(t *testing.T, store *storage.Store, name string, notBefore, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
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
