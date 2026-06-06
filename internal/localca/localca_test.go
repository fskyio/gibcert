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

package localca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"

	"foundry.fsky.io/fsky/gibcert/internal/config"
	"foundry.fsky.io/fsky/gibcert/internal/storage"
)

func TestIssueCreatesLocalCAAndLeafCertificate(t *testing.T) {
	store := storage.New(t.TempDir())
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	ca := &config.CA{
		Name:       "dev",
		Type:       "local",
		CommonName: "test dev CA",
		ValidFor:   365 * 24 * time.Hour,
	}
	cert := &config.Certificate{
		Name:     "localhost",
		CA:       "dev",
		Names:    []string{"localhost", "127.0.0.1", "::1"},
		ValidFor: 30 * 24 * time.Hour,
		Key:      config.KeySpec{Reuse: true},
	}

	var out bytes.Buffer
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	if err := Issue(cert, ca, store, IssueOptions{Out: &out, Now: now}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !strings.Contains(out.String(), "created local CA dev") {
		t.Fatalf("output %q missing local CA creation", out.String())
	}

	caCert := readPEMCert(t, store.CAPaths("dev").Cert)
	if !caCert.IsCA {
		t.Fatal("CA certificate IsCA=false")
	}
	if got, want := caCert.Subject.CommonName, "test dev CA"; got != want {
		t.Fatalf("CA common name: got %q, want %q", got, want)
	}

	leaf := readPEMCert(t, store.CertPaths("localhost").Cert)
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName:     "localhost",
		Roots:       roots,
		CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}); err != nil {
		t.Fatalf("Verify localhost: %v", err)
	}
	if len(leaf.IPAddresses) != 2 {
		t.Fatalf("leaf IPAddresses: got %d, want 2", len(leaf.IPAddresses))
	}
	meta, err := store.LoadCertMeta("localhost")
	if err != nil {
		t.Fatalf("LoadCertMeta: %v", err)
	}
	if got, want := meta.CA, "dev"; got != want {
		t.Fatalf("meta CA: got %q, want %q", got, want)
	}
	if got, want := meta.IssuerType, "local"; got != want {
		t.Fatalf("meta IssuerType: got %q, want %q", got, want)
	}
}

func TestCheckCAStatusTransitions(t *testing.T) {
	store := storage.New(t.TempDir())
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	ca := &config.CA{Name: "dev", Type: "local"}
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	st := CheckCA(ca, store, now)
	if st.Ready || st.Reason != "local CA certificate missing or unreadable" {
		t.Fatalf("missing CheckCA got %#v", st)
	}
	if err := Issue(&config.Certificate{Name: "localhost", CA: "dev", Names: []string{"localhost"}}, ca, store, IssueOptions{Out: bytes.NewBuffer(nil), Now: now}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	st = CheckCA(ca, store, now)
	if !st.Ready || st.Reason != "local CA ready" {
		t.Fatalf("ready CheckCA got %#v", st)
	}
	if err := os.Remove(store.CAPaths("dev").Key); err != nil {
		t.Fatal(err)
	}
	st = CheckCA(ca, store, now)
	if st.Ready || st.Reason != "local CA key missing or unreadable" {
		t.Fatalf("missing key CheckCA got %#v", st)
	}
}

func TestLocalCAHelpers(t *testing.T) {
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caDER, caCert, err := createCA(&config.CA{Name: "dev", Type: "local", ValidFor: time.Hour}, key, now)
	if err != nil {
		t.Fatalf("createCA: %v", err)
	}
	if len(caDER) == 0 || !caCert.IsCA {
		t.Fatalf("createCA got len=%d cert=%#v", len(caDER), caCert)
	}
	if !certReusable(caCert, now) {
		t.Fatal("fresh CA cert should be reusable")
	}
	if certReusable(nil, now) {
		t.Fatal("nil cert should not be reusable")
	}
	if certReusable(caCert, now.Add(2*time.Hour)) {
		t.Fatal("expired cert should not be reusable")
	}

	_, _, err = createLeaf(&config.Certificate{
		Name:     "late",
		Names:    []string{"late.example"},
		ValidFor: 10 * time.Hour,
	}, caCert, key, key, caCert.NotAfter.Add(time.Hour))
	if err == nil || !strings.Contains(err.Error(), "expires before requested certificate validity") {
		t.Fatalf("createLeaf expiry error got %v", err)
	}

	path := t.TempDir() + "/bad.pem"
	if err := os.WriteFile(path, []byte("not pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readCert(path); err == nil {
		t.Fatal("readCert accepted non-PEM input")
	}
}

func readPEMCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("no PEM certificate in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
