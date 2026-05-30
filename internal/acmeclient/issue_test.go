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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"foundry.fsky.io/fsky/gibcert/internal/acme"
	"foundry.fsky.io/fsky/gibcert/internal/challenge"
	"foundry.fsky.io/fsky/gibcert/internal/config"
	"foundry.fsky.io/fsky/gibcert/internal/storage"
)

func TestPresentDNSWithMockProviderRecordsPresentAndCleanup(t *testing.T) {
	var calls []string
	oldFactory, hadFactory := dnsPresenters["mock"]
	dnsPresenters["mock"] = func(_ *config.Provider, _ io.Reader, _ io.Writer) challenge.Presenter {
		return mockPresenter(func(_ context.Context, req challenge.Request) (func(), error) {
			calls = append(calls, "present:"+req.FQDN+"="+req.Value)
			if req.Domain != "example.com" {
				t.Fatalf("domain got %q, want example.com", req.Domain)
			}
			if req.Identifier != "*.example.com" {
				t.Fatalf("identifier got %q, want *.example.com", req.Identifier)
			}
			if req.Timeout != 2*time.Minute {
				t.Fatalf("timeout got %s, want 2m", req.Timeout)
			}
			return func() {
				calls = append(calls, "cleanup:"+req.FQDN+"="+req.Value)
			}, nil
		})
	}
	t.Cleanup(func() {
		if hadFactory {
			dnsPresenters["mock"] = oldFactory
		} else {
			delete(dnsPresenters, "mock")
		}
	})

	cleanup, err := presentDNS(
		context.Background(),
		&config.Provider{Name: "mock-provider", Type: "dns", Driver: "mock"},
		"_acme-challenge.example.com",
		"txt-value",
		"example.com",
		"*.example.com",
		2*time.Minute,
		nil,
		io.Discard,
	)
	if err != nil {
		t.Fatalf("presentDNS: %v", err)
	}
	if cleanup == nil {
		t.Fatal("cleanup got nil")
	}
	cleanup()

	want := []string{
		"present:_acme-challenge.example.com=txt-value",
		"cleanup:_acme-challenge.example.com=txt-value",
	}
	if len(calls) != len(want) {
		t.Fatalf("calls got %v, want %v", calls, want)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("calls got %v, want %v", calls, want)
		}
	}
}

func TestChainMatchesPreferredRootOrIssuer(t *testing.T) {
	root := testCertDER(t, "ISRG Root X1", nil, nil)
	intermediate := testCertDER(t, "R3", root.cert, root.key)

	if !chainMatchesPreferred([][]byte{intermediate.der}, "ISRG Root X1") {
		t.Fatal("chain did not match issuer common name")
	}
	if !chainMatchesPreferred([][]byte{intermediate.der, root.der}, "ISRG Root X1") {
		t.Fatal("chain did not match root subject common name")
	}
	if chainMatchesPreferred([][]byte{intermediate.der}, "Other Root") {
		t.Fatal("chain matched unexpected preferred chain")
	}
}

func TestMakeCSRSplitsDNSAndIP(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := makeCSR(key, []string{"example.com", "192.0.2.10", "2001:db8::1", "www.example.com"})
	if err != nil {
		t.Fatalf("makeCSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	if got, want := csr.DNSNames, []string{"example.com", "www.example.com"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("DNSNames: got %v, want %v", got, want)
	}
	if len(csr.IPAddresses) != 2 {
		t.Fatalf("IPAddresses: got %v, want 2 entries", csr.IPAddresses)
	}
	if csr.IPAddresses[0].String() != "192.0.2.10" || csr.IPAddresses[1].String() != "2001:db8::1" {
		t.Errorf("IPAddresses: got %v", csr.IPAddresses)
	}
}

func TestARIReplaces(t *testing.T) {
	store := storage.New(t.TempDir())

	// No stored certificate (first issuance) yields no replaces hint.
	if got := ariReplaces(store, "example.com", io.Discard); got != "" {
		t.Errorf("ariReplaces with no cert: got %q, want empty", got)
	}

	// A real ACME leaf is signed by an intermediate, so its Authority Key
	// Identifier is populated (it is omitted on self-signed certs). Build a
	// CA and sign the leaf with it.
	ca := testCertDER(t, "Test CA", nil, nil)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x0102030405),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	paths := store.CertPaths("example.com")
	if err := os.MkdirAll(paths.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := storage.WriteSingleCertDER(paths.Cert, der, 0o644); err != nil {
		t.Fatal(err)
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	want, err := acme.ARIUniqueIdentifier(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if got := ariReplaces(store, "example.com", io.Discard); got != want {
		t.Errorf("ariReplaces: got %q, want %q", got, want)
	}
}

func TestDNSPersistChallengeExpectations(t *testing.T) {
	issuers, accountURI, err := dnsPersistChallengeExpectations(acme.Challenge{
		AccountURI:        "https://ca.example/acct/alternate",
		IssuerDomainNames: []string{"ca1.example", "ca2.example"},
	}, "configured.example", "https://ca.example/acct/123")
	if err != nil {
		t.Fatalf("dnsPersistChallengeExpectations: %v", err)
	}
	if accountURI != "https://ca.example/acct/alternate" {
		t.Errorf("accountURI got %q", accountURI)
	}
	if len(issuers) != 2 || issuers[0] != "ca1.example" || issuers[1] != "ca2.example" {
		t.Errorf("issuers got %v", issuers)
	}

	issuers, accountURI, err = dnsPersistChallengeExpectations(acme.Challenge{}, "configured.example", "https://ca.example/acct/123")
	if err != nil {
		t.Fatalf("fallback dnsPersistChallengeExpectations: %v", err)
	}
	if accountURI != "https://ca.example/acct/123" || len(issuers) != 1 || issuers[0] != "configured.example" {
		t.Errorf("fallback got issuers=%v accountURI=%q", issuers, accountURI)
	}
}

func TestDNSPersistChallengeExpectationsRejectsMalformedIssuers(t *testing.T) {
	for _, issuer := range []string{"", "CA.example", "ca.example.", strings.Repeat("a", 254)} {
		t.Run(issuer, func(t *testing.T) {
			_, _, err := dnsPersistChallengeExpectations(acme.Challenge{
				IssuerDomainNames: []string{issuer},
			}, "configured.example", "https://ca.example/acct/123")
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

type testCertificate struct {
	der  []byte
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func testCertDER(t *testing.T, commonName string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) testCertificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:         true,
	}
	if parent == nil {
		parent = tmpl
		parentKey = key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCertificate{der: der, cert: cert, key: key}
}

type mockPresenter func(context.Context, challenge.Request) (func(), error)

func (m mockPresenter) Present(ctx context.Context, req challenge.Request) (func(), error) {
	return m(ctx, req)
}
