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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gitfield.org/fsky/gibcert/internal/acme"
	"gitfield.org/fsky/gibcert/internal/config"
	"gitfield.org/fsky/gibcert/internal/storage"
)

func TestIssueRejectsInvalidChainWithoutChangingState(t *testing.T) {
	defects := []struct {
		name string
		want string
	}{
		{"malformed-leaf", "parse certificate 1"},
		{"malformed-intermediate", "parse certificate 2"},
		{"different-key", "public key does not match"},
		{"missing-dns", "requested name"},
		{"missing-ip", "requested name"},
		{"missing-wildcard", "requested wildcard"},
		{"expired", "not currently valid"},
		{"future", "not currently valid"},
		{"expired-intermediate", "certificate 2 is not currently valid"},
		{"ca-leaf", "leaf is a CA"},
		{"client-only", "TLS server authentication"},
		{"certsign-only", "key usage does not permit TLS"},
		{"critical-extension", "unhandled critical extensions"},
		{"wrong-issuer", "not signed by certificate 2"},
	}
	for _, rotation := range []string{"reused", "new", "staged"} {
		for _, defect := range defects {
			t.Run(rotation+"/"+defect.name, func(t *testing.T) {
				store, cert := seedIssueState(t, rotation)
				before := snapshotIssueState(t, store.CertDir(cert.Name))
				client, downloaded := fakeIssueClient(t, nil, func(csr *x509.CertificateRequest) []byte {
					return issueResponseChain(t, csr, defect.name)
				})
				err := Issue(context.Background(), client, cert, store, &config.Config{}, IssueOptions{Out: io.Discard, NewKey: rotation == "new"})
				if err == nil || !strings.Contains(err.Error(), defect.want) {
					t.Fatalf("Issue error = %v, want %q", err, defect.want)
				}
				if !*downloaded {
					t.Fatal("Issue did not download the fake CA response")
				}
				if after := snapshotIssueState(t, store.CertDir(cert.Name)); !reflect.DeepEqual(before, after) {
					t.Fatalf("invalid response changed canonical material, metadata, archives or staged key\nbefore: %#v\nafter: %#v", before, after)
				}
			})
		}
	}
}

func TestIssueAcceptsPrivateChainAndRequestedSANs(t *testing.T) {
	for _, rotation := range []string{"reused", "new"} {
		t.Run(rotation, func(t *testing.T) {
			store, cert := seedIssueState(t, rotation)
			paths := store.CertPaths(cert.Name)
			oldKey, err := os.ReadFile(paths.Key)
			if err != nil {
				t.Fatal(err)
			}
			var response []byte
			client, _ := fakeIssueClient(t, nil, func(csr *x509.CertificateRequest) []byte {
				response = issueResponseChain(t, csr, "")
				return response
			})
			if err := Issue(context.Background(), client, cert, store, &config.Config{}, IssueOptions{Out: io.Discard, NewKey: rotation == "new"}); err != nil {
				t.Fatalf("Issue private CA: %v", err)
			}
			fullchain, err := os.ReadFile(paths.Fullchain)
			if err != nil || string(fullchain) != string(response) {
				t.Fatalf("stored fullchain differs from accepted response: %v", err)
			}
			block, _ := pem.Decode(fullchain)
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			key, err := storage.ReadKey(paths.Key)
			if err != nil {
				t.Fatal(err)
			}
			publicKeyDER, err := x509.MarshalPKIXPublicKey(key.Public())
			if err != nil || string(publicKeyDER) != string(leaf.RawSubjectPublicKeyInfo) {
				t.Fatalf("stored key does not match accepted leaf: %v", err)
			}
			meta, err := store.LoadCertMeta(cert.Name)
			if err != nil || meta.SerialNumber != leaf.SerialNumber.String() || !reflect.DeepEqual(meta.Names, cert.Names) {
				t.Fatalf("metadata does not describe accepted certificate: %#v, %v", meta, err)
			}
			newKey, err := os.ReadFile(paths.Key)
			if err != nil {
				t.Fatal(err)
			}
			if rotation == "reused" && string(newKey) != string(oldKey) {
				t.Fatal("renewal unexpectedly changed reused key")
			}
			if rotation == "new" {
				if string(newKey) == string(oldKey) {
					t.Fatal("new-key issuance retained the old key")
				}
				archives, err := filepath.Glob(filepath.Join(paths.Dir, "privkey-2*.pem"))
				if err != nil || len(archives) != 1 {
					t.Fatalf("archives = %v, %v; want only previous live key", archives, err)
				}
				archived, err := os.ReadFile(archives[0])
				if err != nil || string(archived) != string(oldKey) {
					t.Fatalf("archive does not preserve previous live key: %v", err)
				}
			}
		})
	}
}

func seedIssueState(t *testing.T, rotation string) (*storage.Store, *config.Certificate) {
	t.Helper()
	store := storage.New(t.TempDir())
	cert := &config.Certificate{
		Name:    "example.com",
		Names:   []string{"example.com", "*.example.com", "192.0.2.1"},
		Key:     config.KeySpec{Type: "ecdsa", Reuse: true},
		Account: "account",
	}
	paths := store.CertPaths(cert.Name)
	if err := os.MkdirAll(paths.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	current := testCertDER(t, "old leaf", nil, nil)
	if err := storage.WriteKey(paths.Key, current.key); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{paths.Cert, paths.Chain, paths.Fullchain} {
		if err := storage.WriteSingleCertDER(path, current.der, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, at := range []time.Time{time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC)} {
		if _, _, err := storage.ArchivePrivateKey(paths.Key, at); err != nil {
			t.Fatal(err)
		}
	}
	meta := storage.CertMeta{Name: cert.Name, SerialNumber: "old serial", Names: cert.Names, Deploys: []storage.CertDeployMeta{{Target: "web", SHA256: "old deployed hash"}}}
	if rotation == "staged" {
		cert.TLSA = &config.TLSASpec{TTL: 60}
		next := testCertDER(t, "next", nil, nil)
		if err := storage.WriteKey(paths.KeyNext, next.key); err != nil {
			t.Fatal(err)
		}
		meta.TLSA = &storage.CertTLSAMeta{TTL: 60, NextPublishedAt: time.Now().Add(-time.Hour), CurrentValue: "current", NextValue: "next"}
	}
	if err := store.SaveCertMeta(cert.Name, meta); err != nil {
		t.Fatal(err)
	}
	return store, cert
}

type issueFileSnapshot struct {
	Contents string
	Mode     os.FileMode
	Modified time.Time
}

func snapshotIssueState(t *testing.T, dir string) map[string]issueFileSnapshot {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string]issueFileSnapshot)
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		contents, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		files[entry.Name()] = issueFileSnapshot{string(contents), info.Mode(), info.ModTime()}
	}
	return files
}

func issueResponseChain(t *testing.T, csr *x509.CertificateRequest, defect string) []byte {
	t.Helper()
	caKey, err := storage.GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Private test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign,
	}
	if defect == "expired-intermediate" {
		ca.NotBefore, ca.NotAfter = now.Add(-2*time.Hour), now.Add(-time.Hour)
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "example.com"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		DNSNames: append([]string(nil), csr.DNSNames...), IPAddresses: append([]net.IP(nil), csr.IPAddresses...),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	publicKey := csr.PublicKey
	switch defect {
	case "different-key":
		publicKey = caKey.Public()
	case "missing-dns":
		leaf.DNSNames = []string{"other.example.com", "*.other.example.com"}
	case "missing-ip":
		leaf.IPAddresses = nil
	case "missing-wildcard":
		leaf.DNSNames = []string{"example.com", "www.example.com"}
	case "expired":
		leaf.NotBefore, leaf.NotAfter = now.Add(-2*time.Hour), now.Add(-time.Hour)
	case "future":
		leaf.NotBefore, leaf.NotAfter = now.Add(time.Hour), now.Add(2*time.Hour)
	case "ca-leaf":
		leaf.IsCA, leaf.BasicConstraintsValid = true, true
	case "client-only":
		leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case "certsign-only":
		leaf.KeyUsage = x509.KeyUsageCertSign
	case "critical-extension":
		leaf.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, publicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	if defect == "malformed-leaf" {
		leafDER = []byte{1, 2, 3}
	}
	if defect == "malformed-intermediate" {
		caDER = []byte{1, 2, 3}
	}
	if defect == "wrong-issuer" {
		otherKey, err := storage.GenerateAccountKey()
		if err != nil {
			t.Fatal(err)
		}
		caDER, err = x509.CreateCertificate(rand.Reader, ca, ca, otherKey.Public(), otherKey)
		if err != nil {
			t.Fatal(err)
		}
	}
	return pemChain(leafDER, caDER)
}

// fakeIssueClient exercises the full Issue path, including decoding the actual
// submitted CSR and issuing a response for its public key and requested SANs.
func fakeIssueClient(t *testing.T, authz *acme.Authorization, chain func(*x509.CertificateRequest) []byte) (*Client, *bool) {
	t.Helper()
	accountKey, err := storage.GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	var certificate []byte
	downloaded := false
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce-value")
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/directory":
			_ = json.NewEncoder(w).Encode(map[string]string{"newNonce": srv.URL + "/nonce", "newOrder": srv.URL + "/new-order"})
		case "/nonce":
			w.WriteHeader(http.StatusOK)
		case "/new-order":
			order := acme.Order{Status: acme.StatusReady, Finalize: srv.URL + "/finalize"}
			if authz != nil {
				order.Authorizations = []string{srv.URL + "/authz"}
			}
			w.Header().Set("Location", srv.URL+"/order")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(order)
		case "/authz":
			_ = json.NewEncoder(w).Encode(authz)
		case "/challenge":
			_ = json.NewEncoder(w).Encode(acme.Challenge{Type: challengeDNSPersist01, Status: acme.StatusValid})
		case "/finalize":
			var jws struct {
				Payload string `json:"payload"`
			}
			if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
				t.Errorf("decode JWS: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			payload, err := base64.RawURLEncoding.DecodeString(jws.Payload)
			var request struct {
				CSR string `json:"csr"`
			}
			if err != nil || json.Unmarshal(payload, &request) != nil {
				t.Error("invalid finalize payload")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			der, err := base64.RawURLEncoding.DecodeString(request.CSR)
			if err != nil {
				t.Errorf("decode CSR: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			csr, err := x509.ParseCertificateRequest(der)
			if err != nil || csr.CheckSignature() != nil {
				t.Errorf("invalid CSR: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			certificate = chain(csr)
			_ = json.NewEncoder(w).Encode(acme.Order{Status: acme.StatusValid, Certificate: srv.URL + "/certificate"})
		case "/certificate":
			downloaded = true
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			_, _ = w.Write(certificate)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return &Client{acme: newACMEClient(srv.URL+"/directory", srv.Client()), account: acme.Account{Location: srv.URL + "/acct/1", PrivateKey: accountKey}}, &downloaded
}
