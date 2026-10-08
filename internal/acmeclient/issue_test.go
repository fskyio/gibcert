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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"gitfield.org/fsky/gibcert/internal/acme"
	"gitfield.org/fsky/gibcert/internal/challenge"
	"gitfield.org/fsky/gibcert/internal/config"
	"gitfield.org/fsky/gibcert/internal/storage"
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

func TestSelectChainAndPEMDecode(t *testing.T) {
	root := testCertDER(t, "Root A", nil, nil)
	otherRoot := testCertDER(t, "Root B", nil, nil)
	leaf := testCertDER(t, "example.com", root.cert, root.key)
	otherLeaf := testCertDER(t, "example.org", otherRoot.cert, otherRoot.key)

	defaultChain := pemChain(leaf.der, root.der)
	alternateChain := pemChain(otherLeaf.der, otherRoot.der)
	selected, err := selectChain([]acme.Certificate{
		{ChainPEM: defaultChain},
		{ChainPEM: alternateChain},
	}, "Root B")
	if err != nil {
		t.Fatalf("selectChain preferred: %v", err)
	}
	if len(selected) != 2 || string(selected[1]) != string(otherRoot.der) {
		t.Fatalf("selected chain got %d certs, top=%x", len(selected), selected[len(selected)-1])
	}

	selected, err = selectChain([]acme.Certificate{{ChainPEM: defaultChain}}, "")
	if err != nil {
		t.Fatalf("selectChain default: %v", err)
	}
	if len(selected) != 2 || string(selected[0]) != string(leaf.der) {
		t.Fatalf("default chain got %d certs", len(selected))
	}
	if _, err := selectChain([]acme.Certificate{{ChainPEM: defaultChain}}, "Missing Root"); err == nil {
		t.Fatal("selectChain matched missing preferred chain")
	}
	if _, err := pemChainToDER([]byte("not certificates")); err == nil {
		t.Fatal("pemChainToDER accepted chain without certificates")
	}
}

func TestFindCAProfileAndAliasFQDN(t *testing.T) {
	cfg := &config.Config{CAs: []*config.CA{{
		Name:    "letsencrypt",
		Type:    "acme",
		Profile: "classic",
	}}}
	if got := findCAProfile(cfg, "letsencrypt"); got == nil || got.Name != "letsencrypt" {
		t.Fatalf("findCAProfile got %#v", got)
	}
	if got := findCAProfile(cfg, "missing"); got != nil {
		t.Fatalf("findCAProfile missing got %#v", got)
	}
	if got := findCAProfile(cfg, ""); got != nil {
		t.Fatalf("findCAProfile empty got %#v", got)
	}

	if got := aliasFQDN(config.ChallengeSpec{AliasFQDN: "custom.example."}, "example.com"); got != "custom.example." {
		t.Fatalf("AliasFQDN got %q", got)
	}
	if got := aliasFQDN(config.ChallengeSpec{AliasDomain: "delegate.example"}, "example.com"); got != "_acme-challenge.example.com.delegate.example" {
		t.Fatalf("AliasDomain got %q", got)
	}
	if got := aliasFQDN(config.ChallengeSpec{}, "example.com"); got != "_acme-challenge.example.com" {
		t.Fatalf("default alias got %q", got)
	}
}

func TestNewOrderRetriesAlreadyReplacedWithoutReplaces(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var newOrderCalls int
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce-value")
		switch r.URL.Path {
		case "/directory":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"newNonce":   srv.URL + "/nonce",
				"newAccount": srv.URL + "/new-account",
				"newOrder":   srv.URL + "/new-order",
				"revokeCert": srv.URL + "/revoke",
				"keyChange":  srv.URL + "/key-change",
			})
		case "/nonce":
			w.WriteHeader(http.StatusOK)
		case "/new-order":
			newOrderCalls++
			if newOrderCalls == 1 {
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"type":   acme.ProblemTypeAlreadyReplaced,
					"status": http.StatusConflict,
					"detail": "already replaced",
				})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Location", srv.URL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(acme.Order{Status: acme.StatusPending})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := &Client{
		acme: newACMEClient(srv.URL+"/directory", srv.Client()),
		account: acme.Account{
			Location:   srv.URL + "/acct/1",
			PrivateKey: key,
		},
	}
	order, err := client.newOrder(context.Background(), acme.Order{
		Identifiers: []acme.Identifier{{Type: "dns", Value: "example.com"}},
		Replaces:    "old-cert-id",
	})
	if err != nil {
		t.Fatalf("newOrder: %v", err)
	}
	if newOrderCalls != 2 {
		t.Fatalf("new-order calls got %d, want 2", newOrderCalls)
	}
	if order.Location != srv.URL+"/order/1" {
		t.Fatalf("order location got %q", order.Location)
	}
}

func TestPresentHTTP01UsesWebrootAndGlobalFallback(t *testing.T) {
	webroot := t.TempDir()
	cleanup, err := presentHTTP01(
		&config.Certificate{Name: "example.com"},
		&config.GlobalChallenge{Webroot: webroot},
		nil,
		"token",
		"key-auth",
	)
	if err != nil {
		t.Fatalf("presentHTTP01: %v", err)
	}
	path := webroot + "/.well-known/acme-challenge/token"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read challenge file: %v", err)
	}
	if string(raw) != "key-auth" {
		t.Fatalf("challenge file got %q", raw)
	}
	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("cleanup left challenge file: %v", err)
	}
}

func TestDNSPresenterFactories(t *testing.T) {
	provider := &config.Provider{Name: "dns", Driver: "rfc2136"}
	if _, ok := nsupdateDNSPresenter(provider, nil, io.Discard).(*challenge.DNSNSUpdate); !ok {
		t.Fatal("nsupdateDNSPresenter did not return DNSNSUpdate")
	}
	provider.Driver = "powerdns"
	if _, ok := powerDNSPresenter(provider, nil, io.Discard).(*challenge.DNSPowerDNS); !ok {
		t.Fatal("powerDNSPresenter did not return DNSPowerDNS")
	}
	if _, err := presentDNS(context.Background(), &config.Provider{Name: "bad", Driver: "missing"}, "", "", "", "", 0, nil, io.Discard); err == nil {
		t.Fatal("presentDNS accepted unsupported driver")
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
	if got := ariReplaces(store, "example.com", "default", "https://ca.example/directory", io.Discard); got != "" {
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
	const directory = "https://ca.example/directory"
	if got := ariReplaces(store, "example.com", "default", directory, io.Discard); got != "" {
		t.Errorf("ariReplaces without metadata: got %q, want empty", got)
	}
	tests := []struct {
		name string
		meta storage.CertMeta
		want string
	}{
		{"imported", storage.CertMeta{IssuerType: "imported", Directory: directory, SerialNumber: leaf.SerialNumber.String()}, ""},
		{"unknown issuer", storage.CertMeta{Account: "default", Directory: directory, SerialNumber: leaf.SerialNumber.String()}, ""},
		{"different account", storage.CertMeta{IssuerType: "acme", Account: "other", Directory: directory, SerialNumber: leaf.SerialNumber.String()}, ""},
		{"different directory", storage.CertMeta{IssuerType: "acme", Account: "default", Directory: "https://other.example/directory", SerialNumber: leaf.SerialNumber.String()}, ""},
		{"different leaf", storage.CertMeta{IssuerType: "acme", Account: "default", Directory: directory, SerialNumber: "123"}, ""},
		{"same issuer and leaf", storage.CertMeta{IssuerType: "acme", Account: "default", Directory: directory, SerialNumber: leaf.SerialNumber.String()}, want},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := store.SaveCertMeta("example.com", tc.meta); err != nil {
				t.Fatal(err)
			}
			var out strings.Builder
			got := ariReplaces(store, "example.com", "default", directory, &out)
			if got != tc.want {
				t.Errorf("ariReplaces: got %q, want %q", got, tc.want)
			}
			if printed := strings.Contains(out.String(), "replacing the existing certificate"); printed != (tc.want != "") {
				t.Errorf("replacement message for %q: %q", got, out.String())
			}
		})
	}
}

func TestIssueTLSALPNCancellationClosesTransports(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve listener address: %v", err)
	}
	addr := reserved.Addr().String()
	_ = reserved.Close()

	challengeReady := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Replay-Nonce", "nonce-value")
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/directory":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"newNonce": srv.URL + "/nonce",
				"newOrder": srv.URL + "/new-order",
			})
		case "/nonce":
			w.WriteHeader(http.StatusOK)
		case "/new-order":
			w.Header().Set("Location", srv.URL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(acme.Order{
				Status:         acme.StatusPending,
				Authorizations: []string{srv.URL + "/authz/1"},
			})
		case "/authz/1":
			_ = json.NewEncoder(w).Encode(acme.Authorization{
				Status:     acme.StatusPending,
				Identifier: acme.Identifier{Type: "dns", Value: "example.test"},
				Challenges: []acme.Challenge{{
					Type:   acme.ChallengeTypeTLSALPN01,
					Token:  "token-xyz",
					URL:    srv.URL + "/challenge/1",
					Status: acme.StatusPending,
				}},
			})
		case "/challenge/1":
			close(challengeReady)
			<-r.Context().Done()
		default:
			http.NotFound(w, r)
		}
	}))
	defer func() {
		cancel()
		srv.Close()
	}()
	client := &Client{
		acme: newACMEClient(srv.URL+"/directory", srv.Client()),
		account: acme.Account{
			Location:   srv.URL + "/acct/1",
			PrivateKey: key,
		},
	}
	cert := &config.Certificate{
		Name:  "example.test",
		Names: []string{"example.test"},
		Key:   config.KeySpec{Type: "ecdsa", Curve: "p256"},
		Challenge: config.ChallengeSpec{
			Type:   "tls-alpn-01",
			Listen: addr,
		},
	}
	store := storage.New(t.TempDir())
	issued := make(chan error, 1)
	go func() {
		issued <- Issue(ctx, client, cert, store, &config.Config{}, IssueOptions{Out: io.Discard})
	}()
	select {
	case <-challengeReady:
	case err := <-issued:
		t.Fatalf("Issue returned before presenting the challenge: %v", err)
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("Issue did not initiate the challenge")
	}

	transport, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial challenge listener: %v", err)
	}
	defer transport.Close()
	// Send a real ClientHello but withhold the client Finished. Reading the
	// server response proves the transport is accepted, not just queued.
	readStarted := make(chan struct{})
	releaseRead := make(chan struct{})
	tlsClient := tls.Client(tlsALPNClientHelloOnlyConn{
		Conn:        transport,
		readStarted: readStarted,
		releaseRead: releaseRead,
	}, &tls.Config{
		ServerName:         "example.test",
		NextProtos:         []string{"acme-tls/1"},
		InsecureSkipVerify: true,
	})
	handshake := make(chan error, 1)
	handshakeDone := make(chan struct{})
	go func() {
		handshake <- tlsClient.Handshake()
		close(handshakeDone)
	}()
	defer func() {
		close(releaseRead)
		select {
		case <-handshakeDone:
		case <-time.After(3 * time.Second):
			t.Error("ClientHello sender did not exit")
		}
	}()
	select {
	case <-readStarted:
	case err := <-handshake:
		t.Fatalf("send ClientHello: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("client did not send ClientHello")
	}
	if err := transport.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set client read deadline: %v", err)
	}
	var response [1]byte
	if _, err := io.ReadFull(transport, response[:]); err != nil {
		t.Fatalf("server did not begin the accepted handshake: %v", err)
	}

	cancel()
	select {
	case err := <-issued:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Issue cancellation: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Issue waited for the active TLS handshake instead of shutting it down")
	}
	if err := transport.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set closure read deadline: %v", err)
	}
	var buf [4096]byte
	for {
		_, err := transport.Read(buf[:])
		if err == nil {
			continue
		}
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatalf("client timed out instead of observing transport closure: %v", err)
		}
		break
	}
	rebound, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("Issue returned without releasing listener: %v", err)
	}
	_ = rebound.Close()
}

type tlsALPNClientHelloOnlyConn struct {
	net.Conn
	readStarted chan struct{}
	releaseRead <-chan struct{}
}

func (conn tlsALPNClientHelloOnlyConn) Read([]byte) (int, error) {
	close(conn.readStarted)
	<-conn.releaseRead
	return 0, io.EOF
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

func pemChain(ders ...[]byte) []byte {
	var out []byte
	for _, der := range ders {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return out
}
