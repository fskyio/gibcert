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

package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestChallengeHelpers(t *testing.T) {
	chal := Challenge{
		Token:            "token-part2",
		KeyAuthorization: "token-part2.thumbprint",
		Identifier:       Identifier{Type: "dns", Value: "example.com"},
	}
	if got := chal.HTTP01ResourcePath(); got != "/.well-known/acme-challenge/token-part2" {
		t.Fatalf("HTTP01ResourcePath got %q", got)
	}
	if got := chal.DNS01TXTRecordName(); got != "_acme-challenge.example.com" {
		t.Fatalf("DNS01TXTRecordName got %q", got)
	}

	digest := sha256.Sum256([]byte(chal.KeyAuthorization))
	if got, want := chal.DNS01KeyAuthorization(), base64.RawURLEncoding.EncodeToString(digest[:]); got != want {
		t.Fatalf("DNS01KeyAuthorization got %q, want %q", got, want)
	}

	account := Account{Location: "https://ca.example/acct/123"}
	accountDigest := sha256.Sum256([]byte(account.Location))
	accountLabel := strings.ToLower(base32.StdEncoding.EncodeToString(accountDigest[:10]))
	if got, want := chal.DNSAccount01TXTRecordName(account), "_"+accountLabel+"._acme-challenge.example.com"; got != want {
		t.Fatalf("DNSAccount01TXTRecordName got %q, want %q", got, want)
	}

	tokenPart1 := []byte("part-one")
	tokenPart2 := []byte("part-two")
	mail := Challenge{
		Token:            base64.RawURLEncoding.EncodeToString(tokenPart2),
		KeyAuthorization: base64.RawURLEncoding.EncodeToString(tokenPart2) + ".thumbprint",
	}
	got, err := mail.MailReply00KeyAuthorization("ACME: " + base64.RawURLEncoding.EncodeToString(tokenPart1))
	if err != nil {
		t.Fatalf("MailReply00KeyAuthorization: %v", err)
	}
	fullToken := append(tokenPart1, tokenPart2...)
	mailKeyAuth := strings.Replace(mail.KeyAuthorization, mail.Token, base64.RawURLEncoding.EncodeToString(fullToken), 1)
	mailDigest := sha256.Sum256([]byte(mailKeyAuth))
	if want := base64.RawURLEncoding.EncodeToString(mailDigest[:]); got != want {
		t.Fatalf("MailReply00KeyAuthorization got %q, want %q", got, want)
	}
	if _, err := mail.MailReply00KeyAuthorization("!"); err == nil {
		t.Fatal("MailReply00KeyAuthorization accepted malformed subject")
	}
}

func TestAuthorizationHelpers(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authz := Authorization{
		Identifier: Identifier{Type: "dns", Value: "example.com"},
		Wildcard:   true,
		Challenges: []Challenge{{Token: "token"}, {Token: "preset", KeyAuthorization: "already-set"}},
	}
	if got := authz.IdentifierValue(); got != "*.example.com" {
		t.Fatalf("IdentifierValue got %q", got)
	}
	if err := authz.fillChallengeFields(Account{PrivateKey: key}); err != nil {
		t.Fatalf("fillChallengeFields: %v", err)
	}
	thumbprint, err := jwkThumbprint(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	if authz.Challenges[0].Identifier != authz.Identifier {
		t.Fatalf("challenge identifier got %#v, want %#v", authz.Challenges[0].Identifier, authz.Identifier)
	}
	if got, want := authz.Challenges[0].KeyAuthorization, "token."+thumbprint; got != want {
		t.Fatalf("challenge key authorization got %q, want %q", got, want)
	}
	if got := authz.Challenges[1].KeyAuthorization; got != "already-set" {
		t.Fatalf("preset key authorization got %q", got)
	}

	for _, tc := range []struct {
		status   string
		finished bool
		wantErr  string
	}{
		{status: StatusPending, finished: false},
		{status: StatusValid, finished: true},
		{status: StatusInvalid, finished: true, wantErr: "authorization failed"},
		{status: StatusExpired, finished: true, wantErr: "authorization expired"},
		{status: "mystery", finished: true, wantErr: "unrecognized authorization status"},
	} {
		t.Run(tc.status, func(t *testing.T) {
			finished, err := authzIsFinalized(Authorization{
				Status:     tc.status,
				Challenges: []Challenge{{Error: &Problem{Detail: "challenge failed"}}},
			})
			if finished != tc.finished {
				t.Fatalf("finished got %v, want %v", finished, tc.finished)
			}
			if tc.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("error got %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestRenewalInfoHelpers(t *testing.T) {
	start := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	end := start.Add(2 * time.Hour)
	ari := RenewalInfo{}
	if ari.HasWindow() || ari.NeedsRefresh() {
		t.Fatal("empty ARI unexpectedly has window or needs refresh")
	}
	ari.SuggestedWindow.Start = start
	ari.SuggestedWindow.End = end
	if !ari.HasWindow() {
		t.Fatal("ARI with start and end has no window")
	}
	if !ari.NeedsRefresh() {
		t.Fatal("ARI without retry-after should need refresh")
	}
	retryAfter := time.Now().Add(time.Hour)
	ari.RetryAfter = &retryAfter
	if ari.NeedsRefresh() {
		t.Fatal("ARI with future retry-after should not need refresh")
	}
	if !ari.SameWindow(RenewalInfo{SuggestedWindow: ari.SuggestedWindow}) {
		t.Fatal("SameWindow returned false for identical window")
	}
	if ari.SameWindow(RenewalInfo{}) {
		t.Fatal("SameWindow returned true for empty window")
	}
}

func TestARIUniqueIdentifier(t *testing.T) {
	cert := &x509.Certificate{
		AuthorityKeyId: []byte{0x01, 0x02, 0x03},
		SerialNumber:   big.NewInt(0x80),
	}
	got, err := ARIUniqueIdentifier(cert)
	if err != nil {
		t.Fatalf("ARIUniqueIdentifier: %v", err)
	}
	serialDER, err := asn1.Marshal(cert.SerialNumber)
	if err != nil {
		t.Fatal(err)
	}
	want := base64.RawURLEncoding.EncodeToString(cert.AuthorityKeyId) + "." +
		base64.RawURLEncoding.EncodeToString(serialDER[2:])
	if got != want {
		t.Fatalf("ARIUniqueIdentifier got %q, want %q", got, want)
	}
	if _, err := ARIUniqueIdentifier(&x509.Certificate{}); err == nil {
		t.Fatal("ARIUniqueIdentifier accepted missing serial")
	}
	client := &Client{dir: Directory{RenewalInfo: "https://ca.example/ari"}}
	if got := client.ariEndpoint(got); got != "https://ca.example/ari/"+want {
		t.Fatalf("ariEndpoint got %q", got)
	}
	if got := (&Client{}).ariEndpoint(want); got != "" {
		t.Fatalf("ariEndpoint without directory got %q", got)
	}
}

func TestJWKAndJWSHelpers(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	ecdsaJWK, err := jwkEncode(ecdsaKey.Public())
	if err != nil {
		t.Fatalf("jwkEncode ECDSA: %v", err)
	}
	if !strings.Contains(ecdsaJWK, `"crv":"P-256"`) || !strings.Contains(ecdsaJWK, `"kty":"EC"`) {
		t.Fatalf("ECDSA JWK missing expected fields: %s", ecdsaJWK)
	}
	rsaJWK, err := jwkEncode(rsaKey.Public())
	if err != nil {
		t.Fatalf("jwkEncode RSA: %v", err)
	}
	if !strings.Contains(rsaJWK, `"kty":"RSA"`) || !strings.Contains(rsaJWK, `"e":"AQAB"`) {
		t.Fatalf("RSA JWK missing expected fields: %s", rsaJWK)
	}
	if _, err := jwkEncode(struct{}{}); err != errUnsupportedKey {
		t.Fatalf("jwkEncode unsupported got %v", err)
	}

	if alg, hash := jwsHasher(ecdsaKey.Public()); alg != "ES256" || hash != crypto.SHA256 {
		t.Fatalf("jwsHasher P-256 got %s/%v", alg, hash)
	}
	if alg, hash := jwsHasher(rsaKey.Public()); alg != "RS256" || hash != crypto.SHA256 {
		t.Fatalf("jwsHasher RSA got %s/%v", alg, hash)
	}
	if alg, hash := jwsHasher(struct{}{}); alg != "" || hash != 0 {
		t.Fatalf("jwsHasher unsupported got %s/%v", alg, hash)
	}

	jws, err := jwsEncodeJSON(map[string]string{"resource": "newAccount"}, ecdsaKey, noKeyID, "nonce", "https://ca.example/new-account")
	if err != nil {
		t.Fatalf("jwsEncodeJSON: %v", err)
	}
	parsed := parseJWS(t, jws)
	protected := decodeJSONPart(t, parsed.Protected)
	if protected["alg"] != "ES256" || protected["nonce"] != "nonce" || protected["url"] != "https://ca.example/new-account" {
		t.Fatalf("protected header got %#v", protected)
	}
	if _, ok := protected["jwk"]; !ok {
		t.Fatalf("protected header missing jwk: %#v", protected)
	}
	payload := decodeJSONPart(t, parsed.Payload)
	if payload["resource"] != "newAccount" {
		t.Fatalf("payload got %#v", payload)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parsed.Signature)
	if err != nil {
		t.Fatalf("signature is not base64url: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("ECDSA signature length got %d, want 64", len(sig))
	}

	kidJWS, err := jwsEncodeJSON(nil, rsaKey, keyID("https://ca.example/acct/1"), "", "https://ca.example/order")
	if err != nil {
		t.Fatalf("jwsEncodeJSON kid: %v", err)
	}
	kidParsed := parseJWS(t, kidJWS)
	kidProtected := decodeJSONPart(t, kidParsed.Protected)
	if kidProtected["kid"] != "https://ca.example/acct/1" {
		t.Fatalf("protected kid got %#v", kidProtected)
	}
	if _, ok := kidProtected["jwk"]; ok {
		t.Fatalf("protected header unexpectedly included jwk: %#v", kidProtected)
	}
	if kidParsed.Payload != "" {
		t.Fatalf("nil payload encoded as %q, want empty", kidParsed.Payload)
	}
}

func TestJwsEncodeEAB(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hmacKey := []byte("shared-secret")
	eab, err := jwsEncodeEAB(key.Public(), hmacKey, keyID("kid-1"), "https://ca.example/new-account")
	if err != nil {
		t.Fatalf("jwsEncodeEAB: %v", err)
	}
	parsed := parseJWS(t, eab)
	protected := decodeJSONPart(t, parsed.Protected)
	if protected["alg"] != "HS256" || protected["kid"] != "kid-1" || protected["url"] != "https://ca.example/new-account" {
		t.Fatalf("EAB protected header got %#v", protected)
	}
	if _, ok := protected["nonce"]; ok {
		t.Fatalf("EAB protected header included nonce: %#v", protected)
	}
	if _, ok := protected["jwk"]; ok {
		t.Fatalf("EAB protected header included jwk: %#v", protected)
	}
	jwkJSON, err := jwkEncode(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	if got := decodeStringPart(t, parsed.Payload); got != jwkJSON {
		t.Fatalf("EAB payload got %q, want %q", got, jwkJSON)
	}
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write([]byte(parsed.Protected + "." + parsed.Payload))
	wantSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if parsed.Signature != wantSig {
		t.Fatalf("EAB signature got %q, want %q", parsed.Signature, wantSig)
	}
}

func TestAccountThumbprintAndExternalAccountBinding(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	account := Account{PrivateKey: key}
	got, err := account.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	want, err := jwkThumbprint(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("Thumbprint got %q, want %q", got, want)
	}

	client := &Client{dir: Directory{NewNonce: "cached", NewAccount: "https://ca.example/new-account"}}
	macKey := base64.RawURLEncoding.EncodeToString([]byte("shared-secret"))
	if err := account.SetExternalAccountBinding(context.Background(), client, EAB{KeyID: "kid-1", MACKey: macKey}); err != nil {
		t.Fatalf("SetExternalAccountBinding: %v", err)
	}
	parsed := parseJWS(t, account.ExternalAccountBinding)
	protected := decodeJSONPart(t, parsed.Protected)
	if protected["alg"] != "HS256" || protected["kid"] != "kid-1" {
		t.Fatalf("EAB protected header got %#v", protected)
	}
	if err := account.SetExternalAccountBinding(context.Background(), client, EAB{KeyID: "kid-1", MACKey: "%"}); err == nil {
		t.Fatal("SetExternalAccountBinding accepted invalid MAC key")
	}
}

func TestAccountHTTPFlowsWithFakeACMEServer(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var serverURL string
	var postPaths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(replayNonce, "nonce-"+strings.TrimPrefix(r.URL.Path, "/"))
		switch r.URL.Path {
		case "/dir":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(Directory{
				NewNonce:   serverURL + "/nonce",
				NewAccount: serverURL + "/new-account",
				NewOrder:   serverURL + "/new-order",
				RevokeCert: serverURL + "/revoke",
				KeyChange:  serverURL + "/key-change",
			})
		case "/nonce":
			if r.Method != http.MethodHead {
				t.Fatalf("nonce method got %s", r.Method)
			}
			w.WriteHeader(http.StatusOK)
		case "/new-account", "/acct/1":
			if r.Method != http.MethodPost {
				t.Fatalf("account method got %s", r.Method)
			}
			assertJWSRequest(t, r)
			postPaths = append(postPaths, r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Location", serverURL+"/acct/1")
			if r.URL.Path == "/new-account" {
				w.WriteHeader(http.StatusCreated)
			}
			_ = json.NewEncoder(w).Encode(Account{
				Status:   StatusValid,
				Contact:  []string{"mailto:admin@example.com"},
				Location: serverURL + "/acct/1",
			})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	client := &Client{Directory: server.URL + "/dir"}
	account, err := client.NewAccount(context.Background(), Account{
		PrivateKey: key,
		Contact:    []string{"mailto:admin@example.com"},
	})
	if err != nil {
		t.Fatalf("NewAccount: %v", err)
	}
	if account.Location != server.URL+"/acct/1" || account.Status != StatusValid {
		t.Fatalf("NewAccount returned %#v", account)
	}
	account.PrivateKey = key
	got, err := client.GetAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("GetAccount: %v", err)
	}
	if got.Location != server.URL+"/acct/1" {
		t.Fatalf("GetAccount location got %q", got.Location)
	}
	account.Contact = []string{"mailto:new@example.com"}
	got, err = client.UpdateAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("UpdateAccount: %v", err)
	}
	if got.Contact[0] != "mailto:admin@example.com" {
		t.Fatalf("UpdateAccount contact got %v", got.Contact)
	}
	if len(postPaths) != 3 || postPaths[0] != "/new-account" || postPaths[1] != "/new-account" || postPaths[2] != "/acct/1" {
		t.Fatalf("account POST paths got %v", postPaths)
	}
}

func TestHTTPHeaderHelpers(t *testing.T) {
	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Add("Link", `<https://ca.example/issuer>; rel="up", <https://ca.example/terms>; rel="terms-of-service"`)
	resp.Header.Add("Link", `<https://ca.example/alt>; rel="up"`)
	if got := extractLinks(resp, "up"); len(got) != 2 || got[0] != "https://ca.example/issuer" || got[1] != "https://ca.example/alt" {
		t.Fatalf("extractLinks got %v", got)
	}
	if got := extractLinks(nil, "up"); got != nil {
		t.Fatalf("extractLinks nil got %v", got)
	}

	resp.Header.Set("Content-Type", "application/json; charset=utf-8")
	if got := parseMediaType(resp); got != "application/json" {
		t.Fatalf("parseMediaType got %q", got)
	}
	if got := parseMediaType(nil); got != "" {
		t.Fatalf("parseMediaType nil got %q", got)
	}

	fallback := 5 * time.Second
	if got, err := retryAfter(nil, fallback); err != nil || got != fallback {
		t.Fatalf("retryAfter nil got %v/%v, want %v/no error", got, err, fallback)
	}
	resp.Header.Del("Retry-After")
	if got, err := retryAfter(resp, fallback); err != nil || got != fallback {
		t.Fatalf("retryAfter missing got %v/%v, want %v/no error", got, err, fallback)
	}
	resp.Header.Set("Retry-After", "2")
	got, err := retryAfter(resp, fallback)
	if err != nil {
		t.Fatalf("retryAfter seconds: %v", err)
	}
	if got <= 0 || got > 3*time.Second {
		t.Fatalf("retryAfter seconds got %v", got)
	}
	when := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	resp.Header.Set("Retry-After", when.Format(http.TimeFormat))
	gotTime, err := retryAfterTime(resp)
	if err != nil {
		t.Fatalf("retryAfterTime date: %v", err)
	}
	if !gotTime.Equal(when) {
		t.Fatalf("retryAfterTime got %v, want %v", gotTime, when)
	}
	resp.Header.Set("Retry-After", "definitely-not-a-date")
	if _, err := retryAfter(resp, fallback); err == nil {
		t.Fatal("retryAfter accepted invalid header")
	}
}

func TestHTTPReqDecodesJSONWriterAndProblem(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		case "/pem":
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			_, _ = w.Write([]byte("pem-body"))
		case "/problem":
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"type":"` + ProblemTypeMalformed + `","detail":"bad request"}`))
		case "/plain-error":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("plain failure"))
		case "/weird":
			w.WriteHeader(http.StatusSwitchingProtocols)
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := &Client{}
	var jsonOut struct {
		OK bool `json:"ok"`
	}
	if _, err := client.httpReq(context.Background(), http.MethodGet, server.URL+"/json", nil, &jsonOut); err != nil {
		t.Fatalf("httpReq JSON: %v", err)
	}
	if !jsonOut.OK {
		t.Fatal("httpReq JSON did not decode body")
	}
	var buf bytes.Buffer
	if _, err := client.httpReq(context.Background(), http.MethodGet, server.URL+"/pem", nil, &buf); err != nil {
		t.Fatalf("httpReq writer: %v", err)
	}
	if buf.String() != "pem-body" {
		t.Fatalf("writer body got %q", buf.String())
	}
	if _, err := client.httpReq(context.Background(), http.MethodGet, server.URL+"/pem", nil, &jsonOut); err == nil {
		t.Fatal("httpReq non-JSON into non-writer succeeded")
	}
	if _, err := client.httpReq(context.Background(), http.MethodGet, server.URL+"/problem", nil, nil); err == nil {
		t.Fatal("httpReq problem response succeeded")
	} else {
		var problem Problem
		if !errors.As(err, &problem) || problem.Status != http.StatusBadRequest || problem.Detail != "bad request" {
			t.Fatalf("problem error got %#v / %v", problem, err)
		}
	}
	if _, err := client.httpReq(context.Background(), http.MethodGet, server.URL+"/plain-error", nil, nil); err == nil || !strings.Contains(err.Error(), "plain failure") {
		t.Fatalf("plain HTTP error got %v", err)
	}
	if _, err := client.httpReq(context.Background(), http.MethodGet, server.URL+"/weird", nil, nil); err == nil || !strings.Contains(err.Error(), "unexpected status code") {
		t.Fatalf("unexpected status error got %v", err)
	}
}

func TestProblemFormattingAndLogValues(t *testing.T) {
	problem := Problem{
		Type:     ProblemTypeMalformed,
		Title:    "Malformed",
		Status:   http.StatusBadRequest,
		Detail:   "bad order",
		Instance: "https://ca.example/problem/1",
		Subproblems: []Subproblem{{
			Problem:    Problem{Type: ProblemTypeDNS, Detail: "no txt"},
			Identifier: Identifier{Type: "dns", Value: "example.com"},
		}},
	}
	msg := problem.Error()
	for _, want := range []string{"HTTP 400", ProblemTypeMalformed, "bad order", "no txt", "dns_identifier=example.com", "https://ca.example/problem/1"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("Problem.Error() = %q, missing %q", msg, want)
		}
	}
	if got := problem.LogValue().Kind(); got.String() != "Group" {
		t.Fatalf("Problem.LogValue kind got %s", got)
	}
	if got := problem.Subproblems[0].LogValue().Kind(); got.String() != "Group" {
		t.Fatalf("Subproblem.LogValue kind got %s", got)
	}
}

func TestClientSmallHelpers(t *testing.T) {
	client := &Client{UserAgent: "gibcert-test"}
	if got := client.httpClient(); got != http.DefaultClient {
		t.Fatal("httpClient without override did not return default client")
	}
	custom := &http.Client{}
	client.HTTPClient = custom
	if got := client.httpClient(); got != custom {
		t.Fatal("httpClient did not return custom client")
	}
	if got := client.userAgent(); !strings.HasPrefix(got, "gibcert-test acmez (") {
		t.Fatalf("userAgent got %q", got)
	}

	if got := (&Client{}).pollInterval(); got != defaultPollInterval {
		t.Fatalf("default poll interval got %v", got)
	}
	if got := (&Client{PollInterval: time.Second}).pollInterval(); got != time.Second {
		t.Fatalf("custom poll interval got %v", got)
	}
	if got := (&Client{}).pollTimeout(); got != defaultPollTimeout {
		t.Fatalf("default poll timeout got %v", got)
	}
	if got := (&Client{PollTimeout: time.Second}).pollTimeout(); got != time.Second {
		t.Fatalf("custom poll timeout got %v", got)
	}
}

func TestStackAndNonceHelpers(t *testing.T) {
	var s stack
	s.push("")
	if got := s.pop(); got != "" {
		t.Fatalf("empty push popped %q", got)
	}
	for i := 0; i < 70; i++ {
		s.push("nonce-" + strconvI(i))
	}
	if got := s.pop(); got != "nonce-63" {
		t.Fatalf("stack cap/pop got %q, want nonce-63", got)
	}
	s.push("last")
	if got := s.pop(); got != "last" {
		t.Fatalf("stack LIFO got %q, want last", got)
	}

	client := &Client{nonces: &stack{}}
	client.nonces.push("cached-nonce")
	if got, err := client.nonce(context.Background()); err != nil || got != "cached-nonce" {
		t.Fatalf("cached nonce got %q/%v", got, err)
	}
	if _, err := (&Client{nonces: &stack{}}).nonce(context.Background()); err == nil {
		t.Fatal("nonce without directory endpoint succeeded")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Fatalf("nonce request method got %s", r.Method)
		}
		w.Header().Set(replayNonce, "fresh-nonce")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client = &Client{dir: Directory{NewNonce: server.URL}, nonces: &stack{}}
	if got, err := client.nonce(context.Background()); err != nil || got != "fresh-nonce" {
		t.Fatalf("server nonce got %q/%v", got, err)
	}
}

func TestGetDirectoryProvision(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dir" {
			t.Fatalf("directory path got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Directory{
			NewNonce:   "https://ca.example/new-nonce",
			NewAccount: "https://ca.example/new-account",
			NewOrder:   "https://ca.example/new-order",
			RevokeCert: "https://ca.example/revoke",
			KeyChange:  "https://ca.example/key-change",
		})
	}))
	defer server.Close()
	client := &Client{Directory: server.URL + "/dir"}
	dir, err := client.GetDirectory(context.Background())
	if err != nil {
		t.Fatalf("GetDirectory: %v", err)
	}
	if dir.NewNonce != "https://ca.example/new-nonce" || dir.NewOrder != "https://ca.example/new-order" {
		t.Fatalf("directory got %#v", dir)
	}
	if _, err := (&Client{}).GetDirectory(context.Background()); err == nil {
		t.Fatal("GetDirectory without directory URL succeeded")
	}
}

func TestOrderHelpers(t *testing.T) {
	order := Order{Identifiers: []Identifier{{Type: "dns", Value: "example.com"}, {Type: "ip", Value: "192.0.2.1"}}}
	if got := order.identifierValues(); len(got) != 2 || got[0] != "example.com" || got[1] != "192.0.2.1" {
		t.Fatalf("identifierValues got %v", got)
	}

	for _, tc := range []struct {
		status   string
		finished bool
		wantErr  string
	}{
		{status: StatusInvalid, finished: true, wantErr: "final order is invalid"},
		{status: StatusPending, finished: true, wantErr: "order pending"},
		{status: StatusReady, finished: true, wantErr: "unexpected state"},
		{status: StatusProcessing, finished: false},
		{status: StatusValid, finished: true},
		{status: "mystery", finished: true, wantErr: "unrecognized order status"},
	} {
		t.Run(tc.status, func(t *testing.T) {
			finished, err := orderIsFinished(Order{
				Status:         tc.status,
				Error:          &Problem{Detail: "order failed"},
				Authorizations: []string{"https://ca.example/authz/1"},
			})
			if finished != tc.finished {
				t.Fatalf("finished got %v, want %v", finished, tc.finished)
			}
			if tc.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("error got %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestNewOrderProfileValidation(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{dir: Directory{NewNonce: "cached", NewOrder: "https://ca.example/new-order"}}
	_, err = client.NewOrder(context.Background(), Account{PrivateKey: key, Location: "https://ca.example/acct/1"}, Order{Profile: "short-lived"})
	if err == nil || !strings.Contains(err.Error(), "does not advertise support for profiles") {
		t.Fatalf("NewOrder without profile metadata error got %v", err)
	}
	client.dir.Meta = &DirectoryMeta{Profiles: map[string]string{"classic": "default"}}
	_, err = client.NewOrder(context.Background(), Account{PrivateKey: key, Location: "https://ca.example/acct/1"}, Order{Profile: "short-lived"})
	if err == nil || !strings.Contains(err.Error(), "unknown profile name") {
		t.Fatalf("NewOrder unknown profile error got %v", err)
	}
}

func TestTLSALPN01ChallengeCert(t *testing.T) {
	chal := Challenge{
		Identifier:       Identifier{Type: "dns", Value: "example.com"},
		KeyAuthorization: "token.thumbprint",
	}
	cert, err := TLSALPN01ChallengeCert(chal)
	if err != nil {
		t.Fatalf("TLSALPN01ChallengeCert DNS: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("challenge cert has no certificate DER")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse challenge cert: %v", err)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "example.com" {
		t.Fatalf("DNS SANs got %v", leaf.DNSNames)
	}
	assertACMETLSALPNExtension(t, leaf, chal.KeyAuthorization)

	ipCert, err := TLSALPN01ChallengeCert(Challenge{
		Identifier:       Identifier{Type: "ip", Value: "192.0.2.10"},
		KeyAuthorization: "token.thumbprint",
	})
	if err != nil {
		t.Fatalf("TLSALPN01ChallengeCert IP: %v", err)
	}
	ipLeaf, err := x509.ParseCertificate(ipCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse IP challenge cert: %v", err)
	}
	if len(ipLeaf.IPAddresses) != 1 || ipLeaf.IPAddresses[0].String() != "192.0.2.10" {
		t.Fatalf("IP SANs got %v", ipLeaf.IPAddresses)
	}
	if _, err := TLSALPN01ChallengeCert(Challenge{Identifier: Identifier{Type: "ip", Value: "not-an-ip"}}); err == nil {
		t.Fatal("TLSALPN01ChallengeCert accepted malformed IP")
	}
	if _, err := TLSALPN01ChallengeCert(Challenge{Identifier: Identifier{Type: "email", Value: "admin@example.com"}}); err == nil {
		t.Fatal("TLSALPN01ChallengeCert accepted unsupported identifier")
	}
}

type jwsJSON struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func parseJWS(t *testing.T, raw []byte) jwsJSON {
	t.Helper()
	var parsed jwsJSON
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal JWS: %v", err)
	}
	if parsed.Protected == "" || parsed.Signature == "" {
		t.Fatalf("JWS missing protected header or signature: %#v", parsed)
	}
	return parsed
}

func assertJWSRequest(t *testing.T, r *http.Request) {
	t.Helper()
	if got := r.Header.Get("Content-Type"); got != "application/jose+json" {
		t.Fatalf("Content-Type got %q", got)
	}
	var parsed jwsJSON
	if err := json.NewDecoder(r.Body).Decode(&parsed); err != nil {
		t.Fatalf("decode request JWS: %v", err)
	}
	if parsed.Protected == "" || parsed.Signature == "" {
		t.Fatalf("request JWS missing protected header or signature: %#v", parsed)
	}
}

func decodeJSONPart(t *testing.T, encoded string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode base64url JSON part: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal JSON part: %v", err)
	}
	return out
}

func decodeStringPart(t *testing.T, encoded string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode base64url string part: %v", err)
	}
	return string(raw)
}

func assertACMETLSALPNExtension(t *testing.T, cert *x509.Certificate, keyAuth string) {
	t.Helper()
	var found bool
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(idPEACMEIdentifierV1) {
			continue
		}
		found = true
		if !ext.Critical {
			t.Fatal("ACME TLS-ALPN extension is not critical")
		}
		var got []byte
		if _, err := asn1.Unmarshal(ext.Value, &got); err != nil {
			t.Fatalf("unmarshal ACME TLS-ALPN extension: %v", err)
		}
		want := sha256.Sum256([]byte(keyAuth))
		if string(got) != string(want[:]) {
			t.Fatalf("ACME TLS-ALPN digest got %x, want %x", got, want)
		}
	}
	if !found {
		t.Fatal("ACME TLS-ALPN extension not found")
	}
}

func strconvI(i int) string {
	return new(big.Int).SetInt64(int64(i)).String()
}

type unsupportedSigner struct{}

func (unsupportedSigner) Public() crypto.PublicKey {
	return struct{}{}
}

func (unsupportedSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errUnsupportedKey
}
