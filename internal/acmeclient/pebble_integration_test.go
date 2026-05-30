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
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"foundry.fsky.io/fsky/gibcert/internal/acme"

	"foundry.fsky.io/fsky/gibcert/internal/config"
	"foundry.fsky.io/fsky/gibcert/internal/renew"
	"foundry.fsky.io/fsky/gibcert/internal/storage"
)

func TestPebbleHTTP01IssueHappyPath(t *testing.T) {
	directoryURL := pebbleDirectoryURL(t)
	store := newPebbleStore(t)
	client := newPebbleClient(t, directoryURL)
	cert := &config.Certificate{
		Name:    "http-pebble",
		Account: "pebble",
		Names:   []string{"http.pebble.invalid"},
		Key:     config.KeySpec{Type: "ecdsa", Curve: "p256"},
		Challenge: config.ChallengeSpec{
			Type:    "http-01",
			Webroot: t.TempDir(),
		},
	}
	cfg := &config.Config{Certificates: []*config.Certificate{cert}}

	var out bytes.Buffer
	if err := Issue(context.Background(), client, cert, store, cfg, IssueOptions{Out: &out}); err != nil {
		t.Fatalf("Issue: %v\noutput:\n%s", err, out.String())
	}
	assertPebbleLeaf(t, store, cert, "http.pebble.invalid")
}

func TestPebbleDNS01IssueHappyPath(t *testing.T) {
	directoryURL := pebbleDirectoryURL(t)
	store := newPebbleStore(t)
	client := newPebbleClient(t, directoryURL)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "dns.log")
	script := filepath.Join(dir, "dns-provider.sh")
	body := `#!/bin/sh
echo "$DNSREC_OPERATION $DNSREC_RECORD_OWNER $DNSREC_RECORD_RDATA" >> "$LOG"
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LOG", logPath)
	timeout := time.Duration(0)
	provider := &config.Provider{
		Name:   "exec",
		Type:   "dns",
		Driver: "exec",
		Fields: map[string][]string{"command": {script}},
	}
	cert := &config.Certificate{
		Name:    "dns-pebble",
		Account: "pebble",
		Names:   []string{"dns.pebble.invalid", "*.dns.pebble.invalid"},
		Key:     config.KeySpec{Type: "ecdsa", Curve: "p256"},
		Challenge: config.ChallengeSpec{
			Type:               "dns-01",
			Provider:           provider.Name,
			PropagationTimeout: &timeout,
		},
	}
	cfg := &config.Config{
		Providers:    []*config.Provider{provider},
		Certificates: []*config.Certificate{cert},
	}

	var out bytes.Buffer
	if err := Issue(context.Background(), client, cert, store, cfg, IssueOptions{Out: &out}); err != nil {
		t.Fatalf("Issue: %v\noutput:\n%s", err, out.String())
	}
	assertPebbleLeaf(t, store, cert, "dns.pebble.invalid")
	assertPebbleLeaf(t, store, cert, "*.dns.pebble.invalid")

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(raw)
	for _, want := range []string{"present _acme-challenge.dns.pebble.invalid.", "cleanup _acme-challenge.dns.pebble.invalid."} {
		if !strings.Contains(log, want) {
			t.Fatalf("dns provider log missing %q:\n%s", want, log)
		}
	}
}

func pebbleDirectoryURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("GIBCERT_PEBBLE_DIRECTORY_URL")
	if url == "" {
		t.Skip("set GIBCERT_PEBBLE_DIRECTORY_URL to run Pebble integration tests; Pebble should use always-valid validation")
	}
	return url
}

func pebbleEABDirectoryURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("GIBCERT_PEBBLE_EAB_DIRECTORY_URL")
	if url == "" {
		t.Skip("set GIBCERT_PEBBLE_EAB_DIRECTORY_URL to run Pebble EAB integration tests")
	}
	return url
}

func newPebbleStore(t *testing.T) *storage.Store {
	t.Helper()
	store := storage.New(filepath.Join(t.TempDir(), "state"))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	return store
}

func newPebbleHTTPClient() *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
	}}}
}

func newPebbleClient(t *testing.T, directoryURL string) *Client {
	t.Helper()
	key, err := storage.GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	client := &acme.Client{
		Directory:  directoryURL,
		UserAgent:  "gibcert-test",
		HTTPClient: newPebbleHTTPClient(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	account, err := client.NewAccount(ctx, acme.Account{
		Contact:              []string{"mailto:test@example.invalid"},
		TermsOfServiceAgreed: true,
		PrivateKey:           key,
	})
	if err != nil {
		t.Fatalf("register Pebble account: %v", err)
	}
	return &Client{acme: client, account: account}
}

func TestPebbleEABLoadOrRegister(t *testing.T) {
	directoryURL := pebbleEABDirectoryURL(t)
	store := newPebbleStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	opts := AccountOptions{
		Name:         "pebble-eab",
		DirectoryURL: directoryURL,
		Email:        "test@example.invalid",
		EAB: &EABOptions{
			KID:          "kid-1",
			HMACKeyValue: "abcdefghijklmnopqrstuvwxyz012345",
		},
		HTTPClient: newPebbleHTTPClient(),
	}
	if _, err := LoadOrRegister(ctx, store, opts); err != nil {
		t.Fatalf("LoadOrRegister with EAB: %v", err)
	}
	meta, err := store.LoadAccountMeta(opts.Name)
	if err != nil {
		t.Fatalf("LoadAccountMeta: %v", err)
	}
	if meta.URL == "" {
		t.Fatal("account metadata URL is empty")
	}

	// EAB is a registration-time credential. Once account metadata exists,
	// loading the account must not require the EAB key anymore.
	opts.EAB = nil
	if _, err := LoadOrRegister(ctx, store, opts); err != nil {
		t.Fatalf("LoadOrRegister existing account without EAB: %v", err)
	}
	if err := RotateAccountKey(ctx, store, opts.Name, opts.DirectoryURL, newPebbleHTTPClient(), io.Discard); err != nil {
		t.Fatalf("RotateAccountKey: %v", err)
	}
}

func TestPebbleEABRequiredRejectsMissingBinding(t *testing.T) {
	directoryURL := pebbleEABDirectoryURL(t)
	store := newPebbleStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := LoadOrRegister(ctx, store, AccountOptions{
		Name:         "pebble-eab-missing",
		DirectoryURL: directoryURL,
		Email:        "test@example.invalid",
		HTTPClient:   newPebbleHTTPClient(),
	})
	if err == nil {
		t.Fatal("LoadOrRegister without EAB succeeded, want error")
	}
	if !strings.Contains(err.Error(), "externalAccountRequired") && !strings.Contains(err.Error(), "External Account Binding") {
		t.Fatalf("LoadOrRegister error = %v, want externalAccountRequired", err)
	}
}

func assertPebbleLeaf(t *testing.T, store *storage.Store, cert *config.Certificate, name string) {
	t.Helper()
	leaf, err := renew.LoadLeaf(cert, store)
	if err != nil {
		t.Fatal(err)
	}
	for _, dnsName := range leaf.DNSNames {
		if dnsName == name {
			return
		}
	}
	t.Fatalf("leaf DNS names got %v, want %q", leaf.DNSNames, name)
}
