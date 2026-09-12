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
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"foundry.fsky.io/fsky/gibcert/internal/config"
)

// reservePort binds an ephemeral port on loopback, closes it, and returns the
// address. There is a tiny race window before the standalone listener rebinds,
// but it is good enough for integration tests where the OS assigns the port.
func reservePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close reserve: %v", err)
	}
	return addr
}

func TestPebbleHTTP01StandaloneIssue(t *testing.T) {
	directoryURL := pebbleDirectoryURL(t)
	store := newPebbleStore(t)
	client := newPebbleClient(t, directoryURL)

	cert := &config.Certificate{
		Name:    "http-standalone-pebble",
		Account: "pebble",
		Names:   []string{"http-standalone.pebble.invalid"},
		Key:     config.KeySpec{Type: "ecdsa", Curve: "p256"},
		Challenge: config.ChallengeSpec{
			Type:   "http-01",
			Listen: reservePort(t),
		},
	}
	cfg := &config.Config{Certificates: []*config.Certificate{cert}}

	var out bytes.Buffer
	if err := Issue(context.Background(), client, cert, store, cfg, IssueOptions{Out: &out}); err != nil {
		t.Fatalf("Issue: %v\noutput:\n%s", err, out.String())
	}
	assertPebbleLeaf(t, store, cert, "http-standalone.pebble.invalid")

	// Listener should have been torn down after issuance.
	if _, err := net.DialTimeout("tcp", cert.Challenge.Listen, 100*time.Millisecond); err == nil {
		t.Errorf("standalone listener %q still accepting after Issue", cert.Challenge.Listen)
	}
}

func TestPebbleHTTP01StandaloneMultiSAN(t *testing.T) {
	directoryURL := pebbleDirectoryURL(t)
	store := newPebbleStore(t)
	client := newPebbleClient(t, directoryURL)

	cert := &config.Certificate{
		Name:    "http-standalone-multi-pebble",
		Account: "pebble",
		Names: []string{
			"a.http-standalone-multi.pebble.invalid",
			"b.http-standalone-multi.pebble.invalid",
			"c.http-standalone-multi.pebble.invalid",
		},
		Key: config.KeySpec{Type: "ecdsa", Curve: "p256"},
		Challenge: config.ChallengeSpec{
			Type:   "http-01",
			Listen: reservePort(t),
		},
	}
	cfg := &config.Config{Certificates: []*config.Certificate{cert}}

	var out bytes.Buffer
	if err := Issue(context.Background(), client, cert, store, cfg, IssueOptions{Out: &out}); err != nil {
		t.Fatalf("Issue: %v\noutput:\n%s", err, out.String())
	}
	for _, n := range cert.Names {
		assertPebbleLeaf(t, store, cert, n)
	}
}

func TestPebbleTLSALPN01StandaloneIssue(t *testing.T) {
	directoryURL := pebbleDirectoryURL(t)
	store := newPebbleStore(t)
	client := newPebbleClient(t, directoryURL)

	cert := &config.Certificate{
		Name:    "tls-alpn-standalone-pebble",
		Account: "pebble",
		Names:   []string{"tls-alpn-standalone.pebble.invalid"},
		Key:     config.KeySpec{Type: "ecdsa", Curve: "p256"},
		Challenge: config.ChallengeSpec{
			Type:   "tls-alpn-01",
			Listen: reservePort(t),
		},
	}
	cfg := &config.Config{Certificates: []*config.Certificate{cert}}

	var out bytes.Buffer
	if err := Issue(context.Background(), client, cert, store, cfg, IssueOptions{Out: &out}); err != nil {
		t.Fatalf("Issue: %v\noutput:\n%s", err, out.String())
	}
	assertPebbleLeaf(t, store, cert, "tls-alpn-standalone.pebble.invalid")

	if _, err := net.DialTimeout("tcp", cert.Challenge.Listen, 100*time.Millisecond); err == nil {
		t.Errorf("tls-alpn-01 listener %q still accepting after Issue", cert.Challenge.Listen)
	}
}

func TestPebbleTLSALPN01StandaloneMultiSAN(t *testing.T) {
	directoryURL := pebbleDirectoryURL(t)
	store := newPebbleStore(t)
	client := newPebbleClient(t, directoryURL)

	cert := &config.Certificate{
		Name:    "tls-alpn-multi-pebble",
		Account: "pebble",
		Names: []string{
			"a.tls-alpn-multi.pebble.invalid",
			"b.tls-alpn-multi.pebble.invalid",
		},
		Key: config.KeySpec{Type: "ecdsa", Curve: "p256"},
		Challenge: config.ChallengeSpec{
			Type:   "tls-alpn-01",
			Listen: reservePort(t),
		},
	}
	cfg := &config.Config{Certificates: []*config.Certificate{cert}}

	var out bytes.Buffer
	if err := Issue(context.Background(), client, cert, store, cfg, IssueOptions{Out: &out}); err != nil {
		t.Fatalf("Issue: %v\noutput:\n%s", err, out.String())
	}
	for _, n := range cert.Names {
		assertPebbleLeaf(t, store, cert, n)
	}
}

func TestPebbleDNS01AliasDomainRewritesFQDN(t *testing.T) {
	directoryURL := pebbleDirectoryURL(t)
	store := newPebbleStore(t)
	client := newPebbleClient(t, directoryURL)

	provider, logPath := newPebbleGibDNSProvider(t)
	timeout := time.Duration(0)
	cert := &config.Certificate{
		Name:    "dns-alias-pebble",
		Account: "pebble",
		Names:   []string{"alias.pebble.invalid"},
		Key:     config.KeySpec{Type: "ecdsa", Curve: "p256"},
		Challenge: config.ChallengeSpec{
			Type:               "dns-01",
			Provider:           provider.Name,
			AliasDomain:        "acme-alias.test",
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
	assertPebbleLeaf(t, store, cert, "alias.pebble.invalid")

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(raw)
	wantFQDN := "_acme-challenge.alias.pebble.invalid.acme-alias.test."
	if !strings.Contains(log, "present "+wantFQDN) {
		t.Fatalf("dns provider log missing present at alias FQDN %q:\n%s", wantFQDN, log)
	}
	if !strings.Contains(log, "cleanup "+wantFQDN) {
		t.Fatalf("dns provider log missing cleanup at alias FQDN %q:\n%s", wantFQDN, log)
	}
}

func TestPebbleDNS01AliasFQDNRewritesFQDN(t *testing.T) {
	directoryURL := pebbleDirectoryURL(t)
	store := newPebbleStore(t)
	client := newPebbleClient(t, directoryURL)

	provider, logPath := newPebbleGibDNSProvider(t)
	timeout := time.Duration(0)
	cert := &config.Certificate{
		Name:    "dns-alias-fqdn-pebble",
		Account: "pebble",
		Names:   []string{"aliased.pebble.invalid"},
		Key:     config.KeySpec{Type: "ecdsa", Curve: "p256"},
		Challenge: config.ChallengeSpec{
			Type:               "dns-01",
			Provider:           provider.Name,
			AliasFQDN:          "shared-record.acme-alias.test",
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
	assertPebbleLeaf(t, store, cert, "aliased.pebble.invalid")

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(raw)
	wantFQDN := "shared-record.acme-alias.test."
	if !strings.Contains(log, "present "+wantFQDN) {
		t.Fatalf("dns provider log missing present at alias FQDN %q:\n%s", wantFQDN, log)
	}
}
