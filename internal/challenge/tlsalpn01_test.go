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

package challenge

import (
	"crypto/tls"
	"net"
	"testing"

	"foundry.fsky.io/fsky/gibcert/internal/acme"
)

func TestTLSALPN01StandaloneHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	s := &TLSALPN01Standalone{Listen: addr}
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = s.Shutdown() })

	chal := acme.Challenge{
		Type:             acme.ChallengeTypeTLSALPN01,
		Token:            "token-xyz",
		KeyAuthorization: "token-xyz.thumbprint",
		Identifier:       acme.Identifier{Type: "dns", Value: "example.test"},
	}
	cert, err := acme.TLSALPN01ChallengeCert(chal)
	if err != nil {
		t.Fatalf("TLSALPN01ChallengeCert: %v", err)
	}
	if _, err := s.Present("example.test", *cert); err != nil {
		t.Fatalf("Present: %v", err)
	}

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName:         "example.test",
		NextProtos:         []string{"acme-tls/1"},
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	state := conn.ConnectionState()
	conn.Close()

	if state.NegotiatedProtocol != "acme-tls/1" {
		t.Errorf("ALPN: got %q, want acme-tls/1", state.NegotiatedProtocol)
	}
	if len(state.PeerCertificates) == 0 {
		t.Fatal("no peer certificate")
	}
}

func TestTLSALPN01StandaloneIPNoSNI(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	s := &TLSALPN01Standalone{Listen: addr}
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = s.Shutdown() })

	chal := acme.Challenge{
		Type:             acme.ChallengeTypeTLSALPN01,
		Token:            "token-xyz",
		KeyAuthorization: "token-xyz.thumbprint",
		Identifier:       acme.Identifier{Type: "ip", Value: "127.0.0.1"},
	}
	cert, err := acme.TLSALPN01ChallengeCert(chal)
	if err != nil {
		t.Fatalf("TLSALPN01ChallengeCert: %v", err)
	}
	if _, err := s.Present("127.0.0.1", *cert); err != nil {
		t.Fatalf("Present: %v", err)
	}

	// IP validation sends no SNI; the server must match on the connected-to
	// address instead.
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		NextProtos:         []string{"acme-tls/1"},
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	state := conn.ConnectionState()
	conn.Close()

	if state.NegotiatedProtocol != "acme-tls/1" {
		t.Errorf("ALPN: got %q, want acme-tls/1", state.NegotiatedProtocol)
	}
	if len(state.PeerCertificates) == 0 {
		t.Fatal("no peer certificate")
	}
}

func TestTLSALPN01StandaloneRejectsNonACME(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	s := &TLSALPN01Standalone{Listen: addr}
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = s.Shutdown() })

	// Client without acme-tls/1 ALPN: handshake should fail.
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName:         "example.test",
		InsecureSkipVerify: true,
	})
	if err == nil {
		conn.Close()
		t.Fatal("handshake unexpectedly succeeded without ALPN")
	}
}
