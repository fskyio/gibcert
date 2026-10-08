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
	"bytes"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	"gitfield.org/fsky/gibcert/internal/acme"
)

func TestTLSALPN01StandaloneHandshake(t *testing.T) {
	s := &TLSALPN01Standalone{Listen: "127.0.0.1:0"}
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = s.Shutdown() })
	addr := s.ln.Addr().String()

	certs := map[string]*tls.Certificate{}
	for _, name := range []string{"example.test", "other.test"} {
		cert := tlsALPNTestCertificate(t, "dns", name)
		certs[name] = cert
		if _, err := s.Present(name, *cert); err != nil {
			t.Fatalf("Present: %v", err)
		}
	}
	for _, name := range []string{"example.test", "other.test", "EXAMPLE.TEST"} {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, &tls.Config{
			ServerName:         name,
			NextProtos:         []string{"acme-tls/1"},
			InsecureSkipVerify: true,
		})
		if err != nil {
			t.Fatalf("dial %s: %v", name, err)
		}
		state := conn.ConnectionState()
		_ = conn.Close()
		want := certs[name]
		if name == "EXAMPLE.TEST" {
			want = certs["example.test"]
		}
		assertTLSALPNCertificate(t, state, want)
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

	assertTLSALPNCertificate(t, state, cert)
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

func TestTLSALPN01StandaloneIdleExpiry(t *testing.T) {
	s, accepted := startObservedTLSALPN(t, 100*time.Millisecond, 1)
	client, server := dialObservedTLSALPN(t, s, accepted)
	awaitTLSALPNDeadline(t, server)

	// A TCP dial succeeding is not proof that the handshake worker admitted
	// the connection. The server-side deadline notification above is.
	assertTLSALPNTransportClosed(t, client)
	awaitTLSALPNCapacity(t, s)
}

func TestTLSALPN01StandaloneHandshakeCapacity(t *testing.T) {
	s, accepted := startObservedTLSALPN(t, time.Hour, 0)
	cert := tlsALPNTestCertificate(t, "dns", "example.test")
	if _, err := s.Present("example.test", *cert); err != nil {
		t.Fatalf("Present: %v", err)
	}
	var clients []net.Conn
	for range 64 {
		client, server := dialObservedTLSALPN(t, s, accepted)
		awaitTLSALPNDeadline(t, server)
		clients = append(clients, client)
	}
	excess, _ := dialObservedTLSALPN(t, s, accepted)
	assertTLSALPNTransportClosed(t, excess)

	for _, client := range clients {
		_ = client.Close()
	}
	awaitTLSALPNCapacity(t, s)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", s.ln.Addr().String(), &tls.Config{
		ServerName:         "example.test",
		NextProtos:         []string{"acme-tls/1"},
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("handshake after capacity released: %v", err)
	}
	defer conn.Close()
	assertTLSALPNCertificate(t, conn.ConnectionState(), cert)
}

func TestTLSALPN01StandaloneShutdownDrainsTransports(t *testing.T) {
	s, accepted := startObservedTLSALPN(t, time.Hour, 2)
	var clients []net.Conn
	for range 2 {
		client, server := dialObservedTLSALPN(t, s, accepted)
		awaitTLSALPNDeadline(t, server)
		clients = append(clients, client)
	}
	shutdown := make(chan error, 1)
	go func() { shutdown <- s.Shutdown() }()
	select {
	case err := <-shutdown:
		if err != nil {
			t.Fatalf("Shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Shutdown waited for the handshake deadline")
	}
	for _, client := range clients {
		assertTLSALPNTransportClosed(t, client)
	}
	s.mu.Lock()
	active := len(s.conns)
	s.mu.Unlock()
	if active != 0 {
		t.Fatalf("Shutdown returned with %d active transports", active)
	}
}

func TestTLSALPN01StandaloneShutdownDuringAdmission(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gated := &gatedTLSALPNListener{
		Listener: ln,
		accepted: make(chan struct{}),
		release:  make(chan struct{}),
		closed:   make(chan struct{}),
	}
	s := &TLSALPN01Standalone{handshakeTimeout: time.Hour}
	s.start(gated)
	var release sync.Once
	unblock := func() { release.Do(func() { close(gated.release) }) }
	t.Cleanup(func() {
		unblock()
		_ = s.Shutdown()
	})
	client, err := net.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	select {
	case <-gated.accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("listener did not accept transport")
	}
	shutdown := make(chan error, 1)
	go func() { shutdown <- s.Shutdown() }()
	select {
	case <-gated.closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Shutdown did not close listener")
	}
	// Release a successful Accept only after the listener is closed. Shutdown
	// must include this last transport and its worker rather than racing Add.
	unblock()
	select {
	case err := <-shutdown:
		if err != nil {
			t.Fatalf("Shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Shutdown did not drain the last admitted transport")
	}
	assertTLSALPNTransportClosed(t, client)
}

func tlsALPNTestCertificate(t *testing.T, idType, name string) *tls.Certificate {
	t.Helper()
	cert, err := acme.TLSALPN01ChallengeCert(acme.Challenge{
		Type:             acme.ChallengeTypeTLSALPN01,
		Token:            "token-" + name,
		KeyAuthorization: "token-" + name + ".thumbprint",
		Identifier:       acme.Identifier{Type: idType, Value: name},
	})
	if err != nil {
		t.Fatalf("TLSALPN01ChallengeCert: %v", err)
	}
	return cert
}

func assertTLSALPNCertificate(t *testing.T, state tls.ConnectionState, cert *tls.Certificate) {
	t.Helper()
	if state.NegotiatedProtocol != "acme-tls/1" {
		t.Errorf("ALPN: got %q, want acme-tls/1", state.NegotiatedProtocol)
	}
	if len(state.PeerCertificates) != 1 || !bytes.Equal(state.PeerCertificates[0].Raw, cert.Certificate[0]) {
		t.Fatal("handshake did not serve the registered challenge certificate")
	}
}

type observedTLSALPNListener struct {
	net.Listener
	accepted chan *observedTLSALPNConn
}

func (ln *observedTLSALPNListener) Accept() (net.Conn, error) {
	conn, err := ln.Listener.Accept()
	if err != nil {
		return nil, err
	}
	observed := &observedTLSALPNConn{Conn: conn, deadline: make(chan time.Time, 1)}
	ln.accepted <- observed
	return observed, nil
}

type observedTLSALPNConn struct {
	net.Conn
	deadline chan time.Time
}

func (conn *observedTLSALPNConn) SetDeadline(deadline time.Time) error {
	err := conn.Conn.SetDeadline(deadline)
	conn.deadline <- deadline
	return err
}

func startObservedTLSALPN(t *testing.T, timeout time.Duration, limit int) (*TLSALPN01Standalone, <-chan *observedTLSALPNConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	observed := &observedTLSALPNListener{Listener: ln, accepted: make(chan *observedTLSALPNConn, 1)}
	s := &TLSALPN01Standalone{handshakeTimeout: timeout, maxHandshakes: limit}
	s.start(observed)
	t.Cleanup(func() { _ = s.Shutdown() })
	return s, observed.accepted
}

func dialObservedTLSALPN(t *testing.T, s *TLSALPN01Standalone, accepted <-chan *observedTLSALPNConn) (net.Conn, *observedTLSALPNConn) {
	t.Helper()
	client, err := net.DialTimeout("tcp", s.ln.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	select {
	case server := <-accepted:
		return client, server
	case <-time.After(3 * time.Second):
		t.Fatal("listener did not accept transport")
		return nil, nil
	}
}

func awaitTLSALPNDeadline(t *testing.T, conn *observedTLSALPNConn) {
	t.Helper()
	select {
	case <-conn.deadline:
	case <-time.After(3 * time.Second):
		t.Fatal("transport was not admitted")
	}
}

func assertTLSALPNTransportClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	var buf [1]byte
	n, err := conn.Read(buf[:])
	if err == nil || n != 0 {
		t.Fatalf("transport is still open: read %d bytes, error %v", n, err)
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatalf("client read timed out instead of observing server closure: %v", err)
	}
}

func awaitTLSALPNCapacity(t *testing.T, s *TLSALPN01Standalone) {
	t.Helper()
	timeout := time.NewTimer(3 * time.Second)
	defer timeout.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		s.mu.Lock()
		active := len(s.conns)
		s.mu.Unlock()
		if active == 0 {
			return
		}
		select {
		case <-timeout.C:
			t.Fatal("handshake transports did not release capacity")
		case <-tick.C:
		}
	}
}

type gatedTLSALPNListener struct {
	net.Listener
	accepted chan struct{}
	release  chan struct{}
	closed   chan struct{}
	once     sync.Once
}

func (ln *gatedTLSALPNListener) Accept() (net.Conn, error) {
	conn, err := ln.Listener.Accept()
	if err != nil {
		return nil, err
	}
	close(ln.accepted)
	<-ln.release
	return conn, nil
}

func (ln *gatedTLSALPNListener) Close() error {
	err := ln.Listener.Close()
	ln.once.Do(func() { close(ln.closed) })
	return err
}
