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
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	tlsALPNHandshakeTimeout = 10 * time.Second
	tlsALPNMaxHandshakes    = 64
)

// TLSALPN01Standalone serves tls-alpn-01 challenge responses on a TLS listener.
// Each Present registers a per-SNI challenge certificate; the handshake itself
// satisfies the challenge.
type TLSALPN01Standalone struct {
	Listen string

	mu      sync.Mutex
	certs   map[string]*tls.Certificate
	ln      net.Listener
	done    chan struct{}
	conns   map[net.Conn]struct{}
	workers sync.WaitGroup

	handshakeTimeout time.Duration
	maxHandshakes    int
}

func (t *TLSALPN01Standalone) Start() error {
	addr := t.Listen
	if addr == "" {
		addr = ":443"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	t.start(ln)
	return nil
}

func (t *TLSALPN01Standalone) start(ln net.Listener) {
	timeout := t.handshakeTimeout
	if timeout <= 0 {
		timeout = tlsALPNHandshakeTimeout
	}
	limit := t.maxHandshakes
	if limit <= 0 {
		limit = tlsALPNMaxHandshakes
	}
	t.certs = map[string]*tls.Certificate{}
	t.conns = map[net.Conn]struct{}{}
	t.done = make(chan struct{})
	t.ln = ln
	tlsConfig := &tls.Config{
		NextProtos:     []string{"acme-tls/1"},
		GetCertificate: t.getCertificate,
	}
	go t.serve(ln, tlsConfig, timeout, limit)
}

func (t *TLSALPN01Standalone) serve(ln net.Listener, tlsConfig *tls.Config, timeout time.Duration, limit int) {
	defer close(t.done)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		t.mu.Lock()
		if len(t.conns) >= limit {
			t.mu.Unlock()
			_ = conn.Close()
			continue
		}
		t.conns[conn] = struct{}{}
		t.workers.Add(1)
		t.mu.Unlock()

		// The deadline is absolute for both directions, including clients
		// that keep sending partial handshake records.
		err = conn.SetDeadline(time.Now().Add(timeout))
		if err != nil {
			t.finish(conn)
			continue
		}
		go func() {
			defer t.finish(conn)
			_ = tls.Server(conn, tlsConfig).Handshake()
		}()
	}
}

func (t *TLSALPN01Standalone) finish(conn net.Conn) {
	// Close the transport directly: TLS close_notify must not delay cleanup.
	_ = conn.Close()
	t.mu.Lock()
	delete(t.conns, conn)
	t.mu.Unlock()
	t.workers.Done()
}

func (t *TLSALPN01Standalone) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	negotiated := false
	for _, p := range hello.SupportedProtos {
		if p == "acme-tls/1" {
			negotiated = true
			break
		}
	}
	if !negotiated {
		return nil, fmt.Errorf("client did not request acme-tls/1 ALPN")
	}
	key := challengeKey(hello.ServerName)
	if key == "" && hello.Conn != nil {
		// IP identifiers (RFC 8738) are validated without SNI, since RFC 6066
		// forbids IP literals in the SNI extension. Fall back to the address
		// the client connected to.
		if host, _, err := net.SplitHostPort(hello.Conn.LocalAddr().String()); err == nil {
			key = challengeKey(host)
		}
	}
	t.mu.Lock()
	cert, ok := t.certs[key]
	t.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("no tls-alpn-01 challenge for %q", key)
	}
	return cert, nil
}

// challengeKey normalizes an identifier value for use as a certificate map
// key. IP addresses are canonicalized so a lookup matches regardless of the
// textual form the CA used in the order.
func challengeKey(name string) string {
	if ip := net.ParseIP(name); ip != nil {
		return ip.String()
	}
	return strings.ToLower(name)
}

func (t *TLSALPN01Standalone) Present(domain string, cert tls.Certificate) (func(), error) {
	if t.ln == nil {
		return nil, fmt.Errorf("TLSALPN01Standalone.Start was not called")
	}
	key := challengeKey(domain)
	t.mu.Lock()
	t.certs[key] = &cert
	t.mu.Unlock()
	return func() {
		t.mu.Lock()
		delete(t.certs, key)
		t.mu.Unlock()
	}, nil
}

func (t *TLSALPN01Standalone) Shutdown() error {
	if t.ln == nil {
		return nil
	}
	err := t.ln.Close()
	<-t.done
	// The accept loop is finished, so it can no longer register a socket
	// or call Add while Shutdown waits for workers.
	t.mu.Lock()
	for conn := range t.conns {
		_ = conn.Close()
	}
	t.mu.Unlock()
	t.workers.Wait()
	return err
}
