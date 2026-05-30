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
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type HTTP01Webroot struct {
	Webroot string
}

func (h *HTTP01Webroot) Present(token, keyAuth string) (cleanup func(), err error) {
	dir := filepath.Join(h.Webroot, ".well-known", "acme-challenge")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create %s: %w", dir, err)
	}
	path := filepath.Join(dir, token)
	if err := os.WriteFile(path, []byte(keyAuth), 0o644); err != nil {
		return nil, fmt.Errorf("write %s: %w", path, err)
	}
	return func() { _ = os.Remove(path) }, nil
}

// HTTP01Standalone serves http-01 challenge responses from a built-in HTTP
// listener. It is reused across all authorizations in a single issuance: call
// Start once before the authz loop, Present per token, and Shutdown at the end.
type HTTP01Standalone struct {
	Listen string

	mu     sync.Mutex
	tokens map[string]string
	srv    *http.Server
}

func (h *HTTP01Standalone) Start() error {
	addr := h.Listen
	if addr == "" {
		addr = ":80"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	h.tokens = map[string]string{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/acme-challenge/", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
		h.mu.Lock()
		keyAuth, ok := h.tokens[token]
		h.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte(keyAuth))
	})
	h.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = h.srv.Serve(ln) }()
	return nil
}

func (h *HTTP01Standalone) Present(token, keyAuth string) (cleanup func(), err error) {
	if h.srv == nil {
		return nil, fmt.Errorf("HTTP01Standalone.Start was not called")
	}
	h.mu.Lock()
	h.tokens[token] = keyAuth
	h.mu.Unlock()
	return func() {
		h.mu.Lock()
		delete(h.tokens, token)
		h.mu.Unlock()
	}, nil
}

func (h *HTTP01Standalone) Shutdown(ctx context.Context) error {
	if h.srv == nil {
		return nil
	}
	return h.srv.Shutdown(ctx)
}
