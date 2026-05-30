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
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestHTTP01StandalonePresent(t *testing.T) {
	h := &HTTP01Standalone{Listen: "127.0.0.1:0"}
	ln, err := net.Listen("tcp", h.Listen)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	h.Listen = ln.Addr().String()
	ln.Close()

	if err := h.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = h.Shutdown(ctx)
	})

	cleanup, err := h.Present("tok123", "key.auth")
	if err != nil {
		t.Fatalf("Present: %v", err)
	}

	resp := getOnce(t, "http://"+h.Listen+"/.well-known/acme-challenge/tok123")
	if resp != "key.auth" {
		t.Errorf("body: got %q, want %q", resp, "key.auth")
	}

	cleanup()
	code := getOnceStatus(t, "http://"+h.Listen+"/.well-known/acme-challenge/tok123")
	if code != http.StatusNotFound {
		t.Errorf("after cleanup: got status %d, want 404", code)
	}
}

func TestHTTP01StandaloneMultipleTokens(t *testing.T) {
	h := &HTTP01Standalone{Listen: "127.0.0.1:0"}
	ln, err := net.Listen("tcp", h.Listen)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	h.Listen = ln.Addr().String()
	ln.Close()

	if err := h.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = h.Shutdown(ctx)
	})

	if _, err := h.Present("a", "alpha"); err != nil {
		t.Fatalf("Present a: %v", err)
	}
	if _, err := h.Present("b", "beta"); err != nil {
		t.Fatalf("Present b: %v", err)
	}

	if got := getOnce(t, "http://"+h.Listen+"/.well-known/acme-challenge/a"); got != "alpha" {
		t.Errorf("a: got %q, want %q", got, "alpha")
	}
	if got := getOnce(t, "http://"+h.Listen+"/.well-known/acme-challenge/b"); got != "beta" {
		t.Errorf("b: got %q, want %q", got, "beta")
	}
}

func getOnce(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func getOnceStatus(t *testing.T, url string) int {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	resp.Body.Close()
	return resp.StatusCode
}
