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
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func noCNAME(ctx context.Context, nsAddr, fqdn string) (string, error) { return "", nil }

func TestDNSCheckerSkipsWhenTimeoutZero(t *testing.T) {
	c := &DNSChecker{
		lookupNS: func(ctx context.Context, domain string) ([]string, error) {
			t.Fatal("lookupNS should not be called when timeout is zero")
			return nil, nil
		},
	}
	if err := c.Wait(context.Background(), "_acme-challenge.example.com", "v", 0); err != nil {
		t.Fatalf("Wait: %v", err)
	}
}

func TestDNSCheckerFindsZoneByWalkingLabels(t *testing.T) {
	var queried []string
	c := &DNSChecker{
		Interval: time.Millisecond,
		lookupNS: func(ctx context.Context, domain string) ([]string, error) {
			queried = append(queried, domain)
			if domain == "example.com" {
				return []string{"ns1.example.com.", "ns2.example.com."}, nil
			}
			return nil, nil
		},
		lookupHost: func(ctx context.Context, host string) ([]string, error) {
			switch host {
			case "ns1.example.com":
				return []string{"192.0.2.1"}, nil
			case "ns2.example.com":
				return []string{"192.0.2.2"}, nil
			}
			return nil, errors.New("unknown")
		},
		lookupCNAMEAt: noCNAME,
		lookupTXTAt: func(ctx context.Context, nsAddr, fqdn string) ([]string, error) {
			return []string{"the-token"}, nil
		},
	}

	if err := c.Wait(context.Background(), "_acme-challenge.www.example.com", "the-token", 5*time.Second); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	want := []string{
		"_acme-challenge.www.example.com",
		"www.example.com",
		"example.com",
	}
	if strings.Join(queried, ",") != strings.Join(want, ",") {
		t.Fatalf("NS walk order: got %v, want %v", queried, want)
	}
}

func TestDNSCheckerWaitsUntilAllNSAgree(t *testing.T) {
	var mu sync.Mutex
	calls := map[string]int{}
	c := &DNSChecker{
		Interval: time.Millisecond,
		lookupNS: func(ctx context.Context, domain string) ([]string, error) {
			if domain == "example.com" {
				return []string{"ns1.example.com.", "ns2.example.com."}, nil
			}
			return nil, nil
		},
		lookupHost: func(ctx context.Context, host string) ([]string, error) {
			switch host {
			case "ns1.example.com":
				return []string{"192.0.2.1"}, nil
			case "ns2.example.com":
				return []string{"192.0.2.2"}, nil
			}
			return nil, errors.New("unknown")
		},
		lookupCNAMEAt: noCNAME,
		lookupTXTAt: func(ctx context.Context, nsAddr, fqdn string) ([]string, error) {
			mu.Lock()
			defer mu.Unlock()
			calls[nsAddr]++
			// ns2 lags: returns wrong value for the first two attempts, then the correct one.
			if strings.HasPrefix(nsAddr, "192.0.2.2") && calls[nsAddr] < 3 {
				return []string{"stale"}, nil
			}
			return []string{"the-token"}, nil
		},
	}

	if err := c.Wait(context.Background(), "_acme-challenge.example.com", "the-token", 5*time.Second); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls["192.0.2.2:53"] < 3 {
		t.Fatalf("expected ns2 to be polled at least 3 times, got %d", calls["192.0.2.2:53"])
	}
}

func TestDNSCheckerTimesOut(t *testing.T) {
	c := &DNSChecker{
		Interval: time.Millisecond,
		lookupNS: func(ctx context.Context, domain string) ([]string, error) {
			if domain == "example.com" {
				return []string{"ns1.example.com."}, nil
			}
			return nil, nil
		},
		lookupHost: func(ctx context.Context, host string) ([]string, error) {
			return []string{"192.0.2.1"}, nil
		},
		lookupCNAMEAt: noCNAME,
		lookupTXTAt: func(ctx context.Context, nsAddr, fqdn string) ([]string, error) {
			return []string{"wrong"}, nil
		},
	}
	err := c.Wait(context.Background(), "_acme-challenge.example.com", "the-token", 25*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "propagation timeout") {
		t.Fatalf("expected propagation timeout error, got %v", err)
	}
}

func TestDNSCheckerFollowsCNAMEDelegation(t *testing.T) {
	c := &DNSChecker{
		Interval: time.Millisecond,
		lookupNS: func(ctx context.Context, domain string) ([]string, error) {
			switch domain {
			case "example.com":
				return []string{"ns1.example.com."}, nil
			case "auth.acme-dns.io":
				return []string{"ns1.acme-dns.io."}, nil
			}
			return nil, nil
		},
		lookupHost: func(ctx context.Context, host string) ([]string, error) {
			switch host {
			case "ns1.example.com":
				return []string{"192.0.2.1"}, nil
			case "ns1.acme-dns.io":
				return []string{"192.0.2.99"}, nil
			}
			return nil, errors.New("unknown")
		},
		lookupCNAMEAt: func(ctx context.Context, nsAddr, fqdn string) (string, error) {
			if nsAddr == "192.0.2.1:53" && fqdn == "_acme-challenge.example.com" {
				return "xyz.auth.acme-dns.io", nil
			}
			return "", nil
		},
		lookupTXTAt: func(ctx context.Context, nsAddr, fqdn string) ([]string, error) {
			if nsAddr == "192.0.2.99:53" && fqdn == "xyz.auth.acme-dns.io" {
				return []string{"the-token"}, nil
			}
			t.Fatalf("unexpected TXT query: %s @ %s", fqdn, nsAddr)
			return nil, nil
		},
	}
	if err := c.Wait(context.Background(), "_acme-challenge.example.com", "the-token", 5*time.Second); err != nil {
		t.Fatalf("Wait: %v", err)
	}
}

func TestDNSCheckerCNAMELoopErrors(t *testing.T) {
	c := &DNSChecker{
		Interval: time.Millisecond,
		lookupNS: func(ctx context.Context, domain string) ([]string, error) {
			return []string{"ns.example.com."}, nil
		},
		lookupHost: func(ctx context.Context, host string) ([]string, error) {
			return []string{"192.0.2.1"}, nil
		},
		lookupCNAMEAt: func(ctx context.Context, nsAddr, fqdn string) (string, error) {
			return "loop." + fqdn, nil
		},
	}
	err := c.Wait(context.Background(), "_acme-challenge.example.com", "v", time.Second)
	if err == nil || !strings.Contains(err.Error(), "CNAME chain") {
		t.Fatalf("expected CNAME chain error, got %v", err)
	}
}

func TestDNSCheckerReportsNoZoneFound(t *testing.T) {
	c := &DNSChecker{
		Interval: time.Millisecond,
		lookupNS: func(ctx context.Context, domain string) ([]string, error) {
			return nil, nil
		},
	}
	err := c.Wait(context.Background(), "_acme-challenge.example.com", "v", time.Second)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "find authoritative nameservers") {
		t.Fatalf("unexpected error: %v", err)
	}
}
