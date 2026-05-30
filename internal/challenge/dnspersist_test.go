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
	"testing"
	"time"
)

func TestDNSPersistRecordName(t *testing.T) {
	cases := map[string]string{
		"example.com":     "_validation-persist.example.com",
		"*.example.com":   "_validation-persist.example.com",
		"example.com.":    "_validation-persist.example.com",
		"foo.bar.example": "_validation-persist.foo.bar.example",
	}
	for in, want := range cases {
		if got := DNSPersistRecordName(in); got != want {
			t.Errorf("%s: got %q, want %q", in, got, want)
		}
	}
}

func TestDNSPersistRecordValue(t *testing.T) {
	got := DNSPersistRecordValue("letsencrypt.org", "https://acme-v02.api.letsencrypt.org/acme/acct/1234", "", "")
	want := "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1234"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	got = DNSPersistRecordValue("letsencrypt.org", "https://x", "wildcard", "1893456000")
	want = "letsencrypt.org; accounturi=https://x; policy=wildcard; persistUntil=1893456000"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestVerifyDNSPersistRecord(t *testing.T) {
	caID := "letsencrypt.org"
	acct := "https://acme-v02.api.letsencrypt.org/acme/acct/42"

	cases := []struct {
		name   string
		txts   []string
		expect bool
	}{
		{
			name:   "exact match",
			txts:   []string{DNSPersistRecordValue(caID, acct, "", "")},
			expect: true,
		},
		{
			name:   "match with policy",
			txts:   []string{DNSPersistRecordValue(caID, acct, "wildcard", "")},
			expect: true,
		},
		{
			name:   "match with future persistUntil",
			txts:   []string{DNSPersistRecordValue(caID, acct, "", "1893456000")},
			expect: true,
		},
		{
			name:   "expired persistUntil",
			txts:   []string{DNSPersistRecordValue(caID, acct, "", "946684800")},
			expect: false,
		},
		{
			name:   "malformed persistUntil",
			txts:   []string{DNSPersistRecordValue(caID, acct, "", "2030-01-01T00:00:00Z")},
			expect: false,
		},
		{
			name:   "wrong account",
			txts:   []string{DNSPersistRecordValue(caID, "https://other", "", "")},
			expect: false,
		},
		{
			name:   "account case is exact",
			txts:   []string{DNSPersistRecordValue(caID, "https://ACME-v02.api.letsencrypt.org/acme/acct/42", "", "")},
			expect: false,
		},
		{
			name:   "wrong ca",
			txts:   []string{DNSPersistRecordValue("other.example", acct, "", "")},
			expect: false,
		},
		{
			name:   "multi-value mixed",
			txts:   []string{"unrelated", DNSPersistRecordValue(caID, acct, "", "")},
			expect: true,
		},
		{
			name:   "empty",
			txts:   nil,
			expect: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lookup := func(_ context.Context, _ string) ([]string, error) {
				return tc.txts, nil
			}
			res, err := verifyDNSPersistRecord(context.Background(), "example.com", DNSPersistVerifyOptions{
				IssuerDomainNames: []string{caID},
				AccountURI:        acct,
				Now:               time.Date(2026, 5, 29, 0, 0, 0, 0, time.UTC),
			}, lookup)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if res.Matched != tc.expect {
				t.Errorf("matched: got %v, want %v", res.Matched, tc.expect)
			}
		})
	}
}

func TestVerifyDNSPersistRecordRequiresWildcardPolicy(t *testing.T) {
	caID := "letsencrypt.org"
	acct := "https://acme-v02.api.letsencrypt.org/acme/acct/42"
	lookup := func(_ context.Context, _ string) ([]string, error) {
		return []string{
			DNSPersistRecordValue(caID, acct, "", ""),
			DNSPersistRecordValue(caID, acct, "WILDCARD", ""),
		}, nil
	}
	res, err := verifyDNSPersistRecord(context.Background(), "*.example.com", DNSPersistVerifyOptions{
		IssuerDomainNames: []string{caID},
		AccountURI:        acct,
		RequireWildcard:   true,
		Now:               time.Date(2026, 5, 29, 0, 0, 0, 0, time.UTC),
	}, lookup)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.Matched {
		t.Fatal("expected wildcard policy to match")
	}
}

func TestVerifyDNSPersistRecordAcceptsChallengeIssuers(t *testing.T) {
	acct := "https://ca.example/acct/42"
	lookup := func(_ context.Context, _ string) ([]string, error) {
		return []string{
			DNSPersistRecordValue("ca2.example", acct, "", ""),
		}, nil
	}
	res, err := verifyDNSPersistRecord(context.Background(), "example.com", DNSPersistVerifyOptions{
		IssuerDomainNames: []string{"ca1.example", "ca2.example"},
		AccountURI:        acct,
		Now:               time.Date(2026, 5, 29, 0, 0, 0, 0, time.UTC),
	}, lookup)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.Matched {
		t.Fatal("expected second issuer to match")
	}
}
