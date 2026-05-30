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
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// DNSPersistRecordName returns the TXT record name where a dns-persist-01
// standing record must be published for the given domain.
func DNSPersistRecordName(domain string) string {
	return "_validation-persist." + strings.TrimSuffix(strings.TrimPrefix(domain, "*."), ".")
}

// DNSPersistRecordValue formats the standing record content. The result is a
// single TXT string of the form:
//
//	"<ca-identifier>; accounturi=<account-uri>"
//
// Optional policy and persistUntil parameters may be empty. persistUntil, when
// set, must be a base-10 UNIX timestamp per draft-ietf-acme-dns-persist.
func DNSPersistRecordValue(caIdentifier, accountURI, policy, persistUntil string) string {
	var b strings.Builder
	b.WriteString(caIdentifier)
	b.WriteString("; accounturi=")
	b.WriteString(accountURI)
	if policy != "" {
		b.WriteString("; policy=")
		b.WriteString(policy)
	}
	if persistUntil != "" {
		b.WriteString("; persistUntil=")
		b.WriteString(persistUntil)
	}
	return b.String()
}

// DNSPersistVerifyResult reports the outcome of a standing-record lookup.
type DNSPersistVerifyResult struct {
	RecordName string
	Found      []string
	Matched    bool
}

// DNSPersistVerifyOptions describes the dns-persist-01 values expected by a CA
// challenge. IssuerDomainNames is the set advertised by the challenge; callers
// that preflight without a challenge may pass a single configured CA identity.
type DNSPersistVerifyOptions struct {
	IssuerDomainNames []string
	AccountURI        string
	RequireWildcard   bool
	Now               time.Time
}

// VerifyDNSPersistRecord performs a TXT lookup for the standing record and
// reports whether any value matches the expected (caIdentifier, accountURI)
// pair. accounturi comparison follows RFC 3986 simple string comparison: no
// case-folding or URI normalization is applied.
func VerifyDNSPersistRecord(ctx context.Context, domain, caIdentifier, accountURI string) (DNSPersistVerifyResult, error) {
	return VerifyDNSPersistRecordWithOptions(ctx, domain, DNSPersistVerifyOptions{
		IssuerDomainNames: []string{caIdentifier},
		AccountURI:        accountURI,
		Now:               time.Now(),
	})
}

func VerifyDNSPersistRecordWithOptions(
	ctx context.Context,
	domain string,
	opts DNSPersistVerifyOptions,
) (DNSPersistVerifyResult, error) {
	return verifyDNSPersistRecord(ctx, domain, opts, net.DefaultResolver.LookupTXT)
}

func verifyDNSPersistRecord(
	ctx context.Context,
	domain string,
	opts DNSPersistVerifyOptions,
	lookupTXT func(ctx context.Context, name string) ([]string, error),
) (DNSPersistVerifyResult, error) {
	res := DNSPersistVerifyResult{RecordName: DNSPersistRecordName(domain)}
	txts, err := lookupTXT(ctx, res.RecordName)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && (dnsErr.IsNotFound || dnsErr.Err == "no such host") {
			return res, nil
		}
		return res, fmt.Errorf("lookup %s: %w", res.RecordName, err)
	}
	res.Found = txts
	issuers := map[string]bool{}
	for _, issuer := range opts.IssuerDomainNames {
		issuer = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(issuer), "."))
		if issuer != "" {
			issuers[issuer] = true
		}
	}
	wantURI := strings.TrimSpace(opts.AccountURI)
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	for _, t := range txts {
		fields := parsePersistFields(t)
		issuer := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(fields[""]), "."))
		if !issuers[issuer] {
			continue
		}
		if strings.TrimSpace(fields["accounturi"]) != wantURI {
			continue
		}
		if opts.RequireWildcard && !strings.EqualFold(strings.TrimSpace(fields["policy"]), "wildcard") {
			continue
		}
		if expiredOrMalformedPersistUntil(fields["persistuntil"], now) {
			continue
		}
		res.Matched = true
		return res, nil
	}
	return res, nil
}

func expiredOrMalformedPersistUntil(v string, now time.Time) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	sec, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return true
	}
	return now.After(time.Unix(sec, 0))
}

// parsePersistFields splits a TXT value into its CA identifier (under the
// empty-string key) and named parameters.
func parsePersistFields(s string) map[string]string {
	out := map[string]string{}
	parts := strings.Split(s, ";")
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if i == 0 && !strings.Contains(p, "=") {
			out[""] = p
			continue
		}
		eq := strings.IndexByte(p, '=')
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(p[:eq]))
		val := strings.TrimSpace(p[eq+1:])
		out[key] = val
	}
	return out
}
