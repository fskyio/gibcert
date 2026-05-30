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
	"strings"
	"time"
)

type DNSChecker struct {
	Interval time.Duration

	lookupNS      func(ctx context.Context, domain string) ([]string, error)
	lookupHost    func(ctx context.Context, host string) ([]string, error)
	lookupTXTAt   func(ctx context.Context, nsAddr, fqdn string) ([]string, error)
	lookupCNAMEAt func(ctx context.Context, nsAddr, fqdn string) (string, error)
}

const cnameChaseMaxHops = 5

func (c *DNSChecker) Wait(ctx context.Context, fqdn, expected string, timeout time.Duration) error {
	if timeout <= 0 {
		return nil
	}
	lookupNS := c.lookupNS
	if lookupNS == nil {
		lookupNS = defaultLookupNS
	}
	lookupHost := c.lookupHost
	if lookupHost == nil {
		lookupHost = defaultLookupHost
	}
	lookupTXTAt := c.lookupTXTAt
	if lookupTXTAt == nil {
		lookupTXTAt = defaultLookupTXTAt
	}
	lookupCNAMEAt := c.lookupCNAMEAt
	if lookupCNAMEAt == nil {
		lookupCNAMEAt = defaultLookupCNAMEAt
	}
	interval := c.Interval
	if interval <= 0 {
		interval = 4 * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	target, nsAddrs, err := followCNAMEs(ctx, fqdn, lookupNS, lookupHost, lookupCNAMEAt)
	if err != nil {
		return err
	}
	if len(nsAddrs) == 0 {
		return fmt.Errorf("no usable nameserver addresses for %s", target)
	}

	var lastErr error
	for {
		ok, err := allNSHaveTXT(ctx, target, expected, nsAddrs, lookupTXTAt)
		if err != nil {
			lastErr = err
		} else if ok {
			return nil
		}

		select {
		case <-ctx.Done():
			if lastErr != nil {
				return fmt.Errorf("propagation timeout waiting for %s: %w", target, lastErr)
			}
			return fmt.Errorf("propagation timeout waiting for %s on %v", target, nsAddrs)
		case <-time.After(interval):
		}
	}
}

func followCNAMEs(
	ctx context.Context,
	fqdn string,
	lookupNS func(ctx context.Context, domain string) ([]string, error),
	lookupHost func(ctx context.Context, host string) ([]string, error),
	lookupCNAMEAt func(ctx context.Context, nsAddr, fqdn string) (string, error),
) (string, []string, error) {
	target := strings.TrimSuffix(fqdn, ".")
	for hops := 0; hops < cnameChaseMaxHops; hops++ {
		_, nsHosts, err := findZoneNS(ctx, target, lookupNS)
		if err != nil {
			return "", nil, fmt.Errorf("find authoritative nameservers for %s: %w", target, err)
		}
		nsAddrs, err := resolveNS(ctx, nsHosts, lookupHost)
		if err != nil {
			return "", nil, fmt.Errorf("resolve nameservers for %s: %w", target, err)
		}
		if len(nsAddrs) == 0 {
			return "", nil, fmt.Errorf("no usable nameserver addresses for %s", target)
		}
		cname, err := lookupCNAMEAt(ctx, nsAddrs[0], target)
		if err != nil {
			return "", nil, fmt.Errorf("CNAME lookup for %s: %w", target, err)
		}
		if cname == "" || strings.EqualFold(cname, target) {
			return target, nsAddrs, nil
		}
		target = cname
	}
	return "", nil, fmt.Errorf("CNAME chain starting at %s exceeded %d hops", fqdn, cnameChaseMaxHops)
}

func allNSHaveTXT(ctx context.Context, fqdn, expected string, nsAddrs []string, lookup func(ctx context.Context, nsAddr, fqdn string) ([]string, error)) (bool, error) {
	var lastErr error
	for _, addr := range nsAddrs {
		txts, err := lookup(ctx, addr, fqdn)
		if err != nil {
			lastErr = fmt.Errorf("query %s: %w", addr, err)
			return false, lastErr
		}
		found := false
		for _, t := range txts {
			if t == expected {
				found = true
				break
			}
		}
		if !found {
			return false, nil
		}
	}
	return true, lastErr
}

func findZoneNS(ctx context.Context, fqdn string, lookupNS func(ctx context.Context, domain string) ([]string, error)) (string, []string, error) {
	name := strings.TrimSuffix(fqdn, ".")
	for {
		ns, err := lookupNS(ctx, name)
		if err == nil && len(ns) > 0 {
			return name, ns, nil
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return "", nil, fmt.Errorf("no NS records found for any parent of %s", fqdn)
		}
		name = name[i+1:]
		if name == "" {
			return "", nil, fmt.Errorf("no NS records found for any parent of %s", fqdn)
		}
	}
}

func resolveNS(ctx context.Context, hosts []string, lookupHost func(ctx context.Context, host string) ([]string, error)) ([]string, error) {
	seen := make(map[string]struct{})
	var addrs []string
	var firstErr error
	for _, h := range hosts {
		ips, err := lookupHost(ctx, strings.TrimSuffix(h, "."))
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, ip := range ips {
			addr := net.JoinHostPort(ip, "53")
			if _, ok := seen[addr]; ok {
				continue
			}
			seen[addr] = struct{}{}
			addrs = append(addrs, addr)
		}
	}
	if len(addrs) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return addrs, nil
}

func defaultLookupNS(ctx context.Context, domain string) ([]string, error) {
	ns, err := net.DefaultResolver.LookupNS(ctx, domain)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && (dnsErr.IsNotFound || dnsErr.Err == "no such host") {
			return nil, nil
		}
		return nil, err
	}
	hosts := make([]string, 0, len(ns))
	for _, n := range ns {
		hosts = append(hosts, n.Host)
	}
	return hosts, nil
}

func defaultLookupHost(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

func defaultLookupCNAMEAt(ctx context.Context, nsAddr, fqdn string) (string, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, nsAddr)
		},
	}
	cname, err := r.LookupCNAME(ctx, fqdn)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && (dnsErr.IsNotFound || dnsErr.Err == "no such host") {
			return "", nil
		}
		return "", err
	}
	cname = strings.TrimSuffix(cname, ".")
	if strings.EqualFold(cname, strings.TrimSuffix(fqdn, ".")) {
		return "", nil
	}
	return cname, nil
}

func defaultLookupTXTAt(ctx context.Context, nsAddr, fqdn string) ([]string, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, nsAddr)
		},
	}
	txts, err := r.LookupTXT(ctx, fqdn)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && (dnsErr.IsNotFound || dnsErr.Err == "no such host") {
			return nil, nil
		}
		return nil, err
	}
	return txts, nil
}
