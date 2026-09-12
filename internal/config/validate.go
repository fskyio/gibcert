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

package config

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"
)

var supportedDNSDrivers = []string{"exec", "manual", "nsupdate", "pdns", "powerdns", "rfc2136"}

const (
	DefaultLocalCAValidFor   = 10 * 365 * 24 * time.Hour
	DefaultLocalCertValidFor = 90 * 24 * time.Hour
)

func (c *Config) Validate() error {
	var errs []error

	cas := caProfiles(c.CAs)
	seenCA := map[string]bool{}
	for _, ca := range c.CAs {
		if err := ValidateStateName(ca.Name); err != nil {
			errs = append(errs, fmt.Errorf("ca %q: invalid name: %w", ca.Name, err))
		}
		if _, dup := seenCA[ca.Name]; dup {
			errs = append(errs, fmt.Errorf("duplicate ca %q", ca.Name))
			continue
		}
		seenCA[ca.Name] = true
		if ca.Type == "" {
			ca.Type = "acme"
		}
		switch ca.Type {
		case "acme":
			if ca.Directory == "" {
				errs = append(errs, fmt.Errorf("ca %q: directory is required", ca.Name))
			}
			if ca.CommonName != "" {
				errs = append(errs, fmt.Errorf("ca %q: common-name is only valid for local ca", ca.Name))
			}
			if ca.ValidFor != 0 {
				errs = append(errs, fmt.Errorf("ca %q: valid-for is only valid for local ca; for ACME certificate lifetimes, use profile if the CA advertises one", ca.Name))
			}
			if err := validateEmptyKey(&ca.Key); err != nil {
				errs = append(errs, fmt.Errorf("ca %q: key is only valid for local ca", ca.Name))
			}
		case "local":
			if ca.Directory != "" {
				errs = append(errs, fmt.Errorf("ca %q: directory is only valid for acme ca", ca.Name))
			}
			if ca.ValidFor < 0 {
				errs = append(errs, fmt.Errorf("ca %q: valid-for must be >= 0", ca.Name))
			}
			if err := validateKey(&ca.Key); err != nil {
				errs = append(errs, fmt.Errorf("ca %q: %w", ca.Name, err))
			}
		default:
			errs = append(errs, fmt.Errorf("ca %q: unsupported type %q", ca.Name, ca.Type))
		}
	}

	accounts := map[string]*Account{}
	for _, a := range c.Accounts {
		if err := ValidateStateName(a.Name); err != nil {
			errs = append(errs, fmt.Errorf("account %q: invalid name: %w", a.Name, err))
		}
		if _, dup := accounts[a.Name]; dup {
			errs = append(errs, fmt.Errorf("duplicate account %q", a.Name))
			continue
		}
		accounts[a.Name] = a
		if a.CA != "" {
			ca, ok := cas[a.CA]
			if !ok {
				errs = append(errs, fmt.Errorf("account %q: unknown ca %q", a.Name, a.CA))
			} else if ca.Type != "acme" {
				errs = append(errs, fmt.Errorf("account %q: ca %q is %s, want acme", a.Name, a.CA, ca.Type))
			} else {
				a.Directory = ca.Directory
				if a.Directory == "" {
					errs = append(errs, fmt.Errorf("account %q: directory is required", a.Name))
				}
			}
		} else {
			ca, ok := cas[a.Name]
			if !ok {
				errs = append(errs, fmt.Errorf("account %q: ca is required", a.Name))
			} else if ca.Type != "acme" {
				errs = append(errs, fmt.Errorf("account %q: ca %q is %s, want acme", a.Name, ca.Name, ca.Type))
			} else {
				a.CA = ca.Name
				a.Directory = ca.Directory
				if a.Directory == "" {
					errs = append(errs, fmt.Errorf("account %q: directory is required", a.Name))
				}
			}
		}
		if a.EAB != nil {
			if a.EAB.KID == "" {
				errs = append(errs, fmt.Errorf("account %q: eab: kid is required", a.Name))
			}
			if err := validateSecretValue(&a.EAB.HMACKey); err != nil {
				errs = append(errs, fmt.Errorf("account %q: eab: hmac-key: %w", a.Name, err))
			}
		}
	}

	providers := map[string]*Provider{}
	for _, p := range c.Providers {
		if _, dup := providers[p.Name]; dup {
			errs = append(errs, fmt.Errorf("duplicate provider %q", p.Name))
			continue
		}
		providers[p.Name] = p
		if p.Type == "" {
			errs = append(errs, fmt.Errorf("provider %q: type is required", p.Name))
		} else if p.Type != "dns" {
			errs = append(errs, fmt.Errorf("provider %q: unknown type %q", p.Name, p.Type))
		}
		if p.Driver == "" {
			errs = append(errs, fmt.Errorf("provider %q: driver is required", p.Name))
		} else if p.Type == "dns" && !slices.Contains(supportedDNSDrivers, p.Driver) {
			errs = append(errs, fmt.Errorf("provider %q: unsupported dns driver %q (supported: %s)", p.Name, p.Driver, strings.Join(supportedDNSDrivers, ", ")))
		}
		if p.Type == "dns" && p.Driver == "exec" {
			errs = append(errs, validateGibDNSProvider(p)...)
		}
		seenSecret := map[string]bool{}
		for _, s := range p.Secrets {
			if seenSecret[s.Name] {
				errs = append(errs, fmt.Errorf("provider %q: duplicate secret %q", p.Name, s.Name))
			}
			seenSecret[s.Name] = true
			if err := validateSecretValue(&SecretValue{
				File:              s.File,
				Value:             s.Value,
				Env:               s.Env,
				Command:           s.Command,
				SystemdCredential: s.SystemdCredential,
			}); err != nil {
				errs = append(errs, fmt.Errorf("provider %q: secret %q: %w", p.Name, s.Name, err))
			}
		}
	}

	if c.GlobalChallenge != nil {
		gc := c.GlobalChallenge
		if gc.Type != "http-01" {
			errs = append(errs, fmt.Errorf("global challenge: only http-01 supported at top level, got %q", gc.Type))
		} else if (gc.Webroot == "") == (gc.Listen == "") {
			errs = append(errs, fmt.Errorf("global challenge http-01: exactly one of webroot or listen is required"))
		}
	}

	// Resolve group references into each certificate before validating the
	// certificates themselves, so validation sees fully merged fields.
	errs = append(errs, c.applyGroups()...)

	seenCert := map[string]bool{}
	for _, cert := range c.Certificates {
		if err := ValidateStateName(cert.Name); err != nil {
			errs = append(errs, fmt.Errorf("certificate %q: invalid name: %w", cert.Name, err))
		}
		if seenCert[cert.Name] {
			errs = append(errs, fmt.Errorf("duplicate certificate %q", cert.Name))
			continue
		}
		seenCert[cert.Name] = true

		certUsesACME := false
		if cert.Account != "" && cert.CA != "" {
			errs = append(errs, fmt.Errorf("certificate %q: exactly one of account or ca is required", cert.Name))
		} else if cert.Account == "" && cert.CA == "" {
			errs = append(errs, fmt.Errorf("certificate %q: account or ca is required", cert.Name))
		} else if cert.Account != "" {
			if _, ok := accounts[cert.Account]; !ok {
				errs = append(errs, fmt.Errorf("certificate %q: unknown account %q", cert.Name, cert.Account))
			} else {
				certUsesACME = true
			}
		} else {
			ca, ok := cas[cert.CA]
			if !ok {
				errs = append(errs, fmt.Errorf("certificate %q: unknown ca %q", cert.Name, cert.CA))
			} else {
				switch ca.Type {
				case "acme":
					certUsesACME = true
					if cert.ValidFor != 0 {
						errs = append(errs, fmt.Errorf("certificate %q: valid-for is only valid for local ca certificates; for ACME short-lived certificates, use profile if the CA advertises one", cert.Name))
					}
				case "local":
					if cert.ValidFor < 0 {
						errs = append(errs, fmt.Errorf("certificate %q: valid-for must be >= 0", cert.Name))
					}
					if cert.PreferredChain != "" {
						errs = append(errs, fmt.Errorf("certificate %q: preferred-chain is only valid for acme certificates", cert.Name))
					}
					if cert.Challenge.Type != "" || cert.Challenge.Provider != "" || cert.Challenge.Webroot != "" || cert.Challenge.PropagationTimeout != nil {
						errs = append(errs, fmt.Errorf("certificate %q: challenge is only valid for acme certificates", cert.Name))
					}
				default:
					errs = append(errs, fmt.Errorf("certificate %q: ca %q has unsupported type %q", cert.Name, cert.CA, ca.Type))
				}
			}
		}

		if len(cert.Names) == 0 {
			errs = append(errs, fmt.Errorf("certificate %q: names is required", cert.Name))
		}

		if err := validateKey(&cert.Key); err != nil {
			errs = append(errs, fmt.Errorf("certificate %q: %w", cert.Name, err))
		}

		if certUsesACME {
			if err := validateChallenge(cert, providers, c.GlobalChallenge); err != nil {
				errs = append(errs, fmt.Errorf("certificate %q: %w", cert.Name, err))
			}
		}

		seenDeploy := map[string]bool{}
		for _, d := range cert.Deploys {
			if seenDeploy[d.Name] {
				errs = append(errs, fmt.Errorf("certificate %q: duplicate deploy %q", cert.Name, d.Name))
			}
			seenDeploy[d.Name] = true
			if err := validateDeploy(d); err != nil {
				errs = append(errs, fmt.Errorf("certificate %q: deploy %q: %w", cert.Name, d.Name, err))
			}
		}

		for _, cmd := range cert.Reloads {
			if strings.TrimSpace(cmd) == "" {
				errs = append(errs, fmt.Errorf("certificate %q: reload command must not be empty", cert.Name))
			}
		}

		if cert.TLSA != nil {
			if err := validateTLSA(cert, providers); err != nil {
				errs = append(errs, fmt.Errorf("certificate %q: %w", cert.Name, err))
			}
		}

		if len(cert.Failover) > 0 {
			errs = append(errs, validateFailover(cert, certUsesACME, accounts, cas)...)
		}
	}

	errs = append(errs, validateDependencies(c.Certificates)...)

	return errors.Join(errs...)
}

func ValidateStateName(name string) error {
	switch {
	case name == "":
		return errors.New("must not be empty")
	case name == "." || name == "..":
		return errors.New("must be a single path component")
	case strings.ContainsAny(name, `/\`):
		return errors.New("must not contain path separators")
	case strings.ContainsRune(name, '\x00'):
		return errors.New("must not contain NUL")
	default:
		return nil
	}
}

// issuerKey identifies an issuer by its account or ca reference, for detecting
// duplicate entries across a certificate's primary issuer and its failover
// list. Two entries naming the same account (explicit or implicit) collide.
func issuerKey(account, ca string) string {
	if account != "" {
		return "account:" + account
	}
	return "ca:" + ca
}

func validateFailover(cert *Certificate, certUsesACME bool, accounts map[string]*Account, cas map[string]*CA) []error {
	var errs []error
	if !certUsesACME {
		errs = append(errs, fmt.Errorf("certificate %q: failover is only valid for acme certificates", cert.Name))
	}
	seen := map[string]bool{issuerKey(cert.Account, cert.CA): true}
	for _, iss := range cert.Failover {
		if iss.Account != "" {
			if _, ok := accounts[iss.Account]; !ok {
				errs = append(errs, fmt.Errorf("certificate %q: failover: unknown account %q", cert.Name, iss.Account))
			}
		} else {
			ca, ok := cas[iss.CA]
			if !ok {
				errs = append(errs, fmt.Errorf("certificate %q: failover: unknown ca %q", cert.Name, iss.CA))
			} else if ca.Type != "acme" {
				errs = append(errs, fmt.Errorf("certificate %q: failover: ca %q is %s, want acme", cert.Name, iss.CA, ca.Type))
			}
		}
		key := issuerKey(iss.Account, iss.CA)
		if seen[key] {
			errs = append(errs, fmt.Errorf("certificate %q: failover: duplicate issuer %s", cert.Name, key))
		}
		seen[key] = true
	}
	return errs
}

func validateSecretValue(s *SecretValue) error {
	count := 0
	if s.File != "" {
		count++
	}
	if s.Value != "" {
		count++
	}
	if s.Env != "" {
		count++
	}
	if len(s.Command) > 0 {
		count++
	}
	if s.SystemdCredential != "" {
		count++
	}
	if count != 1 {
		return fmt.Errorf("exactly one of file, value, env, command, or systemd-credential is required")
	}
	return nil
}

var tlsaEditorDrivers = []string{"exec", "nsupdate", "rfc2136", "pdns", "powerdns"}

func validateTLSA(cert *Certificate, providers map[string]*Provider) error {
	t := cert.TLSA
	if t.Provider == "" {
		return fmt.Errorf("tlsa: provider is required")
	}
	p, ok := providers[t.Provider]
	if !ok {
		return fmt.Errorf("tlsa: unknown provider %q", t.Provider)
	}
	if p.Type != "dns" {
		return fmt.Errorf("tlsa: provider %q is not a dns provider", t.Provider)
	}
	if !slices.Contains(tlsaEditorDrivers, p.Driver) {
		return fmt.Errorf("tlsa: dns driver %q does not support persistent record edits (use one of: %s)", p.Driver, strings.Join(tlsaEditorDrivers, ", "))
	}
	if len(t.Ports) == 0 {
		return fmt.Errorf("tlsa: at least one port is required")
	}
	if t.Usage == 0 && t.Selector == 0 && t.MatchingType == 0 {
		t.Usage = 3
		t.Selector = 1
		t.MatchingType = 1
	}
	if t.Usage != 3 {
		return fmt.Errorf("tlsa: only DANE-EE (usage 3) is supported, got %d", t.Usage)
	}
	if t.Selector != 1 {
		return fmt.Errorf("tlsa: only SPKI (selector 1) is supported, got %d", t.Selector)
	}
	if t.MatchingType != 1 && t.MatchingType != 2 {
		return fmt.Errorf("tlsa: matching type must be 1 (SHA-256) or 2 (SHA-512), got %d", t.MatchingType)
	}
	if t.TTL == 0 {
		t.TTL = 3600
	}
	if t.TTL < 0 {
		return fmt.Errorf("tlsa: ttl must be positive")
	}
	renewWindow := cert.Renew.BeforeExpiry
	if renewWindow == 0 {
		renewWindow = 30 * 24 * time.Hour
	}
	if time.Duration(t.TTL)*time.Second >= renewWindow {
		return fmt.Errorf("tlsa: ttl (%ds) must be less than the renewal window (%s)", t.TTL, renewWindow)
	}
	return nil
}

func validateGibDNSProvider(p *Provider) []error {
	var errs []error
	command := p.Fields["command"]
	if len(command) == 0 || command[0] == "" {
		errs = append(errs, fmt.Errorf("provider %q: gibdns exec driver requires command", p.Name))
	}
	for _, name := range []string{"present", "cleanup", "add-record", "remove-record"} {
		if _, ok := p.Fields[name]; ok {
			errs = append(errs, fmt.Errorf("provider %q: legacy exec field %q is not supported; gibdns uses command for every method", p.Name, name))
		}
	}
	if p.HandlesPropagation {
		errs = append(errs, fmt.Errorf("provider %q: propagation provider is not supported by gibdns; gibcert performs propagation checks", p.Name))
	}
	if zone, ok := p.Fields["zone"]; ok {
		if len(zone) != 1 || zone[0] == "" {
			errs = append(errs, fmt.Errorf("provider %q: gibdns zone requires exactly one non-empty value", p.Name))
		}
	}
	for name, values := range p.Fields {
		if name == "command" || name == "zone" {
			continue
		}
		if len(values) == 0 {
			errs = append(errs, fmt.Errorf("provider %q: gibdns config field %q requires at least one value", p.Name, name))
		}
	}
	return errs
}

func validateKey(k *KeySpec) error {
	switch k.Type {
	case "", "ecdsa":
		curve := k.Curve
		if curve == "" {
			curve = "p256"
		}
		if curve != "p256" && curve != "p384" {
			return fmt.Errorf("key: unsupported ecdsa curve %q", k.Curve)
		}
		if k.Bits != 0 {
			return fmt.Errorf("key: bits is only valid for rsa")
		}
	case "rsa":
		if k.Curve != "" {
			return fmt.Errorf("key: curve is only valid for ecdsa")
		}
		if k.Bits != 0 && k.Bits != 2048 && k.Bits != 3072 && k.Bits != 4096 {
			return fmt.Errorf("key: unsupported rsa bits %d", k.Bits)
		}
	default:
		return fmt.Errorf("key: unsupported type %q", k.Type)
	}
	return nil
}

func validateEmptyKey(k *KeySpec) error {
	if k.Type != "" || k.Curve != "" || k.Bits != 0 || k.Reuse {
		return fmt.Errorf("key block is not allowed")
	}
	return nil
}

// IsIPName reports whether name is an IP address literal rather than a DNS
// name. IP identifiers are issued under RFC 8738.
func IsIPName(name string) bool {
	return net.ParseIP(name) != nil
}

func validateChallenge(cert *Certificate, providers map[string]*Provider, gc *GlobalChallenge) error {
	ch := cert.Challenge
	// IP identifiers (RFC 8738) are only validatable with http-01 or
	// tls-alpn-01, never the DNS-based challenges. gibcert currently solves
	// IP identifiers with http-01 only.
	hasIP := false
	for _, name := range cert.Names {
		if IsIPName(name) {
			hasIP = true
			break
		}
	}
	if hasIP {
		effective := ch.Type
		if effective == "" && gc != nil {
			effective = gc.Type
		}
		switch effective {
		case "http-01", "tls-alpn-01":
			// supported for IP identifiers (RFC 8738 §4)
		default:
			return fmt.Errorf("challenge %s: IP identifiers require http-01 or tls-alpn-01", effective)
		}
	}
	if ch.Type == "" {
		if gc != nil && gc.Type == "http-01" {
			return nil
		}
		return fmt.Errorf("challenge is required (no global default configured)")
	}
	if ch.Type != "dns-01" && ch.Type != "dns-persist-01" {
		if ch.AliasFQDN != "" || ch.AliasDomain != "" {
			return fmt.Errorf("challenge %s: alias-fqdn and alias-domain are only valid for dns-01 and dns-persist-01", ch.Type)
		}
	}
	if ch.AliasFQDN != "" && ch.AliasDomain != "" {
		return fmt.Errorf("challenge %s: alias-fqdn and alias-domain are mutually exclusive", ch.Type)
	}
	if ch.Type != "http-01" && ch.Type != "tls-alpn-01" && ch.Listen != "" {
		return fmt.Errorf("challenge %s: listen is only valid for http-01 and tls-alpn-01", ch.Type)
	}
	if ch.Type != "http-01" && ch.Webroot != "" {
		return fmt.Errorf("challenge %s: webroot is only valid for http-01", ch.Type)
	}
	switch ch.Type {
	case "http-01":
		webroot := ch.Webroot
		listen := ch.Listen
		if webroot == "" && listen == "" && gc != nil && gc.Type == "http-01" {
			webroot = gc.Webroot
			listen = gc.Listen
		}
		if webroot == "" && listen == "" {
			return fmt.Errorf("challenge http-01: one of webroot or listen is required (no global default)")
		}
		if webroot != "" && listen != "" {
			return fmt.Errorf("challenge http-01: webroot and listen are mutually exclusive")
		}
	case "tls-alpn-01":
		if ch.Listen == "" {
			return fmt.Errorf("challenge tls-alpn-01: listen is required")
		}
		if ch.Provider != "" {
			return fmt.Errorf("challenge tls-alpn-01: provider is only valid for dns challenges")
		}
	case "dns-01":
		if ch.Provider == "" {
			return fmt.Errorf("challenge dns-01: provider is required")
		}
		p, ok := providers[ch.Provider]
		if !ok {
			return fmt.Errorf("challenge dns-01: unknown provider %q", ch.Provider)
		}
		if p.Type != "dns" {
			return fmt.Errorf("challenge dns-01: provider %q is not a dns provider", ch.Provider)
		}
	case "dns-persist-01":
		if ch.Provider != "" {
			p, ok := providers[ch.Provider]
			if !ok {
				return fmt.Errorf("challenge dns-persist-01: unknown provider %q", ch.Provider)
			}
			if p.Type != "dns" {
				return fmt.Errorf("challenge dns-persist-01: provider %q is not a dns provider", ch.Provider)
			}
		}
	default:
		return fmt.Errorf("challenge: unsupported type %q", ch.Type)
	}
	return nil
}

func validateDeploy(d *Deploy) error {
	if d.Cert == "" && d.Chain == "" && d.Fullchain == "" && d.Key == "" && d.CertDER == "" && d.KeyDER == "" {
		return fmt.Errorf("at least one of cert, chain, fullchain, key, cert-der, key-der must be set")
	}
	for _, p := range []struct{ name, val string }{
		{"cert", d.Cert}, {"chain", d.Chain}, {"fullchain", d.Fullchain}, {"key", d.Key},
		{"cert-der", d.CertDER}, {"key-der", d.KeyDER},
	} {
		if p.val != "" && !strings.HasPrefix(p.val, "/") {
			return fmt.Errorf("%s: must be an absolute path, got %q", p.name, p.val)
		}
	}
	return nil
}
