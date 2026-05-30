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
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"codeberg.org/emersion/go-scfg"
)

func Load(path string) (*Config, error) {
	block, err := loadBlock(path, map[string]bool{})
	if err != nil {
		return nil, err
	}
	return fromBlock(block)
}

func Read(r io.Reader) (*Config, error) {
	block, err := scfg.Read(r)
	if err != nil {
		return nil, err
	}
	return fromBlock(block)
}

func loadBlock(path string, stack map[string]bool) (scfg.Block, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if stack[abs] {
		return nil, fmt.Errorf("include cycle involving %s", abs)
	}
	stack[abs] = true
	defer delete(stack, abs)

	block, err := scfg.Load(abs)
	if err != nil {
		return nil, err
	}
	return expandIncludes(abs, block, stack)
}

func expandIncludes(parent string, block scfg.Block, stack map[string]bool) (scfg.Block, error) {
	var expanded scfg.Block
	for _, d := range block {
		if d.Name != "include" {
			expanded = append(expanded, d)
			continue
		}
		if len(d.Children) > 0 {
			return nil, fmt.Errorf("include does not take a block")
		}
		if len(d.Params) != 1 {
			return nil, fmt.Errorf("include: want 1 param, got %d", len(d.Params))
		}
		matches, err := includeMatches(filepath.Dir(parent), d.Params[0])
		if err != nil {
			return nil, err
		}
		for _, match := range matches {
			included, err := loadBlock(match, stack)
			if err != nil {
				return nil, fmt.Errorf("include %q: %w", d.Params[0], err)
			}
			expanded = append(expanded, included...)
		}
	}
	return expanded, nil
}

func includeMatches(baseDir, pattern string) ([]string, error) {
	target := pattern
	if !filepath.IsAbs(target) {
		target = filepath.Join(baseDir, target)
	}
	target = filepath.Clean(target)

	if hasGlob(target) {
		matches, err := filepath.Glob(target)
		if err != nil {
			return nil, fmt.Errorf("include %q: %w", pattern, err)
		}
		sort.Strings(matches)
		return matches, nil
	}

	info, err := os.Stat(target)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{target}, nil
	}

	matches, err := filepath.Glob(filepath.Join(target, "*.scfg"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	return matches, nil
}

func hasGlob(path string) bool {
	return strings.ContainsAny(path, "*?[")
}

func fromBlock(block scfg.Block) (*Config, error) {
	cfg := &Config{}
	for _, d := range block {
		switch d.Name {
		case "ca":
			ca, err := parseCA(d)
			if err != nil {
				return nil, err
			}
			cfg.CAs = append(cfg.CAs, ca)
		case "account":
			a, err := parseAccount(d)
			if err != nil {
				return nil, err
			}
			cfg.Accounts = append(cfg.Accounts, a)
		case "provider":
			p, err := parseProvider(d)
			if err != nil {
				return nil, err
			}
			cfg.Providers = append(cfg.Providers, p)
		case "group":
			g, err := parseGroup(d)
			if err != nil {
				return nil, err
			}
			cfg.Groups = append(cfg.Groups, g)
		case "certificate":
			c, err := parseCertificate(d)
			if err != nil {
				return nil, err
			}
			cfg.Certificates = append(cfg.Certificates, c)
		case "challenge":
			if cfg.GlobalChallenge != nil {
				return nil, fmt.Errorf("duplicate top-level challenge block")
			}
			gc, err := parseGlobalChallenge(d)
			if err != nil {
				return nil, err
			}
			cfg.GlobalChallenge = gc
		default:
			return nil, fmt.Errorf("unknown top-level directive %q", d.Name)
		}
	}
	return cfg, nil
}

func parseCA(d *scfg.Directive) (*CA, error) {
	name, err := singleParam(d)
	if err != nil {
		return nil, err
	}
	ca := &CA{Name: name}
	for _, c := range d.Children {
		switch c.Name {
		case "type":
			if ca.Type, err = singleParam(c); err != nil {
				return nil, fmt.Errorf("ca %q: %w", name, err)
			}
		case "directory":
			if ca.Directory, err = singleParam(c); err != nil {
				return nil, fmt.Errorf("ca %q: %w", name, err)
			}
		case "common-name":
			if ca.CommonName, err = singleParam(c); err != nil {
				return nil, fmt.Errorf("ca %q: %w", name, err)
			}
		case "key":
			if err := parseKey(c, &ca.Key); err != nil {
				return nil, fmt.Errorf("ca %q: %w", name, err)
			}
		case "valid-for":
			s, err := singleParam(c)
			if err != nil {
				return nil, fmt.Errorf("ca %q: %w", name, err)
			}
			ca.ValidFor, err = parseExpiry(s)
			if err != nil {
				return nil, fmt.Errorf("ca %q: valid-for %q: %w", name, s, err)
			}
		case "persist-identifier":
			if ca.PersistIdentifier, err = singleParam(c); err != nil {
				return nil, fmt.Errorf("ca %q: %w", name, err)
			}
		case "profile":
			if ca.Profile, err = singleParam(c); err != nil {
				return nil, fmt.Errorf("ca %q: %w", name, err)
			}
		default:
			return nil, fmt.Errorf("ca %q: unknown directive %q", name, c.Name)
		}
	}
	return ca, nil
}

func parseAccount(d *scfg.Directive) (*Account, error) {
	name, err := singleParam(d)
	if err != nil {
		return nil, err
	}
	a := &Account{Name: name}
	for _, c := range d.Children {
		switch c.Name {
		case "ca":
			if a.CA, err = singleParam(c); err != nil {
				return nil, fmt.Errorf("account %q: %w", name, err)
			}
		case "email":
			if a.Email, err = singleParam(c); err != nil {
				return nil, fmt.Errorf("account %q: %w", name, err)
			}
		case "eab":
			if a.EAB != nil {
				return nil, fmt.Errorf("account %q: duplicate eab block", name)
			}
			eab, err := parseEAB(c)
			if err != nil {
				return nil, fmt.Errorf("account %q: %w", name, err)
			}
			a.EAB = eab
		default:
			return nil, fmt.Errorf("account %q: unknown directive %q", name, c.Name)
		}
	}
	return a, nil
}

func parseEAB(d *scfg.Directive) (*EABSpec, error) {
	if len(d.Params) != 0 {
		return nil, fmt.Errorf("eab: want no arguments, got %d", len(d.Params))
	}
	eab := &EABSpec{}
	seenKID := false
	seenHMACKey := false
	for _, c := range d.Children {
		switch c.Name {
		case "kid":
			if seenKID {
				return nil, fmt.Errorf("eab: duplicate kid directive")
			}
			seenKID = true
			var err error
			if eab.KID, err = singleParam(c); err != nil {
				return nil, fmt.Errorf("eab: %w", err)
			}
		case "hmac-key":
			if seenHMACKey {
				return nil, fmt.Errorf("eab: duplicate hmac-key block")
			}
			seenHMACKey = true
			v, err := parseSecretValue(c)
			if err != nil {
				return nil, fmt.Errorf("eab: hmac-key: %w", err)
			}
			eab.HMACKey = v
		default:
			return nil, fmt.Errorf("eab: unknown directive %q", c.Name)
		}
	}
	return eab, nil
}

func parseProvider(d *scfg.Directive) (*Provider, error) {
	name, err := singleParam(d)
	if err != nil {
		return nil, err
	}
	p := &Provider{Name: name, Fields: map[string][]string{}}
	for _, c := range d.Children {
		switch c.Name {
		case "type":
			if p.Type, err = singleParam(c); err != nil {
				return nil, fmt.Errorf("provider %q: %w", name, err)
			}
		case "driver":
			if p.Driver, err = singleParam(c); err != nil {
				return nil, fmt.Errorf("provider %q: %w", name, err)
			}
		case "propagation":
			v, err := singleParam(c)
			if err != nil {
				return nil, fmt.Errorf("provider %q: %w", name, err)
			}
			switch v {
			case "provider":
				p.HandlesPropagation = true
			case "tool":
				p.HandlesPropagation = false
			default:
				return nil, fmt.Errorf("provider %q: propagation %q: want \"provider\" or \"tool\"", name, v)
			}
		case "secret":
			s, err := parseSecret(c)
			if err != nil {
				return nil, fmt.Errorf("provider %q: %w", name, err)
			}
			p.Secrets = append(p.Secrets, s)
		default:
			if len(c.Children) > 0 {
				return nil, fmt.Errorf("provider %q: unexpected block %q", name, c.Name)
			}
			p.Fields[c.Name] = append([]string(nil), c.Params...)
		}
	}
	return p, nil
}

func parseSecret(d *scfg.Directive) (*Secret, error) {
	name, err := singleParam(d)
	if err != nil {
		return nil, fmt.Errorf("secret: %w", err)
	}
	s := &Secret{Name: name}
	v, err := parseSecretValueChildren(d.Children)
	if err != nil {
		return nil, fmt.Errorf("secret %q: %w", name, err)
	}
	s.File = v.File
	s.Value = v.Value
	s.Env = v.Env
	s.Command = v.Command
	s.SystemdCredential = v.SystemdCredential
	return s, nil
}

func parseSecretValue(d *scfg.Directive) (SecretValue, error) {
	if len(d.Params) != 0 {
		return SecretValue{}, fmt.Errorf("want no arguments, got %d", len(d.Params))
	}
	return parseSecretValueChildren(d.Children)
}

func parseSecretValueChildren(children scfg.Block) (SecretValue, error) {
	var v SecretValue
	for _, c := range children {
		switch c.Name {
		case "file":
			var err error
			if v.File, err = singleParam(c); err != nil {
				return SecretValue{}, err
			}
		case "value":
			var err error
			if v.Value, err = singleParam(c); err != nil {
				return SecretValue{}, err
			}
		case "env":
			var err error
			if v.Env, err = singleParam(c); err != nil {
				return SecretValue{}, err
			}
		case "command":
			if len(c.Params) == 0 {
				return SecretValue{}, fmt.Errorf("command: want at least 1 argument, got 0")
			}
			v.Command = append([]string(nil), c.Params...)
		case "systemd-credential":
			var err error
			if v.SystemdCredential, err = singleParam(c); err != nil {
				return SecretValue{}, err
			}
		default:
			return SecretValue{}, fmt.Errorf("unknown directive %q", c.Name)
		}
	}
	return v, nil
}

func parseCertificate(d *scfg.Directive) (*Certificate, error) {
	name, err := singleParam(d)
	if err != nil {
		return nil, err
	}
	c := &Certificate{Name: name}
	for _, child := range d.Children {
		switch child.Name {
		case "account":
			if c.Account, err = singleParam(child); err != nil {
				return nil, fmt.Errorf("certificate %q: %w", name, err)
			}
		case "ca":
			if c.CA, err = singleParam(child); err != nil {
				return nil, fmt.Errorf("certificate %q: %w", name, err)
			}
		case "groups":
			if len(child.Params) == 0 {
				return nil, fmt.Errorf("certificate %q: groups requires at least one value", name)
			}
			c.Groups = append(c.Groups, child.Params...)
		case "requires":
			if len(child.Params) == 0 {
				return nil, fmt.Errorf("certificate %q: requires needs at least one value", name)
			}
			c.Requires = append(c.Requires, child.Params...)
		case "wants":
			if len(child.Params) == 0 {
				return nil, fmt.Errorf("certificate %q: wants needs at least one value", name)
			}
			c.Wants = append(c.Wants, child.Params...)
		case "names":
			if len(child.Params) == 0 {
				return nil, fmt.Errorf("certificate %q: names requires at least one value", name)
			}
			c.Names = append([]string(nil), child.Params...)
		case "valid-for":
			s, err := singleParam(child)
			if err != nil {
				return nil, fmt.Errorf("certificate %q: %w", name, err)
			}
			c.ValidFor, err = parseExpiry(s)
			if err != nil {
				return nil, fmt.Errorf("certificate %q: valid-for %q: %w", name, s, err)
			}
		case "preferred-chain":
			if c.PreferredChain, err = singleParam(child); err != nil {
				return nil, fmt.Errorf("certificate %q: %w", name, err)
			}
		case "profile":
			if c.Profile, err = singleParam(child); err != nil {
				return nil, fmt.Errorf("certificate %q: %w", name, err)
			}
		case "key":
			if err := parseKey(child, &c.Key); err != nil {
				return nil, fmt.Errorf("certificate %q: %w", name, err)
			}
		case "challenge":
			if err := parseCertChallenge(child, &c.Challenge); err != nil {
				return nil, fmt.Errorf("certificate %q: %w", name, err)
			}
		case "renew":
			if err := parseRenew(child, &c.Renew); err != nil {
				return nil, fmt.Errorf("certificate %q: %w", name, err)
			}
		case "deploy":
			dep, err := parseDeploy(child)
			if err != nil {
				return nil, fmt.Errorf("certificate %q: %w", name, err)
			}
			c.Deploys = append(c.Deploys, dep)
		case "reload":
			cmd, err := singleParam(child)
			if err != nil {
				return nil, fmt.Errorf("certificate %q: %w", name, err)
			}
			c.Reloads = append(c.Reloads, cmd)
		case "tlsa":
			t, err := parseTLSA(child)
			if err != nil {
				return nil, fmt.Errorf("certificate %q: %w", name, err)
			}
			c.TLSA = t
		case "failover":
			if c.Failover != nil {
				return nil, fmt.Errorf("certificate %q: duplicate failover block", name)
			}
			fo, err := parseFailover(child)
			if err != nil {
				return nil, fmt.Errorf("certificate %q: %w", name, err)
			}
			c.Failover = fo
		default:
			return nil, fmt.Errorf("certificate %q: unknown directive %q", name, child.Name)
		}
	}
	return c, nil
}

func parseGroup(d *scfg.Directive) (*Group, error) {
	name, err := singleParam(d)
	if err != nil {
		return nil, err
	}
	g := &Group{Name: name}
	for _, child := range d.Children {
		switch child.Name {
		case "account":
			if g.Account, err = singleParam(child); err != nil {
				return nil, fmt.Errorf("group %q: %w", name, err)
			}
		case "ca":
			if g.CA, err = singleParam(child); err != nil {
				return nil, fmt.Errorf("group %q: %w", name, err)
			}
		case "profile":
			if g.Profile, err = singleParam(child); err != nil {
				return nil, fmt.Errorf("group %q: %w", name, err)
			}
		case "preferred-chain":
			if g.PreferredChain, err = singleParam(child); err != nil {
				return nil, fmt.Errorf("group %q: %w", name, err)
			}
		case "valid-for":
			s, err := singleParam(child)
			if err != nil {
				return nil, fmt.Errorf("group %q: %w", name, err)
			}
			g.ValidFor, err = parseExpiry(s)
			if err != nil {
				return nil, fmt.Errorf("group %q: valid-for %q: %w", name, s, err)
			}
		case "key":
			if err := parseKey(child, &g.Key); err != nil {
				return nil, fmt.Errorf("group %q: %w", name, err)
			}
		case "challenge":
			if err := parseCertChallenge(child, &g.Challenge); err != nil {
				return nil, fmt.Errorf("group %q: %w", name, err)
			}
		case "renew":
			if err := parseRenew(child, &g.Renew); err != nil {
				return nil, fmt.Errorf("group %q: %w", name, err)
			}
		case "deploy":
			dep, err := parseDeploy(child)
			if err != nil {
				return nil, fmt.Errorf("group %q: %w", name, err)
			}
			g.Deploys = append(g.Deploys, dep)
		case "reload":
			cmd, err := singleParam(child)
			if err != nil {
				return nil, fmt.Errorf("group %q: %w", name, err)
			}
			g.Reloads = append(g.Reloads, cmd)
		default:
			return nil, fmt.Errorf("group %q: unknown directive %q", name, child.Name)
		}
	}
	return g, nil
}

func parseFailover(d *scfg.Directive) ([]Issuer, error) {
	if len(d.Params) != 0 {
		return nil, fmt.Errorf("failover: takes no arguments")
	}
	issuers := []Issuer{}
	for _, c := range d.Children {
		switch c.Name {
		case "account":
			name, err := singleParam(c)
			if err != nil {
				return nil, fmt.Errorf("failover: %w", err)
			}
			issuers = append(issuers, Issuer{Account: name})
		case "ca":
			name, err := singleParam(c)
			if err != nil {
				return nil, fmt.Errorf("failover: %w", err)
			}
			issuers = append(issuers, Issuer{CA: name})
		default:
			return nil, fmt.Errorf("failover: unknown directive %q", c.Name)
		}
	}
	if len(issuers) == 0 {
		return nil, fmt.Errorf("failover: at least one account or ca is required")
	}
	return issuers, nil
}

func parseTLSA(d *scfg.Directive) (*TLSASpec, error) {
	if len(d.Params) != 0 {
		return nil, fmt.Errorf("tlsa: takes no arguments")
	}
	t := &TLSASpec{}
	for _, c := range d.Children {
		switch c.Name {
		case "provider":
			s, err := singleParam(c)
			if err != nil {
				return nil, fmt.Errorf("tlsa: %w", err)
			}
			t.Provider = s
		case "port":
			s, err := singleParam(c)
			if err != nil {
				return nil, fmt.Errorf("tlsa: %w", err)
			}
			port, proto, err := parseTLSAPort(s)
			if err != nil {
				return nil, fmt.Errorf("tlsa: port %q: %w", s, err)
			}
			t.Ports = append(t.Ports, TLSAPort{Port: port, Protocol: proto})
		case "ttl":
			s, err := singleParam(c)
			if err != nil {
				return nil, fmt.Errorf("tlsa: %w", err)
			}
			n, err := strconv.Atoi(s)
			if err != nil || n <= 0 {
				return nil, fmt.Errorf("tlsa: ttl %q: must be a positive integer", s)
			}
			t.TTL = n
		case "type":
			if len(c.Params) != 3 {
				return nil, fmt.Errorf("tlsa: type takes three integers (usage selector matching-type)")
			}
			vals := make([]int, 3)
			for i, p := range c.Params {
				n, err := strconv.Atoi(p)
				if err != nil {
					return nil, fmt.Errorf("tlsa: type %q: %w", p, err)
				}
				vals[i] = n
			}
			t.Usage = vals[0]
			t.Selector = vals[1]
			t.MatchingType = vals[2]
		default:
			return nil, fmt.Errorf("tlsa: unknown directive %q", c.Name)
		}
	}
	return t, nil
}

func parseTLSAPort(s string) (int, string, error) {
	proto := "tcp"
	port := s
	if i := strings.IndexByte(s, '/'); i >= 0 {
		port = s[:i]
		proto = strings.ToLower(s[i+1:])
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return 0, "", fmt.Errorf("port must be an integer")
	}
	if n < 1 || n > 65535 {
		return 0, "", fmt.Errorf("port must be in 1..65535")
	}
	if proto != "tcp" && proto != "udp" && proto != "sctp" {
		return 0, "", fmt.Errorf("protocol %q: must be tcp, udp, or sctp", proto)
	}
	return n, proto, nil
}

func parseKey(d *scfg.Directive, k *KeySpec) error {
	for _, c := range d.Children {
		switch c.Name {
		case "type":
			s, err := singleParam(c)
			if err != nil {
				return err
			}
			k.Type = s
		case "curve":
			s, err := singleParam(c)
			if err != nil {
				return err
			}
			k.Curve = s
		case "bits":
			s, err := singleParam(c)
			if err != nil {
				return err
			}
			n, err := strconv.Atoi(s)
			if err != nil {
				return fmt.Errorf("key: bits %q: %w", s, err)
			}
			k.Bits = n
		case "reuse":
			if len(c.Params) != 0 {
				return fmt.Errorf("key: reuse takes no arguments")
			}
			k.Reuse = true
		default:
			return fmt.Errorf("key: unknown directive %q", c.Name)
		}
	}
	return nil
}

func parseCertChallenge(d *scfg.Directive, ch *ChallengeSpec) error {
	t, err := singleParam(d)
	if err != nil {
		return fmt.Errorf("challenge: %w", err)
	}
	ch.Type = t
	for _, c := range d.Children {
		switch c.Name {
		case "webroot":
			if ch.Webroot, err = singleParam(c); err != nil {
				return fmt.Errorf("challenge: %w", err)
			}
		case "listen":
			if ch.Listen, err = singleParam(c); err != nil {
				return fmt.Errorf("challenge: %w", err)
			}
		case "provider":
			if ch.Provider, err = singleParam(c); err != nil {
				return fmt.Errorf("challenge: %w", err)
			}
		case "propagation-timeout":
			s, err := singleParam(c)
			if err != nil {
				return fmt.Errorf("challenge: %w", err)
			}
			dur, err := time.ParseDuration(s)
			if err != nil {
				return fmt.Errorf("challenge: propagation-timeout %q: %w", s, err)
			}
			ch.PropagationTimeout = &dur
		case "alias-fqdn":
			if ch.AliasFQDN, err = singleParam(c); err != nil {
				return fmt.Errorf("challenge: %w", err)
			}
		case "alias-domain":
			if ch.AliasDomain, err = singleParam(c); err != nil {
				return fmt.Errorf("challenge: %w", err)
			}
		default:
			return fmt.Errorf("challenge: unknown directive %q", c.Name)
		}
	}
	return nil
}

func parseRenew(d *scfg.Directive, r *RenewSpec) error {
	for _, c := range d.Children {
		switch c.Name {
		case "before-expiry":
			s, err := singleParam(c)
			if err != nil {
				return fmt.Errorf("renew: %w", err)
			}
			dur, err := parseExpiry(s)
			if err != nil {
				return fmt.Errorf("renew: before-expiry %q: %w", s, err)
			}
			r.BeforeExpiry = dur
		default:
			return fmt.Errorf("renew: unknown directive %q", c.Name)
		}
	}
	return nil
}

func parseDeploy(d *scfg.Directive) (*Deploy, error) {
	name, err := singleParam(d)
	if err != nil {
		return nil, fmt.Errorf("deploy: %w", err)
	}
	dep := &Deploy{Name: name}
	for _, c := range d.Children {
		switch c.Name {
		case "cert":
			dep.Cert, err = singleParam(c)
		case "chain":
			dep.Chain, err = singleParam(c)
		case "fullchain":
			dep.Fullchain, err = singleParam(c)
		case "key":
			dep.Key, err = singleParam(c)
		case "cert-der":
			dep.CertDER, err = singleParam(c)
		case "key-der":
			dep.KeyDER, err = singleParam(c)
		case "owner":
			dep.Owner, err = singleParam(c)
		case "group":
			dep.Group, err = singleParam(c)
		case "mode":
			s, perr := singleParam(c)
			if perr != nil {
				err = perr
				break
			}
			n, perr := strconv.ParseUint(s, 0, 32)
			if perr != nil {
				return nil, fmt.Errorf("deploy %q: mode %q: %w", name, s, perr)
			}
			if n > 0o777 {
				return nil, fmt.Errorf("deploy %q: mode %q: must be <= 0777", name, s)
			}
			m := fs.FileMode(n)
			dep.Mode = &m
		case "before":
			dep.Before, err = singleParam(c)
		case "after":
			dep.After, err = singleParam(c)
		default:
			return nil, fmt.Errorf("deploy %q: unknown directive %q", name, c.Name)
		}
		if err != nil {
			return nil, fmt.Errorf("deploy %q: %w", name, err)
		}
	}
	return dep, nil
}

func parseGlobalChallenge(d *scfg.Directive) (*GlobalChallenge, error) {
	t, err := singleParam(d)
	if err != nil {
		return nil, fmt.Errorf("challenge: %w", err)
	}
	gc := &GlobalChallenge{Type: t}
	for _, c := range d.Children {
		switch c.Name {
		case "webroot":
			if gc.Webroot, err = singleParam(c); err != nil {
				return nil, fmt.Errorf("challenge: %w", err)
			}
		case "listen":
			if gc.Listen, err = singleParam(c); err != nil {
				return nil, fmt.Errorf("challenge: %w", err)
			}
		default:
			return nil, fmt.Errorf("challenge: unknown directive %q", c.Name)
		}
	}
	return gc, nil
}

func singleParam(d *scfg.Directive) (string, error) {
	if len(d.Params) != 1 {
		return "", fmt.Errorf("%s: want exactly 1 argument, got %d", d.Name, len(d.Params))
	}
	return d.Params[0], nil
}

func parseExpiry(s string) (time.Duration, error) {
	if len(s) > 1 && s[len(s)-1] == 'd' {
		n, err := strconv.Atoi(s[:len(s)-1])
		if err != nil {
			return 0, err
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}
