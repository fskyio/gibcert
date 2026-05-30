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
	"strings"
)

// applyGroups resolves each certificate's group references into its effective
// fields and expands "{cert}"/"{name}" path templates in deploy targets. It
// mutates certificates in place and returns any resolution errors (unknown
// group references, conflicting settings inherited from multiple groups, bad
// templates). It must run before the per-certificate validation pass so that
// validation sees fully resolved certificates. Resolution is idempotent: a
// certificate's Groups list is cleared once merged, so a second call is a
// no-op.
func (c *Config) applyGroups() []error {
	var errs []error

	groups := map[string]*Group{}
	seen := map[string]bool{}
	for _, g := range c.Groups {
		if seen[g.Name] {
			errs = append(errs, fmt.Errorf("duplicate group %q", g.Name))
			continue
		}
		seen[g.Name] = true
		groups[g.Name] = g
		seenDeploy := map[string]bool{}
		for _, d := range g.Deploys {
			if seenDeploy[d.Name] {
				errs = append(errs, fmt.Errorf("group %q: duplicate deploy %q", g.Name, d.Name))
			}
			seenDeploy[d.Name] = true
		}
	}

	for _, cert := range c.Certificates {
		errs = append(errs, resolveCertGroups(cert, groups)...)
		errs = append(errs, expandCertTemplates(cert)...)
		cert.Reloads = dedupStrings(cert.Reloads)
	}
	return errs
}

func resolveCertGroups(cert *Certificate, groups map[string]*Group) []error {
	refs := cert.Groups
	cert.Groups = nil // mark resolved; makes a second applyGroups a no-op
	if len(refs) == 0 {
		return nil
	}

	var errs []error
	var resolved []*Group
	seen := map[string]bool{}
	for _, name := range refs {
		if seen[name] {
			errs = append(errs, fmt.Errorf("certificate %q: duplicate group reference %q", cert.Name, name))
			continue
		}
		seen[name] = true
		g, ok := groups[name]
		if !ok {
			errs = append(errs, fmt.Errorf("certificate %q: unknown group %q", cert.Name, name))
			continue
		}
		resolved = append(resolved, g)
	}
	if len(resolved) == 0 {
		return errs
	}

	// Issuer: a certificate that names neither account nor ca inherits one from
	// at most one group.
	if cert.Account == "" && cert.CA == "" {
		errs = append(errs, pickGroup(cert.Name, "an issuer", resolved,
			func(g *Group) bool { return g.Account != "" || g.CA != "" },
			func(g *Group) { cert.Account, cert.CA = g.Account, g.CA })...)
	}
	if cert.Profile == "" {
		errs = append(errs, pickGroup(cert.Name, "profile", resolved,
			func(g *Group) bool { return g.Profile != "" },
			func(g *Group) { cert.Profile = g.Profile })...)
	}
	if cert.PreferredChain == "" {
		errs = append(errs, pickGroup(cert.Name, "preferred-chain", resolved,
			func(g *Group) bool { return g.PreferredChain != "" },
			func(g *Group) { cert.PreferredChain = g.PreferredChain })...)
	}
	if cert.ValidFor == 0 {
		errs = append(errs, pickGroup(cert.Name, "valid-for", resolved,
			func(g *Group) bool { return g.ValidFor != 0 },
			func(g *Group) { cert.ValidFor = g.ValidFor })...)
	}
	if isZeroKey(&cert.Key) {
		errs = append(errs, pickGroup(cert.Name, "key", resolved,
			func(g *Group) bool { return !isZeroKey(&g.Key) },
			func(g *Group) { cert.Key = g.Key })...)
	}
	if cert.Challenge.Type == "" {
		errs = append(errs, pickGroup(cert.Name, "challenge", resolved,
			func(g *Group) bool { return g.Challenge.Type != "" },
			func(g *Group) { cert.Challenge = g.Challenge })...)
	}
	if cert.Renew.BeforeExpiry == 0 {
		errs = append(errs, pickGroup(cert.Name, "renew", resolved,
			func(g *Group) bool { return g.Renew.BeforeExpiry != 0 },
			func(g *Group) { cert.Renew = g.Renew })...)
	}

	deploys, derrs := mergeDeploys(cert.Name, resolved, cert.Deploys)
	cert.Deploys = deploys
	errs = append(errs, derrs...)

	// Reloads are additive: every group's reloads, in listed order, followed by
	// the certificate's own. Duplicates are removed by applyGroups.
	var groupReloads []string
	for _, g := range resolved {
		groupReloads = append(groupReloads, g.Reloads...)
	}
	cert.Reloads = append(groupReloads, cert.Reloads...)
	return errs
}

func dedupStrings(in []string) []string {
	if len(in) < 2 {
		return in
	}
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// pickGroup applies the first group that sets a scalar field, reporting an error
// if more than one group sets it (the certificate must then resolve the
// ambiguity itself).
func pickGroup(certName, field string, groups []*Group, isSet func(*Group) bool, apply func(*Group)) []error {
	var errs []error
	var src string
	for _, g := range groups {
		if !isSet(g) {
			continue
		}
		if src != "" {
			errs = append(errs, fmt.Errorf("certificate %q: groups %q and %q both set %s", certName, src, g.Name, field))
			continue
		}
		src = g.Name
		apply(g)
	}
	return errs
}

// mergeDeploys builds the certificate's effective deploys: inherited group
// deploys merged by name (field by field), then overlaid with the
// certificate's own deploys, which win field by field and may add new names.
func mergeDeploys(certName string, groups []*Group, certDeploys []*Deploy) ([]*Deploy, []error) {
	var errs []error
	var order []string
	merged := map[string]*Deploy{}

	for _, g := range groups {
		for _, d := range g.Deploys {
			if cur, ok := merged[d.Name]; ok {
				errs = append(errs, overlayDeploy(cur, d, certName, true)...)
				continue
			}
			cp := *d
			merged[d.Name] = &cp
			order = append(order, d.Name)
		}
	}

	for _, d := range certDeploys {
		if cur, ok := merged[d.Name]; ok {
			overlayDeploy(cur, d, certName, false)
			continue
		}
		cp := *d
		merged[d.Name] = &cp
		order = append(order, d.Name)
	}

	out := make([]*Deploy, 0, len(order))
	for _, name := range order {
		out = append(out, merged[name])
	}
	return out, errs
}

// overlayDeploy copies every field set on over onto base. When strict (two
// groups defining the same deploy name), a field set differently on both is a
// conflict; otherwise over simply wins.
func overlayDeploy(base, over *Deploy, certName string, strict bool) []error {
	var errs []error
	fields := []struct {
		name       string
		base, over *string
	}{
		{"cert", &base.Cert, &over.Cert},
		{"chain", &base.Chain, &over.Chain},
		{"fullchain", &base.Fullchain, &over.Fullchain},
		{"key", &base.Key, &over.Key},
		{"cert-der", &base.CertDER, &over.CertDER},
		{"key-der", &base.KeyDER, &over.KeyDER},
		{"owner", &base.Owner, &over.Owner},
		{"group", &base.Group, &over.Group},
		{"before", &base.Before, &over.Before},
		{"after", &base.After, &over.After},
	}
	for _, f := range fields {
		if *f.over == "" {
			continue
		}
		if strict && *f.base != "" && *f.base != *f.over {
			errs = append(errs, fmt.Errorf("certificate %q: groups set conflicting %s for deploy %q", certName, f.name, base.Name))
			continue
		}
		*f.base = *f.over
	}
	if over.Mode != nil {
		if strict && base.Mode != nil && *base.Mode != *over.Mode {
			errs = append(errs, fmt.Errorf("certificate %q: groups set conflicting mode for deploy %q", certName, base.Name))
		} else {
			base.Mode = over.Mode
		}
	}
	return errs
}

func isZeroKey(k *KeySpec) bool {
	return k.Type == "" && k.Curve == "" && k.Bits == 0 && !k.Reuse
}

// expandCertTemplates rewrites "{cert}" and "{name}" placeholders in deploy
// target paths. Only path fields are templated; hook commands and ownership
// fields are left untouched so shell braces are never mangled.
func expandCertTemplates(cert *Certificate) []error {
	var errs []error
	first := ""
	if len(cert.Names) > 0 {
		first = cert.Names[0]
	}
	repl := map[string]string{"cert": cert.Name, "name": first}
	for _, d := range cert.Deploys {
		for _, p := range []*string{&d.Cert, &d.Chain, &d.Fullchain, &d.Key, &d.CertDER, &d.KeyDER} {
			if *p == "" {
				continue
			}
			out, err := expandTemplate(*p, repl)
			if err != nil {
				errs = append(errs, fmt.Errorf("certificate %q: deploy %q: %w", cert.Name, d.Name, err))
				continue
			}
			*p = out
		}
	}
	return errs
}

func expandTemplate(s string, repl map[string]string) (string, error) {
	if !strings.ContainsRune(s, '{') {
		return s, nil
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '{' {
			b.WriteByte(s[i])
			i++
			continue
		}
		rest := s[i+1:]
		end := strings.IndexByte(rest, '}')
		if end < 0 {
			return "", fmt.Errorf("unterminated template placeholder in %q", s)
		}
		token := rest[:end]
		val, ok := repl[token]
		if !ok {
			return "", fmt.Errorf("unknown template placeholder %q in %q", "{"+token+"}", s)
		}
		if val == "" {
			return "", fmt.Errorf("template placeholder %q in %q expands to nothing", "{"+token+"}", s)
		}
		b.WriteString(val)
		i += 1 + end + 1
	}
	return b.String(), nil
}
