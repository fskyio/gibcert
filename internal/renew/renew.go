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

package renew

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"gitfield.org/fsky/gibcert/internal/config"
	"gitfield.org/fsky/gibcert/internal/localca"
	"gitfield.org/fsky/gibcert/internal/storage"
)

const DefaultBeforeExpiry = 30 * 24 * time.Hour

type Decision struct {
	Due       bool
	Reason    string
	NotBefore time.Time
	NotAfter  time.Time
}

// ShouldRenew is the shared currentness decision for plan, apply, renew and
// status commands. SAN or known issuer drift makes even an unexpired leaf due.
func ShouldRenew(cfg *config.Config, cert *config.Certificate, store *storage.Store, now time.Time) Decision {
	c, err := LoadLeaf(cert, store)
	if err != nil {
		return Decision{Due: true, Reason: "certificate missing or unreadable"}
	}
	d := Decision{Reason: "certificate still valid", NotBefore: c.NotBefore, NotAfter: c.NotAfter}
	if !namesMatch(cert.Names, c) {
		d.Due, d.Reason = true, "certificate names differ from configuration"
		return d
	}
	meta, _ := store.LoadCertMeta(cert.Name)
	if issuerChanged(cfg, cert, meta, c) {
		d.Due, d.Reason = true, "certificate issuer differs from configuration"
		return d
	}

	before := RenewalWindow(cert, c.NotBefore, c.NotAfter)
	if !c.NotAfter.After(now) {
		return Decision{Due: true, Reason: "certificate expired", NotBefore: c.NotBefore, NotAfter: c.NotAfter}
	}
	if !c.NotAfter.After(now.Add(before)) {
		return Decision{Due: true, Reason: "certificate inside renewal window", NotBefore: c.NotBefore, NotAfter: c.NotAfter}
	}
	if ca, ok, _ := config.LocalCAForCertificate(cfg, cert); ok {
		if status := localca.CheckCA(ca, store, now); !status.Ready {
			d.Due, d.Reason = true, status.Reason
			return d
		}
	}

	// ACME Renewal Information can pull renewal earlier than the expiry-based
	// window. Read the cached suggestion best-effort; absence or errors leave
	// the expiry-based decision untouched.
	if meta != nil {
		d = ApplyARI(d, meta.ARI, c.SerialNumber.String(), now)
	}
	return d
}

// namesMatch compares SAN sets, never CommonName or metadata's requested names.
// Wildcards remain literal; IPv4 and IPv6 spellings use net.IP's canonical form.
func namesMatch(names []string, leaf *x509.Certificate) bool {
	type nameKey struct {
		value string
		ip    bool
	}
	actual := make(map[nameKey]bool, len(leaf.DNSNames)+len(leaf.IPAddresses))
	for _, name := range leaf.DNSNames {
		actual[nameKey{value: strings.ToLower(name)}] = false
	}
	for _, ip := range leaf.IPAddresses {
		actual[nameKey{value: ip.String(), ip: true}] = false
	}
	remaining := len(actual)
	for _, name := range names {
		var key nameKey
		if ip := net.ParseIP(name); ip != nil {
			key = nameKey{value: ip.String(), ip: true}
		} else {
			key = nameKey{value: strings.ToLower(name)}
		}
		matched, found := actual[key]
		if !found {
			return false
		}
		if !matched {
			actual[key] = true
			remaining--
		}
	}
	return remaining == 0
}

func issuerChanged(cfg *config.Config, cert *config.Certificate, meta *storage.CertMeta, leaf *x509.Certificate) bool {
	// Imported, incomplete or stale metadata cannot establish issuer ownership.
	// Legacy records with a complete account/directory or local directory still
	// identify their issuer without requiring newer optional metadata fields.
	if meta == nil || (meta.SerialNumber != "" && meta.SerialNumber != leaf.SerialNumber.String()) {
		return false
	}
	issuerType := meta.IssuerType
	if issuerType == "" {
		if strings.HasPrefix(meta.Directory, "local:") {
			issuerType = "local"
		} else if meta.Account != "" && meta.Directory != "" {
			issuerType = "acme"
		}
	}
	storedCA := meta.CA
	switch issuerType {
	case "local":
		if storedCA == "" && strings.HasPrefix(meta.Directory, "local:") {
			storedCA = strings.TrimPrefix(meta.Directory, "local:")
		}
		if storedCA == "" {
			return false
		}
	case "acme":
		if meta.Account == "" || meta.Directory == "" {
			return false
		}
	default:
		return false
	}
	ca, local, err := config.LocalCAForCertificate(cfg, cert)
	if err != nil {
		return false
	}
	if local {
		return issuerType != "local" || storedCA != ca.Name ||
			(meta.Directory != "" && meta.Directory != localca.Directory(ca.Name))
	}
	issuers, err := config.ACMEIssuersForCertificate(cfg, cert)
	if err != nil {
		return false
	}
	for _, account := range issuers {
		if issuerType == "acme" && meta.Account == account.Name && meta.Directory == account.Directory &&
			(meta.CA == "" || meta.CA == account.CA) {
			return false
		}
	}
	return true
}

// RenewalWindow returns the configured renewal window, or a lifetime-aware
// default when before-expiry is unset. The dynamic default is one third of the
// certificate lifetime, capped at the historical 30 day default.
func RenewalWindow(cert *config.Certificate, notBefore, notAfter time.Time) time.Duration {
	if cert.Renew.BeforeExpiry != 0 {
		return cert.Renew.BeforeExpiry
	}
	lifetime := notAfter.Sub(notBefore)
	if lifetime <= 0 {
		return DefaultBeforeExpiry
	}
	if byLifetime := lifetime / 3; byLifetime < DefaultBeforeExpiry {
		return byLifetime
	}
	return DefaultBeforeExpiry
}

// ApplyARI overlays cached ACME Renewal Information (RFC 9773) onto a base
// renewal decision. It can only make renewal due earlier, never later: a base
// decision that is already due is returned unchanged. The cached info is
// ignored if it is absent, belongs to a different leaf (serial mismatch), or
// carries no suggested window. When the server's selected time within the
// window has arrived, renewal becomes due.
func ApplyARI(base Decision, ari *storage.CertARI, leafSerial string, now time.Time) Decision {
	if base.Due || ari == nil {
		return base
	}
	if ari.Serial != "" && ari.Serial != leafSerial {
		return base
	}
	if ari.SelectedTime.IsZero() {
		return base
	}
	if !now.Before(ari.SelectedTime) {
		return Decision{
			Due:       true,
			Reason:    "ACME renewal information suggests renewal",
			NotBefore: base.NotBefore,
			NotAfter:  base.NotAfter,
		}
	}
	return base
}

func LoadLeaf(cert *config.Certificate, store *storage.Store) (*x509.Certificate, error) {
	return readLeaf(store.CertPaths(cert.Name).Cert)
}

func readLeaf(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("no PEM certificate in %s", path)
	}
	return x509.ParseCertificate(block.Bytes)
}
