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
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"strings"
	"time"

	"gitfield.org/fsky/gibcert/internal/challenge"
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
	meta, _ := store.LoadCertMeta(cert.Name)
	if !namesCurrent(cert.Names, meta, c) {
		d.Due, d.Reason = true, "certificate names differ from configuration"
		return d
	}
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

// TLSAReconcileReason reports why the TLSA records published for a current
// certificate no longer match its configuration or stored key, or "" when they
// match. Records are stale when a configured (port, name) owner has none
// published, when records remain under an owner that is no longer configured,
// or when none of them covers the stored canonical key (a key rollover whose
// publication failed). Callers check ShouldRenew first; issuing a due
// certificate reconciles its TLSA records itself.
func TLSAReconcileReason(cert *config.Certificate, store *storage.Store) string {
	if cert.TLSA == nil {
		return ""
	}
	meta, err := store.LoadCertMeta(cert.Name)
	switch {
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return "certificate metadata unreadable"
	case err != nil || meta.TLSA == nil:
		return "TLSA records not published"
	}
	want := map[string]bool{}
	for _, owner := range cert.TLSAOwners() {
		want[owner] = true
	}
	have := map[string]bool{}
	for _, rec := range meta.TLSA.Published {
		have[strings.ToLower(rec.Owner)] = true
	}
	if !maps.Equal(want, have) {
		return "published TLSA owners differ from configuration"
	}
	if StoredKeyTLSAUnpublished(cert, store) {
		return "stored key TLSA not published"
	}
	return ""
}

// StoredKeyTLSAUnpublished reports whether deploying cert's stored material
// would put a key in service that its TLSA records are known not to cover:
// gibcert has published TLSA records for cert, yet none of them matches the
// stored canonical key, as after a key rollover whose publication failed.
// Without TLSA metadata (first publication, or state from before TLSA
// tracking) or when the key or metadata cannot be read, it reports false and
// the deploy itself decides.
func StoredKeyTLSAUnpublished(cert *config.Certificate, store *storage.Store) bool {
	if cert.TLSA == nil {
		return false
	}
	meta, err := store.LoadCertMeta(cert.Name)
	if err != nil || meta.TLSA == nil || len(meta.TLSA.Published) == 0 {
		return false
	}
	key, err := storage.ReadKey(store.CertPaths(cert.Name).Key)
	if err != nil {
		return false
	}
	hash, err := challenge.SPKIHash(key.Public(), meta.TLSA.MatchingType)
	if err != nil {
		return false
	}
	value := challenge.TLSARData(meta.TLSA.Usage, meta.TLSA.Selector, meta.TLSA.MatchingType, hash)
	for _, rec := range meta.TLSA.Published {
		if rec.RData == value {
			return false
		}
	}
	return true
}

// nameKey is the comparison form of a certificate name: DNS names compare
// case-insensitively and literally (wildcards are not hostname patterns), IPv4
// and IPv6 spellings use net.IP's canonical form.
type nameKey struct {
	value string
	ip    bool
}

func keyOf(name string) nameKey {
	if ip := net.ParseIP(name); ip != nil {
		return nameKey{value: ip.String(), ip: true}
	}
	return nameKey{value: strings.ToLower(name)}
}

func nameSet(names []string) map[nameKey]bool {
	set := make(map[nameKey]bool, len(names))
	for _, name := range names {
		set[keyOf(name)] = true
	}
	return set
}

// leafSANs returns the leaf's SAN set; CommonName is never consulted.
func leafSANs(leaf *x509.Certificate) map[nameKey]bool {
	set := make(map[nameKey]bool, len(leaf.DNSNames)+len(leaf.IPAddresses))
	for _, name := range leaf.DNSNames {
		set[nameKey{value: strings.ToLower(name)}] = true
	}
	for _, ip := range leaf.IPAddresses {
		set[nameKey{value: ip.String(), ip: true}] = true
	}
	return set
}

// MissingSAN returns the first of names that the leaf does not list literally
// among its SANs. A wildcard SAN never stands in for a hostname. Issuance
// validation and the currentness decision share this rule.
func MissingSAN(leaf *x509.Certificate, names []string) (string, bool) {
	sans := leafSANs(leaf)
	for _, name := range names {
		if !sans[keyOf(name)] {
			return name, true
		}
	}
	return "", false
}

// namesCurrent reports whether the stored leaf still matches the configured
// names. When metadata records the names requested for this exact leaf, SANs
// the CA added on its own are tolerated: the configured set must equal the
// requested set and the leaf must list every configured name. Without such a
// record (missing or stale metadata) the leaf SAN set must equal the
// configured set.
func namesCurrent(names []string, meta *storage.CertMeta, leaf *x509.Certificate) bool {
	want := nameSet(names)
	if meta != nil && len(meta.Names) > 0 && meta.SerialNumber == leaf.SerialNumber.String() {
		_, missing := MissingSAN(leaf, names)
		return !missing && maps.Equal(want, nameSet(meta.Names))
	}
	return maps.Equal(want, leafSANs(leaf))
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
	for i, account := range issuers {
		if issuerType != "acme" || meta.Directory != account.Directory || (meta.CA != "" && meta.CA != account.CA) {
			continue
		}
		// v0.1.0 and v0.2.0 recorded the primary account name even when a
		// failover issuer issued the certificate; its directory and CA still
		// identify that failover.
		if meta.Account == account.Name || (i > 0 && meta.Account == issuers[0].Name) {
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
