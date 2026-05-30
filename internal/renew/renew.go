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
	"os"
	"time"

	"foundry.fsky.io/fsky/gibcert/internal/config"
	"foundry.fsky.io/fsky/gibcert/internal/storage"
)

const DefaultBeforeExpiry = 30 * 24 * time.Hour

type Decision struct {
	Due       bool
	Reason    string
	NotBefore time.Time
	NotAfter  time.Time
}

func ShouldRenew(cert *config.Certificate, store *storage.Store, now time.Time) Decision {
	c, err := LoadLeaf(cert, store)
	if err != nil {
		return Decision{Due: true, Reason: "certificate missing or unreadable"}
	}

	before := RenewalWindow(cert, c.NotBefore, c.NotAfter)
	if !c.NotAfter.After(now) {
		return Decision{Due: true, Reason: "certificate expired", NotBefore: c.NotBefore, NotAfter: c.NotAfter}
	}
	if !c.NotAfter.After(now.Add(before)) {
		return Decision{Due: true, Reason: "certificate inside renewal window", NotBefore: c.NotBefore, NotAfter: c.NotAfter}
	}
	d := Decision{Due: false, Reason: "certificate still valid", NotBefore: c.NotBefore, NotAfter: c.NotAfter}

	// ACME Renewal Information can pull renewal earlier than the expiry-based
	// window. Read the cached suggestion best-effort; absence or errors leave
	// the expiry-based decision untouched.
	if meta, err := store.LoadCertMeta(cert.Name); err == nil {
		d = ApplyARI(d, meta.ARI, c.SerialNumber.String(), now)
	}
	return d
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
