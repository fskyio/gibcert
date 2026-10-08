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

import "fmt"

var builtinCAs = []*CA{
	{
		Name:              "letsencrypt",
		Type:              "acme",
		Directory:         "https://acme-v02.api.letsencrypt.org/directory",
		PersistIdentifier: "letsencrypt.org",
	},
	{
		Name:              "letsencrypt-staging",
		Type:              "acme",
		Directory:         "https://acme-staging-v02.api.letsencrypt.org/directory",
		PersistIdentifier: "letsencrypt.org",
	},
	{
		Name:      "zerossl",
		Type:      "acme",
		Directory: "https://acme.zerossl.com/v2/DV90",
	},
	{
		Name:      "google",
		Type:      "acme",
		Directory: "https://dv.acme-v02.api.pki.goog/directory",
	},
	{
		Name:      "buypass",
		Type:      "acme",
		Directory: "https://api.buypass.com/acme/directory",
	},
	{
		Name:      "sslcom",
		Type:      "acme",
		Directory: "https://acme.ssl.com/sslcom-dv/directory",
	},
}

func CAProfiles(userCAs []*CA) map[string]*CA {
	profiles := map[string]*CA{}
	for _, ca := range builtinCAs {
		cp := *ca
		profiles[ca.Name] = &cp
	}
	for _, ca := range userCAs {
		profiles[ca.Name] = ca
	}
	return profiles
}

func caProfiles(userCAs []*CA) map[string]*CA {
	return CAProfiles(userCAs)
}

// ACMEAccountForCertificate resolves the primary explicit or implicit account.
func ACMEAccountForCertificate(cfg *Config, cert *Certificate) (*Account, error) {
	return acmeIssuerAccount(cfg, Issuer{Account: cert.Account, CA: cert.CA})
}

// ACMEIssuersForCertificate resolves the primary and configured failover issuers
// in priority order. Both issuance and currentness use these identities.
func ACMEIssuersForCertificate(cfg *Config, cert *Certificate) ([]*Account, error) {
	primary, err := ACMEAccountForCertificate(cfg, cert)
	if err != nil {
		return nil, err
	}
	issuers := []*Account{primary}
	for _, issuer := range cert.Failover {
		account, err := acmeIssuerAccount(cfg, issuer)
		if err != nil {
			return nil, fmt.Errorf("failover: %w", err)
		}
		issuers = append(issuers, account)
	}
	return issuers, nil
}

func acmeIssuerAccount(cfg *Config, issuer Issuer) (*Account, error) {
	if issuer.Account != "" {
		for _, account := range cfg.Accounts {
			if account.Name == issuer.Account {
				return account, nil
			}
		}
		return nil, fmt.Errorf("account %q not in config", issuer.Account)
	}
	ca := issuerCA(cfg, issuer.CA)
	if ca == nil {
		return nil, fmt.Errorf("ca %q not in config", issuer.CA)
	}
	if ca.Type != "acme" {
		return nil, fmt.Errorf("ca %q is %s, want acme", ca.Name, ca.Type)
	}
	return &Account{
		Name:      ImplicitACMEAccountName(ca.Name),
		CA:        ca.Name,
		Directory: ca.Directory,
	}, nil
}

// LocalCAForCertificate identifies certificates configured for local signing.
func LocalCAForCertificate(cfg *Config, cert *Certificate) (*CA, bool, error) {
	if cert.CA == "" {
		return nil, false, nil
	}
	ca := issuerCA(cfg, cert.CA)
	if ca == nil {
		return nil, false, fmt.Errorf("ca %q not in config", cert.CA)
	}
	return ca, ca.Type == "local", nil
}

func issuerCA(cfg *Config, name string) *CA {
	for _, ca := range cfg.CAs {
		if ca.Name == name {
			return ca
		}
	}
	for _, ca := range builtinCAs {
		if ca.Name == name {
			return ca
		}
	}
	return nil
}
