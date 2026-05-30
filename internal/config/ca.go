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
