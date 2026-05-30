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

package acmeclient

import (
	"context"
)

// DirectoryMeta holds the advertised metadata of an ACME directory.
type DirectoryMeta struct {
	RenewalInfo             string
	Terms                   string
	Website                 string
	CAAIdentities           []string
	ExternalAccountRequired bool
	// Profiles maps advertised certificate profile names to their
	// human-readable descriptions. Empty if the CA advertises no profiles.
	Profiles map[string]string
}

// FetchDirectoryMeta retrieves an ACME directory and returns its advertised
// metadata. The fetch is an unauthenticated GET, so no account is required.
func FetchDirectoryMeta(ctx context.Context, directoryURL string) (DirectoryMeta, error) {
	dir, err := newACMEClient(directoryURL, nil).GetDirectory(ctx)
	if err != nil {
		return DirectoryMeta{}, err
	}
	var m DirectoryMeta
	if dir.Meta != nil {
		m.Terms = dir.Meta.TermsOfService
		m.Website = dir.Meta.Website
		m.CAAIdentities = dir.Meta.CAAIdentities
		m.ExternalAccountRequired = dir.Meta.ExternalAccountRequired
		m.Profiles = dir.Meta.Profiles
	}
	m.RenewalInfo = dir.RenewalInfo
	return m, nil
}
