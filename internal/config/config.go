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
	"io/fs"
	"time"
)

type Config struct {
	CAs             []*CA
	Accounts        []*Account
	Providers       []*Provider
	Groups          []*Group
	Certificates    []*Certificate
	GlobalChallenge *GlobalChallenge
}

// Group is a named bundle of inheritable certificate settings. A certificate
// that lists the group (via "groups") inherits any field the group sets and may
// override it. Resolution order is: group defaults are applied first, then the
// certificate's own settings override them, and finally "{cert}"/"{name}" path
// templates in deploy targets are expanded. A group cannot set "names" and
// cannot reference other groups. See applyGroups for the merge rules:
//
//   - Scalar settings (issuer, profile, preferred-chain, valid-for, key,
//     challenge, renew): a certificate value, if set, fully replaces the group
//     value; if the certificate leaves it unset, the value is inherited. It is
//     an error for two groups to set the same scalar.
//   - Deploys: merged by name, field by field. A certificate deploy with the
//     same name as an inherited one overrides only the fields it sets; a deploy
//     with a new name is added alongside the inherited ones.
type Group struct {
	Name           string
	Account        string
	CA             string
	Profile        string
	PreferredChain string
	ValidFor       time.Duration
	Key            KeySpec
	Challenge      ChallengeSpec
	Renew          RenewSpec
	Deploys        []*Deploy
	Reloads        []string
}

type CA struct {
	Name              string
	Type              string
	Directory         string
	CommonName        string
	Key               KeySpec
	ValidFor          time.Duration
	PersistIdentifier string
	// Profile is the default ACME certificate profile requested for
	// certificates issued by this CA. Individual certificates may override
	// it. Empty means no profile is requested.
	Profile string
}

type Account struct {
	Name string
	CA   string
	// Directory is resolved from CA during validation.
	Directory string
	Email     string
	EAB       *EABSpec
}

type EABSpec struct {
	KID     string
	HMACKey SecretValue
}

type Provider struct {
	Name               string
	Type               string
	Driver             string
	HandlesPropagation bool
	Fields             map[string][]string
	Secrets            []*Secret
}

type Secret struct {
	Name              string
	File              string
	Value             string
	Env               string
	Command           []string
	SystemdCredential string
}

type SecretValue struct {
	File              string
	Value             string
	Env               string
	Command           []string
	SystemdCredential string
}

type Certificate struct {
	Name    string
	Account string
	CA      string
	// Groups lists the groups whose settings this certificate inherits, in
	// precedence order. It is cleared once applyGroups has merged them in.
	Groups         []string
	Names          []string
	ValidFor       time.Duration
	PreferredChain string
	// Profile is the ACME certificate profile requested for this
	// certificate. It overrides any profile set on the CA. Empty means the
	// CA's profile (if any) is used.
	Profile   string
	Key       KeySpec
	Challenge ChallengeSpec
	Renew     RenewSpec
	Deploys   []*Deploy
	// Reloads are commands run once per reconcile run (not per deploy) when any
	// deploy on this certificate changed. Unlike a deploy "after" hook they
	// carry no per-certificate environment, so identical commands across
	// certificates are coalesced into a single invocation. Inheritable via
	// groups.
	Reloads []string
	TLSA    *TLSASpec
	// Failover lists alternate ACME issuers, in priority order, tried when the
	// primary issuer (account or ca above) cannot issue. Each entry resolves
	// like a certificate's primary issuer: an explicit account, or a ca whose
	// implicit "ca:<name>" account is used. Only valid for ACME certificates.
	Failover []Issuer
	// Requires and Wants name other certificates this one depends on, modelled
	// on systemd's Requires=/Wants=. Both make the named certificates run first
	// (within "apply" and "renew"). Requires additionally gates: if a required
	// certificate fails or is itself skipped during the run, this certificate is
	// skipped (not issued or deployed). Wants is advisory ordering only.
	Requires []string
	Wants    []string
}

// Issuer names an ACME issuer by either an explicit account or a ca (whose
// implicit "ca:<name>" account is used). Exactly one field is set.
type Issuer struct {
	Account string
	CA      string
}

type TLSASpec struct {
	Provider     string
	Ports        []TLSAPort
	TTL          int
	Usage        int
	Selector     int
	MatchingType int
}

type TLSAPort struct {
	Port     int
	Protocol string
}

type KeySpec struct {
	Type  string
	Curve string
	Bits  int
	Reuse bool
}

type ChallengeSpec struct {
	Type               string
	Webroot            string
	Listen             string
	Provider           string
	PropagationTimeout *time.Duration
	AliasFQDN          string
	AliasDomain        string
}

type RenewSpec struct {
	BeforeExpiry time.Duration
}

type Deploy struct {
	Name      string
	Cert      string
	Chain     string
	Fullchain string
	Key       string
	CertDER   string
	KeyDER    string
	Owner     string
	Group     string
	Mode      *fs.FileMode
	Before    string
	After     string
}

type GlobalChallenge struct {
	Type    string
	Webroot string
	Listen  string
}

func ImplicitACMEAccountName(caName string) string {
	return "ca:" + caName
}
