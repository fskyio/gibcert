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

package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"foundry.fsky.io/fsky/gibcert/internal/config"
)

func acct(name string) *config.Account { return &config.Account{Name: name} }

func TestIssueWithFailoverPrimarySucceeds(t *testing.T) {
	issuers := []*config.Account{acct("primary"), acct("backup")}
	var tried []string
	var out bytes.Buffer
	err := issueWithFailover(&out, "foo", issuers, func(a *config.Account) error {
		tried = append(tried, a.Name)
		return nil
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(tried) != 1 || tried[0] != "primary" {
		t.Fatalf("tried %v, want only [primary]", tried)
	}
	if out.Len() != 0 {
		t.Fatalf("unexpected output: %q", out.String())
	}
}

func TestIssueWithFailoverFallsBack(t *testing.T) {
	issuers := []*config.Account{acct("primary"), acct("backup")}
	var tried []string
	var out bytes.Buffer
	err := issueWithFailover(&out, "foo", issuers, func(a *config.Account) error {
		tried = append(tried, a.Name)
		if a.Name == "primary" {
			return errors.New("503 service unavailable")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(tried) != 2 || tried[1] != "backup" {
		t.Fatalf("tried %v, want [primary backup]", tried)
	}
	o := out.String()
	if !strings.Contains(o, "issuer primary failed") || !strings.Contains(o, "trying failover backup") {
		t.Errorf("transition message missing: %q", o)
	}
	if !strings.Contains(o, "issued via failover backup") {
		t.Errorf("success message missing: %q", o)
	}
}

func TestIssueWithFailoverAllFail(t *testing.T) {
	issuers := []*config.Account{acct("primary"), acct("backup")}
	err := issueWithFailover(new(bytes.Buffer), "foo", issuers, func(a *config.Account) error {
		return errors.New("boom-" + a.Name)
	})
	if err == nil {
		t.Fatal("want error, got nil")
	}
	for _, want := range []string{"primary: boom-primary", "backup: boom-backup"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("joined error %q missing %q", err, want)
		}
	}
}

func TestAcmeIssuersForCert(t *testing.T) {
	cfg := &config.Config{
		Accounts: []*config.Account{{Name: "sectigo", CA: "buypass", Directory: "https://api.buypass.com/acme/directory"}},
		Certificates: []*config.Certificate{{
			Name:    "foo",
			Account: "sectigo",
			Failover: []config.Issuer{
				{CA: "letsencrypt"},
				{Account: "sectigo"},
			},
		}},
	}
	issuers, err := acmeIssuersForCert(cfg, cfg.Certificates[0])
	if err != nil {
		t.Fatalf("acmeIssuersForCert: %v", err)
	}
	got := []string{issuers[0].Name, issuers[1].Name, issuers[2].Name}
	want := []string{"sectigo", config.ImplicitACMEAccountName("letsencrypt"), "sectigo"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("issuer[%d]: got %q, want %q", i, got[i], want[i])
		}
	}
	// The implicit letsencrypt account should carry the builtin directory.
	if issuers[1].Directory == "" {
		t.Error("implicit letsencrypt issuer has empty directory")
	}
}
