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

package plan

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"time"

	"foundry.fsky.io/fsky/gibcert/internal/config"
	"foundry.fsky.io/fsky/gibcert/internal/deploy"
	"foundry.fsky.io/fsky/gibcert/internal/localca"
	"foundry.fsky.io/fsky/gibcert/internal/renew"
	"foundry.fsky.io/fsky/gibcert/internal/storage"
)

type Plan struct {
	Actions []Action
}

type Action struct {
	Subject string
	Verb    string
	Detail  string
}

func (p Plan) Empty() bool {
	return len(p.Actions) == 0
}

func Compute(cfg *config.Config, store *storage.Store, now time.Time) (Plan, error) {
	var p Plan
	for _, account := range cfg.Accounts {
		if action := accountAction(account, store); action != nil {
			p.Actions = append(p.Actions, *action)
		}
	}
	cas := config.CAProfiles(cfg.CAs)
	plannedImplicitAccounts := map[string]bool{}
	plannedLocalCAs := map[string]bool{}
	configuredCerts := map[string]bool{}
	// Preview certificates in the same dependency order the reconcile uses, so
	// the plan reflects execution order. Fall back to config order on the cycle
	// error Validate would already have reported.
	orderedCerts := cfg.Certificates
	if ordered, err := config.OrderCertificates(cfg.Certificates); err == nil {
		orderedCerts = ordered
	}
	for _, cert := range orderedCerts {
		configuredCerts[cert.Name] = true
		certUsesLocalCA := false
		localCAWillChange := false
		if cert.CA != "" {
			ca := cas[cert.CA]
			if ca != nil {
				switch ca.Type {
				case "acme":
					if !plannedImplicitAccounts[ca.Name] {
						plannedImplicitAccounts[ca.Name] = true
						if action := implicitAccountAction(ca, store); action != nil {
							p.Actions = append(p.Actions, *action)
						}
					}
				case "local":
					certUsesLocalCA = true
					if !plannedLocalCAs[ca.Name] {
						plannedLocalCAs[ca.Name] = true
						if action := localCAAction(ca, store, now); action != nil {
							localCAWillChange = true
							p.Actions = append(p.Actions, *action)
						}
					} else if action := localCAAction(ca, store, now); action != nil {
						localCAWillChange = true
					}
				}
			}
		}
		d := renew.ShouldRenew(cert, store, now)
		certWillChange := d.Due || localCAWillChange
		if certWillChange {
			verb := "renew"
			if d.NotAfter.IsZero() {
				verb = "issue"
			}
			if certUsesLocalCA {
				verb = "resign"
				if d.NotAfter.IsZero() {
					verb = "sign"
				}
			}
			p.Actions = append(p.Actions, Action{
				Subject: "certificate " + cert.Name,
				Verb:    verb,
				Detail:  certActionDetail(d, localCAWillChange),
			})
			if cert.TLSA != nil {
				p.Actions = append(p.Actions, tlsaAction(cert, store))
			}
		}

		actions, err := deployActions(cert, store, certWillChange)
		if err != nil {
			return p, err
		}
		p.Actions = append(p.Actions, actions...)
	}
	storedCerts, err := store.ListCertNames()
	if err != nil {
		return p, err
	}
	for _, name := range storedCerts {
		if !configuredCerts[name] {
			p.Actions = append(p.Actions, Action{
				Subject: "orphan certificate " + name,
				Verb:    "review",
				Detail:  "local state exists but certificate is not configured",
			})
		}
	}
	return p, nil
}

func tlsaAction(cert *config.Certificate, store *storage.Store) Action {
	meta, err := store.LoadCertMeta(cert.Name)
	if err != nil || meta == nil || meta.TLSA == nil {
		return Action{
			Subject: "tlsa " + cert.Name,
			Verb:    "bootstrap",
			Detail:  "publish current and next-key fingerprints",
		}
	}
	return Action{
		Subject: "tlsa " + cert.Name,
		Verb:    "rotate",
		Detail:  "promote next key, publish new next-key fingerprint",
	}
}

func certActionDetail(d renew.Decision, localCAWillChange bool) string {
	if localCAWillChange && !d.Due {
		return "local CA changed or missing"
	}
	return d.Reason
}

func accountAction(account *config.Account, store *storage.Store) *Action {
	meta, err := store.LoadAccountMeta(account.Name)
	if err != nil {
		return &Action{
			Subject: "account " + account.Name,
			Verb:    "register",
			Detail:  "account metadata missing",
		}
	}
	var changes []string
	if meta.Directory != account.Directory {
		changes = append(changes, "directory differs")
	}
	if meta.Email != account.Email {
		changes = append(changes, "email differs")
	}
	if len(changes) == 0 {
		return nil
	}
	return &Action{
		Subject: "account " + account.Name,
		Verb:    "update",
		Detail:  join(changes),
	}
}

func implicitAccountAction(ca *config.CA, store *storage.Store) *Action {
	name := config.ImplicitACMEAccountName(ca.Name)
	meta, err := store.LoadAccountMeta(name)
	if err != nil {
		return &Action{
			Subject: "account " + ca.Name,
			Verb:    "register",
			Detail:  "implicit ACME account metadata missing",
		}
	}
	var changes []string
	if meta.Directory != ca.Directory {
		changes = append(changes, "directory differs")
	}
	if meta.Email != "" {
		changes = append(changes, "email differs")
	}
	if len(changes) == 0 {
		return nil
	}
	return &Action{
		Subject: "account " + ca.Name,
		Verb:    "update",
		Detail:  "implicit ACME account " + join(changes),
	}
}

func localCAAction(ca *config.CA, store *storage.Store, now time.Time) *Action {
	status := localca.CheckCA(ca, store, now)
	if status.Ready {
		return nil
	}
	verb := "create"
	if !status.NotAfter.IsZero() {
		verb = "renew"
	}
	return &Action{
		Subject: "ca " + ca.Name,
		Verb:    verb,
		Detail:  status.Reason,
	}
}

func deployActions(cert *config.Certificate, store *storage.Store, certWillChange bool) ([]Action, error) {
	paths := store.CertPaths(cert.Name)
	src, err := readSources(paths)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return pendingDeployActions(cert), nil
		}
		return nil, err
	}

	var actions []Action
	for _, d := range cert.Deploys {
		changes, err := plannedDeployChanges(d, src, certWillChange)
		if err != nil {
			return actions, fmt.Errorf("deploy %q: %w", d.Name, err)
		}
		if len(changes) == 0 {
			continue
		}
		if d.Before != "" {
			actions = append(actions, Action{
				Subject: "hook " + cert.Name + "/" + d.Name,
				Verb:    "run",
				Detail:  "before deploy",
			})
		}
		actions = append(actions, Action{
			Subject: "deploy " + cert.Name + "/" + d.Name,
			Verb:    "update",
			Detail:  join(changes),
		})
		if d.After != "" {
			actions = append(actions, Action{
				Subject: "hook " + cert.Name + "/" + d.Name,
				Verb:    "run",
				Detail:  "after deploy",
			})
		}
	}
	return actions, nil
}

type sources struct {
	cert      []byte
	chain     []byte
	fullchain []byte
	key       []byte
}

func readSources(paths storage.CertPaths) (sources, error) {
	srcCert, err := os.ReadFile(paths.Cert)
	if err != nil {
		return sources{}, err
	}
	srcChain, err := os.ReadFile(paths.Chain)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return sources{}, err
	}
	srcFullchain, err := os.ReadFile(paths.Fullchain)
	if err != nil {
		return sources{}, err
	}
	srcKey, err := os.ReadFile(paths.Key)
	if err != nil {
		return sources{}, err
	}
	return sources{cert: srcCert, chain: srcChain, fullchain: srcFullchain, key: srcKey}, nil
}

func pendingDeployActions(cert *config.Certificate) []Action {
	var actions []Action
	for _, d := range cert.Deploys {
		actions = append(actions, Action{
			Subject: "deploy " + cert.Name + "/" + d.Name,
			Verb:    "pending",
			Detail:  "certificate material not stored yet",
		})
	}
	return actions
}

func plannedDeployChanges(d *config.Deploy, src sources, certWillChange bool) ([]string, error) {
	var changes []string
	var derCert, derKey []byte
	if d.CertDER != "" {
		var err error
		if derCert, err = deploy.CertPEMToDER(src.cert); err != nil {
			return nil, fmt.Errorf("cert-der: %w", err)
		}
	}
	if d.KeyDER != "" {
		var err error
		if derKey, err = deploy.KeyPEMToDER(src.key); err != nil {
			return nil, fmt.Errorf("key-der: %w", err)
		}
	}
	items := []struct {
		name string
		dst  string
		data []byte
		mode os.FileMode
	}{
		{"cert", d.Cert, src.cert, 0o644},
		{"chain", d.Chain, src.chain, 0o644},
		{"fullchain", d.Fullchain, src.fullchain, 0o644},
		{"key", d.Key, src.key, 0o600},
		{"cert-der", d.CertDER, derCert, 0o644},
		{"key-der", d.KeyDER, derKey, 0o600},
	}

	for _, it := range items {
		if it.dst == "" || len(it.data) == 0 {
			continue
		}
		itemChanges, err := plannedFileChanges(it.dst, it.name, it.data, it.mode, d, certWillChange)
		if err != nil {
			return changes, err
		}
		changes = append(changes, itemChanges...)
	}
	return changes, nil
}

func plannedFileChanges(dst, name string, data []byte, defaultMode os.FileMode, d *config.Deploy, certWillChange bool) ([]string, error) {
	info, err := os.Stat(dst)
	if errors.Is(err, os.ErrNotExist) {
		return []string{name + " create"}, nil
	}
	if err != nil {
		return nil, err
	}

	var changes []string
	if certWillChange {
		changes = append(changes, name+" update")
	} else {
		existing, err := os.ReadFile(dst)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(existing, data) {
			changes = append(changes, name+" update")
		}
	}

	desiredMode := info.Mode().Perm()
	if d.Mode != nil {
		desiredMode = *d.Mode
	} else if !info.Mode().IsRegular() {
		desiredMode = defaultMode
	}
	if info.Mode().Perm() != desiredMode {
		changes = append(changes, fmt.Sprintf("%s chmod %#o", name, desiredMode))
	}

	ownerGroupChanges, err := plannedOwnerGroupChanges(info, name, d)
	if err != nil {
		return changes, err
	}
	changes = append(changes, ownerGroupChanges...)
	return changes, nil
}

func plannedOwnerGroupChanges(info os.FileInfo, name string, d *config.Deploy) ([]string, error) {
	return plannedOwnerGroupChangesForOS(info, name, d)
}

func join(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += ", " + p
	}
	return out
}
