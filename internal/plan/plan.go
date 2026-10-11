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
	"strings"
	"time"

	"gitfield.org/fsky/gibcert/internal/config"
	"gitfield.org/fsky/gibcert/internal/deploy"
	"gitfield.org/fsky/gibcert/internal/localca"
	"gitfield.org/fsky/gibcert/internal/renew"
	"gitfield.org/fsky/gibcert/internal/storage"
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

// Compute previews what apply would do. It works offline: remote deploy
// targets are planned from the deploy records, without contacting the hosts.
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
							p.Actions = append(p.Actions, *action)
						}
					}
				}
			}
		}
		d := renew.ShouldRenew(cfg, cert, store, now)
		certWillChange := d.Due
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
				Detail:  d.Reason,
			})
			if cert.TLSA != nil {
				p.Actions = append(p.Actions, tlsaAction(cert, store))
			}
		} else if reason := renew.TLSAReconcileReason(cert, store); reason != "" {
			p.Actions = append(p.Actions, Action{
				Subject: "tlsa " + cert.Name,
				Verb:    "reconcile",
				Detail:  reason,
			})
		}

		actions, err := deployActions(cert, cfg, store, certWillChange)
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

func deployActions(cert *config.Certificate, cfg *config.Config, store *storage.Store, certWillChange bool) ([]Action, error) {
	paths := store.CertPaths(cert.Name)
	src, err := readSources(paths)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return pendingDeployActions(cert), nil
		}
		return nil, err
	}
	meta, err := store.LoadCertMeta(cert.Name)
	if errors.Is(err, os.ErrNotExist) {
		meta = &storage.CertMeta{Name: cert.Name}
	} else if err != nil {
		return nil, fmt.Errorf("load cert metadata: %w", err)
	}
	material := deploy.Material{Cert: src.cert, Chain: src.chain, Fullchain: src.fullchain, Key: src.key}

	var actions []Action
	for _, d := range cert.Deploys {
		req, reqErr := deploy.NewRequest(cert.Name, d, material)
		for _, host := range deploy.Hosts(d) {
			if host != "" {
				actions = append(actions, remoteDeployActions(cert, d, host, cfg, meta, req, reqErr, certWillChange)...)
				continue
			}
			changes, content, err := plannedDeployChanges(d, src, certWillChange)
			if err != nil {
				return actions, fmt.Errorf("deploy %q: %w", d.Name, err)
			}
			// The after hook also runs for kinds not recorded as deployed,
			// which is how a failed hook is retried.
			var unseen []string
			if reqErr == nil {
				unseen = deploy.UnseenKinds(meta, req, "")
			}
			label := targetLabel(cert, d, "")
			switch {
			case len(changes) > 0:
				actions = append(actions, deployTargetActions(d, label, "update", join(changes), content, content || len(unseen) > 0)...)
			case len(unseen) > 0 && d.After != "":
				actions = append(actions, deployTargetActions(d, label, "record", strings.Join(unseen, ", ")+" not recorded as deployed", false, true)...)
			}
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
		for _, host := range deploy.Hosts(d) {
			actions = append(actions, Action{
				Subject: "deploy " + targetLabel(cert, d, host),
				Verb:    "pending",
				Detail:  "certificate material not stored yet",
			})
		}
	}
	return actions
}

func targetLabel(cert *config.Certificate, d *config.Deploy, host string) string {
	label := cert.Name + "/" + d.Name
	if host != "" {
		label += "@" + host
	}
	return label
}

// deployTargetActions returns the deploy action for one target, preceded by
// its before hook when before is set and followed by its after hook when
// after is set. Apply runs the before hook only when content changes, and the
// after hook when content changes or a kind is not recorded as deployed.
func deployTargetActions(d *config.Deploy, label, verb, detail string, before, after bool) []Action {
	var actions []Action
	if before && d.Before != "" {
		actions = append(actions, Action{Subject: "hook " + label, Verb: "run", Detail: "before deploy"})
	}
	actions = append(actions, Action{Subject: "deploy " + label, Verb: verb, Detail: detail})
	if after && d.After != "" {
		actions = append(actions, Action{Subject: "hook " + label, Verb: "run", Detail: "after deploy"})
	}
	return actions
}

// remoteDeployActions plans one target on one remote host from the deploy
// records alone; the host is never contacted. Problems become actions, never
// errors.
func remoteDeployActions(cert *config.Certificate, d *config.Deploy, host string, cfg *config.Config, meta *storage.CertMeta, req deploy.Request, reqErr error, certWillChange bool) []Action {
	label := targetLabel(cert, d, host)
	problem := func(verb, detail string) []Action {
		return []Action{{Subject: "deploy " + label, Verb: verb, Detail: detail}}
	}
	if cfg.FindHost(host) == nil {
		return problem("error", fmt.Sprintf("host %q is not configured", host))
	}
	if certWillChange {
		dests := []struct{ kind, dst string }{
			{"cert", d.Cert}, {"chain", d.Chain}, {"fullchain", d.Fullchain},
			{"key", d.Key}, {"cert-der", d.CertDER}, {"key-der", d.KeyDER},
		}
		var kinds []string
		for _, it := range dests {
			if it.dst != "" {
				kinds = append(kinds, it.kind)
			}
		}
		if len(kinds) == 0 {
			return nil
		}
		return deployTargetActions(d, label, "update", strings.Join(kinds, ", "), true, true)
	}
	if reqErr != nil {
		return problem("error", reqErr.Error())
	}
	recorded := deploy.RecordedOnHost(meta, req, host)
	if recorded.Current() {
		return nil
	}
	var changes []string
	for _, k := range recorded.Unseen {
		changes = append(changes, k+" update")
	}
	changes = append(changes, recorded.Attrs...)
	hooks := len(recorded.Unseen) > 0
	if recorded.Failure == nil {
		return deployTargetActions(d, label, "update", join(changes), hooks, hooks)
	}
	detail := "last attempt failed: " + recorded.Failure.Error
	if len(changes) > 0 {
		detail = join(changes) + "; " + detail
	}
	return deployTargetActions(d, label, "retry", detail, hooks, hooks)
}

// plannedDeployChanges lists the changes deploying d would make on this
// machine, and reports whether any of them rewrites content.
func plannedDeployChanges(d *config.Deploy, src sources, certWillChange bool) ([]string, bool, error) {
	var changes []string
	content := false
	var derCert, derKey []byte
	if d.CertDER != "" {
		var err error
		if derCert, err = deploy.CertPEMToDER(src.cert); err != nil {
			return nil, false, fmt.Errorf("cert-der: %w", err)
		}
	}
	if d.KeyDER != "" {
		var err error
		if derKey, err = deploy.KeyPEMToDER(src.key); err != nil {
			return nil, false, fmt.Errorf("key-der: %w", err)
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
		itemChanges, itemContent, err := plannedFileChanges(it.dst, it.name, it.data, it.mode, d, certWillChange)
		if err != nil {
			return changes, content, err
		}
		changes = append(changes, itemChanges...)
		content = content || itemContent
	}
	return changes, content, nil
}

// plannedFileChanges mirrors how a local deploy treats one destination, and
// reports whether its content changes.
func plannedFileChanges(dst, name string, data []byte, defaultMode os.FileMode, d *config.Deploy, certWillChange bool) ([]string, bool, error) {
	info, err := os.Lstat(dst)
	if errors.Is(err, os.ErrNotExist) {
		return []string{name + " create"}, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		// A deploy never writes through a link: it replaces the link with
		// a regular file.
		return []string{name + " update"}, true, nil
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("destination %s is not a regular file", dst)
	}

	var changes []string
	content := certWillChange
	if !certWillChange {
		existing, err := os.ReadFile(dst)
		if err != nil {
			return nil, false, err
		}
		content = !bytes.Equal(existing, data)
	}
	if content {
		changes = append(changes, name+" update")
	}

	// Match staging's trust check: an unprivileged process with an explicit
	// mode cannot give a new key to another user.
	inherit := info
	if defaultMode == 0o600 &&
		(d.Mode == nil || (os.Geteuid() == 0 && (d.Owner == "" || d.Group == ""))) {
		trusted, err := deploy.InheritTrusted(dst, info)
		if err != nil {
			return nil, false, err
		}
		if !trusted {
			inherit = nil
		}
	}
	desiredMode, err := deploy.DesiredMode(defaultMode, inherit, d)
	if err != nil {
		return nil, false, err
	}
	if deploy.ModeDiffers(info.Mode().Perm(), desiredMode) {
		changes = append(changes, fmt.Sprintf("%s chmod %#o", name, desiredMode))
	}

	ownerGroupChanges, err := plannedOwnerGroupChanges(info, name, d)
	if err != nil {
		return changes, content, err
	}
	changes = append(changes, ownerGroupChanges...)
	return changes, content, nil
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
