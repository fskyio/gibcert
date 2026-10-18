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

// Package prune finds local state that no longer belongs to the config and
// removes the parts the caller selected. Scanning is offline and read-only.
// Apply deletes local files and, only when the caller supplies the hook,
// deactivates accounts at their CA first.
package prune

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"gitfield.org/fsky/gibcert/internal/config"
	"gitfield.org/fsky/gibcert/internal/storage"
)

// Kind names a class of prunable state. It is also the prefix of an item ID.
type Kind string

const (
	KindCert       Kind = "cert"
	KindAccount    Kind = "account"
	KindCA         Kind = "ca"
	KindAccountKey Kind = "account-key"
)

// ErrNoCertificates is returned when the config declares no certificates. A
// wrong config path or an include that matched nothing looks exactly like this,
// and every stored certificate would then appear orphaned.
var ErrNoCertificates = errors.New("config declares no certificates; refusing to prune (wrong --config?)")

// Options selects what Scan may mark for removal.
type Options struct {
	Certs       bool
	Accounts    bool
	CAs         bool
	AccountKeys bool
	// IncludeValid makes orphan certificates that are still valid removable.
	// Without it only expired, revoked, or unreadable orphans are.
	IncludeValid bool
	// Except lists item IDs that must be kept. Every entry must match a known
	// item, so a typo cannot silently widen the removal.
	Except []string
}

// Item is one piece of local state that Scan examined.
type Item struct {
	Kind Kind
	// Name is the certificate, account, or CA name. For KindAccountKey it is
	// "<account>/<file>".
	Name   string
	Remove bool
	Reason string
	// Warnings describe external artifacts that outlive a removal.
	Warnings []string
	// Directory is the ACME directory recorded for an account, if known.
	Directory string
}

// ID is the stable identifier used with Options.Except.
func (i Item) ID() string {
	return string(i.Kind) + "/" + i.Name
}

// Report is the outcome of a scan, limited to the selected kinds. Items are
// ordered as they are applied: certificates, accounts, CAs, account keys.
type Report struct {
	Items []Item
}

// Removals returns the items that Apply will delete.
func (r Report) Removals() []Item {
	var out []Item
	for _, it := range r.Items {
		if it.Remove {
			out = append(out, it)
		}
	}
	return out
}

// Result is the outcome of removing one item.
type Result struct {
	Item Item
	Err  error
}

// Scan classifies local state against the config. Dependencies are computed
// against what survives: certificates that are configured, not selected, or
// excepted keep the accounts and CAs they reference. Accounts and CAs are
// therefore only removable once nothing that remains needs them.
func Scan(cfg *config.Config, store *storage.Store, now time.Time, opts Options) (Report, error) {
	if len(cfg.Certificates) == 0 {
		return Report{}, ErrNoCertificates
	}
	except := make(map[string]bool, len(opts.Except))
	for _, id := range opts.Except {
		except[id] = true
	}

	configured := map[string]bool{}
	accountRefs, caRefs := refs{}, refs{}
	if err := configRefs(cfg, configured, accountRefs, caRefs); err != nil {
		return Report{}, err
	}

	certs, err := scanCerts(store, configured, now, opts, except)
	if err != nil {
		return Report{}, err
	}

	for _, cert := range cfg.Certificates {
		metaRefs(store, cert.Name, accountRefs, caRefs)
	}
	for _, it := range certs {
		if !it.Remove {
			metaRefs(store, it.Name, accountRefs, caRefs)
		}
	}

	accounts, err := scanAccounts(store, accountRefs, opts, except)
	if err != nil {
		return Report{}, err
	}
	cas, err := scanCAs(store, caRefs, opts, except)
	if err != nil {
		return Report{}, err
	}
	keys, err := scanAccountKeys(store, accounts, opts, except)
	if err != nil {
		return Report{}, err
	}

	var all []Item
	for _, group := range [][]Item{certs, accounts, cas, keys} {
		all = append(all, group...)
	}
	known := make(map[string]bool, len(all))
	for _, it := range all {
		known[it.ID()] = true
	}
	for _, id := range opts.Except {
		if !known[id] {
			return Report{}, fmt.Errorf("--except %q does not match any prune candidate", id)
		}
	}

	selected := map[Kind]bool{
		KindCert:       opts.Certs,
		KindAccount:    opts.Accounts,
		KindCA:         opts.CAs,
		KindAccountKey: opts.AccountKeys,
	}
	var report Report
	for _, it := range all {
		if selected[it.Kind] {
			report.Items = append(report.Items, it)
		}
	}
	return report, nil
}

// ApplyOptions configures Apply.
type ApplyOptions struct {
	// DeactivateAccount, when set, runs for every account being removed,
	// before its local state is deleted. It receives the account name and the
	// ACME directory recorded for it (empty if unknown). An error keeps the
	// account's local state, so the account stays orphaned and a later run
	// can retry.
	DeactivateAccount func(ctx context.Context, name, directory string) error
}

// Apply deletes the items marked for removal, continuing past failures. The
// caller must hold the state lock from Scan through Apply.
func Apply(ctx context.Context, report Report, store *storage.Store, opts ApplyOptions) []Result {
	var results []Result
	for _, it := range report.Items {
		if !it.Remove {
			continue
		}
		var err error
		switch it.Kind {
		case KindCert:
			err = store.DeleteCert(it.Name)
		case KindAccount:
			err = removeAccount(ctx, store, it, opts)
		case KindCA:
			err = store.DeleteCA(it.Name)
		case KindAccountKey:
			account, file, _ := strings.Cut(it.Name, "/")
			err = store.RemoveAccountKeyArchive(account, file)
		}
		results = append(results, Result{Item: it, Err: err})
	}
	return results
}

// removeAccount removes an account. The account key lives in its local state,
// so deactivation at the CA has to come first, and a failure of it has to skip
// the deletion: once the key is gone nothing can deactivate the account.
func removeAccount(ctx context.Context, store *storage.Store, it Item, opts ApplyOptions) error {
	if opts.DeactivateAccount != nil {
		if err := opts.DeactivateAccount(ctx, it.Name, it.Directory); err != nil {
			return fmt.Errorf("deactivate at the CA (local state kept): %w", err)
		}
	}
	return store.DeleteAccount(it.Name)
}

// refs maps a name to the reasons it is still needed.
type refs map[string][]string

func (r refs) add(name, why string) {
	r[name] = append(r[name], why)
}

func (r refs) reason(name string) string {
	why := r[name]
	if len(why) == 1 {
		return why[0]
	}
	return fmt.Sprintf("%s (and %d more)", why[0], len(why)-1)
}

// configRefs records every account and CA the config declares or uses, and the
// names of the configured certificates. Implicit "ca:<name>" accounts count
// only when a configured certificate issues through them, as primary or
// failover.
func configRefs(cfg *config.Config, configured map[string]bool, accountRefs, caRefs refs) error {
	for _, a := range cfg.Accounts {
		accountRefs.add(a.Name, "declared in config")
	}
	for _, ca := range cfg.CAs {
		if ca.Type == "local" {
			caRefs.add(ca.Name, "declared in config")
		}
	}
	for _, cert := range cfg.Certificates {
		configured[cert.Name] = true
		why := "used by configured cert/" + cert.Name
		ca, local, err := config.LocalCAForCertificate(cfg, cert)
		if err != nil {
			return fmt.Errorf("certificate %q: %w", cert.Name, err)
		}
		if local {
			caRefs.add(ca.Name, why)
			continue
		}
		issuers, err := config.ACMEIssuersForCertificate(cfg, cert)
		if err != nil {
			return fmt.Errorf("certificate %q: %w", cert.Name, err)
		}
		for _, a := range issuers {
			accountRefs.add(a.Name, why)
		}
	}
	return nil
}

// metaRefs records the account and CA a stored certificate was issued with.
// Revoking a certificate needs the recorded account, so it is kept even when
// the config has since moved to another issuer.
func metaRefs(store *storage.Store, name string, accountRefs, caRefs refs) {
	meta, err := store.LoadCertMeta(name)
	if err != nil {
		return
	}
	why := "needed by cert/" + name
	if meta.Account != "" {
		accountRefs.add(meta.Account, why)
	}
	if meta.CA != "" {
		caRefs.add(meta.CA, why)
	}
}

// decide sets the removal state of an item that is eligible for pruning when
// its kind is selected.
func decide(it *Item, selected bool, except map[string]bool) {
	it.Remove = selected
	if it.Remove && except[it.ID()] {
		it.Remove = false
		it.Reason = "kept by --except; " + it.Reason
	}
}

func scanCerts(store *storage.Store, configured map[string]bool, now time.Time, opts Options, except map[string]bool) ([]Item, error) {
	names, err := store.ListCertNames()
	if err != nil {
		return nil, err
	}
	var items []Item
	for _, name := range names {
		if configured[name] {
			continue
		}
		it := Item{Kind: KindCert, Name: name}
		meta, err := store.LoadCertMeta(name)
		eligible := true
		switch {
		case err != nil:
			it.Reason = "not in config; metadata missing or unreadable"
		case meta.RevokedAt != nil:
			it.Reason = "not in config; revoked " + day(*meta.RevokedAt)
		case meta.NotAfter.IsZero():
			it.Reason = "not in config; no expiry recorded"
		case !meta.NotAfter.After(now):
			it.Reason = "not in config; expired " + day(meta.NotAfter)
		case opts.IncludeValid:
			it.Reason = "not in config; valid until " + day(meta.NotAfter)
		default:
			eligible = false
			it.Reason = "not in config; valid until " + day(meta.NotAfter) + " (use --include-valid)"
		}
		if eligible {
			decide(&it, opts.Certs, except)
		}
		if it.Remove && meta != nil {
			it.Warnings = certWarnings(meta, now)
		}
		items = append(items, it)
	}
	return items, nil
}

// certWarnings lists artifacts of a certificate that removing its local state
// leaves behind.
func certWarnings(meta *storage.CertMeta, now time.Time) []string {
	var warnings []string
	if meta.TLSA != nil && len(meta.TLSA.Published) > 0 {
		warnings = append(warnings, fmt.Sprintf("%d published TLSA record(s) stay in DNS", len(meta.TLSA.Published)))
	}
	paths := map[string]bool{}
	hosts := map[string]bool{}
	for _, d := range meta.Deploys {
		if d.Host != "" {
			hosts[d.Host] = true
		} else if d.Path != "" {
			paths[d.Path] = true
		}
	}
	if len(paths) > 0 {
		warnings = append(warnings, fmt.Sprintf("%d deployed local file(s) stay in place", len(paths)))
	}
	if len(hosts) > 0 {
		names := make([]string, 0, len(hosts))
		for h := range hosts {
			names = append(names, h)
		}
		sort.Strings(names)
		warnings = append(warnings, "deployed files stay on remote host(s): "+strings.Join(names, ", "))
	}
	if meta.RevokedAt == nil && meta.IssuerType != "local" && meta.NotAfter.After(now) {
		warnings = append(warnings, "certificate is still valid and is not revoked at the CA")
	}
	return warnings
}

func scanAccounts(store *storage.Store, accountRefs refs, opts Options, except map[string]bool) ([]Item, error) {
	names, err := store.ListAccountNames()
	if err != nil {
		return nil, err
	}
	var items []Item
	for _, name := range names {
		it := Item{Kind: KindAccount, Name: name}
		if meta, err := store.LoadAccountMeta(name); err == nil {
			it.Directory = meta.Directory
		}
		if _, used := accountRefs[name]; used {
			it.Reason = "in use: " + accountRefs.reason(name)
		} else {
			it.Reason = "not in config; no remaining certificate uses it"
			decide(&it, opts.Accounts, except)
		}
		items = append(items, it)
	}
	return items, nil
}

func scanCAs(store *storage.Store, caRefs refs, opts Options, except map[string]bool) ([]Item, error) {
	names, err := store.ListCANames()
	if err != nil {
		return nil, err
	}
	var items []Item
	for _, name := range names {
		it := Item{Kind: KindCA, Name: name}
		if _, used := caRefs[name]; used {
			it.Reason = "in use: " + caRefs.reason(name)
		} else {
			it.Reason = "not in config; no remaining certificate was signed by it"
			decide(&it, opts.CAs, except)
		}
		items = append(items, it)
	}
	return items, nil
}

// scanAccountKeys lists superseded account key archives of every account that
// is not itself being removed (its archives go with it). The newest archive
// of each account is always kept.
func scanAccountKeys(store *storage.Store, accounts []Item, opts Options, except map[string]bool) ([]Item, error) {
	var items []Item
	for _, a := range accounts {
		if a.Remove {
			continue
		}
		files, err := store.ListAccountKeyArchives(a.Name)
		if err != nil {
			return nil, err
		}
		if len(files) < 2 {
			continue
		}
		newest := files[len(files)-1]
		for _, f := range files[:len(files)-1] {
			it := Item{Kind: KindAccountKey, Name: a.Name + "/" + f, Reason: "superseded by " + newest}
			decide(&it, opts.AccountKeys, except)
			items = append(items, it)
		}
	}
	return items, nil
}

func day(t time.Time) string {
	return t.UTC().Format("2006-01-02")
}
