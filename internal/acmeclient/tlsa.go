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
	"crypto"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"foundry.fsky.io/fsky/gibcert/internal/challenge"
	"foundry.fsky.io/fsky/gibcert/internal/config"
	"foundry.fsky.io/fsky/gibcert/internal/storage"
)

// TLSAKeyDecision describes the pre-issue key choice for a TLSA-managed
// certificate.
type TLSAKeyDecision struct {
	Key         crypto.Signer
	StagedKey   bool
	ReusedKey   bool
	NextNotYet  bool
	NextMissing bool
	Bootstrap   bool
}

// pickTLSAKey selects the cert key to use for a TLSA-managed cert. It prefers
// a staged next-key whose TLSA was pre-published more than TTL ago, falls back
// to the current live key, and finally generates a new key on bootstrap.
func pickTLSAKey(cert *config.Certificate, store *storage.Store, now time.Time) (TLSAKeyDecision, error) {
	paths := store.CertPaths(cert.Name)
	meta, err := store.LoadCertMeta(cert.Name)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return TLSAKeyDecision{}, fmt.Errorf("load cert metadata: %w", err)
	}

	stagedKey, stagedErr := storage.ReadKey(paths.KeyNext)
	if stagedErr != nil && !errors.Is(stagedErr, os.ErrNotExist) {
		return TLSAKeyDecision{}, fmt.Errorf("read staged next key: %w", stagedErr)
	}
	stagedMature := false
	if stagedKey != nil && meta != nil && meta.TLSA != nil && !meta.TLSA.NextPublishedAt.IsZero() {
		ttl := time.Duration(meta.TLSA.TTL) * time.Second
		if ttl <= 0 {
			ttl = time.Duration(cert.TLSA.TTL) * time.Second
		}
		stagedMature = now.Sub(meta.TLSA.NextPublishedAt) >= ttl
	}

	if stagedKey != nil && stagedMature {
		return TLSAKeyDecision{Key: stagedKey, StagedKey: true}, nil
	}

	current, currentErr := storage.ReadKey(paths.Key)
	if currentErr != nil && !errors.Is(currentErr, os.ErrNotExist) {
		return TLSAKeyDecision{}, fmt.Errorf("read existing cert key: %w", currentErr)
	}
	if current != nil {
		return TLSAKeyDecision{
			Key:         current,
			ReusedKey:   true,
			NextNotYet:  stagedKey != nil && !stagedMature,
			NextMissing: stagedKey == nil,
		}, nil
	}

	fresh, err := storage.GenerateKey(cert.Key)
	if err != nil {
		return TLSAKeyDecision{}, fmt.Errorf("generate cert key: %w", err)
	}
	return TLSAKeyDecision{Key: fresh, Bootstrap: true}, nil
}

// reconcileTLSA publishes the current and next-key TLSA records, removes any
// previously published records that no longer match, generates a new staged
// next key if needed, and returns the updated TLSA metadata. The caller saves
// it as part of the cert metadata.
func reconcileTLSA(ctx context.Context, store *storage.Store, cfg *config.Config, cert *config.Certificate, currentKey crypto.Signer, out io.Writer) (*storage.CertTLSAMeta, error) {
	spec := cert.TLSA
	if spec == nil {
		return nil, nil
	}
	provider := findProvider(cfg, spec.Provider)
	if provider == nil {
		return nil, fmt.Errorf("tlsa: provider %q not found", spec.Provider)
	}
	editor, err := newDNSEditor(provider, out)
	if err != nil {
		return nil, err
	}
	if err := challenge.EnsureEditorSupports(ctx, editor, "TLSA", "add-record", "remove-record"); err != nil {
		return nil, fmt.Errorf("tlsa: provider %q: %w", spec.Provider, err)
	}

	currentValue, err := tlsaValue(spec, currentKey.Public())
	if err != nil {
		return nil, err
	}

	meta, err := store.LoadCertMeta(cert.Name)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	var previous *storage.CertTLSAMeta
	if meta != nil {
		previous = meta.TLSA
	}

	paths := store.CertPaths(cert.Name)
	nextKey, nextExisted, err := loadOrGenerateNextKey(paths, cert.Key)
	if err != nil {
		return nil, err
	}
	nextValue, err := tlsaValue(spec, nextKey.Public())
	if err != nil {
		return nil, err
	}

	desired := composeDesiredTLSA(cert.Names, spec.Ports, []string{currentValue, nextValue})

	for _, rec := range desired {
		fmt.Fprintf(out, "tlsa publish: %s IN TLSA %s\n", rec.Owner, rec.RData)
		if err := editor.AddRecord(ctx, challenge.EditRequest{
			Owner:      rec.Owner,
			RecordType: "TLSA",
			RData:      rec.RData,
			TTL:        spec.TTL,
		}); err != nil {
			return nil, fmt.Errorf("publish tlsa %s: %w", rec.Owner, err)
		}
	}

	published := append([]storage.TLSARecord(nil), desired...)
	if previous != nil {
		for _, old := range previous.Published {
			if containsTLSA(desired, old) {
				continue
			}
			fmt.Fprintf(out, "tlsa remove stale: %s IN TLSA %s\n", old.Owner, old.RData)
			if err := editor.RemoveRecord(ctx, challenge.EditRequest{
				Owner:      old.Owner,
				RecordType: "TLSA",
				RData:      old.RData,
				TTL:        spec.TTL,
			}); err != nil {
				fmt.Fprintf(out, "warning: remove stale tlsa %s: %v (will retry)\n", old.Owner, err)
				published = append(published, old)
			}
		}
	}

	nextPublishedAt := time.Now().UTC()
	if previous != nil && previous.NextValue == nextValue && !previous.NextPublishedAt.IsZero() && nextExisted {
		nextPublishedAt = previous.NextPublishedAt
	}

	return &storage.CertTLSAMeta{
		Usage:           spec.Usage,
		Selector:        spec.Selector,
		MatchingType:    spec.MatchingType,
		TTL:             spec.TTL,
		Ports:           portsToStorage(spec.Ports),
		CurrentValue:    currentValue,
		NextValue:       nextValue,
		NextPublishedAt: nextPublishedAt,
		Published:       published,
	}, nil
}

func loadOrGenerateNextKey(paths storage.CertPaths, spec config.KeySpec) (crypto.Signer, bool, error) {
	k, err := storage.ReadKey(paths.KeyNext)
	if err == nil {
		return k, true, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, fmt.Errorf("read staged next key: %w", err)
	}
	fresh, err := storage.GenerateKey(spec)
	if err != nil {
		return nil, false, fmt.Errorf("generate staged next key: %w", err)
	}
	if err := storage.WriteKey(paths.KeyNext, fresh); err != nil {
		return nil, false, fmt.Errorf("write staged next key: %w", err)
	}
	return fresh, false, nil
}

func tlsaValue(spec *config.TLSASpec, pub crypto.PublicKey) (string, error) {
	data, err := challenge.SPKIHash(pub, spec.MatchingType)
	if err != nil {
		return "", err
	}
	return challenge.TLSARData(spec.Usage, spec.Selector, spec.MatchingType, data), nil
}

func composeDesiredTLSA(names []string, ports []config.TLSAPort, values []string) []storage.TLSARecord {
	seenOwner := map[string]bool{}
	var owners []string
	for _, name := range names {
		base := strings.TrimPrefix(name, "*.")
		for _, p := range ports {
			owner := challenge.TLSAOwner(p.Port, p.Protocol, base)
			if seenOwner[owner] {
				continue
			}
			seenOwner[owner] = true
			owners = append(owners, owner)
		}
	}
	var out []storage.TLSARecord
	for _, owner := range owners {
		for _, v := range values {
			out = append(out, storage.TLSARecord{Owner: owner, RData: v})
		}
	}
	return out
}

func containsTLSA(set []storage.TLSARecord, rec storage.TLSARecord) bool {
	for _, r := range set {
		if r.Owner == rec.Owner && r.RData == rec.RData {
			return true
		}
	}
	return false
}

func portsToStorage(p []config.TLSAPort) []storage.TLSAPort {
	out := make([]storage.TLSAPort, len(p))
	for i, x := range p {
		out[i] = storage.TLSAPort{Port: x.Port, Protocol: x.Protocol}
	}
	return out
}

func newDNSEditor(p *config.Provider, out io.Writer) (challenge.DNSEditor, error) {
	switch p.Driver {
	case "exec":
		return &challenge.DNSExec{Provider: p, Out: out}, nil
	case "rfc2136", "nsupdate":
		return &challenge.DNSNSUpdate{Provider: p, Out: out}, nil
	case "powerdns", "pdns":
		return &challenge.DNSPowerDNS{Provider: p, Out: out}, nil
	}
	return nil, fmt.Errorf("dns driver %q does not support persistent record edits", p.Driver)
}
