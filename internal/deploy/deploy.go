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

package deploy

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"

	"gitfield.org/fsky/gibcert/internal/config"
	"gitfield.org/fsky/gibcert/internal/storage"
)

const HookAPIVersion = "1"

type Result struct {
	Target  string
	Changed []string
}

func Deploy(cert *config.Certificate, store *storage.Store, out io.Writer) ([]Result, error) {
	paths := store.CertPaths(cert.Name)
	srcCert, err := os.ReadFile(paths.Cert)
	if err != nil {
		return nil, fmt.Errorf("read canonical cert: %w", err)
	}
	srcChain, _ := os.ReadFile(paths.Chain)
	srcFullchain, err := os.ReadFile(paths.Fullchain)
	if err != nil {
		return nil, fmt.Errorf("read canonical fullchain: %w", err)
	}
	srcKey, err := os.ReadFile(paths.Key)
	if err != nil {
		return nil, fmt.Errorf("read canonical privkey: %w", err)
	}

	var results []Result
	meta, err := store.LoadCertMeta(cert.Name)
	if errors.Is(err, os.ErrNotExist) {
		meta = &storage.CertMeta{Name: cert.Name}
	} else if err != nil {
		return nil, fmt.Errorf("load cert metadata: %w", err)
	}
	for _, d := range cert.Deploys {
		r, records, err := deployOne(cert, d, meta, srcCert, srcChain, srcFullchain, srcKey, out)
		if err != nil {
			return results, fmt.Errorf("deploy %q: %w", d.Name, err)
		}
		results = append(results, r)
		upsertDeployRecords(meta, records)
		if err := store.SaveCertMeta(cert.Name, *meta); err != nil {
			return results, fmt.Errorf("deploy %q: save metadata: %w", d.Name, err)
		}
	}
	return results, nil
}

// derVariants converts the canonical PEM material to DER for any DER deploy
// targets configured on d. Conversions are computed only when the matching
// destination is set.
func derVariants(d *config.Deploy, srcCert, srcKey []byte) (derCert, derKey []byte, err error) {
	if d.CertDER != "" {
		derCert, err = CertPEMToDER(srcCert)
		if err != nil {
			return nil, nil, fmt.Errorf("cert-der: %w", err)
		}
	}
	if d.KeyDER != "" {
		derKey, err = KeyPEMToDER(srcKey)
		if err != nil {
			return nil, nil, fmt.Errorf("key-der: %w", err)
		}
	}
	return derCert, derKey, nil
}

func deployOne(cert *config.Certificate, d *config.Deploy, meta *storage.CertMeta, srcCert, srcChain, srcFullchain, srcKey []byte, out io.Writer) (Result, []storage.CertDeployMeta, error) {
	if d.Before != "" && d.After == "" {
		return Result{}, nil, fmt.Errorf("before hook requires an after hook for recovery")
	}
	var staged stagedDeploy
	defer staged.cleanup()
	if err := staged.prepare(d, srcCert, srcChain, srcFullchain, srcKey, out); err != nil {
		return Result{}, nil, fmt.Errorf("stage: %w", err)
	}
	beforeAttempted := d.Before != "" && len(staged.result.Changed) != 0
	recoverHook := func() error {
		if !beforeAttempted {
			return nil
		}
		if err := runHook(d.After, "rollback-deploy", cert, d, staged.result); err != nil {
			return fmt.Errorf("recovery hook: %w", err)
		}
		return nil
	}
	if err := runHook(d.Before, "before-deploy", cert, d, staged.result); err != nil {
		return Result{}, nil, errors.Join(fmt.Errorf("before hook: %w", err), recoverHook())
	}
	if err := staged.install(); err != nil {
		rollbackErr := staged.rollback()
		var hookErr error
		if rollbackErr == nil {
			hookErr = recoverHook()
		}
		return Result{}, nil, errors.Join(err, rollbackErr, hookErr)
	}
	hookChanged := hookChangedKinds(meta, staged.records, staged.result.Changed)
	if err := runHook(d.After, "after-deploy", cert, d, Result{Target: d.Name, Changed: hookChanged}); err != nil {
		return Result{}, nil, fmt.Errorf("after hook: %w", err)
	}
	return staged.result, staged.records, nil
}

var timeNow = func() time.Time { return time.Now().UTC() }

func upsertDeployRecords(meta *storage.CertMeta, records []storage.CertDeployMeta) {
	for _, rec := range records {
		replaced := false
		for i := range meta.Deploys {
			existing := &meta.Deploys[i]
			if existing.Target == rec.Target && existing.Kind == rec.Kind && existing.Path == rec.Path {
				meta.Deploys[i] = rec
				replaced = true
				break
			}
		}
		if !replaced {
			meta.Deploys = append(meta.Deploys, rec)
		}
	}
}

func hookChangedKinds(meta *storage.CertMeta, records []storage.CertDeployMeta, changed []string) []string {
	seen := map[string]bool{}
	var kinds []string
	add := func(kind string) {
		if !seen[kind] {
			seen[kind] = true
			kinds = append(kinds, kind)
		}
	}
	for _, kind := range changed {
		add(kind)
	}
	for _, rec := range records {
		if !deployRecordCurrent(meta, rec) {
			add(rec.Kind)
		}
	}
	return kinds
}

func deployRecordCurrent(meta *storage.CertMeta, rec storage.CertDeployMeta) bool {
	if meta == nil {
		return false
	}
	for _, existing := range meta.Deploys {
		if existing.Target == rec.Target &&
			existing.Kind == rec.Kind &&
			existing.Path == rec.Path &&
			existing.SHA256 == rec.SHA256 {
			return true
		}
	}
	return false
}

// DesiredMode preserves public-file modes but never inherits group or other
// access for private keys. Group access requires an explicit deploy mode.
func DesiredMode(defaultMode fs.FileMode, existing os.FileInfo, d *config.Deploy) (fs.FileMode, error) {
	if d.Mode != nil {
		mode := *d.Mode
		if defaultMode == 0o600 && mode&0o117 != 0 {
			return 0, fmt.Errorf("private-key mode must not permit other access or execution, got %#o", mode)
		}
		return mode, nil
	}
	if existing == nil {
		return defaultMode, nil
	}
	mode := existing.Mode().Perm()
	if defaultMode == 0o600 {
		mode &= 0o600
	}
	return mode, nil
}

func runHook(command, event string, cert *config.Certificate, d *config.Deploy, r Result) error {
	if command == "" || len(r.Changed) == 0 {
		return nil
	}
	cmd := shellCommand(command)
	env := os.Environ()
	env = append(env,
		"GIBCERT_HOOK_API="+HookAPIVersion,
		"GIBCERT_EVENT="+event,
		"GIBCERT_CERT="+cert.Name,
		"GIBCERT_DEPLOY_TARGET="+d.Name,
		"GIBCERT_CHANGED="+strings.Join(r.Changed, ","),
	)
	for _, p := range []struct {
		envName, dst string
	}{
		{"GIBCERT_CERT_PATH", d.Cert},
		{"GIBCERT_CHAIN_PATH", d.Chain},
		{"GIBCERT_FULLCHAIN_PATH", d.Fullchain},
		{"GIBCERT_KEY_PATH", d.Key},
		{"GIBCERT_CERT_DER_PATH", d.CertDER},
		{"GIBCERT_KEY_DER_PATH", d.KeyDER},
	} {
		if p.dst != "" {
			env = append(env, p.envName+"="+p.dst)
		}
	}
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// RunReload executes a once-per-run reload command. Unlike a per-deploy "after"
// hook it carries no per-certificate environment, so identical commands from
// different certificates can be coalesced into a single invocation. It receives
// only the names of the certificates that changed and triggered it, via
// GIBCERT_CHANGED_CERTS.
func RunReload(command string, changedCerts []string) error {
	if command == "" {
		return nil
	}
	cmd := shellCommand(command)
	cmd.Env = append(os.Environ(),
		"GIBCERT_HOOK_API="+HookAPIVersion,
		"GIBCERT_EVENT=reload",
		"GIBCERT_CHANGED_CERTS="+strings.Join(changedCerts, ","),
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
