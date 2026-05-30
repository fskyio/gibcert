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
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"foundry.fsky.io/fsky/gibcert/internal/config"
	"foundry.fsky.io/fsky/gibcert/internal/storage"
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
		planned, err := planDeploy(d, srcCert, srcChain, srcFullchain, srcKey)
		if err != nil {
			return results, fmt.Errorf("deploy %q: plan: %w", d.Name, err)
		}
		if err := runHook(d.Before, "before-deploy", cert, d, planned); err != nil {
			return results, fmt.Errorf("deploy %q: before hook: %w", d.Name, err)
		}
		r, records, err := deployOne(d, srcCert, srcChain, srcFullchain, srcKey, out)
		if err != nil {
			return results, fmt.Errorf("deploy %q: %w", d.Name, err)
		}
		results = append(results, r)
		hookChanged := hookChangedKinds(meta, records, r.Changed)
		if err := runHook(d.After, "after-deploy", cert, d, Result{Target: r.Target, Changed: hookChanged}); err != nil {
			return results, fmt.Errorf("deploy %q: after hook: %w", d.Name, err)
		}
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

func planDeploy(d *config.Deploy, srcCert, srcChain, srcFullchain, srcKey []byte) (Result, error) {
	r := Result{Target: d.Name}
	derCert, derKey, err := derVariants(d, srcCert, srcKey)
	if err != nil {
		return r, err
	}
	items := []struct {
		kind string
		dst  string
		data []byte
	}{
		{"cert", d.Cert, srcCert},
		{"chain", d.Chain, srcChain},
		{"fullchain", d.Fullchain, srcFullchain},
		{"key", d.Key, srcKey},
		{"cert-der", d.CertDER, derCert},
		{"key-der", d.KeyDER, derKey},
	}

	for _, it := range items {
		if it.dst == "" || len(it.data) == 0 {
			continue
		}
		changed, err := fileContentChanged(it.dst, it.data)
		if err != nil {
			return r, fmt.Errorf("%s: %w", it.kind, err)
		}
		if changed {
			r.Changed = append(r.Changed, it.kind)
		}
	}
	return r, nil
}

func deployOne(d *config.Deploy, srcCert, srcChain, srcFullchain, srcKey []byte, out io.Writer) (Result, []storage.CertDeployMeta, error) {
	r := Result{Target: d.Name}
	var records []storage.CertDeployMeta
	now := timeNow()
	derCert, derKey, err := derVariants(d, srcCert, srcKey)
	if err != nil {
		return r, records, err
	}
	items := []struct {
		kind string
		dst  string
		data []byte
		mode fs.FileMode
	}{
		{"cert", d.Cert, srcCert, 0o644},
		{"chain", d.Chain, srcChain, 0o644},
		{"fullchain", d.Fullchain, srcFullchain, 0o644},
		{"key", d.Key, srcKey, 0o600},
		{"cert-der", d.CertDER, derCert, 0o644},
		{"key-der", d.KeyDER, derKey, 0o600},
	}

	for _, it := range items {
		if it.dst == "" || len(it.data) == 0 {
			continue
		}
		changed, err := installFile(it.dst, it.data, it.mode, d, out)
		if err != nil {
			return r, records, fmt.Errorf("%s: %w", it.kind, err)
		}
		records = append(records, storage.CertDeployMeta{
			Target: d.Name,
			Kind:   it.kind,
			Path:   it.dst,
			SHA256: storage.SHA256Hex(it.data),
			At:     now,
		})
		if changed {
			r.Changed = append(r.Changed, it.kind)
		}
	}
	return r, records, nil
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

func installFile(dst string, data []byte, defaultMode fs.FileMode, d *config.Deploy, out io.Writer) (bool, error) {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return false, err
	}

	existing, statErr := os.Stat(dst)
	if statErr == nil {
		existingData, err := os.ReadFile(dst)
		if err == nil && bytes.Equal(hash(existingData), hash(data)) {
			if err := applyAttrs(dst, existing, defaultMode, d, out); err != nil {
				return false, err
			}
			return false, nil
		}
	}

	mode := defaultMode
	if d.Mode != nil {
		mode = *d.Mode
	} else if statErr == nil {
		mode = existing.Mode().Perm()
	} else {
		fmt.Fprintf(out, "warning: %s: creating with default mode %#o (set deploy.mode to silence)\n", dst, mode)
	}

	tmp, err := os.CreateTemp(filepath.Dir(dst), ".gibcert-*")
	if err != nil {
		return false, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return false, err
	}
	if err := chownTo(tmpName, d, statErr == nil, existing, out); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return false, err
	}
	return true, nil
}

func fileContentChanged(dst string, data []byte) (bool, error) {
	existingData, err := os.ReadFile(dst)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return !bytes.Equal(hash(existingData), hash(data)), nil
}

func applyAttrs(path string, existing os.FileInfo, defaultMode fs.FileMode, d *config.Deploy, out io.Writer) error {
	desiredMode := existing.Mode().Perm()
	if d.Mode != nil {
		desiredMode = *d.Mode
	}
	if existing.Mode().Perm() != desiredMode {
		if err := os.Chmod(path, desiredMode); err != nil {
			return err
		}
	}
	return chownTo(path, d, true, existing, out)
}

func chownTo(path string, d *config.Deploy, dstExists bool, existing os.FileInfo, out io.Writer) error {
	if d.Owner == "" && d.Group == "" {
		return nil
	}
	uid, gid := -1, -1
	if d.Owner != "" {
		u, err := user.Lookup(d.Owner)
		if err != nil {
			return fmt.Errorf("owner %q: %w", d.Owner, err)
		}
		n, _ := strconv.Atoi(u.Uid)
		uid = n
	}
	if d.Group != "" {
		g, err := user.LookupGroup(d.Group)
		if err != nil {
			return fmt.Errorf("group %q: %w", d.Group, err)
		}
		n, _ := strconv.Atoi(g.Gid)
		gid = n
	}
	if err := os.Chown(path, uid, gid); err != nil {
		if os.Geteuid() != 0 {
			return fmt.Errorf("chown requires privileges (running as non-root): %w", err)
		}
		return err
	}
	return nil
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

func hash(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
