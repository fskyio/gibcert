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
	"slices"
	"strings"
	"time"

	"gitfield.org/fsky/gibcert/internal/config"
	"gitfield.org/fsky/gibcert/internal/storage"
)

const HookAPIVersion = "1"

type Result struct {
	Target string
	// Host names the remote host the target was installed on. Empty means this
	// machine.
	Host    string
	Changed []string
}

// Label names the deploy target, qualified as "target@host" when it ran on a
// remote host.
func (r Result) Label() string {
	if r.Host == "" {
		return r.Target
	}
	return r.Target + "@" + r.Host
}

// Remote applies a Request on another machine. With dryRun it stages and
// checks everything the apply would do, without installing files or running
// hooks, and reports which kinds would change. Hook output and warnings are
// written to out.
type Remote interface {
	Apply(host *config.Host, req Request, dryRun bool, out io.Writer) (Result, error)
}

type options struct {
	remote Remote
	hosts  map[string]*config.Host
	only   string
}

// Option adjusts how Deploy treats deploy targets that name remote hosts.
type Option func(*options)

// WithRemote lets Deploy install on the given hosts through r. Without it, a
// deploy target that names a host is an error.
func WithRemote(r Remote, hosts []*config.Host) Option {
	return func(o *options) {
		o.remote = r
		o.hosts = make(map[string]*config.Host, len(hosts))
		for _, h := range hosts {
			o.hosts[h.Name] = h
		}
	}
}

// OnlyHost restricts Deploy to the targets installed on the named host,
// skipping local installs and all other hosts.
func OnlyHost(name string) Option {
	return func(o *options) { o.only = name }
}

// Hosts returns the hosts a deploy target installs on; an empty name stands
// for this machine.
func Hosts(d *config.Deploy) []string {
	if len(d.Hosts) == 0 {
		return []string{""}
	}
	return d.Hosts
}

// Deploy installs the stored material of cert on every deploy target. Targets
// without hosts install in-process and stop at the first failure. A failure on
// a remote host is recorded in the certificate metadata and the remaining
// hosts are still attempted; all remote failures are returned together.
func Deploy(cert *config.Certificate, store *storage.Store, out io.Writer, opts ...Option) ([]Result, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
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
	material := Material{Cert: srcCert, Chain: srcChain, Fullchain: srcFullchain, Key: srcKey}

	var results []Result
	var remoteErrs []error
	meta, err := store.LoadCertMeta(cert.Name)
	if errors.Is(err, os.ErrNotExist) {
		meta = &storage.CertMeta{Name: cert.Name}
	} else if err != nil {
		return nil, fmt.Errorf("load cert metadata: %w", err)
	}
	for _, d := range cert.Deploys {
		req, err := NewRequest(cert.Name, d, material)
		if err != nil {
			return results, fmt.Errorf("deploy %q: stage: %w", d.Name, err)
		}
		for _, host := range Hosts(d) {
			if o.only != "" && host != o.only {
				continue
			}
			req.Unseen = UnseenKinds(meta, req, host)
			if host == "" {
				r, err := Apply(req, ApplyOptions{Out: out})
				if err != nil {
					return results, fmt.Errorf("deploy %q: %w", d.Name, err)
				}
				results = append(results, r)
				upsertDeployRecords(meta, req.Records("", timeNow()))
				if err := store.SaveCertMeta(cert.Name, *meta); err != nil {
					return results, fmt.Errorf("deploy %q: save metadata: %w", d.Name, err)
				}
				continue
			}

			h, ok := o.hosts[host]
			if o.remote == nil || !ok {
				return results, fmt.Errorf("deploy %q: host %q is not available for remote deploy", d.Name, host)
			}
			r, err := o.remote.Apply(h, req, false, out)
			now := timeNow()
			if err != nil {
				err = fmt.Errorf("deploy %q on host %q: %w", d.Name, host, err)
				remoteErrs = append(remoteErrs, err)
				noteFailure(meta, d.Name, host, err, now)
				if serr := store.SaveCertMeta(cert.Name, *meta); serr != nil {
					remoteErrs = append(remoteErrs, fmt.Errorf("deploy %q on host %q: save metadata: %w", d.Name, host, serr))
				}
				continue
			}
			r.Target, r.Host = d.Name, host
			results = append(results, r)
			clearFailure(meta, d.Name, host)
			upsertDeployRecords(meta, req.Records(host, now))
			if err := store.SaveCertMeta(cert.Name, *meta); err != nil {
				remoteErrs = append(remoteErrs, fmt.Errorf("deploy %q on host %q: save metadata: %w", d.Name, host, err))
			}
		}
	}
	return results, errors.Join(remoteErrs...)
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

// ApplyOptions controls how Apply reports and what it is allowed to do.
type ApplyOptions struct {
	// Out receives warnings; nil discards them.
	Out io.Writer
	// HookStdout and HookStderr receive hook output; nil means the process's
	// own stdout and stderr. A receiver whose stdout carries a protocol must
	// redirect both.
	HookStdout io.Writer
	HookStderr io.Writer
	// DryRun stages and discards everything without installing files or
	// running hooks.
	DryRun bool
	// RefuseSymlinks makes a destination that is a symbolic link an error
	// instead of being replaced.
	RefuseSymlinks bool
}

// Apply installs req on this machine: it stages every changed file and its
// attributes, runs the before hook, replaces the files by atomic renames, and
// runs the after hook. Failures roll back earlier replacements and run the
// after hook for recovery.
func Apply(req Request, opts ApplyOptions) (Result, error) {
	if opts.Out == nil {
		opts.Out = io.Discard
	}
	if opts.HookStdout == nil {
		opts.HookStdout = os.Stdout
	}
	if opts.HookStderr == nil {
		opts.HookStderr = os.Stderr
	}
	if err := req.Validate(); err != nil {
		return Result{}, err
	}
	staged := stagedDeploy{refuseSymlinks: opts.RefuseSymlinks}
	defer staged.cleanup()
	if err := staged.prepare(req, opts.Out); err != nil {
		return Result{}, fmt.Errorf("stage: %w", err)
	}
	if opts.DryRun {
		return staged.result, nil
	}
	beforeAttempted := req.Before != "" && len(staged.result.Changed) != 0
	recoverHook := func() error {
		if !beforeAttempted {
			return nil
		}
		if err := runHook(req.After, "rollback-deploy", req, staged.result, opts); err != nil {
			return fmt.Errorf("recovery hook: %w", err)
		}
		return nil
	}
	if err := runHook(req.Before, "before-deploy", req, staged.result, opts); err != nil {
		return Result{}, errors.Join(fmt.Errorf("before hook: %w", err), recoverHook())
	}
	if err := staged.install(); err != nil {
		rollbackErr := staged.rollback()
		var hookErr error
		if rollbackErr == nil {
			hookErr = recoverHook()
		}
		return Result{}, errors.Join(err, rollbackErr, hookErr)
	}
	hookChanged := hookChangedKinds(staged.result.Changed, req.Unseen)
	if err := runHook(req.After, "after-deploy", req, Result{Target: req.Target, Changed: hookChanged}, opts); err != nil {
		return Result{}, fmt.Errorf("after hook: %w", err)
	}
	return staged.result, nil
}

var timeNow = func() time.Time { return time.Now().UTC() }

func upsertDeployRecords(meta *storage.CertMeta, records []storage.CertDeployMeta) {
	for _, rec := range records {
		replaced := false
		for i := range meta.Deploys {
			existing := &meta.Deploys[i]
			if existing.Target == rec.Target && existing.Host == rec.Host && existing.Kind == rec.Kind && existing.Path == rec.Path {
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

// noteFailure records a failed attempt for the target on host, keeping the
// time of the first failure of an unbroken streak.
func noteFailure(meta *storage.CertMeta, target, host string, err error, now time.Time) {
	for i := range meta.DeployFailures {
		f := &meta.DeployFailures[i]
		if f.Target == target && f.Host == host {
			f.At, f.Error = now, err.Error()
			return
		}
	}
	meta.DeployFailures = append(meta.DeployFailures, storage.CertDeployFailure{
		Target: target, Host: host, Since: now, At: now, Error: err.Error(),
	})
}

func clearFailure(meta *storage.CertMeta, target, host string) {
	meta.DeployFailures = slices.DeleteFunc(meta.DeployFailures, func(f storage.CertDeployFailure) bool {
		return f.Target == target && f.Host == host
	})
}

// hookChangedKinds returns the kinds the after hook is told changed: the kinds
// that were rewritten, then the kinds the sender never saw installed.
func hookChangedKinds(changed, unseen []string) []string {
	seen := map[string]bool{}
	var kinds []string
	for _, kind := range slices.Concat(changed, unseen) {
		if !seen[kind] {
			seen[kind] = true
			kinds = append(kinds, kind)
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
			existing.Host == rec.Host &&
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
	return desiredMode(defaultMode, existing, d.Mode)
}

func desiredMode(defaultMode fs.FileMode, existing os.FileInfo, explicit *fs.FileMode) (fs.FileMode, error) {
	if explicit != nil {
		mode := *explicit
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

func runHook(command, event string, req Request, r Result, opts ApplyOptions) error {
	if command == "" || len(r.Changed) == 0 {
		return nil
	}
	cmd := shellCommand(command)
	env := os.Environ()
	env = append(env,
		"GIBCERT_HOOK_API="+HookAPIVersion,
		"GIBCERT_EVENT="+event,
		"GIBCERT_CERT="+req.Cert,
		"GIBCERT_DEPLOY_TARGET="+req.Target,
		"GIBCERT_CHANGED="+strings.Join(r.Changed, ","),
	)
	for _, k := range fileKinds {
		if path := req.file(k.name).Path; path != "" {
			env = append(env, k.hookEnv+"="+path)
		}
	}
	cmd.Env = env
	cmd.Stdout = opts.HookStdout
	cmd.Stderr = opts.HookStderr
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
