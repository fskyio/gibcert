// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 FSKY <development@fsky.io>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"

	"gitfield.org/fsky/gibcert/internal/config"
	"gitfield.org/fsky/gibcert/internal/deploy"
	"gitfield.org/fsky/gibcert/internal/paths"
	"gitfield.org/fsky/gibcert/internal/receive"
	"gitfield.org/fsky/gibcert/internal/remote"
	"gitfield.org/fsky/gibcert/internal/storage"
)

// deployOptions lets deploy.Deploy install on the configured remote hosts.
func deployOptions(cfg *config.Config) []deploy.Option {
	return []deploy.Option{deploy.WithRemote(&remote.Client{}, cfg.Hosts)}
}

// printDeployResults prints one line per installed target. Targets that were
// already current are only listed when showUpToDate is set.
func printDeployResults(results []deploy.Result, showUpToDate bool) {
	for _, r := range results {
		switch {
		case len(r.Changed) > 0:
			fmt.Printf("  %s: updated %v\n", r.Label(), r.Changed)
		case showUpToDate:
			fmt.Printf("  %s: up to date\n", r.Label())
		}
	}
}

// withRemoteHint points at "gibcert host test" when a receiver refused an
// install for lack of permission, the usual first-run problem of an
// unprivileged deploy user.
func withRemoteHint(err error) error {
	var re *remote.Error
	if errors.As(err, &re) && re.Code == receive.CodePermission {
		return fmt.Errorf("%w (run `gibcert host test %s` for setup help)", err, re.Host)
	}
	return err
}

// certInstallsOnHost reports whether any deploy target of cert installs on the
// named host.
func certInstallsOnHost(cert *config.Certificate, host string) bool {
	for _, d := range cert.Deploys {
		if deployInstallsOn(d, host) {
			return true
		}
	}
	return false
}

const hostUsage = "usage: gibcert host test [NAME...]"

func cmdHost(p *paths.Paths, args []string) int {
	if len(args) == 0 || args[0] != "test" {
		fmt.Fprintln(os.Stderr, hostUsage)
		return 2
	}
	cfg, err := loadCfg(p)
	if err != nil {
		logError(err)
		return 1
	}
	var hosts []*config.Host
	if len(args) == 1 {
		hosts = cfg.Hosts
	}
	for _, name := range args[1:] {
		h := cfg.FindHost(name)
		if h == nil {
			fmt.Fprintf(os.Stderr, "gibcert: unknown host %q\n", name)
			fmt.Fprintln(os.Stderr, hostUsage)
			return 2
		}
		hosts = append(hosts, h)
	}
	if len(hosts) == 0 {
		fmt.Fprintln(os.Stderr, "gibcert: no hosts configured")
		return 1
	}
	if hostTest(cfg, storage.New(p.State), hosts, &remote.Client{}, os.Stdout) {
		return 0
	}
	return 1
}

// hostTest checks that every host answers and that every deploy target that
// installs on it could be installed, using dry-run applies that stage and
// discard. It reports whether everything succeeded.
func hostTest(cfg *config.Config, store *storage.Store, hosts []*config.Host, client *remote.Client, out io.Writer) bool {
	allOK := true
	for _, h := range hosts {
		hello, err := client.Hello(h)
		if err != nil {
			fmt.Fprintf(out, "%s: FAIL %v\n", h.Name, err)
			allOK = false
			continue
		}
		user := h.User
		if user == "" {
			user = hello.User
		}
		fmt.Fprintf(out, "%s: ok (%s@%s, gibcert %s, uid %d)\n", h.Name, user, h.Address, hello.Version, hello.UID)
		for _, cert := range cfg.Certificates {
			material, issued := hostTestMaterial(store, cert.Name)
			for _, d := range cert.Deploys {
				if !deployInstallsOn(d, h.Name) {
					continue
				}
				label := cert.Name + "/" + d.Name
				req, err := hostTestRequest(cert.Name, d, material)
				if err == nil {
					_, err = client.Apply(h, req, true, out)
				}
				if err != nil {
					allOK = false
					fmt.Fprintf(out, "  %s: FAIL %v\n", label, err)
					var re *remote.Error
					if errors.As(err, &re) && re.Code == receive.CodePermission {
						printPermissionHint(out, h, hello, d)
					}
					continue
				}
				note := ""
				if !issued {
					note = " (permissions only; certificate not issued yet)"
				}
				fmt.Fprintf(out, "  %s: ok%s\n", label, note)
			}
		}
	}
	return allOK
}

func deployInstallsOn(d *config.Deploy, host string) bool {
	for _, h := range d.Hosts {
		if h == host {
			return true
		}
	}
	return false
}

// hostTestMaterial returns the stored canonical material of a certificate, or
// short placeholders when it has not been issued yet.
func hostTestMaterial(store *storage.Store, name string) (deploy.Material, bool) {
	paths := store.CertPaths(name)
	cert, err1 := os.ReadFile(paths.Cert)
	fullchain, err2 := os.ReadFile(paths.Fullchain)
	key, err3 := os.ReadFile(paths.Key)
	if err1 != nil || err2 != nil || err3 != nil {
		ph := []byte("gibcert host test placeholder\n")
		return deploy.Material{Cert: ph, Chain: ph, Fullchain: ph, Key: ph}, false
	}
	chain, _ := os.ReadFile(paths.Chain)
	return deploy.Material{Cert: cert, Chain: chain, Fullchain: fullchain, Key: key}, true
}

// hostTestRequest builds the request for a dry run. DER destinations are
// filled with the PEM bytes of the matching kind when the material is not
// real, because placeholders cannot be converted.
func hostTestRequest(certName string, d *config.Deploy, m deploy.Material) (deploy.Request, error) {
	req, err := deploy.NewRequest(certName, d, m)
	if err == nil {
		return req, nil
	}
	// Placeholder material cannot be converted to DER; stage the DER
	// destinations with the unconverted bytes instead.
	plain := *d
	plain.CertDER, plain.KeyDER = "", ""
	req, perr := deploy.NewRequest(certName, &plain, m)
	if perr != nil {
		return deploy.Request{}, err
	}
	if d.CertDER != "" {
		req.Files = append(req.Files, deploy.File{Kind: "cert-der", Path: d.CertDER, Data: m.Cert})
	}
	if d.KeyDER != "" {
		req.Files = append(req.Files, deploy.File{Kind: "key-der", Path: d.KeyDER, Data: m.Key})
	}
	return req, nil
}

func printPermissionHint(out io.Writer, h *config.Host, hello *receive.Hello, d *config.Deploy) {
	dirs := map[string]bool{}
	for _, p := range []string{d.Cert, d.Chain, d.Fullchain, d.Key, d.CertDER, d.KeyDER} {
		if p != "" {
			dirs[path.Dir(p)] = true
		}
	}
	sorted := make([]string, 0, len(dirs))
	for dir := range dirs {
		sorted = append(sorted, dir)
	}
	sort.Strings(sorted)
	user := h.User
	if user == "" {
		user = hello.User
	}
	fmt.Fprintf(out, "    hint: an unprivileged deploy user needs write access to the destination.\n")
	fmt.Fprintf(out, "    Example setup, run as root on %s (adjust names):\n", h.Name)
	for _, dir := range sorted {
		if d.Group != "" {
			fmt.Fprintf(out, "      install -d -o root -g %s -m 2750 %s\n", d.Group, dir)
		} else {
			fmt.Fprintf(out, "      install -d -o root -m 0755 %s\n", dir)
		}
		fmt.Fprintf(out, "      setfacl -m u:%s:rwx %s\n", user, dir)
	}
	if d.Group != "" {
		fmt.Fprintf(out, "    with \"mode 0640\" in the deploy block; see docs/remote-deploy.md\n")
	} else {
		fmt.Fprintf(out, "    see docs/remote-deploy.md\n")
	}
}
