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

package importer

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"foundry.fsky.io/fsky/gibcert/internal/storage"
)

type DehydratedOptions struct {
	Path   string
	Only   []string
	Name   string
	DryRun bool
	Force  bool
	Now    time.Time
}

var dehydratedCAs = map[string]string{
	"letsencrypt":      "https://acme-v02.api.letsencrypt.org/directory",
	"letsencrypt-test": "https://acme-staging-v02.api.letsencrypt.org/directory",
	"buypass":          "https://api.buypass.com/acme/directory",
	"buypass-test":     "https://api.test4.buypass.no/acme/directory",
	"zerossl":          "https://acme.zerossl.com/v2/DV90/directory",
	"google":           "https://dv.acme-v02.api.pki.goog/directory",
	"google-test":      "https://dv.acme-v02.api.pki.goog/directory",
}

func ImportDehydrated(store *storage.Store, opts DehydratedOptions) ([]Result, error) {
	if opts.Path == "" {
		return nil, errors.New("import dehydrated: path is required")
	}
	info, err := os.Stat(opts.Path)
	if err != nil {
		return nil, fmt.Errorf("import dehydrated: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("import dehydrated: %s is not a directory", opts.Path)
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}

	certsDir := filepath.Join(opts.Path, "certs")
	entries, err := os.ReadDir(certsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("import dehydrated: %s does not contain a certs/ directory", opts.Path)
		}
		return nil, fmt.Errorf("import dehydrated: read certs directory: %w", err)
	}

	var candidates []dehydratedCandidate
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		dir := filepath.Join(certsDir, name)
		certPath := filepath.Join(dir, "cert.pem")
		keyPath := filepath.Join(dir, "privkey.pem")
		if !fileExists(certPath) || !fileExists(keyPath) {
			continue
		}
		candidates = append(candidates, dehydratedCandidate{
			dir:      dir,
			alias:    name,
			basePath: opts.Path,
		})
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].alias < candidates[j].alias })

	if len(opts.Only) > 0 {
		want := map[string]bool{}
		for _, n := range opts.Only {
			want[n] = true
		}
		filtered := candidates[:0]
		for _, c := range candidates {
			if want[c.alias] {
				filtered = append(filtered, c)
			}
		}
		candidates = filtered
	}
	if opts.Name != "" && len(candidates) != 1 {
		return nil, fmt.Errorf("import dehydrated: --name requires exactly one certificate candidate")
	}

	if err := store.Init(); err != nil {
		return nil, err
	}

	out := make([]Result, 0, len(candidates))
	for _, c := range candidates {
		m, r := materialForDehydratedCandidate(c, opts)
		if r.Status != "" {
			out = append(out, r)
			continue
		}
		results, err := ImportCertMaterials(store, []CertMaterial{m}, CertOptions{
			DryRun: opts.DryRun,
			Force:  opts.Force,
			Now:    opts.Now,
		})
		if err != nil {
			return nil, err
		}
		out = append(out, results...)
	}
	return out, nil
}

type dehydratedCandidate struct {
	dir      string
	alias    string
	basePath string
}

func materialForDehydratedCandidate(c dehydratedCandidate, opts DehydratedOptions) (CertMaterial, Result) {
	name := c.alias
	if opts.Name != "" {
		name = opts.Name
	}
	r := Result{Source: c.alias, Name: name}

	certPath := filepath.Join(c.dir, "cert.pem")
	keyPath := filepath.Join(c.dir, "privkey.pem")
	chainPath := filepath.Join(c.dir, "chain.pem")

	leafPEM, err := os.ReadFile(certPath)
	if err != nil {
		r.Status = StatusFailed
		r.Detail = fmt.Sprintf("read leaf: %v", err)
		return CertMaterial{}, r
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		r.Status = StatusFailed
		r.Detail = fmt.Sprintf("read key: %v", err)
		return CertMaterial{}, r
	}

	var chainPEM []byte
	if fileExists(chainPath) {
		chainPEM, err = os.ReadFile(chainPath)
		if err != nil {
			r.Status = StatusFailed
			r.Detail = fmt.Sprintf("read chain: %v", err)
			return CertMaterial{}, r
		}
	}

	directory := ""
	if ca := readDehydratedCA(c.basePath); ca != "" {
		if resolved, ok := dehydratedCAs[ca]; ok {
			directory = resolved
		} else if strings.HasPrefix(ca, "https://") || strings.HasPrefix(ca, "http://") {
			directory = ca
		}
	}

	return CertMaterial{
		Source:     c.alias,
		Name:       name,
		CertPEM:    leafPEM,
		ChainPEM:   chainPEM,
		KeyPEM:     keyPEM,
		Directory:  directory,
		IssuerType: "imported",
	}, Result{}
}

func readDehydratedCA(basePath string) string {
	paths := []string{
		filepath.Join(basePath, "config"),
		filepath.Join(basePath, "dehydrated_config"),
	}
	for _, p := range paths {
		ca := readShellVar(p, "CA")
		if ca != "" {
			return ca
		}
	}
	return ""
}

func readShellVar(path, varName string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		if key != varName {
			continue
		}
		val := strings.TrimSpace(line[eq+1:])
		val = strings.Trim(val, `"'`)
		return val
	}
	return ""
}
