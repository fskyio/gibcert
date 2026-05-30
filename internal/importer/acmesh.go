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

// Package importer reads existing certificate material from other ACME clients
// and writes it into gibcert's canonical storage.
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

// ACMEShOptions controls a single acme.sh import run.
type ACMEShOptions struct {
	Path   string
	Only   []string
	Name   string
	DryRun bool
	Force  bool
	Now    time.Time
}

// Result describes the outcome for a single candidate directory.
type Result struct {
	Source string
	Name   string
	Status string
	Detail string
}

const (
	StatusImported = "imported"
	StatusSkipped  = "skipped"
	StatusFailed   = "failed"
	StatusPlanned  = "planned"
)

// ImportACMESh walks an acme.sh state directory and imports each candidate
// certificate directory into the given store. Returns one Result per candidate.
// An error is only returned for failures that prevent the walk itself; per-cert
// failures are reported via Result entries with Status=StatusFailed.
func ImportACMESh(store *storage.Store, opts ACMEShOptions) ([]Result, error) {
	if opts.Path == "" {
		return nil, errors.New("import: path is required")
	}
	info, err := os.Stat(opts.Path)
	if err != nil {
		return nil, fmt.Errorf("import: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("import: %s is not a directory", opts.Path)
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}

	candidates, err := findCandidates(opts.Path)
	if err != nil {
		return nil, err
	}
	if len(opts.Only) > 0 {
		want := map[string]bool{}
		for _, n := range opts.Only {
			want[n] = true
		}
		filtered := candidates[:0]
		for _, c := range candidates {
			if want[c.dirName] || want[targetName(c)] {
				filtered = append(filtered, c)
			}
		}
		candidates = filtered
	}
	if opts.Name != "" && len(candidates) != 1 {
		return nil, fmt.Errorf("import: --name requires exactly one certificate candidate")
	}

	if err := store.Init(); err != nil {
		return nil, err
	}

	out := make([]Result, 0, len(candidates))
	for _, c := range candidates {
		m, r := materialForCandidate(c, opts)
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

// candidate describes one acme.sh per-domain directory we might import.
type candidate struct {
	dir     string // absolute path to the acme.sh per-cert directory
	dirName string // base name, e.g. "example.com" or "example.com_ecc"
	ecc     bool
}

func findCandidates(root string) ([]candidate, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var out []candidate
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") || name == "ca" || name == "http.header" {
			continue
		}
		dir := filepath.Join(root, name)
		base := strings.TrimSuffix(name, "_ecc")
		certPath := filepath.Join(dir, base+".cer")
		keyPath := filepath.Join(dir, base+".key")
		if !fileExists(certPath) || !fileExists(keyPath) {
			continue
		}
		out = append(out, candidate{
			dir:     dir,
			dirName: name,
			ecc:     strings.HasSuffix(name, "_ecc"),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].dirName < out[j].dirName })
	return out, nil
}

func targetName(c candidate) string {
	if c.ecc {
		return strings.TrimSuffix(c.dirName, "_ecc") + "-ecc"
	}
	return c.dirName
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func materialForCandidate(c candidate, opts ACMEShOptions) (CertMaterial, Result) {
	name := targetName(c)
	if opts.Name != "" {
		name = opts.Name
	}
	r := Result{Source: c.dirName, Name: name}

	base := strings.TrimSuffix(c.dirName, "_ecc")
	certPath := filepath.Join(c.dir, base+".cer")
	keyPath := filepath.Join(c.dir, base+".key")
	chainPath := filepath.Join(c.dir, "ca.cer")
	confPath := filepath.Join(c.dir, base+".conf")

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
	if fileExists(confPath) {
		directory, _ = readLeAPI(confPath)
	}

	return CertMaterial{
		Source:     c.dirName,
		Name:       name,
		CertPEM:    leafPEM,
		ChainPEM:   chainPEM,
		KeyPEM:     keyPEM,
		Directory:  directory,
		IssuerType: "imported",
	}, Result{}
}

// readLeAPI extracts the Le_API shell variable from an acme.sh per-domain
// conf file. Returns "" if not found. The conf format is shell variable
// assignments like `Le_API='https://acme-v02.api.letsencrypt.org/directory'`.
func readLeAPI(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "Le_API") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		val := strings.TrimSpace(line[eq+1:])
		val = strings.TrimPrefix(val, "'")
		val = strings.TrimSuffix(val, "'")
		val = strings.TrimPrefix(val, `"`)
		val = strings.TrimSuffix(val, `"`)
		return val, nil
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", nil
}
