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

type CertbotOptions struct {
	Path   string
	Only   []string
	Name   string
	DryRun bool
	Force  bool
	Now    time.Time
}

func ImportCertbot(store *storage.Store, opts CertbotOptions) ([]Result, error) {
	if opts.Path == "" {
		return nil, errors.New("import certbot: path is required")
	}
	info, err := os.Stat(opts.Path)
	if err != nil {
		return nil, fmt.Errorf("import certbot: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("import certbot: %s is not a directory", opts.Path)
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}

	liveDir := filepath.Join(opts.Path, "live")
	entries, err := os.ReadDir(liveDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("import certbot: %s does not contain a live/ directory", opts.Path)
		}
		return nil, fmt.Errorf("import certbot: read live directory: %w", err)
	}

	var candidates []certbotCandidate
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") || name == "README" {
			continue
		}
		dir := filepath.Join(liveDir, name)
		certPath := filepath.Join(dir, "cert.pem")
		keyPath := filepath.Join(dir, "privkey.pem")
		if !fileExists(certPath) || !fileExists(keyPath) {
			continue
		}
		candidates = append(candidates, certbotCandidate{
			dir:      dir,
			certName: name,
		})
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].certName < candidates[j].certName })

	if len(opts.Only) > 0 {
		want := map[string]bool{}
		for _, n := range opts.Only {
			want[n] = true
		}
		filtered := candidates[:0]
		for _, c := range candidates {
			if want[c.certName] {
				filtered = append(filtered, c)
			}
		}
		candidates = filtered
	}
	if opts.Name != "" && len(candidates) != 1 {
		return nil, fmt.Errorf("import certbot: --name requires exactly one certificate candidate")
	}

	if err := store.Init(); err != nil {
		return nil, err
	}

	out := make([]Result, 0, len(candidates))
	for _, c := range candidates {
		m, r := materialForCertbotCandidate(c, opts)
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

type certbotCandidate struct {
	dir      string
	certName string
}

func materialForCertbotCandidate(c certbotCandidate, opts CertbotOptions) (CertMaterial, Result) {
	name := c.certName
	if opts.Name != "" {
		name = opts.Name
	}
	r := Result{Source: c.certName, Name: name}

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
	confPath := filepath.Join(opts.Path, "renewal", c.certName+".conf")
	if fileExists(confPath) {
		directory, _ = readCertbotServer(confPath)
	}

	return CertMaterial{
		Source:     c.certName,
		Name:       name,
		CertPEM:    leafPEM,
		ChainPEM:   chainPEM,
		KeyPEM:     keyPEM,
		Directory:  directory,
		IssuerType: "imported",
	}, Result{}
}

func readCertbotServer(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	inRenewalParams := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "[renewalparams]" {
			inRenewalParams = true
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inRenewalParams = false
			continue
		}
		if inRenewalParams {
			eq := strings.IndexByte(line, '=')
			if eq < 0 {
				continue
			}
			key := strings.TrimSpace(line[:eq])
			if key != "server" {
				continue
			}
			val := strings.TrimSpace(line[eq+1:])
			val = strings.Trim(val, `"'`)
			return val, nil
		}
	}
	return "", scanner.Err()
}
