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
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"foundry.fsky.io/fsky/gibcert/internal/storage"
)

type LegoOptions struct {
	Path   string
	Only   []string
	Name   string
	DryRun bool
	Force  bool
	Now    time.Time
}

func ImportLego(store *storage.Store, opts LegoOptions) ([]Result, error) {
	if opts.Path == "" {
		return nil, errors.New("import lego: path is required")
	}
	info, err := os.Stat(opts.Path)
	if err != nil {
		return nil, fmt.Errorf("import lego: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("import lego: %s is not a directory", opts.Path)
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}

	certsDir := filepath.Join(opts.Path, "certificates")
	entries, err := os.ReadDir(certsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("import lego: %s does not contain a certificates/ directory", opts.Path)
		}
		return nil, fmt.Errorf("import lego: read certificates directory: %w", err)
	}

	var candidates []legoCandidate
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".key") {
			continue
		}
		base := strings.TrimSuffix(e.Name(), ".key")
		crtPath := filepath.Join(certsDir, base+".crt")
		if !fileExists(crtPath) {
			continue
		}
		candidates = append(candidates, legoCandidate{
			base:       base,
			certsDir:   certsDir,
			issuerPath: filepath.Join(certsDir, base+".issuer.crt"),
		})
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].base < candidates[j].base })

	if len(opts.Only) > 0 {
		want := map[string]bool{}
		for _, n := range opts.Only {
			want[n] = true
		}
		filtered := candidates[:0]
		for _, c := range candidates {
			if want[c.base] {
				filtered = append(filtered, c)
			}
		}
		candidates = filtered
	}
	if opts.Name != "" && len(candidates) != 1 {
		return nil, fmt.Errorf("import lego: --name requires exactly one certificate candidate")
	}

	if err := store.Init(); err != nil {
		return nil, err
	}

	out := make([]Result, 0, len(candidates))
	for _, c := range candidates {
		m, r := materialForLegoCandidate(c, opts)
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

type legoCandidate struct {
	base       string
	certsDir   string
	issuerPath string
}

func materialForLegoCandidate(c legoCandidate, opts LegoOptions) (CertMaterial, Result) {
	name := c.base
	if opts.Name != "" {
		name = opts.Name
	}
	r := Result{Source: c.base, Name: name}

	crtPath := filepath.Join(c.certsDir, c.base+".crt")
	keyPath := filepath.Join(c.certsDir, c.base+".key")

	crtPEM, err := os.ReadFile(crtPath)
	if err != nil {
		r.Status = StatusFailed
		r.Detail = fmt.Sprintf("read cert: %v", err)
		return CertMaterial{}, r
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		r.Status = StatusFailed
		r.Detail = fmt.Sprintf("read key: %v", err)
		return CertMaterial{}, r
	}

	var leafPEM, chainPEM []byte

	if fileExists(c.issuerPath) {
		issuerPEM, err := os.ReadFile(c.issuerPath)
		if err != nil {
			r.Status = StatusFailed
			r.Detail = fmt.Sprintf("read issuer: %v", err)
			return CertMaterial{}, r
		}
		first, rest, err := splitFirstCert(crtPEM)
		if err != nil {
			r.Status = StatusFailed
			r.Detail = fmt.Sprintf("parse cert: %v", err)
			return CertMaterial{}, r
		}
		leafPEM = first
		chainPEM = append(rest, issuerPEM...)
	} else {
		leafPEM, chainPEM, err = SplitFullchainPEM(crtPEM)
		if err != nil {
			r.Status = StatusFailed
			r.Detail = fmt.Sprintf("parse cert: %v", err)
			return CertMaterial{}, r
		}
	}

	return CertMaterial{
		Source:     c.base,
		Name:       name,
		CertPEM:    leafPEM,
		ChainPEM:   chainPEM,
		KeyPEM:     keyPEM,
		IssuerType: "imported",
	}, Result{}
}

func splitFirstCert(pemBytes []byte) (first []byte, rest []byte, err error) {
	block, tail := pem.Decode(pemBytes)
	if block == nil {
		return nil, nil, errors.New("no PEM block found")
	}
	if block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("unexpected PEM type %q", block.Type)
	}
	first = pem.EncodeToMemory(block)
	rest = append([]byte{}, tail...)
	return first, rest, nil
}
