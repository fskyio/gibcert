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
	"strings"
	"time"

	"foundry.fsky.io/fsky/gibcert/internal/storage"
)

// PEMOptions controls a generic PEM file import.
type PEMOptions struct {
	Name          string
	CertPath      string
	ChainPath     string
	FullchainPath string
	KeyPath       string
	DryRun        bool
	Force         bool
	Now           time.Time
}

// ImportPEM imports certificate material from explicit PEM file paths.
func ImportPEM(store *storage.Store, opts PEMOptions) ([]Result, error) {
	if opts.Name == "" {
		return nil, errors.New("import pem: --name is required")
	}
	if opts.KeyPath == "" {
		return nil, errors.New("import pem: --key is required")
	}
	hasCert := opts.CertPath != ""
	hasFullchain := opts.FullchainPath != ""
	if hasCert == hasFullchain {
		return nil, errors.New("import pem: exactly one of --cert or --fullchain is required")
	}
	if hasFullchain && opts.ChainPath != "" {
		return nil, errors.New("import pem: --chain cannot be used with --fullchain")
	}

	m, r := materialFromPEM(opts)
	if r.Status != "" {
		return []Result{r}, nil
	}
	return ImportCertMaterials(store, []CertMaterial{m}, CertOptions{
		DryRun: opts.DryRun,
		Force:  opts.Force,
		Now:    opts.Now,
	})
}

func materialFromPEM(opts PEMOptions) (CertMaterial, Result) {
	r := Result{Source: "pem", Name: opts.Name}
	keyPEM, err := os.ReadFile(opts.KeyPath)
	if err != nil {
		r.Status = StatusFailed
		r.Detail = fmt.Sprintf("read key: %v", err)
		return CertMaterial{}, r
	}

	var certPEM, chainPEM []byte
	if opts.FullchainPath != "" {
		fullchainPEM, err := os.ReadFile(opts.FullchainPath)
		if err != nil {
			r.Status = StatusFailed
			r.Detail = fmt.Sprintf("read fullchain: %v", err)
			return CertMaterial{}, r
		}
		certPEM, chainPEM, err = SplitFullchainPEM(fullchainPEM)
		if err != nil {
			r.Status = StatusFailed
			r.Detail = fmt.Sprintf("parse fullchain: %v", err)
			return CertMaterial{}, r
		}
	} else {
		certPEM, err = os.ReadFile(opts.CertPath)
		if err != nil {
			r.Status = StatusFailed
			r.Detail = fmt.Sprintf("read cert: %v", err)
			return CertMaterial{}, r
		}
		if opts.ChainPath != "" {
			chainPEM, err = os.ReadFile(opts.ChainPath)
			if err != nil {
				r.Status = StatusFailed
				r.Detail = fmt.Sprintf("read chain: %v", err)
				return CertMaterial{}, r
			}
		}
	}

	return CertMaterial{
		Source:     "pem",
		Name:       opts.Name,
		CertPEM:    certPEM,
		ChainPEM:   chainPEM,
		KeyPEM:     keyPEM,
		IssuerType: "imported",
	}, Result{}
}

// SplitFullchainPEM returns the first certificate PEM block as the leaf and
// remaining certificate PEM blocks as the chain.
func SplitFullchainPEM(fullchainPEM []byte) ([]byte, []byte, error) {
	rest := fullchainPEM
	var certs [][]byte
	for {
		block, tail := pem.Decode(rest)
		if block == nil {
			if strings.TrimSpace(string(rest)) != "" {
				return nil, nil, errors.New("trailing non-PEM data")
			}
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, nil, fmt.Errorf("unexpected PEM type %q", block.Type)
		}
		certs = append(certs, pem.EncodeToMemory(block))
		rest = tail
	}
	if len(certs) == 0 {
		return nil, nil, errors.New("no certificates in fullchain")
	}
	leaf := append([]byte{}, certs[0]...)
	var chain []byte
	for _, cert := range certs[1:] {
		chain = append(chain, cert...)
	}
	return leaf, chain, nil
}
