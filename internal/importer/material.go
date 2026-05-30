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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"foundry.fsky.io/fsky/gibcert/internal/config"
	"foundry.fsky.io/fsky/gibcert/internal/storage"
)

// CertMaterial is one certificate/key pair ready to be copied into gibcert's
// canonical certificate store.
type CertMaterial struct {
	Source     string
	Name       string
	CertPEM    []byte
	ChainPEM   []byte
	KeyPEM     []byte
	Directory  string
	IssuerType string
}

// CertOptions controls generic certificate material imports.
type CertOptions struct {
	DryRun bool
	Force  bool
	Now    time.Time
}

// ImportCertMaterials validates and imports certificate material into the
// canonical store. Per-certificate failures are returned as Result entries.
func ImportCertMaterials(store *storage.Store, materials []CertMaterial, opts CertOptions) ([]Result, error) {
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	if err := store.Init(); err != nil {
		return nil, err
	}
	out := make([]Result, 0, len(materials))
	for _, m := range materials {
		out = append(out, importCertMaterial(store, m, opts))
	}
	return out, nil
}

func importCertMaterial(store *storage.Store, m CertMaterial, opts CertOptions) Result {
	r := Result{Source: m.Source, Name: m.Name}
	if r.Source == "" {
		r.Source = m.Name
	}
	if m.Name == "" {
		r.Status = StatusFailed
		r.Detail = "name is required"
		return r
	}
	if err := config.ValidateStateName(m.Name); err != nil {
		r.Status = StatusFailed
		r.Detail = fmt.Sprintf("invalid name: %v", err)
		return r
	}

	leaf, err := parseSingleCert(m.CertPEM)
	if err != nil {
		r.Status = StatusFailed
		r.Detail = fmt.Sprintf("parse leaf: %v", err)
		return r
	}
	if len(m.KeyPEM) == 0 {
		r.Status = StatusFailed
		r.Detail = "key is required"
		return r
	}
	if err := keyMatchesCert(m.KeyPEM, leaf); err != nil {
		r.Status = StatusFailed
		r.Detail = fmt.Sprintf("key does not match cert: %v", err)
		return r
	}
	if len(m.ChainPEM) > 0 {
		if _, err := parseCerts(m.ChainPEM); err != nil {
			r.Status = StatusFailed
			r.Detail = fmt.Sprintf("parse chain: %v", err)
			return r
		}
	}

	existing, err := store.LoadCertMeta(m.Name)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		r.Status = StatusFailed
		r.Detail = fmt.Sprintf("load existing meta: %v", err)
		return r
	}
	if existing != nil && !opts.Force {
		r.Status = StatusSkipped
		r.Detail = "cert already in store (use --force to overwrite)"
		return r
	}

	expired := leaf.NotAfter.Before(opts.Now)
	if opts.DryRun {
		r.Status = StatusPlanned
		r.Detail = describePlanned(leaf, m.Directory, expired)
		return r
	}

	paths := store.CertPaths(m.Name)
	if err := os.MkdirAll(paths.Dir, 0o755); err != nil {
		r.Status = StatusFailed
		r.Detail = fmt.Sprintf("create cert dir: %v", err)
		return r
	}
	if existing != nil && opts.Force {
		if _, _, err := storage.ArchivePrivateKey(paths.Key, opts.Now); err != nil {
			r.Status = StatusFailed
			r.Detail = fmt.Sprintf("archive existing key: %v", err)
			return r
		}
	}

	fullchainPEM := append([]byte{}, m.CertPEM...)
	if len(m.ChainPEM) > 0 {
		if len(fullchainPEM) > 0 && fullchainPEM[len(fullchainPEM)-1] != '\n' {
			fullchainPEM = append(fullchainPEM, '\n')
		}
		fullchainPEM = append(fullchainPEM, m.ChainPEM...)
	}

	if err := storage.WriteFileAtomic(paths.Cert, m.CertPEM, 0o644); err != nil {
		r.Status = StatusFailed
		r.Detail = fmt.Sprintf("write cert: %v", err)
		return r
	}
	if len(m.ChainPEM) > 0 {
		if err := storage.WriteFileAtomic(paths.Chain, m.ChainPEM, 0o644); err != nil {
			r.Status = StatusFailed
			r.Detail = fmt.Sprintf("write chain: %v", err)
			return r
		}
	} else if err := os.Remove(paths.Chain); err != nil && !errors.Is(err, os.ErrNotExist) {
		r.Status = StatusFailed
		r.Detail = fmt.Sprintf("remove stale chain: %v", err)
		return r
	}
	if err := storage.WriteFileAtomic(paths.Fullchain, fullchainPEM, 0o644); err != nil {
		r.Status = StatusFailed
		r.Detail = fmt.Sprintf("write fullchain: %v", err)
		return r
	}
	if err := storage.WriteFileAtomic(paths.Key, m.KeyPEM, 0o600); err != nil {
		r.Status = StatusFailed
		r.Detail = fmt.Sprintf("write key: %v", err)
		return r
	}

	issuerType := m.IssuerType
	if issuerType == "" {
		issuerType = "imported"
	}
	meta := storage.CertMeta{
		Name:         m.Name,
		IssuerType:   issuerType,
		Directory:    m.Directory,
		Names:        certNames(leaf),
		SerialNumber: leaf.SerialNumber.String(),
		NotBefore:    leaf.NotBefore,
		NotAfter:     leaf.NotAfter,
		IssuedAt:     opts.Now.UTC(),
	}
	if existing != nil {
		meta.Deploys = existing.Deploys
		meta.TLSA = existing.TLSA
	}
	if err := store.SaveCertMeta(m.Name, meta); err != nil {
		r.Status = StatusFailed
		r.Detail = fmt.Sprintf("write meta: %v", err)
		return r
	}

	r.Status = StatusImported
	r.Detail = describeImported(leaf, m.Directory, expired)
	return r
}

func certNames(cert *x509.Certificate) []string {
	names := append([]string(nil), cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		names = append(names, ip.String())
	}
	if len(names) == 0 && cert.Subject.CommonName != "" {
		names = []string{cert.Subject.CommonName}
	}
	return names
}

func describePlanned(leaf *x509.Certificate, directory string, expired bool) string {
	parts := []string{fmt.Sprintf("expires %s", leaf.NotAfter.UTC().Format(time.RFC3339))}
	if directory != "" {
		parts = append(parts, "directory "+directory)
	}
	if expired {
		parts = append(parts, "EXPIRED")
	}
	return strings.Join(parts, "; ")
}

func describeImported(leaf *x509.Certificate, directory string, expired bool) string {
	return describePlanned(leaf, directory, expired)
}

func parseSingleCert(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("unexpected PEM type %q", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseCerts(pemBytes []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no certificates in chain")
	}
	return out, nil
}

func keyMatchesCert(keyPEM []byte, cert *x509.Certificate) error {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return errors.New("no PEM block in key")
	}
	var priv any
	var err error
	switch block.Type {
	case "RSA PRIVATE KEY":
		priv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		priv, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		priv, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return fmt.Errorf("unsupported PEM key type %q", block.Type)
	}
	if err != nil {
		return err
	}
	switch p := priv.(type) {
	case *rsa.PrivateKey:
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("cert public key is not RSA")
		}
		if p.N.Cmp(pub.N) != 0 || p.E != pub.E {
			return errors.New("RSA public key mismatch")
		}
	case *ecdsa.PrivateKey:
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("cert public key is not ECDSA")
		}
		if p.X.Cmp(pub.X) != 0 || p.Y.Cmp(pub.Y) != 0 {
			return errors.New("ECDSA public key mismatch")
		}
	case ed25519.PrivateKey:
		pub, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return errors.New("cert public key is not Ed25519")
		}
		if string(p.Public().(ed25519.PublicKey)) != string(pub) {
			return errors.New("Ed25519 public key mismatch")
		}
	default:
		return fmt.Errorf("unsupported private key type %T", priv)
	}
	return nil
}
