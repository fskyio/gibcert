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

package localca

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"foundry.fsky.io/fsky/gibcert/internal/config"
	"foundry.fsky.io/fsky/gibcert/internal/storage"
)

const directoryPrefix = "local:"

type IssueOptions struct {
	Out    io.Writer
	NewKey bool
	Now    time.Time
}

type CAStatus struct {
	Ready    bool
	Reason   string
	NotAfter time.Time
}

func Directory(name string) string {
	return directoryPrefix + name
}

func CheckCA(ca *config.CA, store *storage.Store, now time.Time) CAStatus {
	if now.IsZero() {
		now = time.Now()
	}
	paths := store.CAPaths(ca.Name)
	cert, err := readCert(paths.Cert)
	if err != nil {
		return CAStatus{Reason: "local CA certificate missing or unreadable"}
	}
	if _, err := storage.ReadKey(paths.Key); err != nil {
		return CAStatus{Reason: "local CA key missing or unreadable", NotAfter: cert.NotAfter}
	}
	if !cert.NotAfter.After(now) {
		return CAStatus{Reason: "local CA certificate expired", NotAfter: cert.NotAfter}
	}
	return CAStatus{Ready: true, Reason: "local CA ready", NotAfter: cert.NotAfter}
}

func Issue(cert *config.Certificate, ca *config.CA, store *storage.Store, opts IssueOptions) error {
	out := opts.Out
	if out == nil {
		out = os.Stdout
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	caCert, caKey, err := ensureCA(ca, store, out, now)
	if err != nil {
		return err
	}

	var certKey crypto.Signer
	reusedKey := false
	paths := store.CertPaths(cert.Name)
	if cert.Key.Reuse && !opts.NewKey {
		certKey, err = storage.ReadKey(paths.Key)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("read existing cert key: %w", err)
		}
		reusedKey = certKey != nil
	}
	if certKey == nil {
		certKey, err = storage.GenerateKey(cert.Key)
		if err != nil {
			return fmt.Errorf("generate cert key: %w", err)
		}
	}

	fmt.Fprintf(out, "issuing %s from local CA %s (names: %s)\n", cert.Name, ca.Name, strings.Join(cert.Names, " "))

	leafDER, leaf, err := createLeaf(cert, caCert, caKey, certKey, now)
	if err != nil {
		return err
	}
	caDER := caCert.Raw

	if err := os.MkdirAll(paths.Dir, 0o755); err != nil {
		return fmt.Errorf("create cert dir: %w", err)
	}
	var archivedKey string
	if !reusedKey {
		var archived bool
		archivedKey, archived, err = storage.ArchivePrivateKey(paths.Key, now)
		if err != nil {
			return fmt.Errorf("archive previous privkey: %w", err)
		}
		if archived {
			fmt.Fprintf(out, "archived previous privkey: %s\n", archivedKey)
		}
	}
	if err := storage.WriteKey(paths.Key, certKey); err != nil {
		return fmt.Errorf("write privkey: %w", err)
	}
	if err := storage.WriteSingleCertDER(paths.Cert, leafDER, 0o644); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if err := storage.WriteSingleCertDER(paths.Chain, caDER, 0o644); err != nil {
		return fmt.Errorf("write chain: %w", err)
	}
	if err := storage.WriteCertChainDER(paths.Fullchain, [][]byte{leafDER, caDER}, 0o644); err != nil {
		return fmt.Errorf("write fullchain: %w", err)
	}
	if archivedKey != "" {
		if err := storage.PrunePrivateKeyArchives(paths.Dir, archivedKey); err != nil {
			return fmt.Errorf("prune previous privkey archives: %w", err)
		}
	}

	meta := storage.CertMeta{
		Name:         cert.Name,
		CA:           ca.Name,
		IssuerType:   "local",
		Directory:    Directory(ca.Name),
		Names:        append([]string(nil), cert.Names...),
		SerialNumber: leaf.SerialNumber.String(),
		NotBefore:    leaf.NotBefore,
		NotAfter:     leaf.NotAfter,
		IssuedAt:     now.UTC(),
	}
	if existing, err := store.LoadCertMeta(cert.Name); err == nil {
		meta.Deploys = existing.Deploys
	}
	if err := store.SaveCertMeta(cert.Name, meta); err != nil {
		return fmt.Errorf("write cert metadata: %w", err)
	}

	fmt.Fprintf(out, "stored:\n  %s\n  %s\n  %s\n  %s\n", paths.Cert, paths.Chain, paths.Fullchain, paths.Key)
	return nil
}

func ensureCA(ca *config.CA, store *storage.Store, out io.Writer, now time.Time) (*x509.Certificate, crypto.Signer, error) {
	paths := store.CAPaths(ca.Name)
	cert, certErr := readCert(paths.Cert)
	key, keyErr := storage.ReadKey(paths.Key)
	if certErr == nil && keyErr == nil && cert.NotAfter.After(now) {
		return cert, key, nil
	}
	if keyErr != nil || !certReusable(cert, now) {
		var err error
		key, err = storage.GenerateKey(ca.Key)
		if err != nil {
			return nil, nil, fmt.Errorf("generate local CA key: %w", err)
		}
	}
	certDER, cert, err := createCA(ca, key, now)
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(paths.Dir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("create local CA dir: %w", err)
	}
	if err := storage.WriteKey(paths.Key, key); err != nil {
		return nil, nil, fmt.Errorf("write local CA key: %w", err)
	}
	if err := storage.WriteSingleCertDER(paths.Cert, certDER, 0o644); err != nil {
		return nil, nil, fmt.Errorf("write local CA certificate: %w", err)
	}
	fmt.Fprintf(out, "created local CA %s\n", ca.Name)
	return cert, key, nil
}

func certReusable(cert *x509.Certificate, now time.Time) bool {
	return cert != nil && cert.NotAfter.After(now)
}

func createCA(ca *config.CA, key crypto.Signer, now time.Time) ([]byte, *x509.Certificate, error) {
	validFor := ca.ValidFor
	if validFor == 0 {
		validFor = config.DefaultLocalCAValidFor
	}
	commonName := ca.CommonName
	if commonName == "" {
		commonName = "gibcert " + ca.Name + " local CA"
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, fmt.Errorf("generate local CA serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-5 * time.Minute).UTC(),
		NotAfter:              now.Add(validFor).UTC(),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, nil, fmt.Errorf("create local CA certificate: %w", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse local CA certificate: %w", err)
	}
	return der, parsed, nil
}

func createLeaf(cert *config.Certificate, caCert *x509.Certificate, caKey crypto.Signer, certKey crypto.Signer, now time.Time) ([]byte, *x509.Certificate, error) {
	validFor := cert.ValidFor
	if validFor == 0 {
		validFor = config.DefaultLocalCertValidFor
	}
	notBefore := now.Add(-5 * time.Minute).UTC()
	notAfter := now.Add(validFor).UTC()
	if notAfter.After(caCert.NotAfter) {
		notAfter = caCert.NotAfter
	}
	if !notAfter.After(notBefore) {
		return nil, nil, fmt.Errorf("local CA expires before requested certificate validity")
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	dnsNames, ipAddresses := splitNames(cert.Names)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: cert.Names[0],
		},
		DNSNames:     dnsNames,
		IPAddresses:  ipAddresses,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SubjectKeyId: nil,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, certKey.Public(), caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create local certificate: %w", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse local certificate: %w", err)
	}
	return der, parsed, nil
}

func splitNames(names []string) ([]string, []net.IP) {
	var dnsNames []string
	var ipAddresses []net.IP
	for _, name := range names {
		if ip := net.ParseIP(name); ip != nil {
			ipAddresses = append(ipAddresses, ip)
			continue
		}
		dnsNames = append(dnsNames, name)
	}
	return dnsNames, ipAddresses
}

func readCert(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("no PEM certificate in %s", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}
