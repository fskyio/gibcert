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

package storage

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Store struct {
	Root string
}

func New(root string) *Store {
	return &Store{Root: root}
}

func (s *Store) Init() error {
	for _, d := range []string{s.Root, filepath.Join(s.Root, "accounts"), filepath.Join(s.Root, "cas"), filepath.Join(s.Root, "certs")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", d, err)
		}
	}
	return nil
}

func (s *Store) LockPath() string {
	return filepath.Join(s.Root, "gibcert.lock")
}

func (s *Store) AccountDir(name string) string {
	return filepath.Join(s.Root, "accounts", name)
}

func (s *Store) AccountKeyPath(name string) string {
	return filepath.Join(s.AccountDir(name), "account.key")
}

func (s *Store) AccountKeyNextPath(name string) string {
	return filepath.Join(s.AccountDir(name), "account.key.next")
}

func (s *Store) AccountMetaPath(name string) string {
	return filepath.Join(s.AccountDir(name), "account.json")
}

func (s *Store) CADir(name string) string {
	return filepath.Join(s.Root, "cas", name)
}

type CAPaths struct {
	Dir  string
	Cert string
	Key  string
	Meta string
}

func (s *Store) CAPaths(name string) CAPaths {
	d := s.CADir(name)
	return CAPaths{
		Dir:  d,
		Cert: filepath.Join(d, "ca.pem"),
		Key:  filepath.Join(d, "ca.key"),
		Meta: filepath.Join(d, "ca.json"),
	}
}

func (s *Store) CertDir(name string) string {
	return filepath.Join(s.Root, "certs", name)
}

type CertPaths struct {
	Dir       string
	Cert      string
	Chain     string
	Fullchain string
	Key       string
	KeyNext   string
	Meta      string
}

func (s *Store) CertPaths(name string) CertPaths {
	d := s.CertDir(name)
	return CertPaths{
		Dir:       d,
		Cert:      filepath.Join(d, "cert.pem"),
		Chain:     filepath.Join(d, "chain.pem"),
		Fullchain: filepath.Join(d, "fullchain.pem"),
		Key:       filepath.Join(d, "privkey.pem"),
		KeyNext:   filepath.Join(d, "privkey-next.pem"),
		Meta:      filepath.Join(d, "meta.json"),
	}
}

type AccountMeta struct {
	URL       string    `json:"url"`
	Email     string    `json:"email"`
	Directory string    `json:"directory"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Store) SaveAccountMeta(name string, meta AccountMeta) error {
	if err := os.MkdirAll(s.AccountDir(name), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.AccountMetaPath(name), b, 0o600)
}

func (s *Store) LoadAccountMeta(name string) (*AccountMeta, error) {
	b, err := os.ReadFile(s.AccountMetaPath(name))
	if err != nil {
		return nil, err
	}
	var m AccountMeta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

type CertMeta struct {
	Name             string           `json:"name"`
	Account          string           `json:"account"`
	CA               string           `json:"ca,omitempty"`
	IssuerType       string           `json:"issuer_type,omitempty"`
	Directory        string           `json:"directory"`
	Names            []string         `json:"names"`
	SerialNumber     string           `json:"serial_number"`
	NotBefore        time.Time        `json:"not_before"`
	NotAfter         time.Time        `json:"not_after"`
	IssuedAt         time.Time        `json:"issued_at"`
	RevokedAt        *time.Time       `json:"revoked_at,omitempty"`
	RevocationReason string           `json:"revocation_reason,omitempty"`
	Deploys          []CertDeployMeta `json:"deploys,omitempty"`
	TLSA             *CertTLSAMeta    `json:"tlsa,omitempty"`
	ARI              *CertARI         `json:"ari,omitempty"`
}

// CertARI is the cached ACME Renewal Information (RFC 9773) for a certificate.
// It is refreshed best-effort during `gibcert renew` and read by the renewal
// decision so the suggested window can pull renewal earlier than the static
// before-expiry window. Serial ties the cached info to a specific issued leaf;
// it is ignored once the certificate is reissued.
type CertARI struct {
	Serial         string     `json:"serial"`
	WindowStart    time.Time  `json:"window_start"`
	WindowEnd      time.Time  `json:"window_end"`
	SelectedTime   time.Time  `json:"selected_time"`
	RetryAfter     *time.Time `json:"retry_after,omitempty"`
	ExplanationURL string     `json:"explanation_url,omitempty"`
	FetchedAt      time.Time  `json:"fetched_at"`
}

type CertDeployMeta struct {
	Target string    `json:"target"`
	Kind   string    `json:"kind"`
	Path   string    `json:"path"`
	SHA256 string    `json:"sha256"`
	At     time.Time `json:"at"`
}

type CertTLSAMeta struct {
	Usage           int          `json:"usage"`
	Selector        int          `json:"selector"`
	MatchingType    int          `json:"matching_type"`
	TTL             int          `json:"ttl"`
	Ports           []TLSAPort   `json:"ports"`
	CurrentValue    string       `json:"current_value"`
	NextValue       string       `json:"next_value,omitempty"`
	NextPublishedAt time.Time    `json:"next_published_at,omitempty"`
	Published       []TLSARecord `json:"published,omitempty"`
}

type TLSAPort struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

// TLSARecord records a TLSA record that gibcert has published. Used to detect
// drift and clean up records that were published in earlier runs.
type TLSARecord struct {
	Owner string `json:"owner"`
	RData string `json:"rdata"`
}

func (s *Store) SaveCertMeta(name string, meta CertMeta) error {
	if err := os.MkdirAll(s.CertDir(name), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.CertPaths(name).Meta, b, 0o600)
}

func (s *Store) LoadCertMeta(name string) (*CertMeta, error) {
	b, err := os.ReadFile(s.CertPaths(name).Meta)
	if err != nil {
		return nil, err
	}
	var m CertMeta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func (s *Store) ListCertNames() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(s.Root, "certs"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names, nil
}

func (s *Store) DeleteCert(name string) error {
	err := os.RemoveAll(s.CertDir(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:])
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	return writeFileAtomic(path, data, mode)
}

// PromoteNextKey moves the staged next-key file to the live key path,
// archiving any previous live key first. It is a no-op if the staged key file
// does not exist.
func PromoteNextKey(paths CertPaths, at time.Time) (archived string, promoted bool, err error) {
	if _, err := os.Stat(paths.KeyNext); errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	} else if err != nil {
		return "", false, err
	}
	archived, _, err = ArchivePrivateKey(paths.Key, at)
	if err != nil {
		return "", false, fmt.Errorf("archive previous privkey: %w", err)
	}
	if err := os.Rename(paths.KeyNext, paths.Key); err != nil {
		return archived, false, fmt.Errorf("promote staged privkey: %w", err)
	}
	return archived, true, nil
}

func ArchivePrivateKey(path string, at time.Time) (string, bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	archive := filepath.Join(filepath.Dir(path), "privkey-"+at.UTC().Format("20060102T150405Z")+".pem")
	if err := writeFileAtomic(archive, b, 0o600); err != nil {
		return "", false, err
	}
	return archive, true, nil
}

func ArchiveAccountKey(path string, at time.Time) (string, bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	archive := filepath.Join(filepath.Dir(path), "account-"+at.UTC().Format("20060102T150405Z")+".key")
	if err := writeFileAtomic(archive, b, 0o600); err != nil {
		return "", false, err
	}
	return archive, true, nil
}

func PrunePrivateKeyArchives(dir, keep string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	keepBase := filepath.Base(keep)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || name == keepBase || !strings.HasPrefix(name, "privkey-") || !strings.HasSuffix(name, ".pem") {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
