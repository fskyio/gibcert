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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"foundry.fsky.io/fsky/gibcert/internal/config"
)

func TestStoreInitAndPathHelpers(t *testing.T) {
	root := t.TempDir()
	store := New(root)
	if store.Root != root {
		t.Fatalf("Root got %q, want %q", store.Root, root)
	}
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	for _, dir := range []string{
		root,
		filepath.Join(root, "accounts"),
		filepath.Join(root, "cas"),
		filepath.Join(root, "certs"),
	} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("stat %s: %v", dir, err)
		}
		if !info.IsDir() {
			t.Fatalf("%s is not a directory", dir)
		}
	}

	if got := store.LockPath(); got != filepath.Join(root, "gibcert.lock") {
		t.Fatalf("LockPath got %q", got)
	}
	if got := store.AccountKeyPath("prod"); got != filepath.Join(root, "accounts", "prod", "account.key") {
		t.Fatalf("AccountKeyPath got %q", got)
	}
	if got := store.AccountKeyNextPath("prod"); got != filepath.Join(root, "accounts", "prod", "account.key.next") {
		t.Fatalf("AccountKeyNextPath got %q", got)
	}
	if got := store.AccountMetaPath("prod"); got != filepath.Join(root, "accounts", "prod", "account.json") {
		t.Fatalf("AccountMetaPath got %q", got)
	}
	ca := store.CAPaths("local")
	if ca.Dir != filepath.Join(root, "cas", "local") || ca.Cert != filepath.Join(ca.Dir, "ca.pem") || ca.Key != filepath.Join(ca.Dir, "ca.key") || ca.Meta != filepath.Join(ca.Dir, "ca.json") {
		t.Fatalf("CAPaths got %#v", ca)
	}
	cert := store.CertPaths("example.com")
	if cert.Dir != filepath.Join(root, "certs", "example.com") || cert.KeyNext != filepath.Join(cert.Dir, "privkey-next.pem") {
		t.Fatalf("CertPaths got %#v", cert)
	}
}

func TestAccountMetaRoundTripAndMode(t *testing.T) {
	store := New(t.TempDir())
	meta := AccountMeta{
		URL:       "https://example.invalid/acct/1",
		Email:     "admin@example.com",
		Directory: "https://example.invalid/directory",
		CreatedAt: time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC),
	}
	if err := store.SaveAccountMeta("letsencrypt", meta); err != nil {
		t.Fatalf("SaveAccountMeta: %v", err)
	}
	got, err := store.LoadAccountMeta("letsencrypt")
	if err != nil {
		t.Fatalf("LoadAccountMeta: %v", err)
	}
	if *got != meta {
		t.Fatalf("metadata round trip got %#v, want %#v", got, meta)
	}
	assertFileMode(t, store.AccountMetaPath("letsencrypt"), 0o600)
}

func TestWriteReadKeysAndGenerateKeyTypes(t *testing.T) {
	accountKey, err := GenerateAccountKey()
	if err != nil {
		t.Fatalf("GenerateAccountKey: %v", err)
	}
	if key, ok := accountKey.(*ecdsa.PrivateKey); !ok || key.Curve != elliptic.P256() {
		t.Fatalf("account key got %T/%v, want P-256 ECDSA", accountKey, keyCurve(accountKey))
	}

	for _, tc := range []struct {
		name string
		spec config.KeySpec
		want func(t *testing.T, key any)
	}{
		{
			name: "default ecdsa p256",
			spec: config.KeySpec{},
			want: func(t *testing.T, key any) {
				k, ok := key.(*ecdsa.PrivateKey)
				if !ok || k.Curve != elliptic.P256() {
					t.Fatalf("got %T/%v, want P-256 ECDSA", key, keyCurve(key))
				}
			},
		},
		{
			name: "ecdsa p384",
			spec: config.KeySpec{Type: "ecdsa", Curve: "p384"},
			want: func(t *testing.T, key any) {
				k, ok := key.(*ecdsa.PrivateKey)
				if !ok || k.Curve != elliptic.P384() {
					t.Fatalf("got %T/%v, want P-384 ECDSA", key, keyCurve(key))
				}
			},
		},
		{
			name: "rsa custom bits",
			spec: config.KeySpec{Type: "rsa", Bits: 1024},
			want: func(t *testing.T, key any) {
				k, ok := key.(*rsa.PrivateKey)
				if !ok || k.N.BitLen() != 1024 {
					t.Fatalf("got %T/%d bits, want 1024-bit RSA", key, rsaBits(key))
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := GenerateKey(tc.spec)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			tc.want(t, key)

			path := filepath.Join(t.TempDir(), "privkey.pem")
			if err := WriteKey(path, key); err != nil {
				t.Fatalf("WriteKey: %v", err)
			}
			assertFileMode(t, path, 0o600)
			read, err := ReadKey(path)
			if err != nil {
				t.Fatalf("ReadKey: %v", err)
			}
			tc.want(t, read)
		})
	}

	if _, err := GenerateKey(config.KeySpec{Type: "dsa"}); err == nil {
		t.Fatal("GenerateKey unsupported type succeeded")
	}

	path := filepath.Join(t.TempDir(), "unsupported.key")
	if err := WriteKey(path, unsupportedSigner{}); err == nil {
		t.Fatal("WriteKey unsupported signer succeeded")
	}
}

func TestReadKeyRejectsInvalidPEMAndAcceptsLegacyECKey(t *testing.T) {
	dir := t.TempDir()
	invalid := filepath.Join(dir, "invalid.key")
	if err := os.WriteFile(invalid, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKey(invalid); err == nil {
		t.Fatal("ReadKey invalid PEM succeeded")
	}

	malformed := filepath.Join(dir, "malformed.key")
	if err := os.WriteFile(malformed, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("bad-der")}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKey(malformed); err == nil {
		t.Fatal("ReadKey malformed PEM succeeded")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(dir, "legacy-ec.key")
	if err := os.WriteFile(legacy, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadKey(legacy)
	if err != nil {
		t.Fatalf("ReadKey legacy EC key: %v", err)
	}
	if _, ok := got.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("ReadKey legacy EC key got %T", got)
	}
}

func TestWriteCertificateDERHelpers(t *testing.T) {
	dir := t.TempDir()
	chainPath := filepath.Join(dir, "chain.pem")
	if err := WriteCertChainDER(chainPath, [][]byte{{1, 2, 3}, {4, 5, 6}}, 0o644); err != nil {
		t.Fatalf("WriteCertChainDER: %v", err)
	}
	assertFileMode(t, chainPath, 0o644)
	chainBytes, err := os.ReadFile(chainPath)
	if err != nil {
		t.Fatal(err)
	}
	first, rest := pem.Decode(chainBytes)
	second, rest := pem.Decode(rest)
	if first == nil || second == nil || len(rest) != 0 {
		t.Fatalf("chain PEM decode failed: first=%v second=%v rest=%q", first, second, rest)
	}
	if first.Type != "CERTIFICATE" || second.Type != "CERTIFICATE" {
		t.Fatalf("chain PEM types got %q and %q", first.Type, second.Type)
	}

	certPath := filepath.Join(dir, "cert.pem")
	if err := WriteSingleCertDER(certPath, []byte{7, 8, 9}, 0o600); err != nil {
		t.Fatalf("WriteSingleCertDER: %v", err)
	}
	assertFileMode(t, certPath, 0o600)
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(certBytes)
	if block == nil || len(rest) != 0 || block.Type != "CERTIFICATE" || string(block.Bytes) != string([]byte{7, 8, 9}) {
		t.Fatalf("single cert PEM got block=%v rest=%q", block, rest)
	}
}

func TestWriteFileAtomicOverwritesWithMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(path, []byte("new"), 0o600); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("content got %q, want new", got)
	}
	assertFileMode(t, path, 0o600)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != "file.txt" {
			t.Fatalf("unexpected temporary file left behind: %s", entry.Name())
		}
	}
}

func TestPromoteNextKeyArchivesLiveKey(t *testing.T) {
	store := New(t.TempDir())
	paths := store.CertPaths("example.com")
	if err := os.MkdirAll(paths.Dir, 0o755); err != nil {
		t.Fatal(err)
	}

	archived, promoted, err := PromoteNextKey(paths, time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("PromoteNextKey without staged key: %v", err)
	}
	if promoted || archived != "" {
		t.Fatalf("PromoteNextKey without staged key got archived=%q promoted=%v", archived, promoted)
	}

	if err := os.WriteFile(paths.Key, []byte("live"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.KeyNext, []byte("next"), 0o600); err != nil {
		t.Fatal(err)
	}
	archived, promoted, err = PromoteNextKey(paths, time.Date(2026, 5, 22, 12, 1, 2, 0, time.UTC))
	if err != nil {
		t.Fatalf("PromoteNextKey: %v", err)
	}
	if !promoted {
		t.Fatal("PromoteNextKey promoted=false, want true")
	}
	if filepath.Base(archived) != "privkey-20260522T120102Z.pem" {
		t.Fatalf("archive path got %q", archived)
	}
	assertFileContent(t, archived, "live")
	assertFileContent(t, paths.Key, "next")
	if _, err := os.Stat(paths.KeyNext); !os.IsNotExist(err) {
		t.Fatalf("staged key still exists: %v", err)
	}
	assertFileMode(t, archived, 0o600)

	withoutLive := store.CertPaths("without-live")
	if err := os.MkdirAll(withoutLive.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(withoutLive.KeyNext, []byte("new-live"), 0o600); err != nil {
		t.Fatal(err)
	}
	archived, promoted, err = PromoteNextKey(withoutLive, time.Date(2026, 5, 22, 12, 2, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("PromoteNextKey without live key: %v", err)
	}
	if !promoted || archived != "" {
		t.Fatalf("PromoteNextKey without live key got archived=%q promoted=%v", archived, promoted)
	}
	assertFileContent(t, withoutLive.Key, "new-live")
}

func TestArchivePrivateKeyAndPrune(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "privkey.pem")
	if err := os.WriteFile(keyPath, []byte("old-key"), 0o600); err != nil {
		t.Fatal(err)
	}

	keep, archived, err := ArchivePrivateKey(keyPath, time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("ArchivePrivateKey: %v", err)
	}
	if !archived {
		t.Fatal("ArchivePrivateKey archived=false, want true")
	}
	got, err := os.ReadFile(keep)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "old-key" {
		t.Fatalf("archive content got %q, want old-key", got)
	}

	stale := filepath.Join(dir, "privkey-20260521T120000Z.pem")
	if err := os.WriteFile(stale, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PrunePrivateKeyArchives(dir, keep); err != nil {
		t.Fatalf("PrunePrivateKeyArchives: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale archive still exists: %v", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("kept archive missing: %v", err)
	}

	missingDir := filepath.Join(dir, "missing")
	if err := PrunePrivateKeyArchives(missingDir, ""); err != nil {
		t.Fatalf("PrunePrivateKeyArchives missing dir: %v", err)
	}
	other := filepath.Join(dir, "account-20260521T120000Z.key")
	if err := os.WriteFile(other, []byte("account"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PrunePrivateKeyArchives(dir, ""); err != nil {
		t.Fatalf("PrunePrivateKeyArchives nonmatching: %v", err)
	}
	assertFileContent(t, other, "account")
}

func TestArchiveAccountKey(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing-account.key")
	archive, archived, err := ArchiveAccountKey(missing, time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("ArchiveAccountKey missing: %v", err)
	}
	if archived || archive != "" {
		t.Fatalf("ArchiveAccountKey missing got archive=%q archived=%v", archive, archived)
	}

	keyPath := filepath.Join(dir, "account.key")
	if err := os.WriteFile(keyPath, []byte("account-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	archive, archived, err = ArchiveAccountKey(keyPath, time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("ArchiveAccountKey: %v", err)
	}
	if !archived {
		t.Fatal("ArchiveAccountKey archived=false, want true")
	}
	if filepath.Base(archive) != "account-20260522T120000Z.key" {
		t.Fatalf("archive path got %q", archive)
	}
	assertFileContent(t, archive, "account-key")
	assertFileMode(t, archive, 0o600)
}

func TestCertMetaRoundTripListAndDelete(t *testing.T) {
	store := New(t.TempDir())
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	meta := CertMeta{
		Name:         "example.com",
		Account:      "letsencrypt",
		Directory:    "https://example.invalid/directory",
		Names:        []string{"example.com", "www.example.com"},
		SerialNumber: "1234",
		IssuedAt:     time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC),
		Deploys: []CertDeployMeta{{
			Target: "local",
			Kind:   "fullchain",
			Path:   "/tmp/fullchain.pem",
			SHA256: SHA256Hex([]byte("fullchain")),
			At:     time.Date(2026, 5, 22, 12, 1, 0, 0, time.UTC),
		}},
	}
	if err := store.SaveCertMeta("example.com", meta); err != nil {
		t.Fatalf("SaveCertMeta: %v", err)
	}
	assertFileMode(t, store.CertPaths("example.com").Meta, 0o600)
	got, err := store.LoadCertMeta("example.com")
	if err != nil {
		t.Fatalf("LoadCertMeta: %v", err)
	}
	if got.Account != meta.Account || got.Deploys[0].SHA256 != meta.Deploys[0].SHA256 {
		t.Fatalf("metadata round trip mismatch: %#v", got)
	}
	names, err := store.ListCertNames()
	if err != nil {
		t.Fatalf("ListCertNames: %v", err)
	}
	if len(names) != 1 || names[0] != "example.com" {
		t.Fatalf("names got %v, want [example.com]", names)
	}
	if err := store.DeleteCert("example.com"); err != nil {
		t.Fatalf("DeleteCert: %v", err)
	}
	if _, err := os.Stat(store.CertDir("example.com")); !os.IsNotExist(err) {
		t.Fatalf("cert dir still exists: %v", err)
	}
}

func TestListCertNamesMissingAndIgnoresFiles(t *testing.T) {
	store := New(t.TempDir())
	names, err := store.ListCertNames()
	if err != nil {
		t.Fatalf("ListCertNames missing root: %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("ListCertNames missing root got %v, want empty", names)
	}
	certsDir := filepath.Join(store.Root, "certs")
	if err := os.MkdirAll(filepath.Join(certsDir, "example.com"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certsDir, "not-a-cert"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	names, err = store.ListCertNames()
	if err != nil {
		t.Fatalf("ListCertNames: %v", err)
	}
	if len(names) != 1 || names[0] != "example.com" {
		t.Fatalf("ListCertNames got %v, want [example.com]", names)
	}
}

func TestLoadMetadataRejectsMalformedJSON(t *testing.T) {
	store := New(t.TempDir())
	if err := os.MkdirAll(store.AccountDir("bad"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.AccountMetaPath("bad"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadAccountMeta("bad"); err == nil {
		t.Fatal("LoadAccountMeta malformed JSON succeeded")
	}

	paths := store.CertPaths("bad")
	if err := os.MkdirAll(paths.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.Meta, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadCertMeta("bad"); err == nil {
		t.Fatal("LoadCertMeta malformed JSON succeeded")
	}
}

func assertFileContent(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("%s content got %q, want %q", path, got, want)
	}
}

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode got %04o, want %04o", path, got, want)
	}
}

func keyCurve(key any) elliptic.Curve {
	k, _ := key.(*ecdsa.PrivateKey)
	if k == nil {
		return nil
	}
	return k.Curve
}

func rsaBits(key any) int {
	k, _ := key.(*rsa.PrivateKey)
	if k == nil {
		return 0
	}
	return k.N.BitLen()
}

type unsupportedSigner struct{}

func (unsupportedSigner) Public() crypto.PublicKey {
	return struct{}{}
}

func (unsupportedSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("unsupported")
}
