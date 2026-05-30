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
	"os"
	"path/filepath"
	"testing"
	"time"
)

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
