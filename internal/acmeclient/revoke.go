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

package acmeclient

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"foundry.fsky.io/fsky/gibcert/internal/acme"

	"foundry.fsky.io/fsky/gibcert/internal/storage"
)

func Revoke(ctx context.Context, store *storage.Store, certName, accountName, directoryURL, reason string) error {
	client, err := LoadExisting(ctx, store, accountName, directoryURL)
	if err != nil {
		return err
	}
	cert, err := readLeafCert(store.CertPaths(certName).Cert)
	if err != nil {
		return err
	}
	// A nil cert key revokes with the account key (RFC 8555 §7.6); internal/acme selects
	// the account-key signing path when certKey == account.PrivateKey.
	if err := client.acme.RevokeCertificate(ctx, client.account, cert, client.account.PrivateKey, RevocationReason(reason)); err != nil {
		return fmt.Errorf("revoke certificate: %w", err)
	}
	meta, err := store.LoadCertMeta(certName)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("load cert metadata: %w", err)
		}
		meta = &storage.CertMeta{
			Name:      certName,
			Account:   accountName,
			Directory: directoryURL,
		}
	}
	now := time.Now().UTC()
	meta.RevokedAt = &now
	meta.RevocationReason = reason
	if err := store.SaveCertMeta(certName, *meta); err != nil {
		return fmt.Errorf("save cert metadata: %w", err)
	}
	return nil
}

func RevocationReason(reason string) int {
	switch reason {
	case "key-compromise":
		return acme.ReasonKeyCompromise
	case "ca-compromise":
		return acme.ReasonCACompromise
	case "affiliation-changed":
		return acme.ReasonAffiliationChanged
	case "superseded":
		return acme.ReasonSuperseded
	case "cessation-of-operation":
		return acme.ReasonCessationOfOperation
	case "certificate-hold":
		return acme.ReasonCertificateHold
	case "privilege-withdrawn":
		return acme.ReasonPrivilegeWithdrawn
	case "aa-compromise":
		return acme.ReasonAACompromise
	default:
		return acme.ReasonUnspecified
	}
}

func KnownRevocationReason(reason string) bool {
	switch reason {
	case "unspecified", "key-compromise", "ca-compromise", "affiliation-changed", "superseded", "cessation-of-operation", "certificate-hold", "privilege-withdrawn", "aa-compromise":
		return true
	default:
		return false
	}
}

func readLeafCert(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read certificate: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("read certificate: no CERTIFICATE PEM block in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}
