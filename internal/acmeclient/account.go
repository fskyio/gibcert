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
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"foundry.fsky.io/fsky/gibcert/internal/acme"

	"foundry.fsky.io/fsky/gibcert/internal/buildinfo"
	"foundry.fsky.io/fsky/gibcert/internal/secrets"
	"foundry.fsky.io/fsky/gibcert/internal/storage"
)

// Client bundles a low-level ACME client (internal/acme) with the account it
// acts as. internal/acme keeps the stateless client (directory + HTTP transport)
// separate from the account (key + URL); this wrapper carries the pair so the
// rest of the package -- and cmd/gibcert -- hold a single handle.
type Client struct {
	acme    *acme.Client
	account acme.Account
}

// DirectoryURL returns the ACME directory URL the client is bound to.
func (c *Client) DirectoryURL() string { return c.acme.Directory }

// AccountURL returns the registered account's URL (the JWS "kid").
func (c *Client) AccountURL() string { return c.account.Location }

type AccountOptions struct {
	Name         string
	DirectoryURL string
	Email        string
	EAB          *EABOptions
	HTTPClient   *http.Client
}

type EABOptions struct {
	KID                      string
	HMACKeyFile              string
	HMACKeyValue             string
	HMACKeyEnv               string
	HMACKeyCommand           []string
	HMACKeySystemdCredential string
}

func LoadOrRegister(ctx context.Context, store *storage.Store, opts AccountOptions) (*Client, error) {
	accountName := opts.Name
	directoryURL := opts.DirectoryURL
	email := opts.Email

	if err := os.MkdirAll(store.AccountDir(accountName), 0o700); err != nil {
		return nil, fmt.Errorf("account dir: %w", err)
	}

	key, err := loadOrCreateAccountKey(store, accountName)
	if err != nil {
		return nil, err
	}

	client := newACMEClient(directoryURL, opts.HTTPClient)
	account := acme.Account{PrivateKey: key}

	meta, err := store.LoadAccountMeta(accountName)
	if err == nil && meta.URL != "" && meta.Directory == directoryURL {
		account.Location = meta.URL
		if meta.Email == email {
			return &Client{acme: client, account: account}, nil
		}
		if email != "" {
			account.Contact = []string{"mailto:" + email}
		}
		updated, err := client.UpdateAccount(ctx, account)
		if err != nil {
			return nil, fmt.Errorf("update account: %w", err)
		}
		if err := saveAccountMeta(store, accountName, updated.Location, email, directoryURL); err != nil {
			return nil, err
		}
		return &Client{acme: client, account: updated}, nil
	}

	account.TermsOfServiceAgreed = true
	if email != "" {
		account.Contact = []string{"mailto:" + email}
	}
	if opts.EAB != nil {
		eab, err := eabFor(ctx, opts.EAB)
		if err != nil {
			return nil, err
		}
		if err := account.SetExternalAccountBinding(ctx, client, eab); err != nil {
			return nil, fmt.Errorf("set external account binding: %w", err)
		}
	}

	// NewAccount returns the existing account when the key is already
	// registered (the server replies 200 per RFC 8555 §7.3), so there is no
	// separate "already exists" path to handle as there was on x/crypto.
	registered, err := client.NewAccount(ctx, account)
	if err != nil {
		return nil, fmt.Errorf("register account: %w", err)
	}

	if err := saveAccountMeta(store, accountName, registered.Location, email, directoryURL); err != nil {
		return nil, err
	}
	return &Client{acme: client, account: registered}, nil
}

func loadOrCreateAccountKey(store *storage.Store, accountName string) (crypto.Signer, error) {
	keyPath := store.AccountKeyPath(accountName)
	if _, err := os.Stat(keyPath); err == nil {
		key, err := storage.ReadKey(keyPath)
		if err != nil {
			return nil, fmt.Errorf("read account key: %w", err)
		}
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	key, err := storage.GenerateAccountKey()
	if err != nil {
		return nil, fmt.Errorf("generate account key: %w", err)
	}
	if err := storage.WriteKey(keyPath, key); err != nil {
		return nil, fmt.Errorf("write account key: %w", err)
	}
	return key, nil
}

// eabFor builds the external-account-binding from the resolved HMAC secret.
// internal/acme base64url-decodes EAB.MACKey before signing, while the
// pre-migration code passed the resolved secret bytes to x/crypto as the raw
// HMAC key; re-encoding here round-trips back to those exact key bytes so the
// binding signature is unchanged across the migration.
func eabFor(ctx context.Context, eab *EABOptions) (acme.EAB, error) {
	key, err := loadEABHMACKey(ctx, eab)
	if err != nil {
		return acme.EAB{}, err
	}
	return acme.EAB{
		KeyID:  eab.KID,
		MACKey: base64.RawURLEncoding.EncodeToString(key),
	}, nil
}

func loadEABHMACKey(ctx context.Context, eab *EABOptions) ([]byte, error) {
	value, err := (secrets.Source{
		File:              eab.HMACKeyFile,
		Value:             eab.HMACKeyValue,
		Env:               eab.HMACKeyEnv,
		Command:           eab.HMACKeyCommand,
		SystemdCredential: eab.HMACKeySystemdCredential,
	}).Resolve(ctx)
	if err != nil {
		return nil, fmt.Errorf("read eab hmac-key: %w", err)
	}
	return []byte(value), nil
}

func LoadExisting(ctx context.Context, store *storage.Store, accountName, directoryURL string) (*Client, error) {
	key, err := storage.ReadKey(store.AccountKeyPath(accountName))
	if err != nil {
		return nil, fmt.Errorf("read account key: %w", err)
	}
	client := newACMEClient(directoryURL, nil)
	account := acme.Account{PrivateKey: key}

	if meta, err := store.LoadAccountMeta(accountName); err == nil && meta.URL != "" {
		account.Location = meta.URL
		return &Client{acme: client, account: account}, nil
	}

	// No stored account URL (e.g. metadata was never written): recover it from
	// the CA using the account key, which internal/acme needs to sign account-key
	// requests such as revocation.
	account, err = client.GetAccount(ctx, account)
	if err != nil {
		return nil, fmt.Errorf("look up existing account: %w", err)
	}
	return &Client{acme: client, account: account}, nil
}

func RotateAccountKey(ctx context.Context, store *storage.Store, accountName, directoryURL string, httpClient *http.Client, out io.Writer) error {
	if out == nil {
		out = io.Discard
	}
	if err := os.MkdirAll(store.AccountDir(accountName), 0o700); err != nil {
		return fmt.Errorf("account dir: %w", err)
	}
	keyPath := store.AccountKeyPath(accountName)
	nextPath := store.AccountKeyNextPath(accountName)
	oldKey, err := storage.ReadKey(keyPath)
	if err != nil {
		return fmt.Errorf("read account key: %w", err)
	}
	newKey, err := storage.GenerateAccountKey()
	if err != nil {
		return fmt.Errorf("generate account key: %w", err)
	}
	if err := storage.WriteKey(nextPath, newKey); err != nil {
		return fmt.Errorf("write staged account key: %w", err)
	}

	client := newACMEClient(directoryURL, httpClient)
	account := acme.Account{PrivateKey: oldKey}
	if meta, err := store.LoadAccountMeta(accountName); err == nil && meta.URL != "" {
		account.Location = meta.URL
	} else {
		account, err = client.GetAccount(ctx, account)
		if err != nil {
			_ = os.Remove(nextPath)
			return fmt.Errorf("look up existing account: %w", err)
		}
	}

	if _, err := client.AccountKeyRollover(ctx, account, newKey); err != nil {
		_ = os.Remove(nextPath)
		return fmt.Errorf("account key rollover: %w", err)
	}
	archive, archived, err := storage.ArchiveAccountKey(keyPath, time.Now())
	if err != nil {
		return fmt.Errorf("archive previous account key: %w", err)
	}
	if err := os.Rename(nextPath, keyPath); err != nil {
		return fmt.Errorf("promote staged account key: %w", err)
	}
	if archived {
		fmt.Fprintf(out, "archived previous account key: %s\n", archive)
	}
	fmt.Fprintf(out, "rotated account key for %s\n", accountName)
	return nil
}

func newACMEClient(directoryURL string, httpClient *http.Client) *acme.Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &acme.Client{
		Directory:  directoryURL,
		HTTPClient: httpClient,
		UserAgent:  buildinfo.UserAgent(),
	}
}

func saveAccountMeta(store *storage.Store, accountName, url, email, directoryURL string) error {
	if err := store.SaveAccountMeta(accountName, storage.AccountMeta{
		URL:       url,
		Email:     email,
		Directory: directoryURL,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		return fmt.Errorf("save account meta: %w", err)
	}
	return nil
}
