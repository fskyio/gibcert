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

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"gitfield.org/fsky/gibcert/internal/acmeclient"
	"gitfield.org/fsky/gibcert/internal/config"
	"gitfield.org/fsky/gibcert/internal/lock"
	"gitfield.org/fsky/gibcert/internal/paths"
	"gitfield.org/fsky/gibcert/internal/prune"
	"gitfield.org/fsky/gibcert/internal/storage"
)

const accountDeactivateUsage = "usage: gibcert account deactivate [--yes] <account>"

const accountDeactivateTimeout = 2 * time.Minute

// deactivateAccountAtCA deactivates a stored account at the CA named by its
// recorded ACME directory. Local state is left for the caller to remove.
func deactivateAccountAtCA(ctx context.Context, store *storage.Store, name, directory string) error {
	if directory == "" {
		return errors.New("account metadata records no ACME directory; remove the local state without contacting the CA instead")
	}
	ctx, cancel := context.WithTimeout(ctx, accountDeactivateTimeout)
	defer cancel()
	return acmeclient.DeactivateAccount(ctx, store, name, directory, nil)
}

func cmdAccountDeactivate(p *paths.Paths, args []string) int {
	fs := flag.NewFlagSet("account deactivate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, accountDeactivateUsage) }
	yes := false
	fs.BoolVar(&yes, "yes", false, "approve deactivation non-interactively")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, accountDeactivateUsage)
		return 2
	}
	name := fs.Arg(0)
	if err := config.ValidateStateName(name); err != nil {
		logError(fmt.Errorf("invalid account name %q: %w", name, err))
		return 2
	}

	cfg, err := loadCfg(p)
	if err != nil {
		logError(err)
		return 1
	}
	store := storage.New(p.State)
	if err := store.Init(); err != nil {
		logError(err)
		return 1
	}
	lk, err := lock.Acquire(store.LockPath(), 5*time.Second)
	if err != nil {
		logError(err)
		return 1
	}
	defer lk.Release()

	// An account is only deactivated once nothing needs it: not the config, and
	// not any stored certificate that records it, because after deactivation
	// the account key can no longer revoke what the account issued. prune
	// applies exactly those rules.
	report, err := prune.Scan(cfg, store, time.Now(), prune.Options{Accounts: true})
	if err != nil {
		logError(err)
		return 1
	}
	var item *prune.Item
	for i := range report.Items {
		if report.Items[i].ID() == "account/"+name {
			item = &report.Items[i]
		}
	}
	if item == nil {
		logError(fmt.Errorf("account %q has no local state", name))
		return 1
	}
	if !item.Remove {
		logError(fmt.Errorf("account %q is %s; remove it from the config and revoke or delete the certificates that need it first", name, item.Reason))
		return 1
	}
	if item.Directory == "" {
		logError(fmt.Errorf("account %q: account metadata records no ACME directory; use `gibcert prune --accounts` to remove its local state without contacting the CA", name))
		return 1
	}

	if !yes {
		prompt := fmt.Sprintf("Deactivate account %s at %s and delete its local state? This cannot be undone. [y/N] ", name, item.Directory)
		ok, err := confirmYesNo(os.Stdin, os.Stdout, prompt)
		if err != nil {
			logError(err)
			return 1
		}
		if !ok {
			logErrorMessage("deactivation cancelled")
			return 1
		}
	}

	if err := deactivateAccountAtCA(context.Background(), store, name, item.Directory); err != nil {
		logError(fmt.Errorf("account %q: %w (local state kept)", name, err))
		return 1
	}
	fmt.Printf("%s: deactivated at %s\n", name, item.Directory)
	if err := store.DeleteAccount(name); err != nil {
		logError(fmt.Errorf("account %q is deactivated but its local state could not be removed: %w", name, err))
		return 1
	}
	fmt.Printf("%s: local state deleted\n", name)
	return 0
}
