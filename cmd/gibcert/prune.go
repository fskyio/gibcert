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
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"gitfield.org/fsky/gibcert/internal/lock"
	"gitfield.org/fsky/gibcert/internal/paths"
	"gitfield.org/fsky/gibcert/internal/prune"
	"gitfield.org/fsky/gibcert/internal/storage"
)

const pruneUsage = "usage: gibcert prune [--certs] [--accounts] [--cas] [--account-keys] [--include-valid] [--except ID]... [--dry-run] [--yes]"

func cmdPrune(p *paths.Paths, args []string) int {
	fs := flag.NewFlagSet("prune", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, pruneUsage) }
	var opts prune.Options
	var except stringList
	dryRun := false
	yes := false
	fs.BoolVar(&opts.Certs, "certs", false, "prune orphan certificates that are expired, revoked, or unreadable")
	fs.BoolVar(&opts.Accounts, "accounts", false, "prune accounts nothing uses")
	fs.BoolVar(&opts.CAs, "cas", false, "prune local CAs nothing uses")
	fs.BoolVar(&opts.AccountKeys, "account-keys", false, "prune superseded account key archives")
	fs.BoolVar(&opts.IncludeValid, "include-valid", false, "with --certs, also prune orphan certificates that are still valid")
	fs.Var(&except, "except", "keep this item, as printed by --dry-run (repeatable)")
	fs.BoolVar(&dryRun, "dry-run", false, "print what would be pruned without removing anything")
	fs.BoolVar(&yes, "yes", false, "approve removal non-interactively")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, pruneUsage)
		return 2
	}
	opts.Except = except

	if !(opts.Certs || opts.Accounts || opts.CAs || opts.AccountKeys) {
		// Without a selection, review everything interactively. An unattended
		// run has to name what it may delete.
		if yes {
			logErrorMessage("--yes requires naming what to prune: --certs, --accounts, --cas, or --account-keys")
			return 2
		}
		opts.Certs, opts.Accounts, opts.CAs, opts.AccountKeys = true, true, true, true
	}
	if opts.IncludeValid && !opts.Certs {
		logErrorMessage("--include-valid requires --certs")
		return 2
	}

	cfg, err := loadCfg(p)
	if err != nil {
		logError(err)
		return 1
	}
	store := storage.New(p.State)
	if !dryRun {
		// A dry run stays read-only. A real run holds the lock from scan to
		// removal so a concurrent renew cannot change what was reviewed.
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
	}

	report, err := prune.Scan(cfg, store, time.Now(), opts)
	if err != nil {
		logError(err)
		return 1
	}
	removals := report.Removals()
	printPruneReport(os.Stdout, report)
	if len(removals) == 0 {
		fmt.Println("nothing to prune")
		return 0
	}
	fmt.Printf("%d item(s) to remove. Private keys are deleted, not wiped.\n", len(removals))
	if dryRun {
		return 0
	}
	if !yes {
		ok, err := confirmYesNo(os.Stdin, os.Stdout, fmt.Sprintf("Remove %d item(s)? [y/N] ", len(removals)))
		if err != nil {
			logError(err)
			return 1
		}
		if !ok {
			logErrorMessage("prune cancelled")
			return 1
		}
	}

	code := 0
	removed := 0
	for _, r := range prune.Apply(report, store) {
		if r.Err != nil {
			logError(fmt.Errorf("remove %s: %w", r.Item.ID(), r.Err))
			code = 1
			continue
		}
		removed++
		fmt.Printf("removed %s\n", r.Item.ID())
	}
	fmt.Printf("%d item(s) removed\n", removed)
	return code
}

func printPruneReport(w io.Writer, report prune.Report) {
	width := 0
	for _, it := range report.Items {
		if n := len(it.ID()); n > width {
			width = n
		}
	}
	for _, it := range report.Items {
		verb := "keep"
		if it.Remove {
			verb = "remove"
		}
		fmt.Fprintf(w, "%-6s  %-*s  %s\n", verb, width, it.ID(), it.Reason)
		if !it.Remove {
			continue
		}
		switch it.Kind {
		case prune.KindAccount:
			if it.Directory != "" {
				fmt.Fprintf(w, "        directory: %s\n", it.Directory)
			}
			fmt.Fprintln(w, "        note: local only; the CA registration stays and the account key is deleted permanently")
		case prune.KindCA:
			fmt.Fprintln(w, "        note: the CA key is deleted permanently")
		}
		for _, warning := range it.Warnings {
			fmt.Fprintf(w, "        warning: %s\n", warning)
		}
	}
}
