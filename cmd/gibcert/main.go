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
	"bufio"
	"context"
	cryptorand "crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"sort"
	"strings"
	"time"

	"foundry.fsky.io/fsky/gibcert/internal/acmeclient"
	"foundry.fsky.io/fsky/gibcert/internal/buildinfo"
	"foundry.fsky.io/fsky/gibcert/internal/challenge"
	"foundry.fsky.io/fsky/gibcert/internal/config"
	"foundry.fsky.io/fsky/gibcert/internal/deploy"
	"foundry.fsky.io/fsky/gibcert/internal/importer"
	"foundry.fsky.io/fsky/gibcert/internal/localca"
	"foundry.fsky.io/fsky/gibcert/internal/lock"
	"foundry.fsky.io/fsky/gibcert/internal/logging"
	"foundry.fsky.io/fsky/gibcert/internal/paths"
	"foundry.fsky.io/fsky/gibcert/internal/plan"
	"foundry.fsky.io/fsky/gibcert/internal/preflight"
	"foundry.fsky.io/fsky/gibcert/internal/renew"
	"foundry.fsky.io/fsky/gibcert/internal/storage"
)

const usage = `usage: gibcert [--config PATH] [--state-dir PATH] <command> [args]

commands:
  help [command]        show usage
  version               print build version information
  check                 parse and validate the config
  plan                  show what apply would change
  apply [flags]         reconcile state with config
  issue [flags] <cert>  issue one certificate
  renew [flags]         renew due certificates and deploy changed material
  account <command>     manage ACME accounts
  ca <command>          list, show, or export CA profiles
  dns-persist <command> manage dns-persist-01 standing records
  tlsa <command>        manage DANE TLSA records
  deploy <certificate>  deploy stored certificate material to configured targets
  revoke [flags] <cert> revoke a stored certificate at the CA
  delete [flags] <cert> remove local certificate state, optionally undeploying
  rename <old> <new>    rename stored certificate state
  list                  list configured certificates and local status
  show <certificate>    show certificate config and local status
  import <source> ...    import certificate material from another client or PEM files
  completion <shell>    generate shell completion scripts (bash, zsh, fish)

global flags:
  --config, -c PATH     path to config file (default: FHS/XDG)
  --state-dir PATH      path to state directory (default: FHS/XDG)
  --log-format FORMAT   log format: text or json (default: text)
  --syslog              also send logs to syslog

apply flags:
  --yes                 approve externally visible actions non-interactively

issue flags:
  --new-key             force certificate key rotation, even with key.reuse

renew flags:
  --max-jitter DURATION sleep up to DURATION before each ACME renewal (default: 5m)
  --no-jitter           disable renewal jitter
  --verbose             print certificates skipped, issued, and deployed

revoke flags:
  --reason REASON       revocation reason (default: unspecified)
  --reissue             issue and deploy a replacement after revocation
  --yes                 approve revocation non-interactively

delete flags:
  --undeploy            remove last deployed files when content still matches
  --revoke              revoke before deleting local state
  --reason REASON       revocation reason for --revoke (default: unspecified)
  --yes                 approve deletion/revocation non-interactively

import flags:
  --dry-run             print what would be imported without writing
  --name NAME           store a single imported certificate under NAME
  --only NAME           import only this cert (repeatable; matches source dir or target name)
  --force               overwrite existing canonical state (archives prior key)
`

const versionUsage = `usage: gibcert version

print build version information
`

var cliLog *logging.Logger

const defaultRenewalJitter = 5 * time.Minute

func main() {
	os.Exit(run())
}

func run() int {
	var configPath, stateDir string
	var logFormat string
	var useSyslog bool
	flag.StringVar(&configPath, "config", "", "path to config file")
	flag.StringVar(&configPath, "c", "", "shorthand for --config")
	flag.StringVar(&stateDir, "state-dir", "", "path to state directory")
	flag.StringVar(&logFormat, "log-format", "text", "log format: text or json")
	flag.BoolVar(&useSyslog, "syslog", false, "also send logs to syslog")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()

	var err error
	cliLog, err = logging.New(logging.Options{Format: logFormat, Syslog: useSyslog, Stderr: os.Stderr})
	if err != nil {
		logError(err)
		return 2
	}
	defer cliLog.Close()

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}

	switch args[0] {
	case "help":
		return cmdHelp(args[1:])
	case "version":
		return cmdVersion(args[1:])
	case "completion":
		return cmdCompletion(args[1:])
	}

	p, err := paths.Resolve(paths.Overrides{Config: configPath, State: stateDir})
	if err != nil {
		logError(err)
		return 1
	}

	switch args[0] {
	case "help":
		return cmdHelp(args[1:])
	case "version":
		return cmdVersion(args[1:])
	case "check":
		return cmdCheck(p)
	case "plan":
		return cmdPlan(p, args[1:])
	case "apply":
		return cmdApply(p, args[1:])
	case "issue":
		return cmdIssue(p, args[1:])
	case "renew":
		return cmdRenew(p, args[1:])
	case "account":
		return cmdAccount(p, args[1:])
	case "ca":
		return cmdCA(p, args[1:])
	case "dns-persist":
		return cmdDNSPersist(p, args[1:])
	case "tlsa":
		return cmdTLSA(p, args[1:])
	case "deploy":
		return cmdDeploy(p, args[1:])
	case "revoke":
		return cmdRevoke(p, args[1:])
	case "delete":
		return cmdDelete(p, args[1:])
	case "rename":
		return cmdRename(p, args[1:])
	case "list":
		return cmdList(p, args[1:])
	case "show":
		return cmdShow(p, args[1:])
	case "import":
		return cmdImport(p, args[1:])
	case "__complete":
		return cmdInternalComplete(p, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "gibcert: unknown command %q\n", args[0])
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
}

func cmdHelp(args []string) int {
	if len(args) == 0 {
		fmt.Print(usage)
		return 0
	}
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: gibcert help [command]")
		return 2
	}
	switch args[0] {
	case "help":
		fmt.Println("usage: gibcert help [command]")
	case "version":
		fmt.Print(versionUsage)
	case "check":
		fmt.Println("usage: gibcert check")
	case "plan":
		fmt.Println("usage: gibcert plan")
	case "apply":
		fmt.Println("usage: gibcert apply [--yes]")
	case "issue":
		fmt.Println("usage: gibcert issue [--new-key] <certificate>")
	case "renew":
		fmt.Println("usage: gibcert renew [--max-jitter DURATION] [--no-jitter] [--verbose]")
	case "account":
		fmt.Println("usage: gibcert account rotate-key <account>")
	case "ca":
		fmt.Println("usage: gibcert ca list|show <ca>|export [--der] <ca>")
	case "dns-persist":
		fmt.Println("usage: gibcert dns-persist install [--print] <certificate>")
		fmt.Println("       gibcert dns-persist check <certificate>")
	case "tlsa":
		fmt.Println("usage: gibcert tlsa reconcile <certificate>")
	case "deploy":
		fmt.Println("usage: gibcert deploy <certificate>")
	case "revoke":
		fmt.Println("usage: gibcert revoke [--reason REASON] [--reissue] [--yes] <certificate>")
	case "delete":
		fmt.Println("usage: gibcert delete [--undeploy] [--revoke] [--reason REASON] [--yes] <certificate>")
	case "rename":
		fmt.Println("usage: gibcert rename <old-name> <new-name>")
	case "list":
		fmt.Println("usage: gibcert list")
	case "show":
		fmt.Println("usage: gibcert show <certificate>")
	case "import":
		printImportUsage(os.Stdout)
	case "completion":
		fmt.Print(completionUsage)
	default:
		fmt.Fprintf(os.Stderr, "gibcert: unknown command %q\n", args[0])
		return 2
	}
	return 0
}

func cmdVersion(args []string) int {
	if len(args) != 0 {
		fmt.Fprint(os.Stderr, versionUsage)
		return 2
	}
	fmt.Printf("gibcert %s\n", buildinfo.Version)
	fmt.Printf("commit: %s\n", buildinfo.Commit)
	fmt.Printf("date:   %s\n", buildinfo.Date)
	fmt.Printf("built:  %s\n", buildinfo.BuiltBy)
	return 0
}

func cmdAccount(p *paths.Paths, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: gibcert account rotate-key <account>")
		return 2
	}
	switch args[0] {
	case "rotate-key":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: gibcert account rotate-key <account>")
			return 2
		}
		return cmdAccountRotateKey(p, args[1])
	default:
		fmt.Fprintf(os.Stderr, "gibcert: unknown account command %q\n", args[0])
		return 2
	}
}

func cmdAccountRotateKey(p *paths.Paths, name string) int {
	if err := config.ValidateStateName(name); err != nil {
		logError(fmt.Errorf("invalid account name %q: %w", name, err))
		return 2
	}
	cfg, err := loadCfg(p)
	if err != nil {
		logError(err)
		return 1
	}
	account, err := findACMEAccount(cfg, name)
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

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := acmeclient.RotateAccountKey(ctx, store, account.Name, account.Directory, nil, os.Stdout); err != nil {
		logError(err)
		return 1
	}
	return 0
}

func cmdCA(p *paths.Paths, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: gibcert ca list|show <ca>|export [--der] <ca>")
		return 2
	}
	cfg, err := loadCfg(p)
	if err != nil {
		logError(err)
		return 1
	}
	store := storage.New(p.State)
	switch args[0] {
	case "list":
		if len(args) != 1 {
			fmt.Fprintln(os.Stderr, "usage: gibcert ca list")
			return 2
		}
		return cmdCAList(cfg, store)
	case "show":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: gibcert ca show <ca>")
			return 2
		}
		return cmdCAShow(cfg, store, args[1])
	case "export":
		return cmdCAExport(cfg, store, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "gibcert: unknown ca command %q\n", args[0])
		return 2
	}
}

func cmdCAList(cfg *config.Config, store *storage.Store) int {
	cas := config.CAProfiles(cfg.CAs)
	names := make([]string, 0, len(cas))
	for name := range cas {
		names = append(names, name)
	}
	sort.Strings(names)
	fmt.Printf("%-24s %-8s %s\n", "CA", "TYPE", "STATUS")
	for _, name := range names {
		ca := cas[name]
		status := "profile"
		if ca.Type == "local" {
			st := localca.CheckCA(ca, store, time.Now())
			status = st.Reason
			if st.Ready {
				status = "ready until " + st.NotAfter.Format(time.RFC3339)
			}
		}
		fmt.Printf("%-24s %-8s %s\n", ca.Name, ca.Type, status)
	}
	return 0
}

func cmdCAShow(cfg *config.Config, store *storage.Store, name string) int {
	ca, err := findCA(cfg, name)
	if err != nil {
		logError(err)
		return 1
	}
	fmt.Printf("ca:          %s\n", ca.Name)
	fmt.Printf("type:        %s\n", ca.Type)
	switch ca.Type {
	case "acme":
		fmt.Printf("directory:   %s\n", ca.Directory)
		if ca.Profile != "" {
			fmt.Printf("profile:     %s\n", ca.Profile)
		}
		printACMEDirectoryMeta(ca.Directory)
	case "local":
		commonName := ca.CommonName
		if commonName == "" {
			commonName = "gibcert " + ca.Name + " local CA"
		}
		validFor := ca.ValidFor
		if validFor == 0 {
			validFor = config.DefaultLocalCAValidFor
		}
		st := localca.CheckCA(ca, store, time.Now())
		fmt.Printf("common name: %s\n", commonName)
		fmt.Printf("valid for:   %s\n", validFor)
		if st.Ready {
			fmt.Printf("status:      ready\n")
			fmt.Printf("not after:   %s\n", st.NotAfter.Format(time.RFC3339))
		} else {
			fmt.Printf("status:      %s\n", st.Reason)
		}
		paths := store.CAPaths(ca.Name)
		fmt.Println("canonical:")
		fmt.Printf("  cert:      %s\n", paths.Cert)
		fmt.Printf("  key:       %s\n", paths.Key)
	}
	return 0
}

// printACMEDirectoryMeta fetches the ACME directory and prints its advertised
// metadata. Discovery is a best-effort, unauthenticated GET; if the CA is
// unreachable we note that rather than failing the command.
func printACMEDirectoryMeta(directoryURL string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	dir, err := acmeclient.FetchDirectoryMeta(ctx, directoryURL)
	if err != nil {
		fmt.Printf("metadata:    unavailable (%v)\n", err)
		return
	}
	if dir.Terms != "" {
		fmt.Printf("terms:       %s\n", dir.Terms)
	}
	if dir.Website != "" {
		fmt.Printf("website:     %s\n", dir.Website)
	}
	if dir.RenewalInfo != "" {
		fmt.Printf("ari:         %s\n", dir.RenewalInfo)
	}
	eab := "no"
	if dir.ExternalAccountRequired {
		eab = "yes"
	}
	fmt.Printf("eab required: %s\n", eab)
	if len(dir.CAAIdentities) > 0 {
		fmt.Printf("caa ids:     %s\n", strings.Join(dir.CAAIdentities, ", "))
	}
	if len(dir.Profiles) > 0 {
		names := make([]string, 0, len(dir.Profiles))
		for name := range dir.Profiles {
			names = append(names, name)
		}
		sort.Strings(names)
		fmt.Println("profiles:")
		for _, name := range names {
			if desc := dir.Profiles[name]; desc != "" {
				fmt.Printf("  %s: %s\n", name, desc)
			} else {
				fmt.Printf("  %s\n", name)
			}
		}
	}
}

func cmdCAExport(cfg *config.Config, store *storage.Store, args []string) int {
	fs := flag.NewFlagSet("ca export", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	der := fs.Bool("der", false, "export the certificate in binary DER form instead of PEM")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: gibcert ca export [--der] <ca>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	name := fs.Arg(0)

	ca, err := findCA(cfg, name)
	if err != nil {
		logError(err)
		return 1
	}
	if ca.Type != "local" {
		logErrorMessage("ca export only supports local ca profiles")
		return 2
	}
	b, err := os.ReadFile(store.CAPaths(ca.Name).Cert)
	if err != nil {
		logError(err)
		return 1
	}
	if *der {
		b, err = deploy.CertPEMToDER(b)
		if err != nil {
			logError(err)
			return 1
		}
	}
	if _, err := os.Stdout.Write(b); err != nil {
		logError(err)
		return 1
	}
	return 0
}

func cmdDNSPersist(p *paths.Paths, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: gibcert dns-persist install [--print] <certificate>")
		fmt.Fprintln(os.Stderr, "       gibcert dns-persist check <certificate>")
		return 2
	}
	cfg, err := loadCfg(p)
	if err != nil {
		logError(err)
		return 1
	}
	store := storage.New(p.State)
	switch args[0] {
	case "install":
		return cmdDNSPersistInstall(cfg, store, args[1:])
	case "check":
		return cmdDNSPersistCheck(cfg, store, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "gibcert: unknown dns-persist command %q\n", args[0])
		return 2
	}
}

func dnsPersistContext(cfg *config.Config, store *storage.Store, certName string) (cert *config.Certificate, ca *config.CA, accountName, accountURI string, err error) {
	cert, err = findCert(cfg, certName)
	if err != nil {
		return nil, nil, "", "", err
	}
	account, err := acmeAccountForCert(cfg, cert)
	if err != nil {
		return nil, nil, "", "", err
	}
	ca, err = findCA(cfg, account.CA)
	if err != nil {
		return nil, nil, "", "", err
	}
	if ca.PersistIdentifier == "" {
		return nil, nil, "", "", fmt.Errorf("ca %q: persist-identifier is not configured", ca.Name)
	}
	meta, err := store.LoadAccountMeta(account.Name)
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("account %q has not been registered (run `gibcert apply` first): %w", account.Name, err)
	}
	if meta.URL == "" {
		return nil, nil, "", "", fmt.Errorf("account %q metadata is missing the registration URL", account.Name)
	}
	return cert, ca, account.Name, meta.URL, nil
}

func cmdDNSPersistInstall(cfg *config.Config, store *storage.Store, args []string) int {
	fs := flag.NewFlagSet("dns-persist install", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, "usage: gibcert dns-persist install [--print] <certificate>") }
	printOnly := false
	fs.BoolVar(&printOnly, "print", false, "print the record without writing it")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: gibcert dns-persist install [--print] <certificate>")
		return 2
	}
	name := fs.Arg(0)
	if err := validateCertificateArg(name); err != nil {
		logError(err)
		return 2
	}
	cert, ca, _, accountURI, err := dnsPersistContext(cfg, store, name)
	if err != nil {
		logError(err)
		return 1
	}

	wildcardDomains := map[string]bool{}
	for _, name := range cert.Names {
		if strings.HasPrefix(name, "*.") {
			wildcardDomains[dnsPersistRecordDomain(cert, name)] = true
		}
	}
	seen := map[string]bool{}
	for _, name := range cert.Names {
		recordDomain := dnsPersistRecordDomain(cert, name)
		if !strings.HasPrefix(name, "*.") && wildcardDomains[recordDomain] {
			continue
		}
		policy := ""
		if strings.HasPrefix(name, "*.") {
			policy = "wildcard"
		}
		value := challenge.DNSPersistRecordValue(ca.PersistIdentifier, accountURI, policy, "")
		recordName := challenge.DNSPersistRecordName(recordDomain)
		seenKey := recordName + "\x00" + value
		if seen[seenKey] {
			continue
		}
		seen[seenKey] = true
		if printOnly {
			fmt.Printf("%s. IN TXT %q\n", recordName, value)
			continue
		}
		if cert.Challenge.Provider == "" {
			return printErr(fmt.Errorf("certificate %q: challenge has no provider; rerun with --print and install the record manually", cert.Name))
		}
		provider := findProvider(cfg, cert.Challenge.Provider)
		if provider == nil {
			return printErr(fmt.Errorf("provider %q not found", cert.Challenge.Provider))
		}
		fmt.Printf("install: %s\n", recordName)
		if err := writePersistRecord(context.Background(), provider, recordName, value, strings.TrimPrefix(name, "*.")); err != nil {
			logError(err)
			return 1
		}
	}
	if printOnly {
		fmt.Fprintln(os.Stderr, "publish the records above at your DNS provider, then run `gibcert dns-persist check "+cert.Name+"`")
	}
	return 0
}

func dnsPersistRecordDomain(cert *config.Certificate, name string) string {
	base := strings.TrimPrefix(name, "*.")
	if cert.Challenge.AliasFQDN != "" {
		return strings.TrimPrefix(strings.TrimSuffix(cert.Challenge.AliasFQDN, "."), "_validation-persist.")
	}
	if cert.Challenge.AliasDomain != "" {
		return base + "." + strings.TrimSuffix(cert.Challenge.AliasDomain, ".")
	}
	return base
}

func printErr(err error) int {
	logError(err)
	return 1
}

func writePersistRecord(ctx context.Context, provider *config.Provider, fqdn, value, domain string) error {
	timeout := 120 * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	pres, err := newDNSPresenter(provider)
	if err != nil {
		return err
	}
	cleanup, err := pres.Present(ctx, challenge.Request{
		FQDN:       fqdn,
		Value:      value,
		Domain:     domain,
		Identifier: domain,
		Timeout:    timeout,
	})
	if cleanup != nil {
		// Standing record is meant to persist; do not run cleanup.
		_ = cleanup
	}
	return err
}

func newDNSPresenter(p *config.Provider) (challenge.Presenter, error) {
	switch p.Driver {
	case "manual":
		return &challenge.DNSManual{In: os.Stdin, Out: os.Stdout}, nil
	case "exec":
		return &challenge.DNSExec{Provider: p, Out: os.Stdout}, nil
	case "rfc2136", "nsupdate":
		return &challenge.DNSNSUpdate{Provider: p, Out: os.Stdout}, nil
	case "powerdns", "pdns":
		return &challenge.DNSPowerDNS{Provider: p, Out: os.Stdout}, nil
	default:
		return nil, fmt.Errorf("dns driver %q not supported for dns-persist install", p.Driver)
	}
}

func cmdDNSPersistCheck(cfg *config.Config, store *storage.Store, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: gibcert dns-persist check <certificate>")
		return 2
	}
	name := args[0]
	if err := validateCertificateArg(name); err != nil {
		logError(err)
		return 2
	}
	cert, ca, _, accountURI, err := dnsPersistContext(cfg, store, name)
	if err != nil {
		logError(err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	failed := 0
	for _, name := range cert.Names {
		recordDomain := dnsPersistRecordDomain(cert, name)
		res, err := challenge.VerifyDNSPersistRecordWithOptions(ctx, recordDomain, challenge.DNSPersistVerifyOptions{
			IssuerDomainNames: []string{ca.PersistIdentifier},
			AccountURI:        accountURI,
			RequireWildcard:   strings.HasPrefix(name, "*."),
		})
		if err != nil {
			fmt.Printf("%s: lookup error: %v\n", res.RecordName, err)
			failed++
			continue
		}
		if !res.Matched {
			fmt.Printf("%s: NOT FOUND (or did not match %s / %s)\n", res.RecordName, ca.PersistIdentifier, accountURI)
			failed++
			continue
		}
		fmt.Printf("%s: ok\n", res.RecordName)
	}
	if failed > 0 {
		return 1
	}
	return 0
}

func cmdTLSA(p *paths.Paths, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: gibcert tlsa reconcile <certificate>")
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
	switch args[0] {
	case "reconcile":
		return cmdTLSAReconcile(cfg, store, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "gibcert tlsa: unknown command %q\n", args[0])
		fmt.Fprintln(os.Stderr, "usage: gibcert tlsa reconcile <certificate>")
		return 2
	}
}

func cmdTLSAReconcile(cfg *config.Config, store *storage.Store, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: gibcert tlsa reconcile <certificate>")
		return 2
	}
	name := args[0]
	if err := validateCertificateArg(name); err != nil {
		logError(err)
		return 2
	}
	cert, err := findCert(cfg, name)
	if err != nil {
		logError(err)
		return 1
	}
	meta, err := tlsaMetaDefaults(cfg, cert)
	if err != nil {
		logError(err)
		return 1
	}
	lk, err := lock.Acquire(store.LockPath(), 5*time.Second)
	if err != nil {
		logError(err)
		return 1
	}
	defer lk.Release()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := acmeclient.ReconcileTLSA(ctx, store, cfg, cert, acmeclient.TLSAReconcileOptions{
		Out:  os.Stdout,
		Meta: meta,
	}); err != nil {
		logError(err)
		return 1
	}
	return 0
}

func tlsaMetaDefaults(cfg *config.Config, cert *config.Certificate) (storage.CertMeta, error) {
	meta := storage.CertMeta{
		Name:  cert.Name,
		Names: append([]string(nil), cert.Names...),
	}
	if ca, ok, err := localCAForCert(cfg, cert); err != nil {
		return meta, err
	} else if ok {
		meta.CA = ca.Name
		meta.IssuerType = "local"
		meta.Directory = localca.Directory(ca.Name)
		return meta, nil
	}
	account, err := acmeAccountForCert(cfg, cert)
	if err != nil {
		return meta, err
	}
	meta.Account = account.Name
	meta.CA = account.CA
	meta.IssuerType = "acme"
	meta.Directory = account.Directory
	return meta, nil
}

func findProvider(cfg *config.Config, name string) *config.Provider {
	for _, p := range cfg.Providers {
		if p.Name == name {
			return p
		}
	}
	return nil
}

func logError(err error) {
	cliLog.Error("command failed", "error", err)
}

func logErrorMessage(msg string) {
	cliLog.Error(msg)
}

func loadCfg(p *paths.Paths) (*config.Config, error) {
	cfg, err := config.Load(p.Config)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p.Config, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", p.Config, err)
	}
	for _, cert := range cfg.Certificates {
		if len(cert.Deploys) == 0 {
			cliLog.Warn("certificate has no deploy blocks; material will only be written to storage", "certificate", cert.Name)
		}
	}
	return cfg, nil
}

func findCert(cfg *config.Config, name string) (*config.Certificate, error) {
	for _, c := range cfg.Certificates {
		if c.Name == name {
			return c, nil
		}
	}
	return nil, fmt.Errorf("certificate %q not in config", name)
}

func validateCertificateArg(name string) error {
	if err := config.ValidateStateName(name); err != nil {
		return fmt.Errorf("invalid certificate name %q: %w", name, err)
	}
	return nil
}

func findAccount(cfg *config.Config, name string) (*config.Account, error) {
	for _, a := range cfg.Accounts {
		if a.Name == name {
			return a, nil
		}
	}
	return nil, fmt.Errorf("account %q not in config", name)
}

func findACMEAccount(cfg *config.Config, name string) (*config.Account, error) {
	if a, err := findAccount(cfg, name); err == nil {
		return a, nil
	}
	if !strings.HasPrefix(name, "ca:") {
		return nil, fmt.Errorf("account %q not in config", name)
	}
	caName := strings.TrimPrefix(name, "ca:")
	ca, err := findCA(cfg, caName)
	if err != nil {
		return nil, err
	}
	if ca.Type != "acme" {
		return nil, fmt.Errorf("ca %q is %s, want acme", ca.Name, ca.Type)
	}
	return &config.Account{
		Name:      config.ImplicitACMEAccountName(ca.Name),
		CA:        ca.Name,
		Directory: ca.Directory,
	}, nil
}

func findCA(cfg *config.Config, name string) (*config.CA, error) {
	if ca := config.CAProfiles(cfg.CAs)[name]; ca != nil {
		return ca, nil
	}
	return nil, fmt.Errorf("ca %q not in config", name)
}

func acmeAccountForCert(cfg *config.Config, cert *config.Certificate) (*config.Account, error) {
	if cert.Account != "" {
		return findAccount(cfg, cert.Account)
	}
	ca, err := findCA(cfg, cert.CA)
	if err != nil {
		return nil, err
	}
	if ca.Type != "acme" {
		return nil, fmt.Errorf("certificate %q uses %s ca %q, not acme", cert.Name, ca.Type, ca.Name)
	}
	return &config.Account{
		Name:      config.ImplicitACMEAccountName(ca.Name),
		CA:        ca.Name,
		Directory: ca.Directory,
	}, nil
}

func localCAForCert(cfg *config.Config, cert *config.Certificate) (*config.CA, bool, error) {
	if cert.CA == "" {
		return nil, false, nil
	}
	ca, err := findCA(cfg, cert.CA)
	if err != nil {
		return nil, false, err
	}
	return ca, ca.Type == "local", nil
}

func cmdCheck(p *paths.Paths) int {
	cfg, err := loadCfg(p)
	if err != nil {
		logError(err)
		return 1
	}
	if err := preflight.Check(cfg); err != nil {
		logError(err)
		return 1
	}
	fmt.Printf("ok: %d account(s), %d provider(s), %d certificate(s)\n",
		len(cfg.Accounts), len(cfg.Providers), len(cfg.Certificates))
	return 0
}

func cmdPlan(p *paths.Paths, args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, "usage: gibcert plan")
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

	pl, err := plan.Compute(cfg, store, time.Now())
	if err != nil {
		logError(err)
		return 1
	}
	printPlan(pl)
	return 0
}

func printPlan(pl plan.Plan) {
	if pl.Empty() {
		fmt.Println("no changes")
		return
	}
	fmt.Println("planned changes:")
	for _, a := range pl.Actions {
		if a.Detail == "" {
			fmt.Printf("  %s: %s\n", a.Subject, a.Verb)
		} else {
			fmt.Printf("  %s: %s (%s)\n", a.Subject, a.Verb, a.Detail)
		}
	}
}

func cmdApply(p *paths.Paths, args []string) int {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, "usage: gibcert apply [--yes]") }
	yes := false
	fs.BoolVar(&yes, "yes", false, "approve externally visible actions")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: gibcert apply [--yes]")
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

	pl, err := plan.Compute(cfg, store, time.Now())
	if err != nil {
		logError(err)
		return 1
	}
	printPlan(pl)
	if pl.Empty() {
		return 0
	}
	if planNeedsConfirmation(pl) && !yes {
		ok, err := confirmApply(os.Stdin, os.Stdout)
		if err != nil {
			logError(err)
			return 1
		}
		if !ok {
			logErrorMessage("apply cancelled")
			return 1
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	clients := map[string]*acmeClientEntry{}
	for _, account := range cfg.Accounts {
		if _, err := loadRenewClient(ctx, store, account, clients); err != nil {
			logError(err)
			return 1
		}
	}
	for _, cert := range cfg.Certificates {
		if cert.Account != "" || cert.CA == "" {
			continue
		}
		ca, _, err := localCAForCert(cfg, cert)
		if err != nil {
			logError(err)
			return 1
		}
		if ca == nil || ca.Type != "acme" {
			continue
		}
		account, err := acmeAccountForCert(cfg, cert)
		if err != nil {
			logError(err)
			return 1
		}
		if _, err := loadRenewClient(ctx, store, account, clients); err != nil {
			logError(err)
			return 1
		}
	}
	ordered, err := config.OrderCertificates(cfg.Certificates)
	if err != nil {
		logError(err)
		return 1
	}
	outcomes := map[string]runOutcome{}
	reloads := newReloadQueue()
	failed := false
	for _, cert := range ordered {
		if reason := gateReason(cert, outcomes); reason != "" {
			fmt.Printf("%s: skipped (%s)\n", cert.Name, reason)
			outcomes[cert.Name] = runSkipped
			failed = true
			continue
		}
		d := issueDecision(cfg, store, cert, time.Now())
		if d.Due {
			if err := issueConfiguredCert(ctx, store, cfg, cert, clients, acmeclient.IssueOptions{}); err != nil {
				logError(fmt.Errorf("%s: %w", cert.Name, err))
				outcomes[cert.Name] = runFailed
				failed = true
				continue
			}
		}
		results, err := deploy.Deploy(cert, store, os.Stdout)
		if err != nil {
			logError(fmt.Errorf("%s: %w", cert.Name, err))
			outcomes[cert.Name] = runFailed
			failed = true
			continue
		}
		for _, r := range results {
			if len(r.Changed) == 0 {
				fmt.Printf("  %s: up to date\n", r.Target)
			} else {
				fmt.Printf("  %s: updated %v\n", r.Target, r.Changed)
			}
		}
		if anyChanged(results) {
			reloads.add(cert)
		}
		outcomes[cert.Name] = runOK
	}
	if errs := reloads.flush(true); len(errs) > 0 {
		failed = true
	}
	if failed {
		return 1
	}
	return 0
}

// runOutcome records how a certificate fared during a reconcile run, so that
// certificates which "require" it can be gated.
type runOutcome int

const (
	runOK runOutcome = iota
	runFailed
	runSkipped
)

// gateReason reports why cert must be skipped given the outcomes of
// already-processed certificates, or "" if it may proceed. A certificate is
// gated when any certificate it requires failed or was itself skipped. Because
// runs process certificates in dependency order, a required certificate always
// has an outcome recorded by the time its dependents are reached; an absent
// entry means the requirement was already satisfied (up to date or not due).
func gateReason(cert *config.Certificate, outcomes map[string]runOutcome) string {
	for _, dep := range cert.Requires {
		switch outcomes[dep] {
		case runFailed:
			return fmt.Sprintf("required certificate %q failed", dep)
		case runSkipped:
			return fmt.Sprintf("required certificate %q was skipped", dep)
		}
	}
	return ""
}

// reloadQueue collects once-per-run reload commands while a reconcile runs and
// flushes each distinct command a single time at the end. A command is enqueued
// only when a certificate that declares it actually changed this run, so an
// unchanged or skipped certificate contributes nothing.
type reloadQueue struct {
	order []string
	certs map[string][]string
}

func newReloadQueue() *reloadQueue {
	return &reloadQueue{certs: map[string][]string{}}
}

func (q *reloadQueue) add(cert *config.Certificate) {
	for _, cmd := range cert.Reloads {
		if _, ok := q.certs[cmd]; !ok {
			q.order = append(q.order, cmd)
		}
		q.certs[cmd] = append(q.certs[cmd], cert.Name)
	}
}

// flush runs each queued command once, in first-seen order, and returns any
// command failures. verbose controls progress output.
func (q *reloadQueue) flush(verbose bool) []error {
	var errs []error
	for _, cmd := range q.order {
		if verbose {
			fmt.Printf("reload (%s): %s\n", strings.Join(q.certs[cmd], ", "), cmd)
		}
		if err := deploy.RunReload(cmd, q.certs[cmd]); err != nil {
			errs = append(errs, fmt.Errorf("reload %q: %w", cmd, err))
			logError(errs[len(errs)-1])
		}
	}
	return errs
}

// anyChanged reports whether any deploy result rewrote material this run.
func anyChanged(results []deploy.Result) bool {
	for _, r := range results {
		if len(r.Changed) > 0 {
			return true
		}
	}
	return false
}

func planNeedsConfirmation(pl plan.Plan) bool {
	for _, a := range pl.Actions {
		if strings.HasPrefix(a.Subject, "account ") {
			return true
		}
		if strings.HasPrefix(a.Subject, "certificate ") && (a.Verb == "issue" || a.Verb == "renew") {
			return true
		}
	}
	return false
}

func confirmApply(in *os.File, out io.Writer) (bool, error) {
	return confirmYesNo(in, out, "Apply externally visible changes? [y/N] ")
}

func confirmYesNo(in *os.File, out io.Writer, prompt string) (bool, error) {
	info, err := in.Stat()
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		return false, fmt.Errorf("confirmation requires --yes when stdin is not a TTY")
	}
	fmt.Fprint(out, prompt)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err == io.EOF {
		return false, nil
	}
	if err != nil && len(line) == 0 {
		return false, err
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}

func cmdIssue(p *paths.Paths, args []string) int {
	fs := flag.NewFlagSet("issue", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, "usage: gibcert issue [--new-key] <certificate>") }
	newKey := false
	fs.BoolVar(&newKey, "new-key", false, "force certificate key rotation")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: gibcert issue [--new-key] <certificate>")
		return 2
	}
	name := fs.Arg(0)
	if err := validateCertificateArg(name); err != nil {
		logError(err)
		return 2
	}
	cfg, err := loadCfg(p)
	if err != nil {
		logError(err)
		return 1
	}
	cert, err := findCert(cfg, name)
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	clients := map[string]*acmeClientEntry{}
	if err := issueConfiguredCert(ctx, store, cfg, cert, clients, acmeclient.IssueOptions{NewKey: newKey}); err != nil {
		logError(err)
		return 1
	}
	return 0
}

func cmdRenew(p *paths.Paths, args []string) int {
	fs := flag.NewFlagSet("renew", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: gibcert renew [--max-jitter DURATION] [--no-jitter] [--verbose]")
	}
	maxJitter := defaultRenewalJitter
	noJitter := false
	verbose := false
	fs.DurationVar(&maxJitter, "max-jitter", maxJitter, "sleep up to duration before each ACME renewal")
	fs.BoolVar(&noJitter, "no-jitter", false, "disable renewal jitter")
	fs.BoolVar(&verbose, "verbose", false, "print renewal activity")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: gibcert renew [--max-jitter DURATION] [--no-jitter] [--verbose]")
		return 2
	}
	if maxJitter < 0 {
		logErrorMessage("--max-jitter must be >= 0")
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

	// Refresh ACME Renewal Information before deciding what is due. This makes
	// network calls but holds no lock; the decision phase below then reads the
	// cached result without further network access.
	clients := map[string]*acmeClientEntry{}
	ariCtx, ariCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	refreshARI(ariCtx, cfg, store, clients, verbose)
	ariCancel()

	type dueCert struct {
		cert     *config.Certificate
		decision renew.Decision
	}
	collectDue := func(printSkipped bool) []dueCert {
		var due []dueCert
		now := time.Now()
		for _, cert := range cfg.Certificates {
			d := issueDecision(cfg, store, cert, now)
			if d.Due {
				due = append(due, dueCert{cert: cert, decision: d})
			} else if verbose && printSkipped {
				fmt.Printf("%s: valid until %s\n", cert.Name, d.NotAfter.Format(time.RFC3339))
			}
		}
		return due
	}

	lk, err := lock.Acquire(store.LockPath(), 5*time.Second)
	if err != nil {
		logError(err)
		return 1
	}
	due := collectDue(true)
	if err := lk.Release(); err != nil {
		logError(err)
		return 1
	}
	if len(due) == 0 {
		if verbose {
			fmt.Println("no certificates due")
		}
		return 0
	}

	// Process due certificates in dependency order so that a certificate's
	// requires/wants targets are handled before it.
	order, err := config.OrderCertificates(cfg.Certificates)
	if err != nil {
		logError(err)
		return 1
	}
	pos := make(map[string]int, len(order))
	for i, c := range order {
		pos[c.Name] = i
	}
	sort.SliceStable(due, func(i, j int) bool { return pos[due[i].cert.Name] < pos[due[j].cert.Name] })
	outcomes := map[string]runOutcome{}
	reloads := newReloadQueue()

	var errs []error
	releaseLock := func(lk *lock.Lock) {
		if err := lk.Release(); err != nil {
			errs = append(errs, err)
			logError(err)
		}
	}

	for _, dc := range due {
		cert := dc.cert

		if reason := gateReason(cert, outcomes); reason != "" {
			if verbose {
				fmt.Printf("%s: skipped (%s)\n", cert.Name, reason)
			}
			outcomes[cert.Name] = runSkipped
			continue
		}

		jitter, err := shouldJitterBeforeRenewal(cfg, cert, noJitter, maxJitter)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", cert.Name, err))
			logError(errs[len(errs)-1])
			outcomes[cert.Name] = runFailed
			continue
		}
		if jitter {
			sleep, err := randomJitter(maxJitter)
			if err != nil {
				errs = append(errs, err)
				logError(err)
				outcomes[cert.Name] = runFailed
				continue
			}
			if verbose && sleep > 0 {
				fmt.Printf("%s: sleeping %s before renewal\n", cert.Name, sleep)
			}
			time.Sleep(sleep)
		}

		lk, err = lock.Acquire(store.LockPath(), 5*time.Second)
		if err != nil {
			logError(err)
			return 1
		}

		dc.decision = issueDecision(cfg, store, cert, time.Now())
		if !dc.decision.Due {
			if verbose {
				fmt.Printf("%s: no longer due\n", cert.Name)
			}
			outcomes[cert.Name] = runOK
			releaseLock(lk)
			continue
		}

		if verbose {
			if dc.decision.NotAfter.IsZero() {
				fmt.Printf("%s: renewing (%s)\n", cert.Name, dc.decision.Reason)
			} else {
				fmt.Printf("%s: renewing (%s; expires %s)\n", cert.Name, dc.decision.Reason, dc.decision.NotAfter.Format(time.RFC3339))
			}
		}

		out := io.Discard
		if verbose || usesManualDNS(cfg, cert) {
			out = os.Stdout
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		if err := issueConfiguredCert(ctx, store, cfg, cert, clients, acmeclient.IssueOptions{Out: out, In: os.Stdin}); err != nil {
			cancel()
			errs = append(errs, fmt.Errorf("%s: %w", cert.Name, err))
			logError(errs[len(errs)-1])
			outcomes[cert.Name] = runFailed
			releaseLock(lk)
			continue
		}
		cancel()

		results, err := deploy.Deploy(cert, store, out)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: deploy: %w", cert.Name, err))
			logError(errs[len(errs)-1])
			outcomes[cert.Name] = runFailed
			releaseLock(lk)
			continue
		}
		if verbose {
			for _, r := range results {
				if len(r.Changed) == 0 {
					fmt.Printf("  %s: up to date\n", r.Target)
				} else {
					fmt.Printf("  %s: updated %v\n", r.Target, r.Changed)
				}
			}
		}
		if anyChanged(results) {
			reloads.add(cert)
		}
		outcomes[cert.Name] = runOK
		releaseLock(lk)
	}
	// Coalesced reloads run once, after every renewal in this run has been
	// deployed (outside the per-certificate locks).
	errs = append(errs, reloads.flush(verbose)...)
	if len(errs) > 0 {
		return 1
	}
	return 0
}

type acmeClientEntry struct {
	client *acmeclient.Client
}

func loadRenewClient(ctx context.Context, store *storage.Store, account *config.Account, clients map[string]*acmeClientEntry) (*acmeclient.Client, error) {
	if entry := clients[account.Name]; entry != nil {
		return entry.client, nil
	}
	client, err := acmeclient.LoadOrRegister(ctx, store, acmeAccountOptions(account))
	if err != nil {
		return nil, err
	}
	clients[account.Name] = &acmeClientEntry{client: client}
	return client, nil
}

func acmeAccountOptions(account *config.Account) acmeclient.AccountOptions {
	opts := acmeclient.AccountOptions{
		Name:         account.Name,
		DirectoryURL: account.Directory,
		Email:        account.Email,
	}
	if account.EAB != nil {
		opts.EAB = &acmeclient.EABOptions{
			KID:                      account.EAB.KID,
			HMACKeyFile:              account.EAB.HMACKey.File,
			HMACKeyValue:             account.EAB.HMACKey.Value,
			HMACKeyEnv:               account.EAB.HMACKey.Env,
			HMACKeyCommand:           account.EAB.HMACKey.Command,
			HMACKeySystemdCredential: account.EAB.HMACKey.SystemdCredential,
		}
	}
	return opts
}

func issueConfiguredCert(ctx context.Context, store *storage.Store, cfg *config.Config, cert *config.Certificate, clients map[string]*acmeClientEntry, opts acmeclient.IssueOptions) error {
	if ca, ok, err := localCAForCert(cfg, cert); err != nil {
		return err
	} else if ok {
		return localca.Issue(cert, ca, store, localca.IssueOptions{
			Out:    opts.Out,
			NewKey: opts.NewKey,
		})
	}
	issuers, err := acmeIssuersForCert(cfg, cert)
	if err != nil {
		return err
	}
	out := opts.Out
	if out == nil {
		out = os.Stdout
	}
	return issueWithFailover(out, cert.Name, issuers, func(account *config.Account) error {
		o := opts
		o.AccountName = account.Name
		o.CAName = account.CA
		client, err := loadRenewClient(ctx, store, account, clients)
		if err != nil {
			return err
		}
		return acmeclient.Issue(ctx, client, cert, store, cfg, o)
	})
}

// acmeIssuersForCert resolves the certificate's primary ACME issuer followed by
// its configured failover issuers, in priority order.
func acmeIssuersForCert(cfg *config.Config, cert *config.Certificate) ([]*config.Account, error) {
	primary, err := acmeAccountForCert(cfg, cert)
	if err != nil {
		return nil, err
	}
	issuers := []*config.Account{primary}
	for _, iss := range cert.Failover {
		account, err := acmeIssuerAccount(cfg, iss)
		if err != nil {
			return nil, fmt.Errorf("failover: %w", err)
		}
		issuers = append(issuers, account)
	}
	return issuers, nil
}

// acmeIssuerAccount resolves a single failover issuer to an ACME account,
// mirroring how a certificate's primary account or ca reference is resolved.
func acmeIssuerAccount(cfg *config.Config, iss config.Issuer) (*config.Account, error) {
	if iss.Account != "" {
		return findAccount(cfg, iss.Account)
	}
	ca, err := findCA(cfg, iss.CA)
	if err != nil {
		return nil, err
	}
	if ca.Type != "acme" {
		return nil, fmt.Errorf("ca %q is %s, want acme", ca.Name, ca.Type)
	}
	return &config.Account{
		Name:      config.ImplicitACMEAccountName(ca.Name),
		CA:        ca.Name,
		Directory: ca.Directory,
	}, nil
}

// issueWithFailover tries each issuer in order, stopping at the first success.
// The primary issuer is always attempted first; a failover is only reached when
// every preceding issuer fails, so a healthy primary is never skipped. If all
// issuers fail, the joined error reports each issuer's failure.
func issueWithFailover(out io.Writer, certName string, issuers []*config.Account, attempt func(*config.Account) error) error {
	var errs []error
	for i, account := range issuers {
		err := attempt(account)
		if err == nil {
			if i > 0 {
				fmt.Fprintf(out, "%s: issued via failover %s\n", certName, account.Name)
			}
			return nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", account.Name, err))
		if i < len(issuers)-1 {
			fmt.Fprintf(out, "%s: issuer %s failed: %v; trying failover %s\n", certName, account.Name, err, issuers[i+1].Name)
		}
	}
	return errors.Join(errs...)
}

// refreshARI updates cached ACME Renewal Information for certificates that are
// not already due by expiry, honoring each CA's Retry-After. It is best-effort:
// any per-certificate failure is logged (verbose only) and skipped, so a CA
// without ARI support or a transient network error never blocks renewal. The
// refreshed state is read later by renew.ShouldRenew without further network
// access, keeping the locked decision phase fast.
func refreshARI(ctx context.Context, cfg *config.Config, store *storage.Store, clients map[string]*acmeClientEntry, verbose bool) {
	now := time.Now()
	for _, cert := range cfg.Certificates {
		if _, ok, _ := localCAForCert(cfg, cert); ok {
			continue // local CAs have no ARI
		}
		if renew.ShouldRenew(cert, store, now).Due {
			continue // already due; ARI can only pull renewal earlier
		}
		leaf, err := renew.LoadLeaf(cert, store)
		if err != nil {
			continue
		}
		serial := leaf.SerialNumber.String()
		if meta, err := store.LoadCertMeta(cert.Name); err == nil && ariFresh(meta.ARI, serial, now) {
			continue // still within the server's Retry-After window
		}
		account, err := acmeAccountForCert(cfg, cert)
		if err != nil {
			continue
		}
		client, err := loadRenewClient(ctx, store, account, clients)
		if err != nil {
			if verbose {
				fmt.Printf("%s: ari: %v\n", cert.Name, err)
			}
			continue
		}
		info, err := client.RenewalInfo(ctx, leaf)
		if err != nil {
			if verbose && !errors.Is(err, acmeclient.ErrARIUnsupported) {
				fmt.Printf("%s: ari: %v\n", cert.Name, err)
			}
			continue
		}
		meta, err := store.LoadCertMeta(cert.Name)
		if err != nil {
			continue
		}
		meta.ARI = &storage.CertARI{
			Serial:         serial,
			WindowStart:    info.WindowStart,
			WindowEnd:      info.WindowEnd,
			SelectedTime:   info.SelectedTime,
			RetryAfter:     info.RetryAfter,
			ExplanationURL: info.ExplanationURL,
			FetchedAt:      now,
		}
		if err := store.SaveCertMeta(cert.Name, *meta); err != nil {
			if verbose {
				fmt.Printf("%s: ari: %v\n", cert.Name, err)
			}
			continue
		}
		if verbose {
			fmt.Printf("%s: ari window %s..%s, renew at %s\n", cert.Name,
				info.WindowStart.Format(time.RFC3339), info.WindowEnd.Format(time.RFC3339),
				info.SelectedTime.Format(time.RFC3339))
		}
	}
}

// ariFresh reports whether cached ARI is still authoritative for the given leaf
// and within the server's Retry-After window (so no refetch is needed).
func ariFresh(ari *storage.CertARI, serial string, now time.Time) bool {
	if ari == nil || ari.Serial != serial {
		return false
	}
	return ari.RetryAfter != nil && now.Before(*ari.RetryAfter)
}

func issueDecision(cfg *config.Config, store *storage.Store, cert *config.Certificate, now time.Time) renew.Decision {
	d := renew.ShouldRenew(cert, store, now)
	if d.Due {
		return d
	}
	if ca, ok, _ := localCAForCert(cfg, cert); ok {
		st := localca.CheckCA(ca, store, now)
		if !st.Ready {
			d.Due = true
			d.Reason = st.Reason
		}
	}
	return d
}

func usesManualDNS(cfg *config.Config, cert *config.Certificate) bool {
	if cert.Challenge.Type != "dns-01" {
		return false
	}
	p := findProvider(cfg, cert.Challenge.Provider)
	return p != nil && p.Driver == "manual"
}

func shouldJitterBeforeRenewal(cfg *config.Config, cert *config.Certificate, noJitter bool, maxJitter time.Duration) (bool, error) {
	if noJitter || maxJitter <= 0 {
		return false, nil
	}
	if _, ok, err := localCAForCert(cfg, cert); err != nil {
		return false, err
	} else if ok {
		return false, nil
	}
	return true, nil
}

func randomJitter(max time.Duration) (time.Duration, error) {
	if max <= 0 {
		return 0, nil
	}
	n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(max)+1))
	if err != nil {
		return 0, fmt.Errorf("generate renewal jitter: %w", err)
	}
	return time.Duration(n.Int64()), nil
}

type certIdentity struct {
	account   string
	directory string
}

func resolveCertIdentity(cfg *config.Config, store *storage.Store, name string) (certIdentity, error) {
	if meta, err := store.LoadCertMeta(name); err == nil {
		if meta.IssuerType == "local" || strings.HasPrefix(meta.Directory, "local:") {
			return certIdentity{}, fmt.Errorf("certificate %q was issued by local ca %q and cannot be revoked via ACME", name, meta.CA)
		}
		id := certIdentity{account: meta.Account, directory: meta.Directory}
		if id.account != "" && id.directory != "" {
			return id, nil
		}
		if cfg != nil {
			if cert, err := findCert(cfg, name); err == nil {
				if ca, ok, err := localCAForCert(cfg, cert); err != nil {
					return certIdentity{}, err
				} else if ok {
					return certIdentity{}, fmt.Errorf("certificate %q uses local ca %q and cannot be revoked via ACME", name, ca.Name)
				}
				if account, err := acmeAccountForCert(cfg, cert); err == nil {
					id.account = account.Name
					id.directory = account.Directory
				}
			}
		}
		if id.account != "" && id.directory != "" {
			return id, nil
		}
		return certIdentity{}, fmt.Errorf("certificate %q metadata is missing account or directory", name)
	} else if !errors.Is(err, os.ErrNotExist) {
		return certIdentity{}, err
	}

	if cfg == nil {
		return certIdentity{}, fmt.Errorf("certificate %q metadata missing and config unavailable", name)
	}
	cert, err := findCert(cfg, name)
	if err != nil {
		return certIdentity{}, err
	}
	if ca, ok, err := localCAForCert(cfg, cert); err != nil {
		return certIdentity{}, err
	} else if ok {
		return certIdentity{}, fmt.Errorf("certificate %q uses local ca %q and cannot be revoked via ACME", name, ca.Name)
	}
	account, err := acmeAccountForCert(cfg, cert)
	if err != nil {
		return certIdentity{}, err
	}
	return certIdentity{account: account.Name, directory: account.Directory}, nil
}

func cmdRevoke(p *paths.Paths, args []string) int {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: gibcert revoke [--reason REASON] [--reissue] [--yes] <certificate>")
	}
	reason := "unspecified"
	reissue := false
	yes := false
	fs.StringVar(&reason, "reason", reason, "revocation reason")
	fs.BoolVar(&reissue, "reissue", false, "issue and deploy a replacement")
	fs.BoolVar(&yes, "yes", false, "approve revocation")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: gibcert revoke [--reason REASON] [--reissue] [--yes] <certificate>")
		return 2
	}
	if !acmeclient.KnownRevocationReason(reason) {
		logErrorMessage("unknown revocation reason")
		return 2
	}
	name := fs.Arg(0)
	if err := validateCertificateArg(name); err != nil {
		logError(err)
		return 2
	}

	cfg, cfgErr := loadCfg(p)
	if cfgErr != nil && reissue {
		logError(cfgErr)
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

	id, err := resolveCertIdentity(cfg, store, name)
	if err != nil {
		if cfgErr != nil {
			err = fmt.Errorf("%w; config load also failed: %v", err, cfgErr)
		}
		logError(err)
		return 1
	}
	if !yes {
		ok, err := confirmYesNo(os.Stdin, os.Stdout, fmt.Sprintf("Revoke certificate %s? [y/N] ", name))
		if err != nil {
			logError(err)
			return 1
		}
		if !ok {
			logErrorMessage("revoke cancelled")
			return 1
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := acmeclient.Revoke(ctx, store, name, id.account, id.directory, reason); err != nil {
		logError(err)
		return 1
	}
	fmt.Printf("%s: revoked (%s)\n", name, reason)

	if reissue {
		cert, err := findCert(cfg, name)
		if err != nil {
			logError(err)
			return 1
		}
		clients := map[string]*acmeClientEntry{}
		if err := issueConfiguredCert(ctx, store, cfg, cert, clients, acmeclient.IssueOptions{NewKey: true}); err != nil {
			logError(err)
			return 1
		}
		results, err := deploy.Deploy(cert, store, os.Stdout)
		if err != nil {
			logError(err)
			return 1
		}
		for _, r := range results {
			if len(r.Changed) == 0 {
				fmt.Printf("  %s: up to date\n", r.Target)
			} else {
				fmt.Printf("  %s: updated %v\n", r.Target, r.Changed)
			}
		}
	}
	return 0
}

func cmdDelete(p *paths.Paths, args []string) int {
	fs := flag.NewFlagSet("delete", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: gibcert delete [--undeploy] [--revoke] [--reason REASON] [--yes] <certificate>")
	}
	undeploy := false
	revoke := false
	yes := false
	reason := "unspecified"
	fs.BoolVar(&undeploy, "undeploy", false, "remove last deployed files when content still matches")
	fs.BoolVar(&revoke, "revoke", false, "revoke before deleting local state")
	fs.BoolVar(&yes, "yes", false, "approve deletion")
	fs.StringVar(&reason, "reason", reason, "revocation reason")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: gibcert delete [--undeploy] [--revoke] [--reason REASON] [--yes] <certificate>")
		return 2
	}
	if !acmeclient.KnownRevocationReason(reason) {
		logErrorMessage("unknown revocation reason")
		return 2
	}
	name := fs.Arg(0)
	if err := validateCertificateArg(name); err != nil {
		logError(err)
		return 2
	}

	cfg, cfgErr := loadCfg(p)
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

	if !yes {
		action := "Delete local certificate state"
		if revoke && undeploy {
			action = "Revoke, undeploy, and delete local certificate state"
		} else if revoke {
			action = "Revoke and delete local certificate state"
		} else if undeploy {
			action = "Undeploy and delete local certificate state"
		}
		ok, err := confirmYesNo(os.Stdin, os.Stdout, fmt.Sprintf("%s for %s? [y/N] ", action, name))
		if err != nil {
			logError(err)
			return 1
		}
		if !ok {
			logErrorMessage("delete cancelled")
			return 1
		}
	}

	if revoke {
		id, err := resolveCertIdentity(cfg, store, name)
		if err != nil {
			if cfgErr != nil {
				err = fmt.Errorf("%w; config load also failed: %v", err, cfgErr)
			}
			logError(err)
			return 1
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if err := acmeclient.Revoke(ctx, store, name, id.account, id.directory, reason); err != nil {
			logError(err)
			return 1
		}
		fmt.Printf("%s: revoked (%s)\n", name, reason)
	}
	if undeploy {
		results, err := deploy.Undeploy(name, store)
		if err != nil {
			logError(err)
			return 1
		}
		for _, r := range results {
			fmt.Printf("  %s/%s: %s: %s\n", r.Target, r.Kind, r.Status, r.Path)
		}
	}
	if err := store.DeleteCert(name); err != nil {
		logError(err)
		return 1
	}
	fmt.Printf("%s: local state deleted\n", name)
	return 0
}

func cmdRename(p *paths.Paths, args []string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: gibcert rename <old-name> <new-name>")
		return 2
	}
	oldName, newName := args[0], args[1]
	if oldName == newName {
		fmt.Fprintln(os.Stderr, "gibcert: old and new names are identical")
		return 2
	}
	if err := config.ValidateStateName(oldName); err != nil {
		fmt.Fprintf(os.Stderr, "gibcert: invalid old certificate name %q: %v\n", oldName, err)
		return 2
	}
	if err := config.ValidateStateName(newName); err != nil {
		fmt.Fprintf(os.Stderr, "gibcert: invalid new certificate name %q: %v\n", newName, err)
		return 2
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

	if _, err := os.Stat(store.CertDir(oldName)); errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "gibcert: certificate %q not found in storage\n", oldName)
		return 1
	} else if err != nil {
		logError(err)
		return 1
	}
	if _, err := os.Stat(store.CertDir(newName)); err == nil {
		fmt.Fprintf(os.Stderr, "gibcert: certificate %q already exists in storage\n", newName)
		return 1
	}

	if err := os.Rename(store.CertDir(oldName), store.CertDir(newName)); err != nil {
		logError(err)
		return 1
	}

	if meta, err := store.LoadCertMeta(newName); err == nil {
		meta.Name = newName
		if err := store.SaveCertMeta(newName, *meta); err != nil {
			logError(err)
			return 1
		}
	}

	fmt.Printf("%s: renamed to %s\n", oldName, newName)

	if cfg, err := loadCfg(p); err == nil {
		if _, err := findCert(cfg, oldName); err == nil {
			fmt.Fprintf(os.Stderr, "warning: %q is still referenced in your config; update it to %q\n", oldName, newName)
		}
	}

	return 0
}

func cmdList(p *paths.Paths, args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, "usage: gibcert list")
		return 2
	}
	cfg, cfgErr := loadCfg(p)
	store := storage.New(p.State)
	if cfgErr != nil {
		fmt.Fprintf(os.Stderr, "warning: config unavailable (%v); showing storage-only view\n", cfgErr)
	}
	fmt.Printf("%-24s %-10s %-25s %-25s %-16s %-8s %s\n", "CERTIFICATE", "STATUS", "EXPIRES", "RENEW_AT", "ISSUER", "DEPLOY", "NAMES")
	now := time.Now()
	configNames := make(map[string]struct{})
	if cfg != nil {
		for _, cert := range cfg.Certificates {
			configNames[cert.Name] = struct{}{}
			d := issueDecision(cfg, store, cert, now)
			meta, metaErr := loadCertMetaSoft(store, cert.Name)
			status := certificateStatusLabel(d, meta, metaErr)
			expires := formatInstant(d.NotAfter)
			renewAt := formatRenewAt(d, renewWindow(cert, d))
			issuer := issuerSummary(cfg, cert, meta)
			deployStatus := deploySummary(cert, store)
			fmt.Printf("%-24s %-10s %-25s %-25s %-16s %-8s %s\n", cert.Name, status, expires, renewAt, issuer, deployStatus, strings.Join(cert.Names, " "))
		}
	}
	storageNames, _ := store.ListCertNames()
	sort.Strings(storageNames)
	for _, name := range storageNames {
		if _, ok := configNames[name]; ok {
			continue
		}
		meta, _ := loadCertMetaSoft(store, name)
		status := orphanedCertStatus(meta)
		expires := "-"
		names := ""
		issuer := orphanedIssuerSummary(meta)
		if meta != nil {
			expires = formatInstant(meta.NotAfter)
			names = strings.Join(meta.Names, " ")
		}
		fmt.Printf("%-24s %-10s %-25s %-25s %-16s %-8s %s\n", name, status, expires, "-", issuer, "-", names)
	}
	if cfgErr != nil {
		return 1
	}
	return 0
}

func cmdShowOrphaned(store *storage.Store, name string) int {
	meta, err := loadCertMetaSoft(store, name)
	if meta == nil {
		if err == nil {
			fmt.Fprintf(os.Stderr, "gibcert: certificate %q not found in config or storage\n", name)
		} else {
			fmt.Fprintf(os.Stderr, "gibcert: certificate %q: %v\n", name, err)
		}
		return 1
	}
	fmt.Printf("certificate: %s  (not in config)\n", name)
	if meta.IssuerType == "local" && meta.CA != "" {
		fmt.Printf("ca:          %s (local)\n", meta.CA)
	} else {
		if meta.Account != "" {
			fmt.Printf("account:     %s\n", meta.Account)
		}
		if meta.Directory != "" {
			fmt.Printf("directory:   %s\n", meta.Directory)
		}
	}
	if len(meta.Names) > 0 {
		fmt.Printf("names:       %s\n", strings.Join(meta.Names, " "))
	}
	if meta.IssuerType != "" {
		fmt.Printf("issuer type: %s\n", meta.IssuerType)
	}
	fmt.Printf("status:      %s\n", orphanedCertStatus(meta))
	if !meta.NotAfter.IsZero() {
		fmt.Printf("not after:   %s\n", formatInstant(meta.NotAfter))
	}
	if !meta.NotBefore.IsZero() {
		fmt.Printf("not before:  %s\n", formatInstant(meta.NotBefore))
	}
	if !meta.IssuedAt.IsZero() {
		fmt.Printf("issued at:   %s\n", formatInstant(meta.IssuedAt))
	}
	if meta.SerialNumber != "" {
		fmt.Printf("serial:      %s\n", meta.SerialNumber)
	}
	if meta.RevokedAt != nil {
		fmt.Printf("revoked at:  %s\n", formatInstant(*meta.RevokedAt))
		if meta.RevocationReason != "" {
			fmt.Printf("revocation:  %s\n", meta.RevocationReason)
		}
	}
	cp := store.CertPaths(name)
	fmt.Println("canonical:")
	fmt.Printf("  cert:      %s\n", cp.Cert)
	fmt.Printf("  chain:     %s\n", cp.Chain)
	fmt.Printf("  fullchain: %s\n", cp.Fullchain)
	fmt.Printf("  key:       %s\n", cp.Key)
	fmt.Println("deploy:")
	fmt.Println("  (not in config)")
	return 0
}

func cmdShow(p *paths.Paths, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: gibcert show <certificate>")
		return 2
	}
	if err := validateCertificateArg(args[0]); err != nil {
		logError(err)
		return 2
	}
	store := storage.New(p.State)
	cfg, err := loadCfg(p)
	if err != nil {
		return cmdShowOrphaned(store, args[0])
	}
	cert, err := findCert(cfg, args[0])
	if err != nil {
		return cmdShowOrphaned(store, args[0])
	}
	meta, metaErr := loadCertMetaSoft(store, cert.Name)
	d := issueDecision(cfg, store, cert, time.Now())
	fmt.Printf("certificate: %s\n", cert.Name)
	if cert.Account != "" {
		fmt.Printf("account:     %s\n", cert.Account)
		if account, err := acmeAccountForCert(cfg, cert); err == nil && account.Directory != "" {
			fmt.Printf("directory:   %s\n", account.Directory)
		}
	} else if cert.CA != "" {
		ca, _ := findCA(cfg, cert.CA)
		caType := ""
		if ca != nil {
			caType = " (" + ca.Type + ")"
		}
		fmt.Printf("ca:          %s%s\n", cert.CA, caType)
		if ca != nil && ca.Type == "acme" {
			fmt.Printf("account:     implicit %s\n", config.ImplicitACMEAccountName(ca.Name))
			if ca.Directory != "" {
				fmt.Printf("directory:   %s\n", ca.Directory)
			}
		}
	}
	if meta != nil {
		if meta.Account != "" && cert.Account == "" && cert.CA == "" {
			fmt.Printf("account:     %s\n", meta.Account)
		}
		if meta.Directory != "" && cert.Account == "" && cert.CA == "" {
			fmt.Printf("directory:   %s\n", meta.Directory)
		}
	}
	fmt.Printf("names:       %s\n", strings.Join(cert.Names, " "))
	if cert.PreferredChain != "" {
		fmt.Printf("chain:       prefer %s\n", cert.PreferredChain)
	}
	if ca, ok, _ := localCAForCert(cfg, cert); ok {
		validFor := cert.ValidFor
		if validFor == 0 {
			validFor = config.DefaultLocalCertValidFor
		}
		fmt.Printf("issuer:      local ca %s\n", ca.Name)
		fmt.Printf("valid for:   %s\n", validFor)
	} else {
		chType := cert.Challenge.Type
		if chType == "" && cfg.GlobalChallenge != nil {
			chType = cfg.GlobalChallenge.Type
		}
		fmt.Printf("challenge:   %s\n", chType)
		if cert.Challenge.Provider != "" {
			fmt.Printf("provider:    %s\n", cert.Challenge.Provider)
		}
		webroot := cert.Challenge.Webroot
		if webroot == "" && cfg.GlobalChallenge != nil {
			webroot = cfg.GlobalChallenge.Webroot
		}
		if webroot != "" {
			fmt.Printf("webroot:     %s\n", webroot)
		}
	}
	fmt.Printf("renew:       before expiry %s\n", renewWindow(cert, d))
	fmt.Printf("status:      %s (%s)\n", certificateStatusLabel(d, meta, metaErr), d.Reason)
	if metaErr != nil {
		fmt.Printf("metadata:    unreadable (%v)\n", metaErr)
	}
	if !d.NotAfter.IsZero() {
		fmt.Printf("not after:   %s\n", formatInstant(d.NotAfter))
		fmt.Printf("renew at:    %s\n", formatRenewAt(d, renewWindow(cert, d)))
	}
	if meta != nil {
		if !meta.NotBefore.IsZero() {
			fmt.Printf("not before:  %s\n", formatInstant(meta.NotBefore))
		}
		if !meta.IssuedAt.IsZero() {
			fmt.Printf("issued at:   %s\n", formatInstant(meta.IssuedAt))
		}
		if meta.SerialNumber != "" {
			fmt.Printf("serial:      %s\n", meta.SerialNumber)
		}
		if meta.RevokedAt != nil {
			fmt.Printf("revoked at:  %s\n", formatInstant(*meta.RevokedAt))
			if meta.RevocationReason != "" {
				fmt.Printf("revocation:  %s\n", meta.RevocationReason)
			}
		}
	}
	paths := store.CertPaths(cert.Name)
	fmt.Println("canonical:")
	fmt.Printf("  cert:      %s\n", paths.Cert)
	fmt.Printf("  chain:     %s\n", paths.Chain)
	fmt.Printf("  fullchain: %s\n", paths.Fullchain)
	fmt.Printf("  key:       %s\n", paths.Key)
	if cert.TLSA != nil {
		printTLSAStatus(cert, store)
	}
	fmt.Println("deploy:")
	deployDetails := deployStatusByKey(deployStatuses(cert, store))
	if len(cert.Deploys) == 0 {
		fmt.Println("  none")
	}
	for _, d := range cert.Deploys {
		fmt.Printf("  %s:\n", d.Name)
		if d.Cert != "" {
			printDeployPathStatus("cert", d.Cert, deployDetails[deployStatusKey(d.Name, "cert", d.Cert)])
		}
		if d.Chain != "" {
			printDeployPathStatus("chain", d.Chain, deployDetails[deployStatusKey(d.Name, "chain", d.Chain)])
		}
		if d.Fullchain != "" {
			printDeployPathStatus("fullchain", d.Fullchain, deployDetails[deployStatusKey(d.Name, "fullchain", d.Fullchain)])
		}
		if d.Key != "" {
			printDeployPathStatus("key", d.Key, deployDetails[deployStatusKey(d.Name, "key", d.Key)])
		}
		if d.Before != "" {
			fmt.Printf("    before:    %s\n", d.Before)
		}
		if d.After != "" {
			fmt.Printf("    after:     %s\n", d.After)
		}
	}
	return 0
}

func loadCertMetaSoft(store *storage.Store, name string) (*storage.CertMeta, error) {
	meta, err := store.LoadCertMeta(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return meta, err
}

func certificateStatusLabel(d renew.Decision, meta *storage.CertMeta, metaErr error) string {
	if metaErr != nil {
		return "meta-error"
	}
	if meta != nil && meta.RevokedAt != nil {
		return "revoked"
	}
	if d.NotAfter.IsZero() {
		return "missing"
	}
	if d.Due {
		if d.Reason == "certificate expired" {
			return "expired"
		}
		return "due"
	}
	return "valid"
}

func orphanedCertStatus(meta *storage.CertMeta) string {
	if meta == nil || meta.NotAfter.IsZero() {
		return "missing"
	}
	if meta.RevokedAt != nil {
		return "revoked"
	}
	if time.Now().After(meta.NotAfter) {
		return "expired"
	}
	return "valid"
}

func orphanedIssuerSummary(meta *storage.CertMeta) string {
	if meta == nil {
		return "-"
	}
	if meta.IssuerType == "local" && meta.CA != "" {
		return "local:" + meta.CA
	}
	if meta.IssuerType == "imported" {
		return "imported"
	}
	if meta.Account != "" {
		return meta.Account
	}
	if meta.CA != "" {
		return meta.CA
	}
	return "-"
}

func issuerSummary(cfg *config.Config, cert *config.Certificate, meta *storage.CertMeta) string {
	if ca, ok, _ := localCAForCert(cfg, cert); ok {
		return "local:" + ca.Name
	}
	if cert.Account != "" {
		return cert.Account
	}
	if cert.CA != "" {
		if ca, err := findCA(cfg, cert.CA); err == nil && ca.Type == "local" {
			return "local:" + ca.Name
		}
		return cert.CA
	}
	if meta != nil {
		if meta.IssuerType == "local" && meta.CA != "" {
			return "local:" + meta.CA
		}
		if meta.Account != "" {
			return meta.Account
		}
		if meta.CA != "" {
			return meta.CA
		}
	}
	return "-"
}

func formatInstant(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

func formatRenewAt(d renew.Decision, before time.Duration) string {
	if d.NotAfter.IsZero() || d.Due {
		return "now"
	}
	return formatInstant(d.NotAfter.Add(-before))
}

type deployPathStatus struct {
	Target string
	Kind   string
	Path   string
	Status string
	At     time.Time
	Detail string
}

func deployStatuses(cert *config.Certificate, store *storage.Store) []deployPathStatus {
	paths := store.CertPaths(cert.Name)
	sources := map[string]string{
		"cert":      paths.Cert,
		"chain":     paths.Chain,
		"fullchain": paths.Fullchain,
		"key":       paths.Key,
	}
	meta, _ := loadCertMetaSoft(store, cert.Name)
	var statuses []deployPathStatus
	for _, d := range cert.Deploys {
		items := []struct {
			kind string
			path string
		}{
			{"cert", d.Cert},
			{"chain", d.Chain},
			{"fullchain", d.Fullchain},
			{"key", d.Key},
		}
		for _, it := range items {
			if it.path == "" {
				continue
			}
			st := deployPathStatus{
				Target: d.Name,
				Kind:   it.kind,
				Path:   it.path,
				Status: "unknown",
			}
			if rec := findDeployRecord(meta, d.Name, it.kind, it.path); rec != nil {
				st.At = rec.At
			}
			src, err := os.ReadFile(sources[it.kind])
			if err != nil {
				st.Status = "no-source"
				st.Detail = err.Error()
				statuses = append(statuses, st)
				continue
			}
			dst, err := os.ReadFile(it.path)
			if errors.Is(err, os.ErrNotExist) {
				if st.At.IsZero() {
					st.Status = "never"
				} else {
					st.Status = "missing"
				}
				statuses = append(statuses, st)
				continue
			}
			if err != nil {
				st.Status = "error"
				st.Detail = err.Error()
				statuses = append(statuses, st)
				continue
			}
			if storage.SHA256Hex(dst) == storage.SHA256Hex(src) {
				st.Status = "ok"
			} else {
				st.Status = "stale"
			}
			statuses = append(statuses, st)
		}
	}
	return statuses
}

func findDeployRecord(meta *storage.CertMeta, target, kind, path string) *storage.CertDeployMeta {
	if meta == nil {
		return nil
	}
	for i := range meta.Deploys {
		rec := &meta.Deploys[i]
		if rec.Target == target && rec.Kind == kind && rec.Path == path {
			return rec
		}
	}
	return nil
}

func deploySummary(cert *config.Certificate, store *storage.Store) string {
	if len(cert.Deploys) == 0 {
		return "-"
	}
	statuses := deployStatuses(cert, store)
	if len(statuses) == 0 {
		return "-"
	}
	counts := map[string]int{}
	for _, st := range statuses {
		counts[st.Status]++
	}
	total := len(statuses)
	switch {
	case counts["error"] > 0:
		return "error"
	case counts["ok"] == total:
		return "ok"
	case counts["no-source"] == total:
		return "-"
	case counts["never"] == total:
		return "never"
	case counts["missing"]+counts["never"] == total:
		return "missing"
	case counts["stale"] == total:
		return "stale"
	default:
		return "partial"
	}
}

func deployStatusByKey(statuses []deployPathStatus) map[string]deployPathStatus {
	out := make(map[string]deployPathStatus, len(statuses))
	for _, st := range statuses {
		out[deployStatusKey(st.Target, st.Kind, st.Path)] = st
	}
	return out
}

func deployStatusKey(target, kind, path string) string {
	return target + "\x00" + kind + "\x00" + path
}

func printDeployPathStatus(kind, path string, st deployPathStatus) {
	suffix := ""
	if st.Status != "" {
		suffix = " [" + st.Status
		if !st.At.IsZero() {
			suffix += ", last " + formatInstant(st.At)
		}
		if st.Detail != "" && st.Status != "no-source" {
			suffix += ", " + st.Detail
		}
		suffix += "]"
	}
	fmt.Printf("    %-10s %s%s\n", kind+":", path, suffix)
}

func printTLSAStatus(cert *config.Certificate, store *storage.Store) {
	fmt.Println("tlsa:")
	fmt.Printf("  provider:  %s\n", cert.TLSA.Provider)
	fmt.Printf("  type:      %d %d %d\n", cert.TLSA.Usage, cert.TLSA.Selector, cert.TLSA.MatchingType)
	fmt.Printf("  ttl:       %ds\n", cert.TLSA.TTL)
	ports := make([]string, len(cert.TLSA.Ports))
	for i, p := range cert.TLSA.Ports {
		ports[i] = fmt.Sprintf("%d/%s", p.Port, p.Protocol)
	}
	fmt.Printf("  ports:     %s\n", strings.Join(ports, " "))
	meta, err := store.LoadCertMeta(cert.Name)
	if err != nil || meta == nil || meta.TLSA == nil {
		fmt.Printf("  state:     not bootstrapped\n")
		return
	}
	tm := meta.TLSA
	fmt.Printf("  current:   %s\n", tm.CurrentValue)
	if tm.NextValue != "" {
		fmt.Printf("  next:      %s\n", tm.NextValue)
		if !tm.NextPublishedAt.IsZero() {
			fmt.Printf("  next-pub:  %s\n", tm.NextPublishedAt.Format(time.RFC3339))
			ttl := time.Duration(tm.TTL) * time.Second
			rotatesAfter := tm.NextPublishedAt.Add(ttl)
			if time.Now().Before(rotatesAfter) {
				fmt.Printf("  matures:   %s\n", rotatesAfter.Format(time.RFC3339))
			} else {
				fmt.Printf("  matures:   already mature (next renewal will rotate)\n")
			}
		}
	}
	if len(tm.Published) > 0 {
		fmt.Printf("  published: %d record(s)\n", len(tm.Published))
	}
}

func renewWindow(cert *config.Certificate, d renew.Decision) time.Duration {
	return renew.RenewalWindow(cert, d.NotBefore, d.NotAfter)
}

func cmdDeploy(p *paths.Paths, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: gibcert deploy <certificate>")
		return 2
	}
	if err := validateCertificateArg(args[0]); err != nil {
		logError(err)
		return 2
	}
	cfg, err := loadCfg(p)
	if err != nil {
		logError(err)
		return 1
	}
	cert, err := findCert(cfg, args[0])
	if err != nil {
		logError(err)
		return 1
	}

	store := storage.New(p.State)
	lk, err := lock.Acquire(store.LockPath(), 5*time.Second)
	if err != nil {
		logError(err)
		return 1
	}
	defer lk.Release()

	results, err := deploy.Deploy(cert, store, os.Stdout)
	if err != nil {
		logError(err)
		return 1
	}
	for _, r := range results {
		if len(r.Changed) == 0 {
			fmt.Printf("  %s: up to date\n", r.Target)
		} else {
			fmt.Printf("  %s: updated %v\n", r.Target, r.Changed)
		}
	}
	return 0
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func cmdImport(p *paths.Paths, args []string) int {
	if len(args) == 0 {
		printImportUsage(os.Stderr)
		return 2
	}
	if strings.HasPrefix(args[0], "-") {
		return cmdImportLegacy(p, args)
	}
	switch args[0] {
	case "acme.sh":
		return cmdImportACMESh(p, args[1:])
	case "certbot":
		return cmdImportCertbot(p, args[1:])
	case "dehydrated":
		return cmdImportDehydrated(p, args[1:])
	case "lego":
		return cmdImportLego(p, args[1:])
	case "pem":
		return cmdImportPEM(p, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "gibcert: unknown import source %q (supported: acme.sh, certbot, dehydrated, lego, pem)\n", args[0])
		return 2
	}
}

func printImportUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: gibcert import acme.sh [--dry-run] [--only NAME]... [--name NAME] [--force] <path>")
	fmt.Fprintln(w, "       gibcert import certbot [--dry-run] [--only NAME]... [--name NAME] [--force] <path>")
	fmt.Fprintln(w, "       gibcert import dehydrated [--dry-run] [--only NAME]... [--name NAME] [--force] <path>")
	fmt.Fprintln(w, "       gibcert import lego [--dry-run] [--only NAME]... [--name NAME] [--force] <path>")
	fmt.Fprintln(w, "       gibcert import pem [--dry-run] [--force] --name NAME --key KEY (--cert CERT [--chain CHAIN] | --fullchain FULLCHAIN)")
}

func cmdImportLegacy(p *paths.Paths, args []string) int {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		printImportUsage(os.Stderr)
	}
	dryRun := false
	force := false
	name := ""
	var only stringList
	fs.BoolVar(&dryRun, "dry-run", false, "print what would be imported without writing")
	fs.BoolVar(&force, "force", false, "overwrite existing canonical state")
	fs.StringVar(&name, "name", "", "store a single imported certificate under this name")
	fs.Var(&only, "only", "import only this cert (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 2 {
		printImportUsage(os.Stderr)
		return 2
	}
	source, path := fs.Arg(0), fs.Arg(1)
	if source != "acme.sh" {
		fmt.Fprintf(os.Stderr, "gibcert: unknown import source %q (supported: acme.sh, certbot, dehydrated, lego, pem)\n", source)
		return 2
	}
	return runImport(p, dryRun, func(store *storage.Store) ([]importer.Result, error) {
		return importer.ImportACMESh(store, importer.ACMEShOptions{
			Path:   path,
			Only:   only,
			Name:   name,
			DryRun: dryRun,
			Force:  force,
			Now:    time.Now(),
		})
	})
}

func cmdImportACMESh(p *paths.Paths, args []string) int {
	fs := flag.NewFlagSet("import acme.sh", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		printImportUsage(os.Stderr)
	}
	dryRun := false
	force := false
	name := ""
	var only stringList
	fs.BoolVar(&dryRun, "dry-run", false, "print what would be imported without writing")
	fs.BoolVar(&force, "force", false, "overwrite existing canonical state")
	fs.StringVar(&name, "name", "", "store a single imported certificate under this name")
	fs.Var(&only, "only", "import only this cert (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		printImportUsage(os.Stderr)
		return 2
	}
	path := fs.Arg(0)

	return runImport(p, dryRun, func(store *storage.Store) ([]importer.Result, error) {
		return importer.ImportACMESh(store, importer.ACMEShOptions{
			Path:   path,
			Only:   only,
			Name:   name,
			DryRun: dryRun,
			Force:  force,
			Now:    time.Now(),
		})
	})
}

func cmdImportPEM(p *paths.Paths, args []string) int {
	fs := flag.NewFlagSet("import pem", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		printImportUsage(os.Stderr)
	}
	dryRun := false
	force := false
	name := ""
	certPath := ""
	chainPath := ""
	fullchainPath := ""
	keyPath := ""
	fs.BoolVar(&dryRun, "dry-run", false, "print what would be imported without writing")
	fs.BoolVar(&force, "force", false, "overwrite existing canonical state")
	fs.StringVar(&name, "name", "", "store imported certificate under this name")
	fs.StringVar(&certPath, "cert", "", "path to leaf certificate PEM")
	fs.StringVar(&chainPath, "chain", "", "path to chain certificate PEM")
	fs.StringVar(&fullchainPath, "fullchain", "", "path to fullchain PEM")
	fs.StringVar(&keyPath, "key", "", "path to private key PEM")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		printImportUsage(os.Stderr)
		return 2
	}
	if name == "" {
		fmt.Fprintln(os.Stderr, "gibcert: import pem requires --name")
		return 2
	}
	if keyPath == "" {
		fmt.Fprintln(os.Stderr, "gibcert: import pem requires --key")
		return 2
	}
	hasCert := certPath != ""
	hasFullchain := fullchainPath != ""
	if hasCert == hasFullchain {
		fmt.Fprintln(os.Stderr, "gibcert: import pem requires exactly one of --cert or --fullchain")
		return 2
	}
	if hasFullchain && chainPath != "" {
		fmt.Fprintln(os.Stderr, "gibcert: import pem cannot use --chain with --fullchain")
		return 2
	}

	return runImport(p, dryRun, func(store *storage.Store) ([]importer.Result, error) {
		return importer.ImportPEM(store, importer.PEMOptions{
			Name:          name,
			CertPath:      certPath,
			ChainPath:     chainPath,
			FullchainPath: fullchainPath,
			KeyPath:       keyPath,
			DryRun:        dryRun,
			Force:         force,
			Now:           time.Now(),
		})
	})
}

func cmdImportCertbot(p *paths.Paths, args []string) int {
	fs := flag.NewFlagSet("import certbot", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		printImportUsage(os.Stderr)
	}
	dryRun := false
	force := false
	name := ""
	var only stringList
	fs.BoolVar(&dryRun, "dry-run", false, "print what would be imported without writing")
	fs.BoolVar(&force, "force", false, "overwrite existing canonical state")
	fs.StringVar(&name, "name", "", "store a single imported certificate under this name")
	fs.Var(&only, "only", "import only this cert (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		printImportUsage(os.Stderr)
		return 2
	}
	path := fs.Arg(0)

	return runImport(p, dryRun, func(store *storage.Store) ([]importer.Result, error) {
		return importer.ImportCertbot(store, importer.CertbotOptions{
			Path:   path,
			Only:   only,
			Name:   name,
			DryRun: dryRun,
			Force:  force,
			Now:    time.Now(),
		})
	})
}

func cmdImportDehydrated(p *paths.Paths, args []string) int {
	fs := flag.NewFlagSet("import dehydrated", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		printImportUsage(os.Stderr)
	}
	dryRun := false
	force := false
	name := ""
	var only stringList
	fs.BoolVar(&dryRun, "dry-run", false, "print what would be imported without writing")
	fs.BoolVar(&force, "force", false, "overwrite existing canonical state")
	fs.StringVar(&name, "name", "", "store a single imported certificate under this name")
	fs.Var(&only, "only", "import only this cert (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		printImportUsage(os.Stderr)
		return 2
	}
	path := fs.Arg(0)

	return runImport(p, dryRun, func(store *storage.Store) ([]importer.Result, error) {
		return importer.ImportDehydrated(store, importer.DehydratedOptions{
			Path:   path,
			Only:   only,
			Name:   name,
			DryRun: dryRun,
			Force:  force,
			Now:    time.Now(),
		})
	})
}

func cmdImportLego(p *paths.Paths, args []string) int {
	fs := flag.NewFlagSet("import lego", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		printImportUsage(os.Stderr)
	}
	dryRun := false
	force := false
	name := ""
	var only stringList
	fs.BoolVar(&dryRun, "dry-run", false, "print what would be imported without writing")
	fs.BoolVar(&force, "force", false, "overwrite existing canonical state")
	fs.StringVar(&name, "name", "", "store a single imported certificate under this name")
	fs.Var(&only, "only", "import only this cert (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		printImportUsage(os.Stderr)
		return 2
	}
	path := fs.Arg(0)

	return runImport(p, dryRun, func(store *storage.Store) ([]importer.Result, error) {
		return importer.ImportLego(store, importer.LegoOptions{
			Path:   path,
			Only:   only,
			Name:   name,
			DryRun: dryRun,
			Force:  force,
			Now:    time.Now(),
		})
	})
}

func runImport(p *paths.Paths, dryRun bool, fn func(*storage.Store) ([]importer.Result, error)) int {
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

	results, err := fn(store)
	if err != nil {
		logError(err)
		return 1
	}

	imported, planned, skipped, failed := 0, 0, 0, 0
	for _, r := range results {
		label := r.Source
		if r.Name != "" && r.Name != r.Source {
			label = fmt.Sprintf("%s -> %s", r.Source, r.Name)
		}
		fmt.Printf("  %s: %s", label, r.Status)
		if r.Detail != "" {
			fmt.Printf(" (%s)", r.Detail)
		}
		fmt.Println()
		switch r.Status {
		case importer.StatusImported:
			imported++
		case importer.StatusPlanned:
			planned++
		case importer.StatusSkipped:
			skipped++
		case importer.StatusFailed:
			failed++
		}
	}
	if len(results) == 0 {
		fmt.Println("no certificates found to import")
		return 0
	}
	if dryRun {
		fmt.Printf("dry-run: %d planned, %d skipped, %d failed\n", planned, skipped, failed)
	} else {
		fmt.Printf("imported %d, skipped %d, failed %d\n", imported, skipped, failed)
		if imported > 0 {
			fmt.Println("next: add `certificate` blocks referencing these names to your config, then run `gibcert check`")
		}
	}
	if failed > 0 {
		return 1
	}
	return 0
}
