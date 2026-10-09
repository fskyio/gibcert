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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"gitfield.org/fsky/gibcert/internal/acme"
	"gitfield.org/fsky/gibcert/internal/challenge"
	"gitfield.org/fsky/gibcert/internal/config"
	"gitfield.org/fsky/gibcert/internal/storage"
)

const challengeDNSPersist01 = "dns-persist-01"

type IssueOptions struct {
	Out         io.Writer
	In          io.Reader
	NewKey      bool
	AccountName string
	CAName      string
}

const defaultPropagationTimeout = 120 * time.Second

var dnsPresenters = map[string]func(*config.Provider, io.Reader, io.Writer) challenge.Presenter{
	"manual": func(_ *config.Provider, in io.Reader, out io.Writer) challenge.Presenter {
		return &challenge.DNSManual{In: in, Out: out}
	},
	"exec": func(p *config.Provider, _ io.Reader, out io.Writer) challenge.Presenter {
		return &challenge.DNSExec{Provider: p, Out: out}
	},
	"rfc2136":  nsupdateDNSPresenter,
	"nsupdate": nsupdateDNSPresenter,
	"powerdns": powerDNSPresenter,
	"pdns":     powerDNSPresenter,
}

func Issue(ctx context.Context, c *Client, cert *config.Certificate, store *storage.Store, cfg *config.Config, opts IssueOptions) error {
	gc := cfg.GlobalChallenge
	out := opts.Out
	if out == nil {
		out = os.Stdout
	}
	in := opts.In
	if in == nil {
		in = os.Stdin
	}

	var certKey crypto.Signer
	var err error
	reusedKey := false
	stagedRotation := false
	if cert.TLSA != nil {
		d, err := SelectTLSAKey(cert, store, opts.NewKey, out, time.Now())
		if err != nil {
			return err
		}
		certKey, reusedKey, stagedRotation = d.Key, d.ReusedKey, d.StagedKey
	}
	if certKey == nil && cert.Key.Reuse && !opts.NewKey {
		certKey, err = storage.ReadKey(store.CertPaths(cert.Name).Key)
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

	fmt.Fprintf(out, "issuing %s (names: %s)\n", cert.Name, strings.Join(cert.Names, " "))

	ids := make([]acme.Identifier, 0, len(cert.Names))
	for _, name := range cert.Names {
		idType := "dns"
		if config.IsIPName(name) {
			idType = "ip"
		}
		ids = append(ids, acme.Identifier{Type: idType, Value: name})
	}
	profile := cert.Profile
	if profile == "" {
		caName := opts.CAName
		if caName == "" {
			caName = cert.CA
		}
		if ca := findCAProfile(cfg, caName); ca != nil {
			profile = ca.Profile
		}
	}
	if profile != "" {
		fmt.Fprintf(out, "  requesting profile: %s\n", profile)
	}
	accountName := opts.AccountName
	if accountName == "" {
		accountName = cert.Account
	}
	replaces := ariReplaces(store, cert.Name, accountName, c.DirectoryURL(), out)
	order, err := c.newOrder(ctx, acme.Order{Identifiers: ids, Profile: profile, Replaces: replaces})
	if err != nil {
		return fmt.Errorf("authorize order: %w", err)
	}

	var cleanups []func()
	defer func() {
		for _, cleanup := range cleanups {
			cleanup()
		}
	}()

	chType := cert.Challenge.Type
	if chType == "" && gc != nil {
		chType = gc.Type
	}

	var httpStandalone *challenge.HTTP01Standalone
	var tlsAlpn *challenge.TLSALPN01Standalone
	switch chType {
	case "http-01":
		listen := cert.Challenge.Listen
		if listen == "" && gc != nil {
			listen = gc.Listen
		}
		if listen != "" {
			httpStandalone = &challenge.HTTP01Standalone{Listen: listen}
			if err := httpStandalone.Start(); err != nil {
				return fmt.Errorf("http-01 standalone: %w", err)
			}
			cleanups = append(cleanups, func() {
				sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = httpStandalone.Shutdown(sctx)
			})
		}
	case "tls-alpn-01":
		tlsAlpn = &challenge.TLSALPN01Standalone{Listen: cert.Challenge.Listen}
		if err := tlsAlpn.Start(); err != nil {
			return fmt.Errorf("tls-alpn-01 standalone: %w", err)
		}
		cleanups = append(cleanups, func() { _ = tlsAlpn.Shutdown() })
	}

	persistCAIdentifier := ""
	persistAccountURI := ""
	if chType == challengeDNSPersist01 {
		caName := opts.CAName
		if caName == "" {
			caName = cert.CA
		}
		ca := findCAProfile(cfg, caName)
		if ca == nil || ca.PersistIdentifier == "" {
			return fmt.Errorf("dns-persist-01: ca %q has no persist-identifier configured", caName)
		}
		persistCAIdentifier = ca.PersistIdentifier
		persistAccountURI = c.AccountURL()
	}

	type pendingAuthz struct {
		authz      acme.Authorization
		identifier string
		chal       acme.Challenge
	}
	var pending []pendingAuthz

	for _, authzURL := range order.Authorizations {
		authz, err := c.acme.GetAuthorization(ctx, c.account, authzURL)
		if err != nil {
			return fmt.Errorf("get authz: %w", err)
		}
		if authz.Status == acme.StatusValid {
			continue
		}

		var chal acme.Challenge
		found := false
		for _, ch := range authz.Challenges {
			if ch.Type == chType {
				chal = ch
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("authz %s: no %s challenge offered by CA", authz.Identifier.Value, chType)
		}

		switch chType {
		case "http-01":
			cleanup, err := presentHTTP01(cert, gc, httpStandalone, chal.Token, chal.KeyAuthorization)
			if err != nil {
				return fmt.Errorf("http-01 present: %w", err)
			}
			cleanups = append(cleanups, cleanup)

		case "tls-alpn-01":
			tlsCert, err := acme.TLSALPN01ChallengeCert(chal)
			if err != nil {
				return fmt.Errorf("tls-alpn-01 cert: %w", err)
			}
			cleanup, err := tlsAlpn.Present(authz.Identifier.Value, *tlsCert)
			if err != nil {
				return fmt.Errorf("tls-alpn-01 present: %w", err)
			}
			cleanups = append(cleanups, cleanup)

		case "dns-01":
			record := chal.DNS01KeyAuthorization()
			baseDomain := strings.TrimPrefix(authz.Identifier.Value, "*.")
			fqdn := aliasFQDN(cert.Challenge, baseDomain)

			provider := findProvider(cfg, cert.Challenge.Provider)
			if provider == nil {
				return fmt.Errorf("dns-01: provider %q not found", cert.Challenge.Provider)
			}
			timeout := defaultPropagationTimeout
			if cert.Challenge.PropagationTimeout != nil {
				timeout = *cert.Challenge.PropagationTimeout
			}
			cleanup, err := presentDNS(ctx, provider, fqdn, record, baseDomain, authz.Identifier.Value, timeout, in, out)
			if err != nil {
				return fmt.Errorf("dns-01 present: %w", err)
			}
			cleanups = append(cleanups, cleanup)

			if provider.Driver != "manual" && !provider.HandlesPropagation && timeout > 0 {
				fmt.Fprintf(out, "  %s: waiting for DNS propagation (up to %s)\n", fqdn, timeout)
				checker := &challenge.DNSChecker{}
				if err := checker.Wait(ctx, fqdn, record, timeout); err != nil {
					return fmt.Errorf("dns-01 propagation: %w", err)
				}
			}

		case challengeDNSPersist01:
			base := strings.TrimPrefix(authz.Identifier.Value, "*.")
			verifyDomain := base
			if cert.Challenge.AliasFQDN != "" {
				verifyDomain = strings.TrimPrefix(strings.TrimSuffix(cert.Challenge.AliasFQDN, "."), "_validation-persist.")
			} else if cert.Challenge.AliasDomain != "" {
				verifyDomain = base + "." + strings.TrimSuffix(cert.Challenge.AliasDomain, ".")
			}
			issuerDomainNames, accountURI, err := dnsPersistChallengeExpectations(chal, persistCAIdentifier, persistAccountURI)
			if err != nil {
				return err
			}
			res, err := challenge.VerifyDNSPersistRecordWithOptions(ctx, verifyDomain, challenge.DNSPersistVerifyOptions{
				IssuerDomainNames: issuerDomainNames,
				AccountURI:        accountURI,
				RequireWildcard:   authz.Wildcard,
			})
			if err != nil {
				return fmt.Errorf("dns-persist-01 verify: %w", err)
			}
			if !res.Matched {
				return fmt.Errorf("dns-persist-01: standing record at %s does not authorize account %s for %s; install it with `gibcert dns-persist install %s`", res.RecordName, accountURI, strings.Join(issuerDomainNames, ", "), cert.Name)
			}
			fmt.Fprintf(out, "  %s: standing record present at %s\n", authz.Identifier.Value, res.RecordName)

		default:
			return fmt.Errorf("unsupported challenge type %q", chType)
		}

		pending = append(pending, pendingAuthz{
			authz:      authz,
			identifier: authz.Identifier.Value,
			chal:       chal,
		})
	}

	// All challenges are presented (and, for dns-01, propagated to the
	// authoritative nameservers) before any challenge is initiated. Two
	// authorizations for the same FQDN -- e.g. fsky.net plus *.fsky.net --
	// share one TXT RRset; validating one before the other is published lets
	// Boulder's recursive resolvers cache the partial RRset, after which the
	// second validation sees stale data and reports "Incorrect TXT record".
	for _, p := range pending {
		if _, err := c.acme.InitiateChallenge(ctx, c.account, p.chal); err != nil {
			return fmt.Errorf("initiate challenge: %w", err)
		}
		if _, err := c.acme.PollAuthorization(ctx, c.account, p.authz); err != nil {
			return fmt.Errorf("wait authorization for %s: %w", p.identifier, err)
		}
		fmt.Fprintf(out, "  %s: authorization valid\n", p.identifier)
	}

	csrDER, err := makeCSR(certKey, cert.Names)
	if err != nil {
		return fmt.Errorf("create CSR: %w", err)
	}
	order, err = c.acme.FinalizeOrder(ctx, c.account, order, csrDER)
	if err != nil {
		return fmt.Errorf("finalize order: %w", err)
	}
	if order.Certificate == "" {
		return fmt.Errorf("order has no certificate URL after finalize")
	}
	chains, err := c.acme.GetCertificateChain(ctx, c.account, order.Certificate)
	if err != nil {
		return fmt.Errorf("download certificate chain: %w", err)
	}
	if len(chains) == 0 {
		return fmt.Errorf("CA returned no chains")
	}
	chain, err := selectChain(chains, cert.PreferredChain)
	if err != nil {
		return fmt.Errorf("preferred-chain %q: %w", cert.PreferredChain, err)
	}
	leaf, err := validateIssuedChain(chain, certKey, cert.Names, time.Now())
	if err != nil {
		return fmt.Errorf("validate issued certificate chain: %w", err)
	}

	paths := store.CertPaths(cert.Name)
	if err := os.MkdirAll(paths.Dir, 0o755); err != nil {
		return fmt.Errorf("create cert dir: %w", err)
	}
	var archivedKey string
	switch {
	case stagedRotation:
		var promoted bool
		archivedKey, promoted, err = storage.PromoteNextKey(paths, time.Now())
		if err != nil {
			return fmt.Errorf("promote staged privkey: %w", err)
		}
		if archivedKey != "" {
			fmt.Fprintf(out, "archived previous privkey: %s\n", archivedKey)
		}
		if !promoted {
			if err := storage.WriteKey(paths.Key, certKey); err != nil {
				return fmt.Errorf("write privkey: %w", err)
			}
		}
	case !reusedKey:
		var archived bool
		archivedKey, archived, err = storage.ArchivePrivateKey(paths.Key, time.Now())
		if err != nil {
			return fmt.Errorf("archive previous privkey: %w", err)
		}
		if archived {
			fmt.Fprintf(out, "archived previous privkey: %s\n", archivedKey)
		}
		if err := storage.WriteKey(paths.Key, certKey); err != nil {
			return fmt.Errorf("write privkey: %w", err)
		}
	default:
		if err := storage.WriteKey(paths.Key, certKey); err != nil {
			return fmt.Errorf("write privkey: %w", err)
		}
	}
	if err := storage.WriteSingleCertDER(paths.Cert, chain[0], 0o644); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if len(chain) > 1 {
		if err := storage.WriteCertChainDER(paths.Chain, chain[1:], 0o644); err != nil {
			return fmt.Errorf("write chain: %w", err)
		}
	} else {
		_ = os.Remove(paths.Chain)
	}
	if err := storage.WriteCertChainDER(paths.Fullchain, chain, 0o644); err != nil {
		return fmt.Errorf("write fullchain: %w", err)
	}
	if archivedKey != "" {
		if err := storage.PrunePrivateKeyArchives(paths.Dir, archivedKey); err != nil {
			return fmt.Errorf("prune previous privkey archives: %w", err)
		}
	}
	meta := storage.CertMeta{
		Name:         cert.Name,
		Account:      accountName,
		CA:           opts.CAName,
		IssuerType:   "acme",
		Directory:    c.DirectoryURL(),
		Names:        append([]string(nil), cert.Names...),
		SerialNumber: leaf.SerialNumber.String(),
		NotBefore:    leaf.NotBefore,
		NotAfter:     leaf.NotAfter,
		IssuedAt:     time.Now().UTC(),
	}
	if existing, err := store.LoadCertMeta(cert.Name); err == nil {
		meta.Deploys = existing.Deploys
		meta.DeployFailures = existing.DeployFailures
		meta.TLSA = existing.TLSA
	}

	if cert.TLSA != nil {
		tlsaMeta, err := reconcileTLSA(ctx, store, cfg, cert, certKey, out)
		if err != nil {
			return fmt.Errorf("tlsa reconcile: %w", err)
		}
		meta.TLSA = tlsaMeta
	}

	if err := store.SaveCertMeta(cert.Name, meta); err != nil {
		return fmt.Errorf("write cert metadata: %w", err)
	}

	fmt.Fprintf(out, "stored:\n  %s\n  %s\n  %s\n  %s\n", paths.Cert, paths.Chain, paths.Fullchain, paths.Key)
	return nil
}

// validateIssuedChain checks the returned material before any canonical state
// changes. The supplied chain need not terminate at a system-trusted root:
// private ACME servers and chains omitting their root are supported.
func validateIssuedChain(chain [][]byte, key crypto.Signer, names []string, now time.Time) (*x509.Certificate, error) {
	if len(chain) == 0 {
		return nil, errors.New("chain contained no certificates")
	}
	parsed := make([]*x509.Certificate, len(chain))
	for i, der := range chain {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parse certificate %d: %w", i+1, err)
		}
		if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			return nil, fmt.Errorf("certificate %d is not currently valid", i+1)
		}
		if len(cert.UnhandledCriticalExtensions) != 0 {
			return nil, fmt.Errorf("certificate %d has unhandled critical extensions", i+1)
		}
		parsed[i] = cert
	}
	leaf := parsed[0]
	publicKey, ok := leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !publicKey.Equal(key.Public()) {
		return nil, errors.New("leaf public key does not match CSR/private key")
	}
	if leaf.IsCA {
		return nil, errors.New("leaf is a CA certificate")
	}
	if leaf.KeyUsage != 0 && leaf.KeyUsage&(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment|x509.KeyUsageKeyAgreement) == 0 {
		return nil, errors.New("leaf key usage does not permit TLS")
	}
	if len(leaf.ExtKeyUsage) != 0 || len(leaf.UnknownExtKeyUsage) != 0 {
		serverAuth := false
		for _, usage := range leaf.ExtKeyUsage {
			if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
				serverAuth = true
			}
		}
		if !serverAuth {
			return nil, errors.New("leaf extended key usage does not permit TLS server authentication")
		}
	}
	for _, name := range names {
		if strings.HasPrefix(name, "*.") {
			found := false
			for _, san := range leaf.DNSNames {
				if strings.EqualFold(san, name) {
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("leaf does not cover requested wildcard %q", name)
			}
		} else if err := leaf.VerifyHostname(name); err != nil {
			return nil, fmt.Errorf("leaf does not cover requested name %q: %w", name, err)
		}
	}
	for i := range len(parsed) - 1 {
		if err := parsed[i].CheckSignatureFrom(parsed[i+1]); err != nil {
			return nil, fmt.Errorf("certificate %d is not signed by certificate %d: %w", i+1, i+2, err)
		}
	}
	return leaf, nil
}

// selectChain picks the chain to store from the alternates the ACME client downloaded.
// chains[0] is the CA's default; when a preferred issuer is configured, the
// alternates are scanned for one whose topmost certificate matches. Each
// each acme.Certificate carries the whole chain as PEM, which is decoded back to
// the DER blocks the storage layer writes.
func selectChain(chains []acme.Certificate, preferred string) ([][]byte, error) {
	for _, ch := range chains {
		der, err := pemChainToDER(ch.ChainPEM)
		if err != nil {
			return nil, err
		}
		if preferred == "" || chainMatchesPreferred(der, preferred) {
			return der, nil
		}
	}
	return nil, fmt.Errorf("no offered chain matched")
}

func pemChainToDER(chainPEM []byte) ([][]byte, error) {
	var ders [][]byte
	rest := chainPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		ders = append(ders, block.Bytes)
	}
	if len(ders) == 0 {
		return nil, fmt.Errorf("chain contained no certificates")
	}
	return ders, nil
}

func chainMatchesPreferred(chain [][]byte, preferred string) bool {
	if len(chain) == 0 {
		return false
	}
	cert, err := x509.ParseCertificate(chain[len(chain)-1])
	if err != nil {
		return false
	}
	for _, name := range []string{
		cert.Subject.CommonName,
		cert.Subject.String(),
		cert.Issuer.CommonName,
		cert.Issuer.String(),
	} {
		if name == preferred {
			return true
		}
	}
	return false
}

func findProvider(cfg *config.Config, name string) *config.Provider {
	for _, p := range cfg.Providers {
		if p.Name == name {
			return p
		}
	}
	return nil
}

func findCAProfile(cfg *config.Config, name string) *config.CA {
	if name == "" {
		return nil
	}
	return config.CAProfiles(cfg.CAs)[name]
}

func presentHTTP01(cert *config.Certificate, gc *config.GlobalChallenge, standalone *challenge.HTTP01Standalone, token, keyAuth string) (func(), error) {
	if standalone != nil {
		return standalone.Present(token, keyAuth)
	}
	webroot := cert.Challenge.Webroot
	if webroot == "" && gc != nil {
		webroot = gc.Webroot
	}
	h := &challenge.HTTP01Webroot{Webroot: webroot}
	return h.Present(token, keyAuth)
}

func aliasFQDN(spec config.ChallengeSpec, baseDomain string) string {
	if spec.AliasFQDN != "" {
		return spec.AliasFQDN
	}
	if spec.AliasDomain != "" {
		return "_acme-challenge." + baseDomain + "." + spec.AliasDomain
	}
	return "_acme-challenge." + baseDomain
}

func presentDNS(ctx context.Context, p *config.Provider, fqdn, value, domain, identifier string, timeout time.Duration, in io.Reader, out io.Writer) (func(), error) {
	factory := dnsPresenters[p.Driver]
	if factory == nil {
		return nil, fmt.Errorf("unsupported dns driver %q", p.Driver)
	}
	return factory(p, in, out).Present(ctx, challenge.Request{
		FQDN:       fqdn,
		Value:      value,
		Domain:     domain,
		Identifier: identifier,
		Timeout:    timeout,
	})
}

func nsupdateDNSPresenter(p *config.Provider, _ io.Reader, out io.Writer) challenge.Presenter {
	return &challenge.DNSNSUpdate{Provider: p, Out: out}
}

func powerDNSPresenter(p *config.Provider, _ io.Reader, out io.Writer) challenge.Presenter {
	return &challenge.DNSPowerDNS{Provider: p, Out: out}
}

func dnsPersistChallengeExpectations(chal acme.Challenge, configuredIssuer, accountURI string) ([]string, string, error) {
	issuers := []string{configuredIssuer}
	if len(chal.IssuerDomainNames) > 0 {
		if len(chal.IssuerDomainNames) > 10 {
			return nil, "", fmt.Errorf("dns-persist-01: challenge has %d issuer-domain-names, want at most 10", len(chal.IssuerDomainNames))
		}
		issuers = chal.IssuerDomainNames
	}
	for _, issuer := range issuers {
		issuer = strings.TrimSpace(issuer)
		if issuer == "" || strings.HasSuffix(issuer, ".") || strings.ToLower(issuer) != issuer || len(issuer) > 253 {
			return nil, "", fmt.Errorf("dns-persist-01: malformed issuer-domain-name %q", issuer)
		}
	}
	if chal.AccountURI != "" {
		accountURI = chal.AccountURI
	}
	if accountURI == "" {
		return nil, "", fmt.Errorf("dns-persist-01: challenge/account has no accounturi")
	}
	return issuers, accountURI, nil
}

// newOrder creates an order, transparently retrying without the ARI "replaces"
// field if the CA reports the predecessor certificate has already been replaced
// (RFC 9773 §5: "The server ... returns an error with status code 409 ... and
// type "alreadyReplaced"). The renewal itself is still valid, so we drop the
// hint and try again.
func (c *Client) newOrder(ctx context.Context, order acme.Order) (acme.Order, error) {
	o, err := c.acme.NewOrder(ctx, c.account, order)
	if err != nil && order.Replaces != "" {
		var prob acme.Problem
		if errors.As(err, &prob) && prob.Type == acme.ProblemTypeAlreadyReplaced {
			order.Replaces = ""
			return c.acme.NewOrder(ctx, c.account, order)
		}
	}
	return o, err
}

// ariReplaces returns the ARI identifier of the stored certificate only when
// its metadata ties that exact leaf to the account and directory issuing this
// order. Imported certificates and certificates from a different issuer cannot
// be claimed as replacements by the current account. If provenance or the
// certificate is missing, the new order is sent without the hint.
func ariReplaces(store *storage.Store, name, accountName, directory string, out io.Writer) string {
	meta, err := store.LoadCertMeta(name)
	if err != nil || meta.IssuerType != "acme" || meta.Account == "" ||
		meta.Account != accountName || meta.Directory != directory {
		return ""
	}
	raw, err := os.ReadFile(store.CertPaths(name).Cert)
	if err != nil {
		return ""
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return ""
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil || len(leaf.AuthorityKeyId) == 0 || meta.SerialNumber != leaf.SerialNumber.String() {
		return ""
	}
	id, err := acme.ARIUniqueIdentifier(leaf)
	if err != nil {
		return ""
	}
	fmt.Fprintln(out, "  replacing the existing certificate (ARI)")
	return id
}

func makeCSR(key crypto.Signer, names []string) ([]byte, error) {
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: names[0]},
	}
	for _, name := range names {
		if ip := net.ParseIP(name); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, name)
		}
	}
	return x509.CreateCertificateRequest(rand.Reader, tmpl, key)
}
