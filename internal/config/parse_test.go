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

package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReadExample(t *testing.T) {
	src := `
account letsencrypt {
  ca letsencrypt
  email admin@example.com
  eab {
    kid kid-1
    hmac-key {
      file /etc/gibcert/eab.key
    }
  }
}

provider dynamic-dns {
  type dns
  driver rfc2136
  server 192.0.2.53
  zone example.com
  secret tsig-key {
    file /etc/gibcert/rfc2136.key
  }
}

certificate example.com {
  account letsencrypt
  names example.com www.example.com *.example.com
  preferred-chain "ISRG Root X1"
  key {
    type ecdsa
    curve p256
  }
  challenge dns-01 {
    provider dynamic-dns
    propagation-timeout 120s
  }
  renew {
    before-expiry 30d
  }
  deploy nginx {
    fullchain /etc/nginx/tls/example.com/fullchain.pem
    key /etc/nginx/tls/example.com/privkey.pem
    mode 0640
    before "systemctl stop nginx"
    after "systemctl reload nginx"
  }
}
`
	cfg, err := Read(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if got, want := len(cfg.Accounts), 1; got != want {
		t.Fatalf("accounts: got %d, want %d", got, want)
	}
	if got, want := cfg.Accounts[0].Email, "admin@example.com"; got != want {
		t.Errorf("email: got %q, want %q", got, want)
	}
	if got, want := cfg.Accounts[0].Directory, "https://acme-v02.api.letsencrypt.org/directory"; got != want {
		t.Errorf("account directory: got %q, want %q", got, want)
	}
	if cfg.Accounts[0].EAB == nil {
		t.Fatalf("account eab: got nil")
	}
	if got, want := cfg.Accounts[0].EAB.KID, "kid-1"; got != want {
		t.Errorf("eab kid: got %q, want %q", got, want)
	}
	if got, want := cfg.Accounts[0].EAB.HMACKey.File, "/etc/gibcert/eab.key"; got != want {
		t.Errorf("eab hmac-key file: got %q, want %q", got, want)
	}

	if got, want := len(cfg.Providers), 1; got != want {
		t.Fatalf("providers: got %d, want %d", got, want)
	}
	p := cfg.Providers[0]
	if got, want := p.Driver, "rfc2136"; got != want {
		t.Errorf("driver: got %q, want %q", got, want)
	}
	if got, want := p.Fields["server"], []string{"192.0.2.53"}; len(got) != 1 || got[0] != want[0] {
		t.Errorf("fields[server]: got %v, want %v", got, want)
	}
	if len(p.Secrets) != 1 || p.Secrets[0].File != "/etc/gibcert/rfc2136.key" {
		t.Errorf("secret: got %+v", p.Secrets)
	}

	if got, want := len(cfg.Certificates), 1; got != want {
		t.Fatalf("certs: got %d, want %d", got, want)
	}
	c := cfg.Certificates[0]
	if got, want := c.Names, []string{"example.com", "www.example.com", "*.example.com"}; !equalSlices(got, want) {
		t.Errorf("names: got %v, want %v", got, want)
	}
	if got, want := c.PreferredChain, "ISRG Root X1"; got != want {
		t.Errorf("preferred-chain: got %q, want %q", got, want)
	}
	if c.Challenge.PropagationTimeout == nil {
		t.Errorf("propagation-timeout: got nil, want 120s")
	} else if got, want := *c.Challenge.PropagationTimeout, 120*time.Second; got != want {
		t.Errorf("propagation-timeout: got %v, want %v", got, want)
	}
	if got, want := c.Renew.BeforeExpiry, 30*24*time.Hour; got != want {
		t.Errorf("before-expiry: got %v, want %v", got, want)
	}
	if len(c.Deploys) != 1 {
		t.Fatalf("deploys: got %d, want 1", len(c.Deploys))
	}
	dep := c.Deploys[0]
	if dep.Mode == nil || *dep.Mode != fs.FileMode(0o640) {
		t.Errorf("mode: got %v, want 0640", dep.Mode)
	}
	if got, want := dep.Before, "systemctl stop nginx"; got != want {
		t.Errorf("before: got %q, want %q", got, want)
	}
	if got, want := dep.After, "systemctl reload nginx"; got != want {
		t.Errorf("after: got %q, want %q", got, want)
	}
}

func TestLoadIncludesDirectory(t *testing.T) {
	dir := t.TempDir()
	confDir := filepath.Join(dir, "conf.d")
	if err := os.Mkdir(confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "gibcert.scfg"), `
include conf.d

certificate example.com {
  account letsencrypt
  names example.com
  challenge dns-01 {
    provider manual
  }
  deploy local {
    cert /tmp/example.com.pem
  }
}
`)
	writeFile(t, filepath.Join(confDir, "20-provider.scfg"), `
provider manual {
  type dns
  driver manual
}
`)
	writeFile(t, filepath.Join(confDir, "10-account.scfg"), `
account letsencrypt {
  ca letsencrypt
  email admin@example.com
}
`)

	cfg, err := Load(filepath.Join(dir, "gibcert.scfg"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got, want := cfg.Accounts[0].Name, "letsencrypt"; got != want {
		t.Errorf("account: got %q, want %q", got, want)
	}
	if got, want := cfg.Providers[0].Name, "manual"; got != want {
		t.Errorf("provider: got %q, want %q", got, want)
	}
}

func TestLoadIncludesGlob(t *testing.T) {
	dir := t.TempDir()
	confDir := filepath.Join(dir, "conf.d")
	if err := os.Mkdir(confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "gibcert.scfg"), `include conf.d/*.scfg`)
	writeFile(t, filepath.Join(confDir, "account.scfg"), `
account letsencrypt {
  ca letsencrypt
}
`)
	writeFile(t, filepath.Join(confDir, "provider.scfg"), `
provider manual {
  type dns
  driver manual
}
`)

	cfg, err := Load(filepath.Join(dir, "gibcert.scfg"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, want := len(cfg.Accounts), 1; got != want {
		t.Fatalf("accounts: got %d, want %d", got, want)
	}
	if got, want := len(cfg.Providers), 1; got != want {
		t.Fatalf("providers: got %d, want %d", got, want)
	}
}

func TestLoadIncludeCycle(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.scfg"), `include b.scfg`)
	writeFile(t, filepath.Join(dir, "b.scfg"), `include a.scfg`)

	_, err := Load(filepath.Join(dir, "a.scfg"))
	if err == nil {
		t.Fatal("Load: got nil error, want cycle error")
	}
	if !strings.Contains(err.Error(), "include cycle") {
		t.Fatalf("Load error %q, want include cycle", err)
	}
}

func TestValidateRejectsUnsafeStateNames(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "ca path separator",
			src: `
ca "../dev" {
  type local
}
`,
			want: `ca "../dev": invalid name: must not contain path separators`,
		},
		{
			name: "account path separator",
			src: `
account "../letsencrypt" {
  ca letsencrypt
}
`,
			want: `account "../letsencrypt": invalid name: must not contain path separators`,
		},
		{
			name: "certificate path separator",
			src: `
ca dev {
  type local
}

certificate "../../outside" {
  ca dev
  names example.com
}
`,
			want: `certificate "../../outside": invalid name: must not contain path separators`,
		},
		{
			name: "dot certificate",
			src: `
ca dev {
  type local
}

certificate "." {
  ca dev
  names example.com
}
`,
			want: `certificate ".": invalid name: must be a single path component`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Read(strings.NewReader(tt.src))
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			err = cfg.Validate()
			if err == nil {
				t.Fatal("Validate: got nil error, want unsafe name error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestReadSecretSources(t *testing.T) {
	src := `
account zerossl {
  ca zerossl
  eab {
    kid kid-1
    hmac-key {
      env ZEROSSL_EAB_KEY
    }
  }
}

provider custom {
  type dns
  driver exec
  command /usr/local/bin/hook
  secret api-token {
    env GIBCERT_TEST_TOKEN
  }
  secret password {
    command pass show dns/password
  }
  secret key {
    systemd-credential dns-key
  }
}
`
	cfg, err := Read(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if got, want := cfg.Accounts[0].EAB.HMACKey.Env, "ZEROSSL_EAB_KEY"; got != want {
		t.Errorf("eab hmac-key env got %q, want %q", got, want)
	}
	secrets := cfg.Providers[0].Secrets
	if got, want := secrets[0].Env, "GIBCERT_TEST_TOKEN"; got != want {
		t.Errorf("secret env got %q, want %q", got, want)
	}
	if got, want := secrets[1].Command, []string{"pass", "show", "dns/password"}; !equalSlices(got, want) {
		t.Errorf("secret command got %v, want %v", got, want)
	}
	if got, want := secrets[2].SystemdCredential, "dns-key"; got != want {
		t.Errorf("secret systemd credential got %q, want %q", got, want)
	}
}

func TestCAProfiles(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		accountCA string
		directory string
	}{
		{
			name: "built-in ca",
			src: `
account default {
  ca letsencrypt-staging
}
`,
			accountCA: "letsencrypt-staging",
			directory: "https://acme-staging-v02.api.letsencrypt.org/directory",
		},
		{
			name: "account name implies built-in ca",
			src: `
account zerossl {
  email admin@example.com
}
`,
			accountCA: "zerossl",
			directory: "https://acme.zerossl.com/v2/DV90",
		},
		{
			name: "user ca overrides built-in ca",
			src: `
ca letsencrypt {
  directory https://acme-proxy.example/directory
}
account default {
  ca letsencrypt
}
`,
			accountCA: "letsencrypt",
			directory: "https://acme-proxy.example/directory",
		},
		{
			name: "custom ca",
			src: `
ca private {
  directory https://ca.example/acme/directory
}
account default {
  ca private
}
`,
			accountCA: "private",
			directory: "https://ca.example/acme/directory",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Read(strings.NewReader(tc.src))
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if got := cfg.Accounts[0].CA; got != tc.accountCA {
				t.Errorf("account ca: got %q, want %q", got, tc.accountCA)
			}
			if got := cfg.Accounts[0].Directory; got != tc.directory {
				t.Errorf("directory: got %q, want %q", got, tc.directory)
			}
		})
	}
}

func TestParseProfile(t *testing.T) {
	src := `
ca private {
  directory https://ca.example/acme/directory
  profile classic
}
account default {
  ca private
}
challenge http-01 {
  webroot /var/www/html
}
certificate a.example.com {
  account default
  names a.example.com
}
certificate b.example.com {
  account default
  names b.example.com
  profile tlsserver
}
`
	cfg, err := Read(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	ca := CAProfiles(cfg.CAs)["private"]
	if ca == nil {
		t.Fatalf("ca private: not found")
	}
	if got, want := ca.Profile, "classic"; got != want {
		t.Errorf("ca profile: got %q, want %q", got, want)
	}
	certs := map[string]*Certificate{}
	for _, c := range cfg.Certificates {
		certs[c.Name] = c
	}
	if got := certs["a.example.com"].Profile; got != "" {
		t.Errorf("cert a profile: got %q, want empty", got)
	}
	if got, want := certs["b.example.com"].Profile, "tlsserver"; got != want {
		t.Errorf("cert b profile: got %q, want %q", got, want)
	}
}

func TestValidateIPIdentifierChallenge(t *testing.T) {
	cases := []struct {
		name      string
		challenge string
		wantErr   string
	}{
		{name: "http-01 ok", challenge: "challenge http-01 {\n    webroot /var/www\n  }"},
		{name: "tls-alpn-01 ok", challenge: "challenge tls-alpn-01 {\n    listen :443\n  }"},
		{name: "dns-01 rejected", challenge: "challenge dns-01 {\n    provider p\n  }", wantErr: "require http-01 or tls-alpn-01"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := `
provider p {
  type dns
  driver manual
}
account default {
  ca letsencrypt-staging
}
certificate ip-cert {
  account default
  names 192.0.2.10
  ` + tc.challenge + `
}
`
			cfg, err := Read(strings.NewReader(src))
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			err = cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate: unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate: got %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestLocalCAAndCertificate(t *testing.T) {
	src := `
ca dev {
  type local
  common-name "gibcert dev CA"
  valid-for 365d
  key {
    type ecdsa
    curve p384
  }
}
certificate localhost {
  ca dev
  names localhost 127.0.0.1 ::1
  valid-for 30d
  key {
    type ecdsa
    curve p256
    reuse
  }
  deploy local {
    fullchain /tmp/localhost-fullchain.pem
    key /tmp/localhost-key.pem
  }
}`
	cfg, err := Read(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got, want := cfg.CAs[0].Type, "local"; got != want {
		t.Errorf("ca type: got %q, want %q", got, want)
	}
	if got, want := cfg.CAs[0].CommonName, "gibcert dev CA"; got != want {
		t.Errorf("common-name: got %q, want %q", got, want)
	}
	if got, want := cfg.CAs[0].ValidFor, 365*24*time.Hour; got != want {
		t.Errorf("ca valid-for: got %v, want %v", got, want)
	}
	cert := cfg.Certificates[0]
	if got, want := cert.CA, "dev"; got != want {
		t.Errorf("cert ca: got %q, want %q", got, want)
	}
	if got, want := cert.ValidFor, 30*24*time.Hour; got != want {
		t.Errorf("cert valid-for: got %v, want %v", got, want)
	}
}

func TestCertificateCanUseACMECAWithoutAccount(t *testing.T) {
	src := `
challenge http-01 {
  webroot /tmp
}
certificate foo {
  ca letsencrypt
  names foo.example
  deploy d {
    cert /tmp/c.pem
  }
}`
	cfg, err := Read(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got, want := cfg.Certificates[0].CA, "letsencrypt"; got != want {
		t.Errorf("cert ca: got %q, want %q", got, want)
	}
}

func TestFailoverParseAndValidate(t *testing.T) {
	src := `
account zerossl {
  ca zerossl
}
account sectigo {
  ca buypass
}
certificate foo {
  account zerossl
  names foo.example
  challenge http-01 {
    webroot /tmp
  }
  failover {
    ca letsencrypt
    account sectigo
  }
  deploy d {
    cert /tmp/c.pem
  }
}`
	cfg, err := Read(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	fo := cfg.Certificates[0].Failover
	want := []Issuer{{CA: "letsencrypt"}, {Account: "sectigo"}}
	if len(fo) != len(want) {
		t.Fatalf("failover len: got %d, want %d (%+v)", len(fo), len(want), fo)
	}
	for i := range want {
		if fo[i] != want[i] {
			t.Errorf("failover[%d]: got %+v, want %+v", i, fo[i], want[i])
		}
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "unknown account",
			src: `
account letsencrypt {
}
certificate foo {
  account b
  names foo.example
  challenge http-01 {
    webroot /tmp
  }
  deploy d {
    cert /tmp/c.pem
  }
}`,
			want: `unknown account "b"`,
		},
		{
			name: "account and ca",
			src: `
account letsencrypt {
}
certificate foo {
  account letsencrypt
  ca letsencrypt
  names foo.example
  challenge http-01 {
    webroot /tmp
  }
  deploy d {
    cert /tmp/c.pem
  }
}`,
			want: `exactly one of account or ca is required`,
		},
		{
			name: "local ca challenge",
			src: `
ca dev {
  type local
}
certificate foo {
  ca dev
  names foo.example
  challenge http-01 {
    webroot /tmp
  }
  deploy d {
    cert /tmp/c.pem
  }
}`,
			want: `challenge is only valid for acme certificates`,
		},
		{
			name: "account local ca",
			src: `
ca dev {
  type local
}
account dev {
}
`,
			want: `ca "dev" is local, want acme`,
		},
		{
			name: "unknown ca",
			src: `
account a {
  ca missing
}`,
			want: `unknown ca "missing"`,
		},
		{
			name: "duplicate ca",
			src: `
ca private {
  directory https://ca-one.example/directory
}
ca private {
  directory https://ca-two.example/directory
}
account a {
  ca private
}`,
			want: `duplicate ca "private"`,
		},
		{
			name: "account directory",
			src: `
account a {
  directory https://example.invalid/directory
}`,
			want: `unknown directive "directory"`,
		},
		{
			name: "eab missing kid",
			src: `
account letsencrypt {
  eab {
    hmac-key {
      value secret
    }
  }
}`,
			want: `eab: kid is required`,
		},
		{
			name: "eab missing hmac key",
			src: `
account letsencrypt {
  eab {
    kid kid-1
  }
}`,
			want: `eab: hmac-key: exactly one of file, value, env, command, or systemd-credential is required`,
		},
		{
			name: "eab hmac key file and value",
			src: `
account letsencrypt {
  eab {
    kid kid-1
    hmac-key {
      file /tmp/eab.key
      value secret
    }
  }
}`,
			want: `eab: hmac-key: exactly one of file, value, env, command, or systemd-credential is required`,
		},
		{
			name: "secret file and env",
			src: `
provider custom {
  type dns
  driver exec
  command /usr/local/bin/hook
  secret api-token {
    file /tmp/token
    env GIBCERT_TEST_TOKEN
  }
}`,
			want: `secret "api-token": exactly one of file, value, env, command, or systemd-credential is required`,
		},
		{
			name: "unknown dns provider",
			src: `
account letsencrypt {
}
certificate foo {
  account letsencrypt
  names foo.example
  challenge dns-01 {
    provider missing
  }
  deploy d {
    cert /tmp/c.pem
  }
}`,
			want: `unknown provider "missing"`,
		},
		{
			name: "unsupported dns driver",
			src: `
account letsencrypt {
}
provider bad {
  type dns
  driver imaginary
}
certificate foo {
  account letsencrypt
  names foo.example
  challenge dns-01 {
    provider bad
  }
  deploy d {
    cert /tmp/c.pem
  }
}`,
			want: `unsupported dns driver "imaginary"`,
		},
		{
			name: "legacy exec operation command",
			src: `
provider custom {
  type dns
  driver exec
  command /usr/local/bin/provider
  present /usr/local/bin/legacy-hook
}`,
			want: `legacy exec field "present" is not supported`,
		},
		{
			name: "gibdns provider propagation",
			src: `
provider custom {
  type dns
  driver exec
  command /usr/local/bin/provider
  propagation provider
}`,
			want: `propagation provider is not supported by gibdns`,
		},
		{
			name: "duplicate cert",
			src: `
account letsencrypt {
}
certificate foo {
  account letsencrypt
  names foo.example
  challenge http-01 {
    webroot /tmp
  }
  deploy d {
    cert /tmp/c.pem
  }
}
certificate foo {
  account letsencrypt
  names foo.example
  challenge http-01 {
    webroot /tmp
  }
  deploy d {
    cert /tmp/c.pem
  }
}`,
			want: `duplicate certificate "foo"`,
		},
		{
			name: "mode too high",
			src: `
account letsencrypt {
}
certificate foo {
  account letsencrypt
  names foo.example
  challenge http-01 {
    webroot /tmp
  }
  deploy d {
    cert /tmp/c.pem
    mode 01000
  }
}`,
			want: `must be <= 0777`,
		},
		{
			name: "relative deploy path",
			src: `
account letsencrypt {
}
certificate foo {
  account letsencrypt
  names foo.example
  challenge http-01 {
    webroot /tmp
  }
  deploy d {
    cert relative/path.pem
  }
}`,
			want: `must be an absolute path`,
		},
		{
			name: "http-01 without webroot or global default",
			src: `
account letsencrypt {
}
certificate foo {
  account letsencrypt
  names foo.example
  challenge http-01 {
  }
  deploy d {
    cert /tmp/c.pem
  }
}`,
			want: `one of webroot or listen is required`,
		},
		{
			name: "failover unknown account",
			src: `
account letsencrypt {
}
certificate foo {
  account letsencrypt
  names foo.example
  challenge http-01 {
    webroot /tmp
  }
  failover {
    account missing
  }
}`,
			want: `failover: unknown account "missing"`,
		},
		{
			name: "failover non-acme ca",
			src: `
ca dev {
  type local
}
account letsencrypt {
}
certificate foo {
  account letsencrypt
  names foo.example
  challenge http-01 {
    webroot /tmp
  }
  failover {
    ca dev
  }
}`,
			want: `failover: ca "dev" is local, want acme`,
		},
		{
			name: "failover duplicate of primary",
			src: `
certificate foo {
  ca letsencrypt
  names foo.example
  challenge http-01 {
    webroot /tmp
  }
  failover {
    ca letsencrypt
  }
}`,
			want: `failover: duplicate issuer ca:letsencrypt`,
		},
		{
			name: "failover on local certificate",
			src: `
ca dev {
  type local
}
certificate foo {
  ca dev
  names foo.example
  failover {
    ca letsencrypt
  }
}`,
			want: `failover is only valid for acme certificates`,
		},
		{
			name: "empty failover block",
			src: `
certificate foo {
  ca letsencrypt
  names foo.example
  challenge http-01 {
    webroot /tmp
  }
  failover {
  }
}`,
			want: `failover: at least one account or ca is required`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Read(strings.NewReader(tc.src))
			if err != nil {
				if !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("parse error %q, want substring %q", err, tc.want)
				}
				return
			}
			err = cfg.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got error %q, want substring %q", err, tc.want)
			}
		})
	}
}

func TestChallengeListenAndAlias(t *testing.T) {
	src := `
account letsencrypt {
}
provider dynamic-dns {
  type dns
  driver rfc2136
  server 192.0.2.53
  zone alias.example
  secret tsig-key {
    file /etc/gibcert/rfc2136.key
  }
}
certificate http-standalone {
  account letsencrypt
  names a.example
  challenge http-01 {
    listen ":8080"
  }
  deploy d {
    cert /tmp/a.pem
  }
}
certificate tls-standalone {
  account letsencrypt
  names b.example
  challenge tls-alpn-01 {
    listen ":8443"
  }
  deploy d {
    cert /tmp/b.pem
  }
}
certificate dns-aliased {
  account letsencrypt
  names c.example
  challenge dns-01 {
    provider dynamic-dns
    alias-domain alias.example
  }
  deploy d {
    cert /tmp/c.pem
  }
}
certificate persist {
  account letsencrypt
  names d.example
  challenge dns-persist-01 {
    provider dynamic-dns
  }
  deploy d {
    cert /tmp/d.pem
  }
}
`
	cfg, err := Read(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got := cfg.Certificates[0].Challenge.Listen; got != ":8080" {
		t.Errorf("http listen: got %q", got)
	}
	if got := cfg.Certificates[1].Challenge.Listen; got != ":8443" {
		t.Errorf("tls listen: got %q", got)
	}
	if got := cfg.Certificates[2].Challenge.AliasDomain; got != "alias.example" {
		t.Errorf("alias-domain: got %q", got)
	}
	if got := cfg.Certificates[3].Challenge.Type; got != "dns-persist-01" {
		t.Errorf("dns-persist-01 type: got %q", got)
	}
}

func TestChallengeRejects(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "alias on http-01",
			src: `
account letsencrypt {
}
certificate foo {
  account letsencrypt
  names foo.example
  challenge http-01 {
    webroot /tmp
    alias-fqdn _acme-challenge.foo.alias.example
  }
  deploy d {
    cert /tmp/c.pem
  }
}`,
			want: `alias-fqdn and alias-domain are only valid for dns-01`,
		},
		{
			name: "both alias kinds",
			src: `
account letsencrypt {
}
provider d {
  type dns
  driver manual
}
certificate foo {
  account letsencrypt
  names foo.example
  challenge dns-01 {
    provider d
    alias-fqdn _acme-challenge.foo.alias.example
    alias-domain alias.example
  }
  deploy d {
    cert /tmp/c.pem
  }
}`,
			want: `mutually exclusive`,
		},
		{
			name: "http-01 webroot and listen",
			src: `
account letsencrypt {
}
certificate foo {
  account letsencrypt
  names foo.example
  challenge http-01 {
    webroot /tmp
    listen :80
  }
  deploy d {
    cert /tmp/c.pem
  }
}`,
			want: `webroot and listen are mutually exclusive`,
		},
		{
			name: "tls-alpn-01 missing listen",
			src: `
account letsencrypt {
}
certificate foo {
  account letsencrypt
  names foo.example
  challenge tls-alpn-01 {
  }
  deploy d {
    cert /tmp/c.pem
  }
}`,
			want: `tls-alpn-01: listen is required`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Read(strings.NewReader(tc.src))
			if err != nil {
				if !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("parse error %q, want substring %q", err, tc.want)
				}
				return
			}
			err = cfg.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got error %q, want substring %q", err, tc.want)
			}
		})
	}
}

func TestGlobalHTTP01Default(t *testing.T) {
	src := `
account letsencrypt {
}
challenge http-01 {
  webroot /var/www/acme
}
certificate foo {
  account letsencrypt
  names foo.example
  deploy d {
    cert /tmp/c.pem
  }
}`
	cfg, err := Read(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func writeFile(t *testing.T, path, src string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
