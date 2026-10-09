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
	"slices"
	"strings"
	"testing"
	"time"
)

const hostsBase = `
ca dev {
  type local
}
host web1 {
  address web1.example.com
  user deploy
  port 2222
  identity-file /etc/gibcert/id
  known-hosts /etc/gibcert/known_hosts
  timeout 10s
  remote-command /usr/local/bin/gibcert
}
host web2 {
  address 192.0.2.7
}
`

func hostsCfg(t *testing.T, src string) *Config {
	t.Helper()
	cfg, err := Read(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return cfg
}

func TestParseHostsAndDeployHosts(t *testing.T) {
	cfg := hostsCfg(t, hostsBase+`
certificate a {
  ca dev
  names a.example
  deploy d {
    cert /etc/a.pem
    host web1
    host web2
  }
}
`)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	h := cfg.FindHost("web1")
	want := Host{Name: "web1", Address: "web1.example.com", User: "deploy", Port: 2222,
		IdentityFile: "/etc/gibcert/id", KnownHosts: "/etc/gibcert/known_hosts",
		Timeout: 10 * time.Second, RemoteCommand: "/usr/local/bin/gibcert"}
	if h == nil || *h != want {
		t.Fatalf("web1 = %+v, want %+v", h, want)
	}
	if cfg.FindHost("nope") != nil {
		t.Fatal("FindHost(nope) != nil")
	}
	if got := cfg.Certificates[0].Deploys[0].Hosts; !slices.Equal(got, []string{"web1", "web2"}) {
		t.Fatalf("deploy hosts = %v", got)
	}
}

func TestHostDefaults(t *testing.T) {
	cfg := hostsCfg(t, hostsBase)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	h := cfg.FindHost("web2")
	if h.Timeout != DefaultHostTimeout || h.RemoteCommand != DefaultHostRemoteCommand || h.Port != 0 {
		t.Fatalf("web2 = %+v, want defaults", h)
	}
}

func TestHostParseErrors(t *testing.T) {
	for name, src := range map[string]string{
		"unknown directive": "host h {\n address a\n bogus x\n}",
		"bad port":          "host h {\n address a\n port x\n}",
		"bad timeout":       "host h {\n address a\n timeout soon\n}",
		"deploy empty host": "certificate a {\n ca dev\n names a.example\n deploy d {\n cert /x\n host\n }\n}",
	} {
		if _, err := Read(strings.NewReader(src)); err == nil {
			t.Errorf("%s: Read succeeded, want error", name)
		}
	}
}

func TestHostValidateErrors(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
	}{
		{"no address", "", "address is required"},
		{"option injection", "address -oProxyCommand=x", "must not start with '-'"},
		{"address space", `address "a b"`, "whitespace"},
		{"user at", "address a\n user a@b", "user"},
		{"user dash", "address a\n user -x", "user"},
		{"port high", "address a\n port 70000", "port"},
		{"port negative", "address a\n port -1", "port"},
		{"relative identity", "address a\n identity-file id", "identity-file"},
		{"relative known-hosts", "address a\n known-hosts kh", "known-hosts"},
		{"negative timeout", "address a\n timeout -1s", "timeout"},
		{"command space", `address a` + "\n" + ` remote-command "gibcert; id"`, "remote-command"},
		{"command dash", "address a\n remote-command -x", "remote-command"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := hostsCfg(t, "host h {\n "+tc.body+"\n}\n")
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestHostNameErrors(t *testing.T) {
	for name, src := range map[string]string{
		"at":        "host \"a@b\" {\n address a\n}",
		"space":     "host \"a b\" {\n address a\n}",
		"duplicate": "host h {\n address a\n}\nhost h {\n address b\n}",
	} {
		if err := hostsCfg(t, src).Validate(); err == nil {
			t.Errorf("%s: Validate succeeded, want error", name)
		}
	}
}

func TestDeployHostReferenceErrors(t *testing.T) {
	for _, tc := range []struct{ name, hosts, want string }{
		{"unknown", "nope", `unknown host "nope"`},
		{"duplicate", "web2 web2", "duplicate host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := hostsCfg(t, hostsBase+"certificate a {\n ca dev\n names a.example\n deploy d {\n cert /etc/a.pem\n host "+tc.hosts+"\n }\n}\n")
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestDestinationCollisionsPerHost(t *testing.T) {
	cert := func(deploys string) string {
		return hostsBase + "certificate a {\n ca dev\n names a.example\n" + deploys + "}\n"
	}
	for _, tc := range []struct {
		name, deploys, want string // want "" means valid
	}{
		{"one deploy two hosts", "deploy d {\n cert /p\n host web1 web2\n}\n", ""},
		{"same path different hosts", "deploy d1 {\n cert /p\n host web1\n}\ndeploy d2 {\n cert /p\n host web2\n}\n", ""},
		{"local and remote", "deploy d1 {\n cert /p\n}\ndeploy d2 {\n cert /p\n host web1\n}\n", ""},
		{"same host", "deploy d1 {\n cert /p\n host web1\n}\ndeploy d2 {\n cert /p\n host web1 web2\n}\n", `on host "web1" collides`},
		{"same local", "deploy d1 {\n cert /p\n}\ndeploy d2 {\n cert /p\n}\n", "collides"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := hostsCfg(t, cert(tc.deploys)).Validate()
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("Validate: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("Validate = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestGroupDeployHostsReplace(t *testing.T) {
	c := resolveCert(t, hostsBase+`
group g {
  ca dev
  deploy d {
    cert /etc/{cert}.pem
    host web1 web2
  }
  deploy e {
    cert /etc/e-{cert}.pem
    host web1
  }
}
certificate a {
  groups g
  names a.example
  deploy d {
    host web2
  }
}
`)
	if got := findDeploy(c, "d").Hosts; !slices.Equal(got, []string{"web2"}) {
		t.Errorf("overridden hosts = %v, want [web2]", got)
	}
	if got := findDeploy(c, "e").Hosts; !slices.Equal(got, []string{"web1"}) {
		t.Errorf("inherited hosts = %v, want [web1]", got)
	}
}

func TestGroupsConflictingDeployHosts(t *testing.T) {
	msg := validateErr(t, hostsBase+`
group g1 {
  ca dev
  deploy d {
    cert /etc/c.pem
    host web1
  }
}
group g2 {
  deploy d {
    host web2
  }
}
certificate a {
  groups g1 g2
  names a.example
}
`)
	if !strings.Contains(msg, "conflicting host") {
		t.Fatalf("error = %q, want conflicting host", msg)
	}
}
