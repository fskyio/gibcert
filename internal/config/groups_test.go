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
	"strings"
	"testing"
)

func resolveCert(t *testing.T, src string) *Certificate {
	t.Helper()
	cfg, err := Read(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("certs: got %d, want 1", len(cfg.Certificates))
	}
	return cfg.Certificates[0]
}

func findDeploy(c *Certificate, name string) *Deploy {
	for _, d := range c.Deploys {
		if d.Name == name {
			return d
		}
	}
	return nil
}

const groupsBase = `
account letsencrypt {
  ca letsencrypt
  email admin@example.com
}
group web {
  account letsencrypt
  challenge http-01 {
    webroot /var/www/acme-challenge
  }
  deploy nginx {
    fullchain /etc/nginx/tls/{cert}/fullchain.pem
    key /etc/nginx/tls/{cert}/privkey.pem
    after "systemctl reload nginx"
  }
}
`

func TestGroupInheritsAndTemplates(t *testing.T) {
	c := resolveCert(t, groupsBase+`
certificate example.com {
  groups web
  names example.com www.example.com
}
`)
	if got, want := c.Account, "letsencrypt"; got != want {
		t.Errorf("account: got %q, want %q", got, want)
	}
	if got, want := c.Challenge.Type, "http-01"; got != want {
		t.Errorf("challenge: got %q, want %q", got, want)
	}
	if got, want := c.Challenge.Webroot, "/var/www/acme-challenge"; got != want {
		t.Errorf("webroot: got %q, want %q", got, want)
	}
	d := findDeploy(c, "nginx")
	if d == nil {
		t.Fatalf("deploy nginx: missing")
	}
	if got, want := d.Fullchain, "/etc/nginx/tls/example.com/fullchain.pem"; got != want {
		t.Errorf("fullchain: got %q, want %q", got, want)
	}
	if got, want := d.After, "systemctl reload nginx"; got != want {
		t.Errorf("after: got %q, want %q", got, want)
	}
	if c.Groups != nil {
		t.Errorf("Groups should be cleared after resolution, got %v", c.Groups)
	}
}

func TestGroupOverrideAndAddDeploy(t *testing.T) {
	c := resolveCert(t, groupsBase+`
certificate api.example.com {
  groups web
  names api.example.com
  deploy nginx {
    after "systemctl restart api-gateway"
  }
  deploy haproxy {
    fullchain /etc/haproxy/{cert}.pem
  }
}
`)
	nginx := findDeploy(c, "nginx")
	if nginx == nil {
		t.Fatalf("deploy nginx: missing")
	}
	// Overridden field wins.
	if got, want := nginx.After, "systemctl restart api-gateway"; got != want {
		t.Errorf("after: got %q, want %q", got, want)
	}
	// Unset fields still inherited (and templated).
	if got, want := nginx.Fullchain, "/etc/nginx/tls/api.example.com/fullchain.pem"; got != want {
		t.Errorf("fullchain: got %q, want %q", got, want)
	}
	// Added deploy present and templated.
	haproxy := findDeploy(c, "haproxy")
	if haproxy == nil {
		t.Fatalf("deploy haproxy: missing")
	}
	if got, want := haproxy.Fullchain, "/etc/haproxy/api.example.com.pem"; got != want {
		t.Errorf("haproxy fullchain: got %q, want %q", got, want)
	}
}

func TestGroupReloadInheritedAndDeduped(t *testing.T) {
	src := `
account letsencrypt {
  ca letsencrypt
}
group web {
  account letsencrypt
  challenge http-01 {
    webroot /var/www/acme-challenge
  }
  reload "systemctl reload nginx"
}
certificate example.com {
  groups web
  names example.com
  reload "systemctl reload nginx"
  reload "systemctl reload haproxy"
}
`
	c := resolveCert(t, src)
	// Group reload + the cert's duplicate collapse to one; haproxy is kept.
	want := []string{"systemctl reload nginx", "systemctl reload haproxy"}
	if len(c.Reloads) != len(want) {
		t.Fatalf("reloads: got %v, want %v", c.Reloads, want)
	}
	for i := range want {
		if c.Reloads[i] != want[i] {
			t.Fatalf("reloads: got %v, want %v", c.Reloads, want)
		}
	}
}

func TestReloadEmptyRejected(t *testing.T) {
	got := validateErr(t, `
account letsencrypt {
  ca letsencrypt
}
certificate c {
  account letsencrypt
  names c.example.com
  challenge http-01 {
    webroot /var/www
  }
  reload ""
}
`)
	if !strings.Contains(got, "reload command must not be empty") {
		t.Errorf("error: got %q", got)
	}
}

func TestGroupCertOverridesScalar(t *testing.T) {
	src := groupsBase + `
account zerossl {
  ca zerossl
  email admin@example.com
}
certificate example.com {
  groups web
  account zerossl
  names example.com
}
`
	c := resolveCert(t, src)
	if got, want := c.Account, "zerossl"; got != want {
		t.Errorf("account: got %q, want %q", got, want)
	}
}

func TestGroupNameTemplate(t *testing.T) {
	c := resolveCert(t, `
account letsencrypt {
  ca letsencrypt
}
certificate primary {
  account letsencrypt
  names www.example.com example.com
  challenge http-01 {
    webroot /var/www
  }
  deploy d {
    fullchain /etc/tls/{name}/fullchain.pem
  }
}
`)
	d := findDeploy(c, "d")
	if got, want := d.Fullchain, "/etc/tls/www.example.com/fullchain.pem"; got != want {
		t.Errorf("fullchain: got %q, want %q", got, want)
	}
}

func validateErr(t *testing.T, src string) string {
	t.Helper()
	cfg, err := Read(strings.NewReader(src))
	if err != nil {
		return err.Error()
	}
	if err := cfg.Validate(); err != nil {
		return err.Error()
	}
	return ""
}

func TestGroupErrors(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "unknown group",
			src: `
account letsencrypt {
  ca letsencrypt
}
certificate c {
  groups nope
  account letsencrypt
  names c.example.com
}
`,
			want: `unknown group "nope"`,
		},
		{
			name: "conflicting issuer",
			src: `
account a1 {
  ca letsencrypt
}
account a2 {
  ca letsencrypt
}
group g1 {
  account a1
}
group g2 {
  account a2
}
certificate c {
  groups g1 g2
  names c.example.com
  challenge http-01 {
    webroot /var/www
  }
}
`,
			want: "both set an issuer",
		},
		{
			name: "unknown placeholder",
			src: `
account letsencrypt {
  ca letsencrypt
}
certificate c {
  account letsencrypt
  names c.example.com
  challenge http-01 {
    webroot /var/www
  }
  deploy d {
    fullchain /etc/tls/{wat}/fullchain.pem
  }
}
`,
			want: `unknown template placeholder "{wat}"`,
		},
		{
			name: "duplicate group",
			src: `
group g {
  profile a
}
group g {
  profile b
}
account letsencrypt {
  ca letsencrypt
}
certificate c {
  account letsencrypt
  names c.example.com
  challenge http-01 {
    webroot /var/www
  }
}
`,
			want: `duplicate group "g"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := validateErr(t, tc.src)
			if !strings.Contains(got, tc.want) {
				t.Errorf("error: got %q, want substring %q", got, tc.want)
			}
		})
	}
}
