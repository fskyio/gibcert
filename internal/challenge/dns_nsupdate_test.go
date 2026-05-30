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

package challenge

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"foundry.fsky.io/fsky/gibcert/internal/config"
)

func TestDNSNSUpdateProtocol(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "nsupdate.log")
	script := filepath.Join(dir, "nsupdate-stub.sh")
	body := `#!/bin/sh
echo "args=$*" >> "$LOG"
cat >> "$LOG"
echo "---" >> "$LOG"
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LOG", logPath)

	provider := &config.Provider{
		Name:   "rfc2136-test",
		Type:   "dns",
		Driver: "rfc2136",
		Fields: map[string][]string{
			"command": {script},
			"server":  {"192.0.2.53"},
			"zone":    {"example.com"},
		},
		Secrets: []*config.Secret{{Name: "tsig-key", File: "/tmp/Kexample.key"}},
	}

	d := &DNSNSUpdate{Provider: provider}
	cleanup, err := d.Present(context.Background(), Request{FQDN: "_acme-challenge.example.com", Value: "txt-value"})
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	cleanup()

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	for _, want := range []string{
		"args=-k /tmp/Kexample.key",
		"server 192.0.2.53",
		"zone example.com.",
		"update add _acme-challenge.example.com. 60 TXT \"txt-value\"",
		"update delete _acme-challenge.example.com. TXT \"txt-value\"",
		"send",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("log missing %q:\n%s", want, got)
		}
	}
}
