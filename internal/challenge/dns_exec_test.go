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
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"foundry.fsky.io/fsky/gibcert/internal/config"
)

func TestDNSExecProtocol(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls.log")
	script := filepath.Join(dir, "provider.sh")
	body := `#!/bin/sh
{
  echo "argv=$1"
  echo "protocol=$DNSREC_PROTOCOL"
  echo "op=$DNSREC_OPERATION"
  echo "type=$DNSREC_RECORD_TYPE"
  echo "owner=$DNSREC_RECORD_OWNER"
  echo "rdata=$DNSREC_RECORD_RDATA"
  echo "domain=$DNSREC_DOMAIN"
  echo "identifier=$DNSREC_IDENTIFIER"
  echo "timeout=$DNSREC_TIMEOUT"
  echo "secret_file=$DNSREC_SECRET_API_TOKEN_FILE"
  echo "secret_value=$DNSREC_SECRET_INLINE"
  echo "secret_env=$DNSREC_SECRET_FROM_ENV"
  echo "secret_command=$DNSREC_SECRET_FROM_COMMAND"
  echo "secret_credential_file=$DNSREC_SECRET_FROM_CREDENTIAL_FILE"
  echo "---"
} >> "$LOG"
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	credentialDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credentialDir, 0o755); err != nil {
		t.Fatal(err)
	}

	provider := &config.Provider{
		Name:   "exec-test",
		Type:   "dns",
		Driver: "exec",
		Fields: map[string][]string{
			"command": {script},
		},
		Secrets: []*config.Secret{
			{Name: "api-token", File: "/tmp/token"},
			{Name: "inline", Value: "secret"},
			{Name: "from-env", Env: "GIBCERT_EXEC_TEST_SECRET"},
			{Name: "from-command", Command: []string{"sh", "-c", "printf command-secret\\n"}},
			{Name: "from-credential", SystemdCredential: "dns-api-key"},
		},
	}
	t.Setenv("LOG", logPath)
	t.Setenv("GIBCERT_EXEC_TEST_SECRET", "env-secret")
	t.Setenv("CREDENTIALS_DIRECTORY", credentialDir)

	d := &DNSExec{Provider: provider}
	cleanup, err := d.Present(context.Background(), Request{
		FQDN:       "_acme-challenge.example.com",
		Value:      "txt-value",
		Domain:     "example.com",
		Identifier: "*.example.com",
		Timeout:    2 * time.Minute,
	})
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
		"argv=present",
		"protocol=1",
		"op=present",
		"argv=cleanup",
		"op=cleanup",
		"type=TXT",
		"owner=_acme-challenge.example.com.",
		"rdata=txt-value",
		"domain=example.com",
		"identifier=*.example.com",
		"timeout=120",
		"secret_file=/tmp/token",
		"secret_value=secret",
		"secret_env=env-secret",
		"secret_command=command-secret",
		"secret_credential_file=" + filepath.Join(credentialDir, "dns-api-key"),
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("log missing %q:\n%s", want, got)
		}
	}
}

func TestDNSExecEditRecord(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls.log")
	script := filepath.Join(dir, "provider.sh")
	body := `#!/bin/sh
{
  echo "argv=$1"
  echo "op=$DNSREC_OPERATION"
  echo "type=$DNSREC_RECORD_TYPE"
  echo "owner=$DNSREC_RECORD_OWNER"
  echo "rdata=$DNSREC_RECORD_RDATA"
  echo "ttl=$DNSREC_RECORD_TTL"
  echo "tlsa_usage=$DNSREC_TLSA_USAGE"
  echo "---"
} >> "$LOG"
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}

	provider := &config.Provider{
		Name:   "exec-test",
		Type:   "dns",
		Driver: "exec",
		Fields: map[string][]string{"command": {script}},
	}
	t.Setenv("LOG", logPath)

	d := &DNSExec{Provider: provider}
	req := EditRequest{
		Owner:      "_443._tcp.example.com",
		RecordType: "TLSA",
		RData:      "3 1 1 abcdef",
		TTL:        3600,
	}
	if err := d.AddRecord(context.Background(), req); err != nil {
		t.Fatalf("AddRecord: %v", err)
	}
	if err := d.RemoveRecord(context.Background(), req); err != nil {
		t.Fatalf("RemoveRecord: %v", err)
	}

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	for _, want := range []string{
		"argv=add-record",
		"op=add-record",
		"argv=remove-record",
		"op=remove-record",
		"type=TLSA",
		"owner=_443._tcp.example.com.",
		"rdata=3 1 1 abcdef",
		"ttl=3600",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("log missing %q:\n%s", want, got)
		}
	}
	// The unified protocol carries canonical RDATA only; no per-type vars.
	if strings.Contains(got, "tlsa_usage=3") {
		t.Fatalf("unexpected per-type TLSA variable in environment:\n%s", got)
	}
}

func TestDNSExecCapabilities(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "provider.sh")
	body := `#!/bin/sh
case "$DNSREC_OPERATION" in
  capabilities)
    echo "protocol 1"
    echo "binding env"
    echo "operations present cleanup add-record remove-record"
    echo "types TXT TLSA"
    ;;
  *)
    exit 0
    ;;
esac
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	provider := &config.Provider{
		Name:   "exec-test",
		Type:   "dns",
		Driver: "exec",
		Fields: map[string][]string{"command": {script}},
	}
	d := &DNSExec{Provider: provider}

	caps, err := d.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	if !caps.Reported {
		t.Fatal("expected Reported capabilities")
	}
	if caps.Protocol != "1" {
		t.Fatalf("protocol = %q, want 1", caps.Protocol)
	}
	if !caps.Supports("add-record") || !caps.SupportsType("TLSA") {
		t.Fatalf("expected add-record/TLSA support, got %+v", caps)
	}

	// A TLSA-capable provider passes the fail-fast check.
	if err := EnsureEditorSupports(context.Background(), d, "TLSA", "add-record", "remove-record"); err != nil {
		t.Fatalf("EnsureEditorSupports: %v", err)
	}
	// An unadvertised record type is rejected before any edit runs.
	if err := EnsureEditorSupports(context.Background(), d, "HTTPS", "add-record"); err == nil {
		t.Fatal("expected error for unsupported HTTPS record type")
	}
}

func TestDNSExecCapabilitiesUnsupportedIsAdvisory(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "provider.sh")
	// A provider that does not implement capabilities exits non-zero for it.
	body := `#!/bin/sh
case "$DNSREC_OPERATION" in
  capabilities) exit 2 ;;
  *) exit 0 ;;
esac
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	provider := &config.Provider{
		Name:   "exec-test",
		Type:   "dns",
		Driver: "exec",
		Fields: map[string][]string{"command": {script}},
	}
	d := &DNSExec{Provider: provider}

	if _, err := d.Capabilities(context.Background()); err == nil {
		t.Fatal("expected error probing a provider without capabilities")
	}
	// Providers that cannot report capabilities are allowed through.
	if err := EnsureEditorSupports(context.Background(), d, "TLSA", "add-record"); err != nil {
		t.Fatalf("EnsureEditorSupports should be advisory, got: %v", err)
	}
}

func TestDNSExecUsesOperationSpecificShellCommand(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "present.log")
	t.Setenv("GIBCERT_TEST_PRESENT_LOG", logPath)
	provider := &config.Provider{
		Name:   "exec-test",
		Type:   "dns",
		Driver: "exec",
		Fields: map[string][]string{
			"present": {`printf '%s|%s|%s' "$DNSREC_OPERATION" "$DNSREC_RECORD_OWNER" "$DNSREC_RECORD_RDATA" > "$GIBCERT_TEST_PRESENT_LOG"`},
		},
	}
	d := &DNSExec{Provider: provider}

	if _, err := d.Present(context.Background(), Request{
		FQDN:  "_acme-challenge.example.com",
		Value: "txt-value",
	}); err != nil {
		t.Fatalf("Present: %v", err)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(raw); got != "present|_acme-challenge.example.com.|txt-value" {
		t.Fatalf("operation shell command env got %q", got)
	}
}

func TestDNSExecFailureIncludesOutput(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "provider.sh")
	body := `#!/bin/sh
echo "provider stdout"
echo "provider stderr" >&2
exit 7
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}

	provider := &config.Provider{
		Name:   "exec-test",
		Type:   "dns",
		Driver: "exec",
		Fields: map[string][]string{
			"command": {script},
		},
	}
	d := &DNSExec{Provider: provider, Out: io.Discard}
	_, err := d.Present(context.Background(), Request{
		FQDN:    "_acme-challenge.example.com",
		Value:   "txt-value",
		Domain:  "example.com",
		Timeout: time.Minute,
	})
	if err == nil {
		t.Fatal("Present succeeded, want error")
	}
	got := err.Error()
	for _, want := range []string{"exit status 7", "provider stdout", "provider stderr"} {
		if !strings.Contains(got, want) {
			t.Fatalf("error missing %q:\n%s", want, got)
		}
	}
}

func TestDNSExecFailureOutputIsLimited(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "provider.sh")
	body := `#!/bin/sh
yes x | head -c 40000
exit 9
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	provider := &config.Provider{
		Name:   "exec-test",
		Type:   "dns",
		Driver: "exec",
		Fields: map[string][]string{"command": {script}},
	}
	d := &DNSExec{Provider: provider}

	_, err := d.Present(context.Background(), Request{FQDN: "_acme-challenge.example.com", Value: "txt"})
	if err == nil {
		t.Fatal("Present succeeded, want error")
	}
	got := err.Error()
	if !strings.Contains(got, "... output truncated ...") {
		t.Fatalf("error missing truncation marker:\n%s", got)
	}
	if len(got) > dnsExecOutputLimit+1024 {
		t.Fatalf("error length got %d, want bounded near output limit", len(got))
	}
}

func TestDNSExecMissingProviderAndCommandErrors(t *testing.T) {
	d := &DNSExec{}
	if _, err := d.Present(context.Background(), Request{}); err == nil || !strings.Contains(err.Error(), "missing provider") {
		t.Fatalf("missing provider error = %v", err)
	}
	d.Provider = &config.Provider{Name: "exec-test", Fields: map[string][]string{}}
	if _, err := d.Present(context.Background(), Request{}); err == nil || !strings.Contains(err.Error(), "requires command or present field") {
		t.Fatalf("missing command error = %v", err)
	}
}

func TestDNSExecCleanupUsesTimeout(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "provider.sh")
	body := `#!/bin/sh
case "$1" in
  present)
    exit 0
    ;;
  cleanup)
    sleep 5
    ;;
esac
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}

	provider := &config.Provider{
		Name:   "exec-test",
		Type:   "dns",
		Driver: "exec",
		Fields: map[string][]string{
			"command": {script},
		},
	}
	var out bytes.Buffer
	d := &DNSExec{Provider: provider, Out: &out}
	cleanup, err := d.Present(context.Background(), Request{
		FQDN:    "_acme-challenge.example.com",
		Value:   "txt-value",
		Domain:  "example.com",
		Timeout: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Present: %v", err)
	}

	start := time.Now()
	cleanup()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("cleanup took %s, want bounded by timeout", elapsed)
	}
	if got := out.String(); !strings.Contains(got, "warning: dns exec cleanup failed") {
		t.Fatalf("cleanup warning missing:\n%s", got)
	}
}
