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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"testing"
	"time"

	"foundry.fsky.io/fsky/gibcert/internal/config"
)

type gibDNSTestRequest struct {
	Version  string          `json:"version"`
	ID       string          `json:"id"`
	Method   string          `json:"method"`
	Params   json.RawMessage `json:"params"`
	Provider *gibDNSProvider `json:"provider,omitempty"`
	Deadline string          `json:"deadline,omitempty"`
}

func TestDNSExecGibDNSProtocol(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "requests.log")
	secretPath := filepath.Join(dir, "token")
	if err := os.WriteFile(secretPath, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	credentialDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credentialDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(credentialDir, "credential"), []byte("credential-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	provider := gibDNSTestProvider("safe", logPath)
	provider.Fields["zone"] = []string{"example.com"}
	provider.Fields["api-url"] = []string{"https://dns.example/api"}
	provider.Fields["tags"] = []string{"one", "two"}
	provider.Secrets = []*config.Secret{
		{Name: "inline", Value: "inline-secret"},
		{Name: "file-token", File: secretPath},
		{Name: "from-env", Env: "GIBCERT_GIBDNS_TEST_SECRET"},
		{Name: "credential", SystemdCredential: "credential"},
	}
	t.Setenv("GIBCERT_GIBDNS_TEST_SECRET", "env-secret")
	t.Setenv("CREDENTIALS_DIRECTORY", credentialDir)
	// Neither arbitrary variables nor the legacy protocol reach the provider.
	t.Setenv("GIBCERT_EXEC_TEST_LEAK", "must-not-leak")
	t.Setenv("DNSREC_PROTOCOL", "1")

	d := &DNSExec{Provider: provider}
	cleanup, err := d.Present(context.Background(), Request{
		FQDN:       "_acme-challenge.example.com",
		Value:      "txt-value",
		Domain:     "example.com",
		Identifier: "*.example.com",
		Timeout:    time.Minute,
	})
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	cleanup()

	requests := readGibDNSTestRequests(t, logPath)
	if len(requests) != 3 {
		t.Fatalf("requests got %d, want capabilities, add, remove", len(requests))
	}
	for _, req := range requests {
		if req.Version != GibDNSProtocolVersion || req.ID == "" || req.Deadline == "" {
			t.Fatalf("invalid request envelope: %+v", req)
		}
	}
	if requests[0].Method != "capabilities" || requests[0].Provider == nil {
		t.Fatalf("capabilities request = %+v", requests[0])
	}
	if len(requests[0].Provider.Secrets) != 0 {
		t.Fatalf("capabilities request exposed secrets: %+v", requests[0].Provider.Secrets)
	}
	if got := requests[0].Provider.Config["api-url"]; got != "https://dns.example/api" {
		t.Fatalf("api-url config = %#v", got)
	}
	if got, ok := requests[0].Provider.Config["tags"].([]any); !ok || len(got) != 2 {
		t.Fatalf("tags config = %#v", requests[0].Provider.Config["tags"])
	}
	if _, ok := requests[0].Provider.Config["zone"]; ok {
		t.Fatal("zone was sent as provider config")
	}

	var add, remove gibDNSPatchParams
	if err := json.Unmarshal(requests[1].Params, &add); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(requests[2].Params, &remove); err != nil {
		t.Fatal(err)
	}
	if add.Key.Owner != "_acme-challenge.example.com." || add.Key.Type != "TXT" ||
		!slices.Equal(add.Add, []string{`"txt-value"`}) || add.Zone != "example.com." {
		t.Fatalf("add params = %+v", add)
	}
	if !slices.Equal(remove.Remove, add.Add) || remove.TTL != nil {
		t.Fatalf("remove params = %+v", remove)
	}
	wantSecrets := map[string]string{
		"inline":     "inline-secret",
		"file-token": "file-secret",
		"from-env":   "env-secret",
		"credential": "credential-secret",
	}
	if !mapsEqual(requests[1].Provider.Secrets, wantSecrets) {
		t.Fatalf("mutation secrets = %#v, want %#v", requests[1].Provider.Secrets, wantSecrets)
	}
}

func TestDNSExecPersistentRecordPatch(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "requests.log")
	d := &DNSExec{Provider: gibDNSTestProvider("safe", logPath)}
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

	requests := readGibDNSTestRequests(t, logPath)
	if len(requests) != 3 {
		t.Fatalf("requests got %d, want 3", len(requests))
	}
	var add, remove gibDNSPatchParams
	_ = json.Unmarshal(requests[1].Params, &add)
	_ = json.Unmarshal(requests[2].Params, &remove)
	if add.TTL == nil || *add.TTL != 3600 || add.TTLPolicy != "exact" {
		t.Fatalf("add TTL policy = %+v", add)
	}
	if remove.TTL != nil || remove.TTLPolicy != "" || len(remove.Remove) != 1 {
		t.Fatalf("remove params = %+v", remove)
	}
}

func TestDNSExecUsesGenericRDataForWildcardProvider(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "requests.log")
	d := &DNSExec{Provider: gibDNSTestProvider("wildcard", logPath)}
	if err := d.AddRecord(context.Background(), EditRequest{
		Owner: "_443._tcp.example.com", RecordType: "TLSA", RData: "3 1 1 abcdef", TTL: 300,
	}); err != nil {
		t.Fatalf("AddRecord: %v", err)
	}
	requests := readGibDNSTestRequests(t, logPath)
	if len(requests) != 2 {
		t.Fatalf("requests got %d, want capabilities and patch", len(requests))
	}
	var patch gibDNSPatchParams
	if err := json.Unmarshal(requests[1].Params, &patch); err != nil {
		t.Fatal(err)
	}
	if patch.Key.Type != "TYPE52" || !slices.Equal(patch.Add, []string{`\# 6 030101abcdef`}) {
		t.Fatalf("generic patch = %+v", patch)
	}
}

func TestDNSExecUsesConditionalPatchWhenRequired(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "requests.log")
	d := &DNSExec{Provider: gibDNSTestProvider("unsafe-cas", logPath)}
	if err := d.AddRecord(context.Background(), EditRequest{
		Owner: "_443._tcp.example.com", RecordType: "TLSA", RData: "3 1 1 abcdef", TTL: 300,
	}); err != nil {
		t.Fatalf("AddRecord: %v", err)
	}
	requests := readGibDNSTestRequests(t, logPath)
	methods := make([]string, len(requests))
	for i, req := range requests {
		methods[i] = req.Method
	}
	if !slices.Equal(methods, []string{"capabilities", "rrset.get", "rrset.patch"}) {
		t.Fatalf("methods = %v", methods)
	}
	var patch gibDNSPatchParams
	if err := json.Unmarshal(requests[2].Params, &patch); err != nil {
		t.Fatal(err)
	}
	if !patch.IfAbsent || patch.IfRevision != "" {
		t.Fatalf("conditional patch = %+v", patch)
	}
}

func TestDNSExecRejectsUnsafeProviderWithoutCAS(t *testing.T) {
	d := &DNSExec{Provider: gibDNSTestProvider("unsafe", filepath.Join(t.TempDir(), "requests.log"))}
	err := d.AddRecord(context.Background(), EditRequest{
		Owner: "_443._tcp.example.com", RecordType: "TLSA", RData: "3 1 1 abcdef", TTL: 300,
	})
	if err == nil || !strings.Contains(err.Error(), "cannot patch shared RRsets safely") {
		t.Fatalf("AddRecord error = %v", err)
	}
}

func TestDNSExecProviderErrorsRedactSecrets(t *testing.T) {
	provider := gibDNSTestProvider("provider-error", filepath.Join(t.TempDir(), "requests.log"))
	provider.Secrets = []*config.Secret{{Name: "token", Value: "supersecret"}}
	d := &DNSExec{Provider: provider}
	_, err := d.Present(context.Background(), Request{FQDN: "_acme-challenge.example.com", Value: "token"})
	if err == nil {
		t.Fatal("Present succeeded")
	}
	if strings.Contains(err.Error(), "supersecret") || !strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatalf("error was not redacted: %v", err)
	}
	var providerErr *GibDNSError
	if !errors.As(err, &providerErr) || providerErr.Code != "unauthorized" {
		t.Fatalf("error type = %T, value = %v", err, err)
	}
}

func TestDNSExecRejectsProtocolViolations(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want string
	}{
		{mode: "invalid-json", want: "invalid JSON"},
		{mode: "duplicate", want: "duplicate JSON member"},
		{mode: "wrong-version", want: "response version"},
		{mode: "oversized", want: "stdout exceeds"},
		{mode: "missing-error-message", want: "code, message, and retryable are required"},
		{mode: "invalid-error-details", want: "details: want JSON object"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			d := &DNSExec{Provider: gibDNSTestProvider(tc.mode, filepath.Join(t.TempDir(), "requests.log"))}
			_, err := d.Capabilities(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Capabilities error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestDNSExecCapabilitiesAreMandatory(t *testing.T) {
	d := &DNSExec{Provider: gibDNSTestProvider("capability-error", filepath.Join(t.TempDir(), "requests.log"))}
	err := EnsureEditorSupports(context.Background(), d, "TLSA", "rrset.patch")
	if err == nil || !strings.Contains(err.Error(), "unsupported_method") {
		t.Fatalf("EnsureEditorSupports error = %v", err)
	}
}

func TestDNSExecCleanupUsesTimeout(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "requests.log")
	var out bytes.Buffer
	d := &DNSExec{Provider: gibDNSTestProvider("slow-cleanup", logPath), Out: &out}
	d.gibDNSClient().caps = &GibDNSCapabilities{
		Methods:     []string{"capabilities", "rrset.patch"},
		RecordTypes: []string{"TXT"},
		Features: gibDNSFeatures{
			ZoneDiscovery:       true,
			ConcurrentSafePatch: true,
			Preconditions:       map[string][]string{},
		},
	}
	timeout := 200 * time.Millisecond
	maxElapsed := time.Second
	if raceDetectorEnabled() {
		// Race-instrumented helper processes pause for about a second at exit.
		timeout = 2 * time.Second
		maxElapsed = 4 * time.Second
	}
	cleanup, err := d.Present(context.Background(), Request{
		FQDN: "_acme-challenge.example.com", Value: "txt-value", Timeout: timeout,
	})
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	start := time.Now()
	cleanup()
	if elapsed := time.Since(start); elapsed > maxElapsed {
		t.Fatalf("cleanup took %s", elapsed)
	}
	if !strings.Contains(out.String(), "warning: dns exec cleanup failed") {
		t.Fatalf("cleanup warning missing: %s", out.String())
	}
}

func raceDetectorEnabled() bool {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return false
	}
	for _, setting := range info.Settings {
		if setting.Key == "-race" {
			return setting.Value == "true"
		}
	}
	return false
}

func TestGibDNSTXTAndSemanticRData(t *testing.T) {
	value := strings.Repeat("a", 255) + `"\\` + "\x01"
	presentation := quoteGibDNSTXT(value)
	wire, err := gibDNSSemanticRData("TXT", presentation)
	if err != nil {
		t.Fatalf("parse quoted TXT: %v", err)
	}
	if len(wire) != len(value)+2 {
		t.Fatalf("wire length = %d, want %d", len(wire), len(value)+2)
	}
	a, err := gibDNSSemanticRData("TLSA", "3 1 1 ABCDEF")
	if err != nil {
		t.Fatal(err)
	}
	b, err := gibDNSSemanticRData("TYPE52", `\# 6 030101abcdef`)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("TLSA semantic values differ: %x != %x", a, b)
	}
}

func TestGibDNSRecordTypeValidation(t *testing.T) {
	for _, recordType := range []string{"TXT", "TYPE16", "NXNAME", "TYPE128", "UNECE", "TYPE65280"} {
		if _, err := gibDNSTypeCode(recordType); err != nil {
			t.Errorf("valid record type %q: %v", recordType, err)
		}
	}
	for _, recordType := range []string{"OPT", "TYPE41", "UINFO", "TYPE100", "TYPE129", "ANY", "TYPE61440"} {
		if _, err := gibDNSTypeCode(recordType); err == nil {
			t.Errorf("invalid record type %q was accepted", recordType)
		}
	}
}

func TestValidateGibDNSMutationWarnings(t *testing.T) {
	code := "ttl_adjusted"
	message := "provider selected its minimum TTL"
	ttl := 300
	exists := true
	changed := true
	result := gibDNSMutationResult{
		Changed: &changed,
		Exists:  &exists,
		Zone:    "example.com.",
		RRSet: &gibDNSRRSet{
			Owner: "_443._tcp.example.com.",
			Type:  "TLSA",
			TTL:   &ttl,
			RData: []string{"3 1 1 abcdef"},
		},
		Warnings: []gibDNSWarning{{
			Code:    &code,
			Message: &message,
			Details: json.RawMessage(`{"requested_ttl":60,"effective_ttl":300}`),
		}},
	}
	params := gibDNSPatchParams{
		Key: gibDNSKey{Owner: "_443._tcp.example.com.", Type: "TLSA"},
		Add: []string{"3 1 1 abcdef"},
	}
	if err := validateGibDNSMutationResult(result, params, GibDNSCapabilities{}); err != nil {
		t.Fatalf("valid ttl_adjusted warning: %v", err)
	}

	result.Warnings[0].Details = json.RawMessage(`[]`)
	if err := validateGibDNSMutationResult(result, params, GibDNSCapabilities{}); err == nil ||
		!strings.Contains(err.Error(), "want JSON object") {
		t.Fatalf("invalid warning details error = %v", err)
	}
}

func TestDNSExecMissingProviderAndCommandErrors(t *testing.T) {
	if _, err := (&DNSExec{}).Capabilities(context.Background()); err == nil || !strings.Contains(err.Error(), "missing provider") {
		t.Fatalf("missing provider error = %v", err)
	}
	d := &DNSExec{Provider: &config.Provider{Name: "exec-test", Fields: map[string][]string{}}}
	if _, err := d.Capabilities(context.Background()); err == nil || !strings.Contains(err.Error(), "requires command") {
		t.Fatalf("missing command error = %v", err)
	}
}

// TestGibDNSProviderProcess is re-executed as the external provider by tests
// above. Arguments after -- select its behavior and request log.
func TestGibDNSProviderProcess(t *testing.T) {
	separator := slices.Index(os.Args, "--")
	if separator < 0 {
		return
	}
	args := os.Args[separator+1:]
	if len(args) != 2 {
		os.Exit(97)
	}
	os.Exit(runGibDNSTestProvider(args[0], args[1]))
}

func runGibDNSTestProvider(mode, logPath string) int {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		return 2
	}
	if err := appendGibDNSTestLog(logPath, raw); err != nil {
		return 2
	}
	if os.Getenv("DNSREC_PROTOCOL") != "" || os.Getenv("GIBCERT_EXEC_TEST_LEAK") != "" {
		fmt.Fprint(os.Stderr, "legacy or unrelated environment leaked")
		return 2
	}
	if mode == "oversized" {
		_, _ = os.Stdout.Write(bytes.Repeat([]byte("x"), gibDNSOutputLimit+1))
		return 0
	}
	if mode == "invalid-json" {
		fmt.Fprint(os.Stdout, "not json")
		return 0
	}
	var req gibDNSTestRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return 2
	}
	if mode == "duplicate" {
		fmt.Fprintf(os.Stdout, `{"version":%q,"version":%q,"id":%q,"ok":true,"result":{}}`, GibDNSProtocolVersion, GibDNSProtocolVersion, req.ID)
		return 0
	}
	if mode == "wrong-version" {
		writeGibDNSTestJSON(map[string]any{"version": "gibdns/draft-02", "id": req.ID, "ok": true, "result": map[string]any{}})
		return 0
	}
	if req.Version != GibDNSProtocolVersion {
		return writeGibDNSTestError(req.ID, "unsupported_version", "wrong version", false)
	}
	if mode == "missing-error-message" {
		writeGibDNSTestJSON(map[string]any{
			"version": GibDNSProtocolVersion,
			"id":      req.ID,
			"ok":      false,
			"error":   map[string]any{"code": "temporary", "retryable": true},
		})
		return 1
	}
	if mode == "invalid-error-details" {
		writeGibDNSTestJSON(map[string]any{
			"version": GibDNSProtocolVersion,
			"id":      req.ID,
			"ok":      false,
			"error": map[string]any{
				"code": "temporary", "message": "try again", "retryable": true, "details": []any{},
			},
		})
		return 1
	}
	if req.Method == "capabilities" {
		if mode == "capability-error" {
			return writeGibDNSTestError(req.ID, "unsupported_method", "capabilities unavailable", false)
		}
		concurrentSafe := mode != "unsafe" && mode != "unsafe-cas"
		methods := []string{"capabilities", "rrset.patch"}
		preconditions := map[string][]string{}
		if mode == "unsafe-cas" {
			methods = append(methods, "rrset.get")
			preconditions["rrset.patch"] = []string{"if_revision", "if_absent"}
		}
		result := map[string]any{
			"provider":     map[string]any{"name": "test-provider", "version": "1"},
			"methods":      methods,
			"record_types": []string{"TXT", "TLSA"},
			"features": map[string]any{
				"zone_discovery":        true,
				"concurrent_safe_patch": concurrentSafe,
				"preconditions":         preconditions,
			},
		}
		if mode == "wildcard" {
			result["record_types"] = []string{"*"}
		}
		return writeGibDNSTestSuccess(req.ID, result)
	}
	if mode == "provider-error" {
		fmt.Fprint(os.Stderr, "diagnostic contains supersecret")
		return writeGibDNSTestError(req.ID, "unauthorized", "supersecret was rejected", false)
	}
	if req.Method == "rrset.get" {
		var params gibDNSGetParams
		if json.Unmarshal(req.Params, &params) != nil {
			return 2
		}
		return writeGibDNSTestSuccess(req.ID, map[string]any{
			"exists": false,
			"zone":   testEffectiveZone(params.Zone),
		})
	}
	if req.Method != "rrset.patch" {
		return writeGibDNSTestError(req.ID, "unsupported_method", "unsupported", false)
	}
	var params gibDNSPatchParams
	if json.Unmarshal(req.Params, &params) != nil {
		return 2
	}
	if mode == "unsafe-cas" && !params.IfAbsent && params.IfRevision == "" {
		return writeGibDNSTestError(req.ID, "invalid_request", "precondition required", false)
	}
	if mode == "slow-cleanup" && len(params.Remove) != 0 {
		time.Sleep(5 * time.Second)
		return 2
	}
	if len(params.Add) == 0 {
		return writeGibDNSTestSuccess(req.ID, map[string]any{
			"changed": true,
			"exists":  false,
			"zone":    testEffectiveZone(params.Zone),
		})
	}
	ttl := 60
	if params.TTL != nil {
		ttl = *params.TTL
	}
	result := map[string]any{
		"changed": true,
		"exists":  true,
		"zone":    testEffectiveZone(params.Zone),
		"rrset": map[string]any{
			"owner": params.Key.Owner,
			"type":  params.Key.Type,
			"ttl":   ttl,
			"rdata": params.Add,
		},
	}
	if mode == "unsafe-cas" {
		result["revision"] = "revision-1"
	}
	return writeGibDNSTestSuccess(req.ID, result)
}

func gibDNSTestProvider(mode, logPath string) *config.Provider {
	return &config.Provider{
		Name:   "exec-test",
		Type:   "dns",
		Driver: "exec",
		Fields: map[string][]string{
			"command": {os.Args[0], "-test.run=TestGibDNSProviderProcess", "--", mode, logPath},
		},
	}
}

func appendGibDNSTestLog(path string, raw []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(raw); err != nil {
		return err
	}
	_, err = f.Write([]byte("\n"))
	return err
}

func readGibDNSTestRequests(t *testing.T, path string) []gibDNSTestRequest {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	requests := make([]gibDNSTestRequest, len(lines))
	for i, line := range lines {
		if err := json.Unmarshal(line, &requests[i]); err != nil {
			t.Fatalf("decode request %d: %v", i, err)
		}
	}
	return requests
}

func writeGibDNSTestSuccess(id string, result any) int {
	writeGibDNSTestJSON(map[string]any{
		"version": GibDNSProtocolVersion,
		"id":      id,
		"ok":      true,
		"result":  result,
	})
	return 0
}

func writeGibDNSTestError(id, code, message string, retryable bool) int {
	writeGibDNSTestJSON(map[string]any{
		"version": GibDNSProtocolVersion,
		"id":      id,
		"ok":      false,
		"error": map[string]any{
			"code": code, "message": message, "retryable": retryable,
		},
	})
	return 1
}

func writeGibDNSTestJSON(value any) {
	_ = json.NewEncoder(os.Stdout).Encode(value)
}

func testEffectiveZone(zone string) string {
	if zone != "" {
		return zone
	}
	return "example.com."
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}
