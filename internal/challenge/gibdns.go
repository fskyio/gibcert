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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"foundry.fsky.io/fsky/gibcert/internal/config"
)

const (
	GibDNSProtocolVersion   = "gibdns/draft-01"
	gibDNSOutputLimit       = 128 * 1024
	gibDNSDiagnosticLimit   = 32 * 1024
	gibDNSOperationTimeout  = 2 * time.Minute
	gibDNSCapabilityTimeout = 30 * time.Second
	gibDNSConflictAttempts  = 5
)

type gibDNSClient struct {
	provider *config.Provider
	out      io.Writer

	mu   sync.Mutex
	caps *GibDNSCapabilities
}

type gibDNSRequest struct {
	Version  string            `json:"version"`
	ID       string            `json:"id"`
	Method   string            `json:"method"`
	Params   any               `json:"params"`
	Provider *gibDNSProvider   `json:"provider,omitempty"`
	Deadline string            `json:"deadline,omitempty"`
	Context  map[string]string `json:"context,omitempty"`
}

type gibDNSProvider struct {
	Config  map[string]any    `json:"config,omitempty"`
	Secrets map[string]string `json:"secrets,omitempty"`
}

type gibDNSKey struct {
	Owner string `json:"owner"`
	Type  string `json:"type"`
}

type gibDNSPatchParams struct {
	Key        gibDNSKey `json:"key"`
	Add        []string  `json:"add,omitempty"`
	Remove     []string  `json:"remove,omitempty"`
	TTL        *int      `json:"ttl,omitempty"`
	Zone       string    `json:"zone,omitempty"`
	IfRevision string    `json:"if_revision,omitempty"`
	IfAbsent   bool      `json:"if_absent,omitempty"`
	TTLPolicy  string    `json:"ttl_policy,omitempty"`
}

type gibDNSGetParams struct {
	Key  gibDNSKey `json:"key"`
	Zone string    `json:"zone,omitempty"`
}

type gibDNSWireResponse struct {
	Version string          `json:"version"`
	ID      json.RawMessage `json:"id"`
	OK      *bool           `json:"ok"`
	Result  json.RawMessage `json:"result"`
	Error   json.RawMessage `json:"error"`
}

type gibDNSErrorObject struct {
	Code              *string         `json:"code"`
	Message           *string         `json:"message"`
	Retryable         *bool           `json:"retryable"`
	RetryAfterSeconds *int64          `json:"retry_after_seconds"`
	Details           json.RawMessage `json:"details"`
}

type GibDNSError struct {
	Code              string
	Message           string
	Retryable         bool
	RetryAfterSeconds *int64
	Diagnostic        string
}

func (e *GibDNSError) Error() string {
	if e == nil {
		return "gibdns provider error"
	}
	msg := "gibdns provider: " + e.Code
	if e.Message != "" {
		msg += ": " + e.Message
	}
	if e.Diagnostic != "" {
		msg += "\ndiagnostic:\n" + e.Diagnostic
	}
	return msg
}

type GibDNSCapabilities struct {
	Provider    gibDNSProviderInfo
	Methods     []string
	RecordTypes []string
	Features    gibDNSFeatures
	Constraints *gibDNSConstraints
}

type gibDNSCapabilitiesWire struct {
	Provider      gibDNSProviderInfo   `json:"provider"`
	Methods       []string             `json:"methods"`
	RecordTypes   *[]string            `json:"record_types"`
	Features      gibDNSFeaturesWire   `json:"features"`
	Constraints   *gibDNSConstraints   `json:"constraints,omitempty"`
	Configuration *gibDNSConfiguration `json:"configuration,omitempty"`
}

type gibDNSProviderInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type gibDNSFeatures struct {
	ZoneDiscovery       bool
	ConcurrentSafePatch bool
	Preconditions       map[string][]string
}

type gibDNSFeaturesWire struct {
	ZoneDiscovery       *bool               `json:"zone_discovery"`
	ConcurrentSafePatch *bool               `json:"concurrent_safe_patch,omitempty"`
	Preconditions       map[string][]string `json:"preconditions"`
}

type gibDNSConstraints struct {
	MinimumTTL *int `json:"minimum_ttl,omitempty"`
	MaximumTTL *int `json:"maximum_ttl,omitempty"`
}

type gibDNSConfiguration struct {
	Fields  []gibDNSFieldDescriptor  `json:"fields,omitempty"`
	Secrets []gibDNSSecretDescriptor `json:"secrets,omitempty"`
}

type gibDNSFieldDescriptor struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Required    *bool  `json:"required"`
	Description string `json:"description,omitempty"`
}

type gibDNSSecretDescriptor struct {
	Name        string `json:"name"`
	Required    *bool  `json:"required"`
	Description string `json:"description,omitempty"`
}

type gibDNSRRSet struct {
	Owner string   `json:"owner"`
	Type  string   `json:"type"`
	TTL   *int     `json:"ttl"`
	RData []string `json:"rdata"`
}

type gibDNSGetResult struct {
	Exists   *bool        `json:"exists"`
	Zone     string       `json:"zone"`
	RRSet    *gibDNSRRSet `json:"rrset,omitempty"`
	Revision *string      `json:"revision,omitempty"`
}

type gibDNSMutationResult struct {
	Changed  *bool           `json:"changed"`
	Exists   *bool           `json:"exists"`
	Zone     string          `json:"zone"`
	RRSet    *gibDNSRRSet    `json:"rrset,omitempty"`
	Revision *string         `json:"revision,omitempty"`
	Warnings []gibDNSWarning `json:"warnings,omitempty"`
}

type gibDNSWarning struct {
	Code    *string         `json:"code"`
	Message *string         `json:"message"`
	Details json.RawMessage `json:"details,omitempty"`
}

type gibDNSTTLAdjustedDetails struct {
	RequestedTTL *int64 `json:"requested_ttl"`
	EffectiveTTL *int64 `json:"effective_ttl"`
}

func (c GibDNSCapabilities) Supports(method string) bool {
	return slices.Contains(c.Methods, method)
}

func (c GibDNSCapabilities) SupportsType(recordType string) bool {
	want, err := gibDNSTypeCode(recordType)
	if err != nil {
		return false
	}
	for _, got := range c.RecordTypes {
		if got == "*" {
			return true
		}
		code, err := gibDNSTypeCode(got)
		if err == nil && code == want {
			return true
		}
	}
	return false
}

func (c GibDNSCapabilities) SupportsPrecondition(method, precondition string) bool {
	return slices.Contains(c.Features.Preconditions[method], precondition)
}

func (c *gibDNSClient) capabilities(ctx context.Context) (GibDNSCapabilities, error) {
	c.mu.Lock()
	if c.caps != nil {
		caps := *c.caps
		c.mu.Unlock()
		return caps, nil
	}
	c.mu.Unlock()

	cctx, cancel := contextWithTimeout(ctx, gibDNSCapabilityTimeout)
	defer cancel()
	var wire gibDNSCapabilitiesWire
	if err := c.invoke(cctx, "capabilities", struct{}{}, false, nil, &wire); err != nil {
		return GibDNSCapabilities{}, fmt.Errorf("gibdns capabilities: %w", err)
	}
	caps, err := validateGibDNSCapabilities(wire)
	if err != nil {
		return GibDNSCapabilities{}, fmt.Errorf("gibdns capabilities response: %w", err)
	}
	c.mu.Lock()
	if c.caps == nil {
		c.caps = &caps
	}
	caps = *c.caps
	c.mu.Unlock()
	return caps, nil
}

func (c *gibDNSClient) patch(ctx context.Context, params gibDNSPatchParams) error {
	if err := validateGibDNSPatchParams(params); err != nil {
		return err
	}
	caps, err := c.capabilities(ctx)
	if err != nil {
		return err
	}
	if !caps.Supports("rrset.patch") {
		return fmt.Errorf("gibdns provider does not support rrset.patch")
	}
	params, err = adaptGibDNSPatch(params, caps)
	if err != nil {
		return err
	}
	if !caps.Features.ZoneDiscovery && params.Zone == "" {
		return fmt.Errorf("gibdns provider requires an explicit zone")
	}

	if caps.Features.ConcurrentSafePatch {
		return c.invokePatch(ctx, params, caps)
	}
	if !caps.Supports("rrset.get") ||
		!caps.SupportsPrecondition("rrset.patch", "if_revision") ||
		!caps.SupportsPrecondition("rrset.patch", "if_absent") {
		return fmt.Errorf("gibdns provider cannot patch shared RRsets safely: concurrent_safe_patch is false and rrset.get with if_revision/if_absent is unavailable")
	}

	for attempt := 0; attempt < gibDNSConflictAttempts; attempt++ {
		state, err := c.get(ctx, params.Key, params.Zone, caps)
		if err != nil {
			return err
		}
		holds, err := gibDNSPatchPostcondition(state, params)
		if err != nil {
			return err
		}
		if holds {
			return nil
		}
		conditional := params
		if *state.Exists {
			if state.Revision == nil || *state.Revision == "" {
				return fmt.Errorf("gibdns protocol violation: rrset.get omitted revision required by advertised preconditions")
			}
			conditional.IfRevision = *state.Revision
		} else {
			conditional.IfAbsent = true
		}
		err = c.invokePatch(ctx, conditional, caps)
		var providerErr *GibDNSError
		if errors.As(err, &providerErr) && providerErr.Code == "conflict" {
			continue
		}
		return err
	}
	return fmt.Errorf("gibdns patch conflicted %d times", gibDNSConflictAttempts)
}

func adaptGibDNSPatch(params gibDNSPatchParams, caps GibDNSCapabilities) (gibDNSPatchParams, error) {
	code, err := gibDNSTypeCode(params.Key.Type)
	if err != nil {
		return gibDNSPatchParams{}, err
	}
	for _, advertised := range caps.RecordTypes {
		if advertised == "*" {
			return genericGibDNSPatch(params, fmt.Sprintf("TYPE%d", code))
		}
		advertisedCode, err := gibDNSTypeCode(advertised)
		if err != nil || advertisedCode != code {
			continue
		}
		if strings.HasPrefix(advertised, "TYPE") {
			return genericGibDNSPatch(params, advertised)
		}
		return params, nil
	}
	return gibDNSPatchParams{}, fmt.Errorf("gibdns provider does not support %s records", params.Key.Type)
}

func genericGibDNSPatch(params gibDNSPatchParams, recordType string) (gibDNSPatchParams, error) {
	originalType := params.Key.Type
	convert := func(values []string) ([]string, error) {
		converted := make([]string, len(values))
		for i, value := range values {
			wire, err := gibDNSSemanticRData(originalType, value)
			if err != nil {
				return nil, err
			}
			if len(wire) == 0 {
				converted[i] = `\# 0`
			} else {
				converted[i] = fmt.Sprintf(`\# %d %x`, len(wire), wire)
			}
		}
		return converted, nil
	}
	add, err := convert(params.Add)
	if err != nil {
		return gibDNSPatchParams{}, err
	}
	remove, err := convert(params.Remove)
	if err != nil {
		return gibDNSPatchParams{}, err
	}
	params.Key.Type = recordType
	params.Add = add
	params.Remove = remove
	return params, nil
}

func (c *gibDNSClient) invokePatch(ctx context.Context, params gibDNSPatchParams, caps GibDNSCapabilities) error {
	var result gibDNSMutationResult
	if err := c.invoke(ctx, "rrset.patch", params, true, nil, &result); err != nil {
		return err
	}
	if err := validateGibDNSMutationResult(result, params, caps); err != nil {
		return fmt.Errorf("gibdns rrset.patch response: %w", err)
	}
	for _, warning := range result.Warnings {
		if c.out != nil {
			fmt.Fprintf(c.out, "warning: gibdns %s: %s\n", *warning.Code, *warning.Message)
		}
	}
	return nil
}

func (c *gibDNSClient) get(ctx context.Context, key gibDNSKey, zone string, caps GibDNSCapabilities) (gibDNSGetResult, error) {
	params := gibDNSGetParams{Key: key, Zone: zone}
	var result gibDNSGetResult
	if err := c.invoke(ctx, "rrset.get", params, true, nil, &result); err != nil {
		return gibDNSGetResult{}, err
	}
	if err := validateGibDNSGetResult(result, key, zone, caps); err != nil {
		return gibDNSGetResult{}, fmt.Errorf("gibdns rrset.get response: %w", err)
	}
	return result, nil
}

func (c *gibDNSClient) invoke(ctx context.Context, method string, params any, includeSecrets bool, requestContext map[string]string, result any) error {
	if c.provider == nil {
		return fmt.Errorf("missing provider")
	}
	argv := c.provider.Fields["command"]
	if len(argv) == 0 || argv[0] == "" {
		return fmt.Errorf("provider %q: gibdns exec driver requires command", c.provider.Name)
	}
	provider, secretValues, err := c.providerInput(ctx, includeSecrets)
	if err != nil {
		return err
	}
	id, err := gibDNSRequestID()
	if err != nil {
		return fmt.Errorf("generate gibdns request id: %w", err)
	}
	req := gibDNSRequest{
		Version:  GibDNSProtocolVersion,
		ID:       id,
		Method:   method,
		Params:   params,
		Provider: provider,
		Context:  requestContext,
	}
	if deadline, ok := ctx.Deadline(); ok {
		req.Deadline = deadline.UTC().Format(time.RFC3339Nano)
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("encode gibdns request: %w", err)
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	prepareCommand(cmd)
	cmd.Env = gibDNSExecEnvironment()
	cmd.Stdin = bytes.NewReader(payload)
	var stdout, stderr limitedOutput
	stdout.Limit = gibDNSOutputLimit
	stderr.Limit = gibDNSDiagnosticLimit
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	diagnostic := redactSecrets(stderr.String(), secretValues)
	if ctx.Err() != nil {
		msg := fmt.Sprintf("gibdns %s execution: %v", method, ctx.Err())
		if method == "rrset.patch" || method == "rrset.replace" {
			msg += "; mutation outcome may be indeterminate"
		}
		if diagnostic != "" {
			msg += "\ndiagnostic:\n" + diagnostic
		}
		return errors.New(msg)
	}
	if stdout.Truncated {
		return fmt.Errorf("gibdns %s protocol violation: stdout exceeds %d bytes", method, gibDNSOutputLimit)
	}

	status := 0
	if runErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			return fmt.Errorf("start gibdns provider for %s: %w", method, runErr)
		}
		status = exitErr.ExitCode()
	}
	if status < 0 || status > 2 {
		msg := fmt.Sprintf("gibdns %s binding failure: provider exited with status %d", method, status)
		if diagnostic != "" {
			msg += "\ndiagnostic:\n" + diagnostic
		}
		return errors.New(msg)
	}

	wire, err := decodeGibDNSResponse([]byte(stdout.buf.String()), id)
	if err != nil {
		msg := fmt.Sprintf("gibdns %s protocol violation: %v", method, err)
		if diagnostic != "" {
			msg += "\ndiagnostic:\n" + diagnostic
		}
		return errors.New(msg)
	}
	if *wire.OK != (status == 0) {
		return fmt.Errorf("gibdns %s protocol violation: exit status %d contradicts ok=%t", method, status, *wire.OK)
	}
	if *wire.OK {
		if len(wire.Error) != 0 {
			return fmt.Errorf("gibdns %s protocol violation: success response contains error", method)
		}
		if err := unmarshalJSONObject(wire.Result, result); err != nil {
			return fmt.Errorf("gibdns %s result: %w", method, err)
		}
		if diagnostic != "" && c.out != nil {
			fmt.Fprintln(c.out, diagnostic)
		}
		return nil
	}
	if len(wire.Result) != 0 {
		return fmt.Errorf("gibdns %s protocol violation: error response contains result", method)
	}
	var obj gibDNSErrorObject
	if err := unmarshalJSONObject(wire.Error, &obj); err != nil {
		return fmt.Errorf("gibdns %s error response: %w", method, err)
	}
	if obj.Code == nil || *obj.Code == "" || obj.Message == nil || obj.Retryable == nil {
		return fmt.Errorf("gibdns %s error response: code, message, and retryable are required", method)
	}
	if obj.RetryAfterSeconds != nil && *obj.RetryAfterSeconds < 0 {
		return fmt.Errorf("gibdns %s error response: retry_after_seconds must be non-negative", method)
	}
	if err := validateOptionalJSONObject(obj.Details); err != nil {
		return fmt.Errorf("gibdns %s error response details: %w", method, err)
	}
	return &GibDNSError{
		Code:              *obj.Code,
		Message:           redactSecrets(*obj.Message, secretValues),
		Retryable:         *obj.Retryable,
		RetryAfterSeconds: obj.RetryAfterSeconds,
		Diagnostic:        diagnostic,
	}
}

func (c *gibDNSClient) providerInput(ctx context.Context, includeSecrets bool) (*gibDNSProvider, []string, error) {
	provider := &gibDNSProvider{Config: make(map[string]any)}
	for name, vals := range c.provider.Fields {
		switch name {
		case "command", "zone", "present", "cleanup", "add-record", "remove-record":
			continue
		}
		if !utf8.ValidString(name) {
			return nil, nil, fmt.Errorf("provider %q: gibdns config field name is not valid UTF-8", c.provider.Name)
		}
		for _, value := range vals {
			if !utf8.ValidString(value) {
				return nil, nil, fmt.Errorf("provider %q: gibdns config field %q is not valid UTF-8", c.provider.Name, name)
			}
		}
		switch len(vals) {
		case 0:
			return nil, nil, fmt.Errorf("provider %q: gibdns config field %q requires a value", c.provider.Name, name)
		case 1:
			provider.Config[name] = vals[0]
		default:
			provider.Config[name] = append([]string(nil), vals...)
		}
	}
	if includeSecrets {
		provider.Secrets = make(map[string]string, len(c.provider.Secrets))
		secretValues := make([]string, 0, len(c.provider.Secrets))
		for _, secret := range c.provider.Secrets {
			if !utf8.ValidString(secret.Name) {
				return nil, nil, fmt.Errorf("provider %q: gibdns secret name is not valid UTF-8", c.provider.Name)
			}
			value, err := providerSecretSource(secret).Resolve(ctx)
			if err != nil {
				return nil, nil, fmt.Errorf("secret %q: %w", secret.Name, err)
			}
			if !utf8.ValidString(value) {
				return nil, nil, fmt.Errorf("secret %q: value is not valid UTF-8", secret.Name)
			}
			provider.Secrets[secret.Name] = value
			if value != "" {
				secretValues = append(secretValues, value)
			}
		}
		if len(provider.Secrets) == 0 {
			provider.Secrets = nil
		}
		if len(provider.Config) == 0 && len(provider.Secrets) == 0 {
			return nil, secretValues, nil
		}
		return provider, secretValues, nil
	}
	if len(provider.Config) == 0 {
		return nil, nil, nil
	}
	return provider, nil, nil
}

func validateGibDNSCapabilities(wire gibDNSCapabilitiesWire) (GibDNSCapabilities, error) {
	if wire.Provider.Name == "" || wire.Provider.Version == "" {
		return GibDNSCapabilities{}, fmt.Errorf("provider name and version are required")
	}
	if hasDuplicateStrings(wire.Methods) || !slices.Contains(wire.Methods, "capabilities") {
		return GibDNSCapabilities{}, fmt.Errorf("methods must be unique and contain capabilities")
	}
	if slices.Contains(wire.Methods, "") {
		return GibDNSCapabilities{}, fmt.Errorf("methods must not contain an empty name")
	}
	if wire.RecordTypes == nil {
		return GibDNSCapabilities{}, fmt.Errorf("record_types is required")
	}
	if wire.Features.ZoneDiscovery == nil || wire.Features.Preconditions == nil {
		return GibDNSCapabilities{}, fmt.Errorf("features.zone_discovery and features.preconditions are required")
	}
	hasPatch := slices.Contains(wire.Methods, "rrset.patch")
	if hasPatch != (wire.Features.ConcurrentSafePatch != nil) {
		return GibDNSCapabilities{}, fmt.Errorf("features.concurrent_safe_patch must be present exactly when rrset.patch is advertised")
	}
	seenTypes := make(map[int]struct{})
	for i, recordType := range *wire.RecordTypes {
		if recordType == "*" {
			if len(*wire.RecordTypes) != 1 {
				return GibDNSCapabilities{}, fmt.Errorf("record_types wildcard must be the sole value")
			}
			continue
		}
		code, err := gibDNSTypeCode(recordType)
		if err != nil {
			return GibDNSCapabilities{}, fmt.Errorf("record_types[%d]: %w", i, err)
		}
		if _, ok := seenTypes[code]; ok {
			return GibDNSCapabilities{}, fmt.Errorf("record_types contains duplicate type code %d", code)
		}
		seenTypes[code] = struct{}{}
	}
	for method, preconditions := range wire.Features.Preconditions {
		if !slices.Contains(wire.Methods, method) {
			return GibDNSCapabilities{}, fmt.Errorf("preconditions names unadvertised method %q", method)
		}
		if hasDuplicateStrings(preconditions) {
			return GibDNSCapabilities{}, fmt.Errorf("preconditions for %s contain duplicates", method)
		}
		if preconditions == nil {
			return GibDNSCapabilities{}, fmt.Errorf("preconditions for %s must be an array", method)
		}
		for _, precondition := range preconditions {
			if precondition == "if_revision" && !slices.Contains(wire.Methods, "rrset.get") {
				return GibDNSCapabilities{}, fmt.Errorf("if_revision requires rrset.get")
			}
		}
	}
	if wire.Constraints != nil {
		if err := validateGibDNSConstraints(*wire.Constraints); err != nil {
			return GibDNSCapabilities{}, err
		}
	}
	if wire.Configuration != nil {
		if err := validateGibDNSConfiguration(*wire.Configuration); err != nil {
			return GibDNSCapabilities{}, err
		}
	}
	concurrentSafe := false
	if wire.Features.ConcurrentSafePatch != nil {
		concurrentSafe = *wire.Features.ConcurrentSafePatch
	}
	return GibDNSCapabilities{
		Provider:    wire.Provider,
		Methods:     wire.Methods,
		RecordTypes: append([]string(nil), (*wire.RecordTypes)...),
		Features: gibDNSFeatures{
			ZoneDiscovery:       *wire.Features.ZoneDiscovery,
			ConcurrentSafePatch: concurrentSafe,
			Preconditions:       wire.Features.Preconditions,
		},
		Constraints: wire.Constraints,
	}, nil
}

func validateGibDNSConstraints(c gibDNSConstraints) error {
	for name, value := range map[string]*int{"minimum_ttl": c.MinimumTTL, "maximum_ttl": c.MaximumTTL} {
		if value != nil && (*value < 0 || *value > 2147483647) {
			return fmt.Errorf("constraint %s is outside the DNS TTL range", name)
		}
	}
	if c.MinimumTTL != nil && c.MaximumTTL != nil && *c.MinimumTTL > *c.MaximumTTL {
		return fmt.Errorf("constraint minimum_ttl exceeds maximum_ttl")
	}
	return nil
}

func validateGibDNSConfiguration(c gibDNSConfiguration) error {
	fieldNames := make(map[string]struct{})
	validTypes := []string{"string", "number", "integer", "boolean", "array", "object"}
	for _, field := range c.Fields {
		if field.Name == "" || field.Required == nil || !slices.Contains(validTypes, field.Type) {
			return fmt.Errorf("configuration field descriptors require a name, valid type, and required flag")
		}
		if _, ok := fieldNames[field.Name]; ok {
			return fmt.Errorf("duplicate configuration field descriptor %q", field.Name)
		}
		fieldNames[field.Name] = struct{}{}
	}
	secretNames := make(map[string]struct{})
	for _, secret := range c.Secrets {
		if secret.Name == "" || secret.Required == nil {
			return fmt.Errorf("configuration secret descriptors require a name and required flag")
		}
		if _, ok := secretNames[secret.Name]; ok {
			return fmt.Errorf("duplicate configuration secret descriptor %q", secret.Name)
		}
		secretNames[secret.Name] = struct{}{}
	}
	return nil
}

func validateGibDNSPatchParams(params gibDNSPatchParams) error {
	if err := validateGibDNSKey(params.Key); err != nil {
		return err
	}
	if len(params.Add) == 0 && len(params.Remove) == 0 && params.TTL == nil {
		return fmt.Errorf("gibdns patch requires add, remove, or ttl")
	}
	if params.TTL != nil && (*params.TTL < 0 || *params.TTL > 2147483647) {
		return fmt.Errorf("gibdns ttl is outside the DNS TTL range")
	}
	if params.Zone != "" {
		if _, err := parseGibDNSName(params.Zone); err != nil {
			return fmt.Errorf("gibdns zone: %w", err)
		}
		if !gibDNSNameWithin(params.Key.Owner, params.Zone) {
			return fmt.Errorf("gibdns zone %q is not an ancestor of owner %q", params.Zone, params.Key.Owner)
		}
	}
	if params.IfRevision != "" && params.IfAbsent {
		return fmt.Errorf("gibdns if_revision and if_absent are mutually exclusive")
	}
	if params.TTL == nil && params.TTLPolicy != "" {
		return fmt.Errorf("gibdns ttl_policy requires ttl")
	}
	if params.TTLPolicy != "" && params.TTLPolicy != "exact" && params.TTLPolicy != "provider-adjust" {
		return fmt.Errorf("gibdns ttl_policy must be exact or provider-adjust")
	}
	seenAdd := make(map[string]struct{})
	for _, rdata := range params.Add {
		key, err := gibDNSSemanticRData(params.Key.Type, rdata)
		if err != nil {
			return fmt.Errorf("gibdns add rdata: %w", err)
		}
		if _, ok := seenAdd[string(key)]; ok {
			return fmt.Errorf("gibdns add contains duplicate rdata")
		}
		seenAdd[string(key)] = struct{}{}
	}
	seenRemove := make(map[string]struct{})
	for _, rdata := range params.Remove {
		key, err := gibDNSSemanticRData(params.Key.Type, rdata)
		if err != nil {
			return fmt.Errorf("gibdns remove rdata: %w", err)
		}
		if _, ok := seenRemove[string(key)]; ok {
			return fmt.Errorf("gibdns remove contains duplicate rdata")
		}
		if _, ok := seenAdd[string(key)]; ok {
			return fmt.Errorf("gibdns rdata occurs in both add and remove")
		}
		seenRemove[string(key)] = struct{}{}
	}
	return nil
}

func validateGibDNSKey(key gibDNSKey) error {
	if _, err := parseGibDNSName(key.Owner); err != nil {
		return fmt.Errorf("gibdns owner: %w", err)
	}
	if _, err := gibDNSTypeCode(key.Type); err != nil {
		return fmt.Errorf("gibdns record type: %w", err)
	}
	return nil
}

func validateGibDNSGetResult(result gibDNSGetResult, key gibDNSKey, zone string, caps GibDNSCapabilities) error {
	if result.Exists == nil || result.Zone == "" {
		return fmt.Errorf("exists and zone are required")
	}
	if err := validateGibDNSResultZone(result.Zone, zone); err != nil {
		return err
	}
	if !gibDNSNameWithin(key.Owner, result.Zone) {
		return fmt.Errorf("result zone %q is not an ancestor of owner %q", result.Zone, key.Owner)
	}
	if !*result.Exists {
		if result.RRSet != nil || result.Revision != nil {
			return fmt.Errorf("absent RRset result contains rrset or revision")
		}
		return nil
	}
	if result.RRSet == nil {
		return fmt.Errorf("existing RRset result omits rrset")
	}
	if err := validateGibDNSRRSet(*result.RRSet, key); err != nil {
		return err
	}
	if result.Revision != nil && *result.Revision == "" {
		return fmt.Errorf("existing RRset result contains an empty revision")
	}
	if capabilitiesRequireRevision(caps) && result.Revision == nil {
		return fmt.Errorf("existing RRset result omits required revision")
	}
	return nil
}

func validateGibDNSMutationResult(result gibDNSMutationResult, params gibDNSPatchParams, caps GibDNSCapabilities) error {
	if result.Changed == nil || result.Exists == nil || result.Zone == "" {
		return fmt.Errorf("changed, exists, and zone are required")
	}
	if err := validateGibDNSResultZone(result.Zone, params.Zone); err != nil {
		return err
	}
	if !gibDNSNameWithin(params.Key.Owner, result.Zone) {
		return fmt.Errorf("result zone %q is not an ancestor of owner %q", result.Zone, params.Key.Owner)
	}
	for _, warning := range result.Warnings {
		if warning.Code == nil || *warning.Code == "" || warning.Message == nil {
			return fmt.Errorf("warning code and message are required")
		}
		if err := validateOptionalJSONObject(warning.Details); err != nil {
			return fmt.Errorf("warning %q details: %w", *warning.Code, err)
		}
		if *warning.Code == "ttl_adjusted" {
			var details gibDNSTTLAdjustedDetails
			if err := unmarshalJSONObject(warning.Details, &details); err != nil {
				return fmt.Errorf("warning ttl_adjusted details: %w", err)
			}
			if details.RequestedTTL == nil || details.EffectiveTTL == nil {
				return fmt.Errorf("warning ttl_adjusted details require requested_ttl and effective_ttl")
			}
			if !validGibDNSTTL(*details.RequestedTTL) || !validGibDNSTTL(*details.EffectiveTTL) {
				return fmt.Errorf("warning ttl_adjusted details contain a TTL outside the DNS TTL range")
			}
		}
	}
	if !*result.Exists {
		if result.RRSet != nil || result.Revision != nil {
			return fmt.Errorf("absent RRset result contains rrset or revision")
		}
		if len(params.Add) != 0 {
			return fmt.Errorf("result does not satisfy requested additions")
		}
		return nil
	}
	if result.RRSet == nil {
		return fmt.Errorf("existing RRset result omits rrset")
	}
	if err := validateGibDNSRRSet(*result.RRSet, params.Key); err != nil {
		return err
	}
	if result.Revision != nil && *result.Revision == "" {
		return fmt.Errorf("existing RRset result contains an empty revision")
	}
	if capabilitiesRequireRevision(caps) && result.Revision == nil {
		return fmt.Errorf("existing RRset result omits required revision")
	}
	state := gibDNSGetResult{Exists: result.Exists, Zone: result.Zone, RRSet: result.RRSet, Revision: result.Revision}
	holds, err := gibDNSPatchPostcondition(state, params)
	if err != nil {
		return err
	}
	if !holds {
		return fmt.Errorf("result does not satisfy requested patch")
	}
	return nil
}

func validateGibDNSResultZone(got, want string) error {
	gotName, err := parseGibDNSName(got)
	if err != nil {
		return fmt.Errorf("invalid result zone: %w", err)
	}
	if want == "" {
		return nil
	}
	wantName, err := parseGibDNSName(want)
	if err != nil {
		return err
	}
	if !bytes.Equal(gotName, wantName) {
		return fmt.Errorf("result zone %q does not match requested zone %q", got, want)
	}
	return nil
}

func validateGibDNSRRSet(rrset gibDNSRRSet, key gibDNSKey) error {
	gotOwner, err := parseGibDNSName(rrset.Owner)
	if err != nil {
		return fmt.Errorf("invalid result owner: %w", err)
	}
	wantOwner, err := parseGibDNSName(key.Owner)
	if err != nil {
		return err
	}
	if !bytes.Equal(gotOwner, wantOwner) {
		return fmt.Errorf("result owner %q does not match request owner %q", rrset.Owner, key.Owner)
	}
	gotType, err := gibDNSTypeCode(rrset.Type)
	if err != nil {
		return fmt.Errorf("invalid result record type: %w", err)
	}
	wantType, _ := gibDNSTypeCode(key.Type)
	if gotType != wantType {
		return fmt.Errorf("result record type %q does not match request type %q", rrset.Type, key.Type)
	}
	if rrset.TTL == nil || *rrset.TTL < 0 || *rrset.TTL > 2147483647 {
		return fmt.Errorf("result ttl is missing or outside the DNS TTL range")
	}
	if len(rrset.RData) == 0 {
		return fmt.Errorf("existing result RRset has no rdata")
	}
	seen := make(map[string]struct{})
	for _, rdata := range rrset.RData {
		semantic, err := gibDNSSemanticRData(key.Type, rdata)
		if err != nil {
			return fmt.Errorf("invalid result rdata: %w", err)
		}
		if _, ok := seen[string(semantic)]; ok {
			return fmt.Errorf("result RRset contains semantically duplicate rdata")
		}
		seen[string(semantic)] = struct{}{}
	}
	return nil
}

func gibDNSPatchPostcondition(state gibDNSGetResult, params gibDNSPatchParams) (bool, error) {
	if state.Exists == nil {
		return false, fmt.Errorf("gibdns state omits exists")
	}
	if !*state.Exists {
		return len(params.Add) == 0, nil
	}
	if state.RRSet == nil {
		return false, fmt.Errorf("gibdns state omits rrset")
	}
	present := make(map[string]struct{}, len(state.RRSet.RData))
	for _, rdata := range state.RRSet.RData {
		key, err := gibDNSSemanticRData(params.Key.Type, rdata)
		if err != nil {
			return false, err
		}
		present[string(key)] = struct{}{}
	}
	for _, rdata := range params.Add {
		key, _ := gibDNSSemanticRData(params.Key.Type, rdata)
		if _, ok := present[string(key)]; !ok {
			return false, nil
		}
	}
	for _, rdata := range params.Remove {
		key, _ := gibDNSSemanticRData(params.Key.Type, rdata)
		if _, ok := present[string(key)]; ok {
			return false, nil
		}
	}
	if params.TTL != nil && (state.RRSet.TTL == nil || *state.RRSet.TTL != *params.TTL) {
		return false, nil
	}
	return true, nil
}

func capabilitiesRequireRevision(caps GibDNSCapabilities) bool {
	for _, preconditions := range caps.Features.Preconditions {
		if slices.Contains(preconditions, "if_revision") {
			return true
		}
	}
	return false
}

func decodeGibDNSResponse(raw []byte, requestID string) (gibDNSWireResponse, error) {
	if err := validateStrictJSONObject(raw); err != nil {
		return gibDNSWireResponse{}, err
	}
	var wire gibDNSWireResponse
	if err := json.Unmarshal(raw, &wire); err != nil {
		return gibDNSWireResponse{}, err
	}
	if wire.Version != GibDNSProtocolVersion {
		return gibDNSWireResponse{}, fmt.Errorf("response version %q, want %q", wire.Version, GibDNSProtocolVersion)
	}
	var id string
	if err := json.Unmarshal(wire.ID, &id); err != nil || id != requestID {
		return gibDNSWireResponse{}, fmt.Errorf("response id does not match request")
	}
	if wire.OK == nil {
		return gibDNSWireResponse{}, fmt.Errorf("response omits ok")
	}
	return wire, nil
}

func unmarshalJSONObject(raw json.RawMessage, dst any) error {
	if len(raw) == 0 {
		return fmt.Errorf("required object is missing")
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return fmt.Errorf("want JSON object")
	}
	return json.Unmarshal(raw, dst)
}

func validateOptionalJSONObject(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return fmt.Errorf("want JSON object")
	}
	return nil
}

func validGibDNSTTL(ttl int64) bool {
	return ttl >= 0 && ttl <= 2147483647
}

func validateStrictJSONObject(raw []byte) error {
	if !utf8.Valid(raw) {
		return fmt.Errorf("response is not valid UTF-8")
	}
	if err := validateJSONSurrogates(raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	token, err := dec.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '{' {
		return fmt.Errorf("response must be a JSON object")
	}
	if err := validateJSONObjectTokens(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("response contains more than one JSON value")
		}
		return fmt.Errorf("invalid trailing JSON: %w", err)
	}
	return nil
}

func validateJSONObjectTokens(dec *json.Decoder) error {
	seen := make(map[string]struct{})
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return fmt.Errorf("invalid JSON object: %w", err)
		}
		name, ok := token.(string)
		if !ok {
			return fmt.Errorf("invalid JSON object member name")
		}
		if _, ok := seen[name]; ok {
			return fmt.Errorf("duplicate JSON member %q", name)
		}
		seen[name] = struct{}{}
		if err := validateJSONValueTokens(dec); err != nil {
			return err
		}
	}
	token, err := dec.Token()
	if err != nil || token != json.Delim('}') {
		return fmt.Errorf("invalid JSON object")
	}
	return nil
}

func validateJSONValueTokens(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON value: %w", err)
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		return validateJSONObjectTokens(dec)
	case '[':
		for dec.More() {
			if err := validateJSONValueTokens(dec); err != nil {
				return err
			}
		}
		token, err := dec.Token()
		if err != nil || token != json.Delim(']') {
			return fmt.Errorf("invalid JSON array")
		}
		return nil
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
}

func validateJSONSurrogates(raw []byte) error {
	inString := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return nil
		}
		if raw[i] != 'u' || i+4 >= len(raw) {
			continue
		}
		value, ok := parseHex16(raw[i+1 : i+5])
		if !ok {
			continue
		}
		i += 4
		if value >= 0xdc00 && value <= 0xdfff {
			return fmt.Errorf("JSON string contains unpaired UTF-16 surrogate")
		}
		if value < 0xd800 || value > 0xdbff {
			continue
		}
		if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
			return fmt.Errorf("JSON string contains unpaired UTF-16 surrogate")
		}
		low, ok := parseHex16(raw[i+3 : i+7])
		if !ok || low < 0xdc00 || low > 0xdfff {
			return fmt.Errorf("JSON string contains unpaired UTF-16 surrogate")
		}
		i += 6
	}
	return nil
}

func parseHex16(raw []byte) (uint16, bool) {
	if len(raw) != 4 {
		return 0, false
	}
	var value uint16
	for _, b := range raw {
		value <<= 4
		switch {
		case b >= '0' && b <= '9':
			value |= uint16(b - '0')
		case b >= 'a' && b <= 'f':
			value |= uint16(b-'a') + 10
		case b >= 'A' && b <= 'F':
			value |= uint16(b-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

func gibDNSRequestID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(id[:]), nil
}

func gibDNSExecEnvironment() []string {
	names := []string{
		"PATH", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL", "LC_CTYPE", "TZ",
		"HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT",
		"SSL_CERT_FILE", "SSL_CERT_DIR", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
		"http_proxy", "https_proxy", "no_proxy",
	}
	var env []string
	for _, name := range names {
		if value, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+value)
		}
	}
	return env
}

func contextWithTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= timeout {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}

func redactSecrets(value string, secrets []string) string {
	secrets = append([]string(nil), secrets...)
	slices.SortFunc(secrets, func(a, b string) int { return len(b) - len(a) })
	for _, secret := range secrets {
		if secret != "" {
			value = strings.ReplaceAll(value, secret, "[REDACTED]")
		}
	}
	return value
}

func hasDuplicateStrings(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}
