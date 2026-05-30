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
	"net/http"
	"strconv"
	"strings"
	"time"

	"foundry.fsky.io/fsky/gibcert/internal/config"
	"foundry.fsky.io/fsky/gibcert/internal/secrets"
)

type DNSPowerDNS struct {
	Provider *config.Provider
	Out      io.Writer
	Client   *http.Client
}

const (
	powerDNSDefaultTTL    = 60
	powerDNSDefaultServer = "localhost"
)

func (d *DNSPowerDNS) Present(ctx context.Context, req Request) (func(), error) {
	if err := d.update(ctx, "present", req.FQDN, "TXT", strconv.Quote(req.Value), 0); err != nil {
		return nil, err
	}
	return func() {
		if err := d.update(context.Background(), "cleanup", req.FQDN, "TXT", strconv.Quote(req.Value), 0); err != nil && d.Out != nil {
			fmt.Fprintf(d.Out, "warning: powerdns cleanup failed: %v\n", err)
		}
	}, nil
}

func (d *DNSPowerDNS) AddRecord(ctx context.Context, req EditRequest) error {
	return d.update(ctx, "present", req.Owner, req.RecordType, req.RData, req.TTL)
}

func (d *DNSPowerDNS) RemoveRecord(ctx context.Context, req EditRequest) error {
	return d.update(ctx, "cleanup", req.Owner, req.RecordType, req.RData, req.TTL)
}

func (d *DNSPowerDNS) update(ctx context.Context, op, fqdn, recordType, content string, ttlOverride int) error {
	if d.Provider == nil {
		return errors.New("missing provider")
	}
	apiURL := strings.TrimRight(firstField(d.Provider, "api-url"), "/")
	if apiURL == "" {
		return errors.New("powerdns: api-url is required")
	}
	server := firstField(d.Provider, "server-id")
	if server == "" {
		server = powerDNSDefaultServer
	}
	ttl := powerDNSDefaultTTL
	if v := firstField(d.Provider, "ttl"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return fmt.Errorf("powerdns: invalid ttl %q", v)
		}
		ttl = n
	}
	if ttlOverride > 0 {
		ttl = ttlOverride
	}
	apiKey, err := readNamedSecret(ctx, d.Provider, "api-key")
	if err != nil {
		return err
	}
	if apiKey == "" {
		return errors.New("powerdns: secret \"api-key\" is required")
	}

	client := d.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	name := ensureDot(fqdn)
	zones, err := powerDNSListZones(ctx, client, apiURL, server, apiKey)
	if err != nil {
		return err
	}
	zone := powerDNSPickZone(zones, name)
	if zone == "" {
		return fmt.Errorf("powerdns: no zone on server %q matches %q", server, fqdn)
	}
	zoneURL := fmt.Sprintf("%s/api/v1/servers/%s/zones/%s", apiURL, server, zone)

	existing, err := powerDNSReadRecords(ctx, client, zoneURL, apiKey, name, recordType)
	if err != nil {
		return err
	}

	var records []powerDNSRecord
	switch op {
	case "present":
		records = append(records, existing...)
		if !containsRecord(records, content) {
			records = append(records, powerDNSRecord{Content: content})
		}
	case "cleanup":
		for _, r := range existing {
			if r.Content != content {
				records = append(records, r)
			}
		}
	}

	rrset := powerDNSRRset{
		Name: name,
		Type: recordType,
		TTL:  ttl,
	}
	if len(records) == 0 {
		rrset.ChangeType = "DELETE"
	} else {
		rrset.ChangeType = "REPLACE"
		rrset.Records = records
	}

	body, err := json.Marshal(map[string]any{"rrsets": []powerDNSRRset{rrset}})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, zoneURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("powerdns %s: %w", op, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("powerdns %s: %s: %s", op, resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}

type powerDNSRRset struct {
	Name       string           `json:"name"`
	Type       string           `json:"type"`
	TTL        int              `json:"ttl,omitempty"`
	ChangeType string           `json:"changetype"`
	Records    []powerDNSRecord `json:"records,omitempty"`
}

type powerDNSRecord struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

func powerDNSListZones(ctx context.Context, client *http.Client, apiURL, server, apiKey string) ([]string, error) {
	url := fmt.Sprintf("%s/api/v1/servers/%s/zones", apiURL, server)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", apiKey)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("powerdns list zones: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("powerdns list zones: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	var zones []struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&zones); err != nil {
		return nil, fmt.Errorf("powerdns list zones: decode: %w", err)
	}
	out := make([]string, 0, len(zones))
	for _, z := range zones {
		if z.Name != "" {
			out = append(out, z.Name)
		}
	}
	return out, nil
}

func powerDNSPickZone(zones []string, fqdn string) string {
	name := ensureDot(fqdn)
	var best string
	for _, z := range zones {
		zd := ensureDot(z)
		if name == zd || strings.HasSuffix(name, "."+zd) {
			if len(zd) > len(best) {
				best = zd
			}
		}
	}
	return best
}

func powerDNSReadRecords(ctx context.Context, client *http.Client, zoneURL, apiKey, name, recordType string) ([]powerDNSRecord, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, zoneURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", apiKey)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("powerdns get zone: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("powerdns get zone: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	var z struct {
		RRsets []struct {
			Name    string           `json:"name"`
			Type    string           `json:"type"`
			Records []powerDNSRecord `json:"records"`
		} `json:"rrsets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&z); err != nil {
		return nil, fmt.Errorf("powerdns get zone: decode: %w", err)
	}
	for _, r := range z.RRsets {
		if r.Type == recordType && r.Name == name {
			return r.Records, nil
		}
	}
	return nil, nil
}

func containsRecord(records []powerDNSRecord, content string) bool {
	for _, r := range records {
		if r.Content == content {
			return true
		}
	}
	return false
}

func readNamedSecret(ctx context.Context, p *config.Provider, name string) (string, error) {
	for _, s := range p.Secrets {
		if s.Name != name {
			continue
		}
		value, err := providerSecretSource(s).Resolve(ctx)
		if err != nil {
			return "", fmt.Errorf("read secret %q: %w", name, err)
		}
		return value, nil
	}
	return "", nil
}

func providerSecretSource(s *config.Secret) secrets.Source {
	return secrets.Source{
		File:              s.File,
		Value:             s.Value,
		Env:               s.Env,
		Command:           s.Command,
		SystemdCredential: s.SystemdCredential,
	}
}
