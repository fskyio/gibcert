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
	"slices"
	"strconv"
	"strings"
	"time"

	"gitfield.org/fsky/gibcert/internal/config"
	"gitfield.org/fsky/gibcert/internal/secrets"
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
	edit := EditRequest{Owner: req.FQDN, RecordType: "TXT", RData: strconv.Quote(req.Value)}
	if err := d.ApplyEdits(ctx, []EditOp{{EditRequest: edit}}); err != nil {
		return nil, err
	}
	return func() {
		if err := d.ApplyEdits(context.Background(), []EditOp{{Remove: true, EditRequest: edit}}); err != nil && d.Out != nil {
			fmt.Fprintf(d.Out, "warning: powerdns cleanup failed: %v\n", err)
		}
	}, nil
}

func (d *DNSPowerDNS) AddRecord(ctx context.Context, req EditRequest) error {
	return d.ApplyEdits(ctx, []EditOp{{EditRequest: req}})
}

func (d *DNSPowerDNS) RemoveRecord(ctx context.Context, req EditRequest) error {
	return d.ApplyEdits(ctx, []EditOp{{Remove: true, EditRequest: req}})
}

// ApplyEdits applies ops with one zone listing, one zone read, and one PATCH
// per affected zone. Ops on the same name and type are merged into a single
// RRset replacement, since PowerDNS replaces whole RRsets. Every op is matched
// to a zone before anything is sent, so an unknown zone fails the batch
// without changing DNS.
func (d *DNSPowerDNS) ApplyEdits(ctx context.Context, ops []EditOp) error {
	if len(ops) == 0 {
		return nil
	}
	api, err := d.api(ctx)
	if err != nil {
		return err
	}
	zones, err := powerDNSListZones(ctx, api.client, api.url, api.server, api.key)
	if err != nil {
		return err
	}
	plans, err := planPowerDNSEdits(zones, api.server, ops)
	if err != nil {
		return err
	}
	for _, plan := range plans {
		if err := api.patchZone(ctx, plan); err != nil {
			return err
		}
	}
	return nil
}

type powerDNSAPI struct {
	url    string
	server string
	key    string
	ttl    int
	client *http.Client
}

func (d *DNSPowerDNS) api(ctx context.Context) (*powerDNSAPI, error) {
	if d.Provider == nil {
		return nil, errors.New("missing provider")
	}
	apiURL := strings.TrimRight(firstField(d.Provider, "api-url"), "/")
	if apiURL == "" {
		return nil, errors.New("powerdns: api-url is required")
	}
	server := firstField(d.Provider, "server-id")
	if server == "" {
		server = powerDNSDefaultServer
	}
	ttl := powerDNSDefaultTTL
	if v := firstField(d.Provider, "ttl"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("powerdns: invalid ttl %q", v)
		}
		ttl = n
	}
	apiKey, err := readNamedSecret(ctx, d.Provider, "api-key")
	if err != nil {
		return nil, err
	}
	if apiKey == "" {
		return nil, errors.New("powerdns: secret \"api-key\" is required")
	}
	client := d.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &powerDNSAPI{url: apiURL, server: server, key: apiKey, ttl: ttl, client: client}, nil
}

// powerDNSZonePlan lists the RRsets one batch touches in a zone, in the order
// the batch first mentions them.
type powerDNSZonePlan struct {
	zone   string
	rrsets []*powerDNSRRsetPlan
}

type powerDNSRRsetPlan struct {
	key        string
	name       string
	recordType string
	ttl        int // last explicit TTL among ops; 0 selects the provider default
	ops        []EditOp
}

func powerDNSRRsetKey(name, recordType string) string {
	return strings.ToLower(ensureDot(name)) + "|" + strings.ToUpper(recordType)
}

func planPowerDNSEdits(zones []string, server string, ops []EditOp) ([]*powerDNSZonePlan, error) {
	var plans []*powerDNSZonePlan
	for _, op := range ops {
		name := ensureDot(op.Owner)
		zone := powerDNSPickZone(zones, name)
		if zone == "" {
			return nil, fmt.Errorf("powerdns: no zone on server %q matches %q", server, op.Owner)
		}
		var plan *powerDNSZonePlan
		for _, p := range plans {
			if p.zone == zone {
				plan = p
				break
			}
		}
		if plan == nil {
			plan = &powerDNSZonePlan{zone: zone}
			plans = append(plans, plan)
		}
		key := powerDNSRRsetKey(name, op.RecordType)
		var rrset *powerDNSRRsetPlan
		for _, r := range plan.rrsets {
			if r.key == key {
				rrset = r
				break
			}
		}
		if rrset == nil {
			rrset = &powerDNSRRsetPlan{key: key, name: name, recordType: op.RecordType}
			plan.rrsets = append(plan.rrsets, rrset)
		}
		if op.TTL > 0 {
			rrset.ttl = op.TTL
		}
		rrset.ops = append(rrset.ops, op)
	}
	return plans, nil
}

// rrset applies the planned ops, in order, to the members read from the zone.
// It deletes the RRset when no member is left.
func (p *powerDNSRRsetPlan) rrset(existing []powerDNSRecord, defaultTTL int) powerDNSRRset {
	records := slices.Clone(existing)
	for _, op := range p.ops {
		if op.Remove {
			records = slices.DeleteFunc(records, func(r powerDNSRecord) bool { return r.Content == op.RData })
		} else if !containsRecord(records, op.RData) {
			records = append(records, powerDNSRecord{Content: op.RData})
		}
	}
	ttl := defaultTTL
	if p.ttl > 0 {
		ttl = p.ttl
	}
	rrset := powerDNSRRset{Name: p.name, Type: p.recordType, TTL: ttl}
	if len(records) == 0 {
		rrset.ChangeType = "DELETE"
	} else {
		rrset.ChangeType = "REPLACE"
		rrset.Records = records
	}
	return rrset
}

func (a *powerDNSAPI) patchZone(ctx context.Context, plan *powerDNSZonePlan) error {
	zoneURL := fmt.Sprintf("%s/api/v1/servers/%s/zones/%s", a.url, a.server, plan.zone)
	existing, err := powerDNSReadRRsets(ctx, a.client, zoneURL, a.key)
	if err != nil {
		return err
	}
	rrsets := make([]powerDNSRRset, 0, len(plan.rrsets))
	for _, p := range plan.rrsets {
		rrsets = append(rrsets, p.rrset(existing[p.key], a.ttl))
	}
	body, err := json.Marshal(map[string]any{"rrsets": rrsets})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, zoneURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", a.key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("powerdns patch zone %s: %w", plan.zone, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("powerdns patch zone %s: %s: %s", plan.zone, resp.Status, strings.TrimSpace(string(msg)))
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

// powerDNSReadRRsets reads a zone once and indexes its member records by
// powerDNSRRsetKey.
func powerDNSReadRRsets(ctx context.Context, client *http.Client, zoneURL, apiKey string) (map[string][]powerDNSRecord, error) {
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
	out := make(map[string][]powerDNSRecord, len(z.RRsets))
	for _, r := range z.RRsets {
		out[powerDNSRRsetKey(r.Name, r.Type)] = r.Records
	}
	return out, nil
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
