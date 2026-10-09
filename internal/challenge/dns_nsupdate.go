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
	"fmt"
	"io"
	"os/exec"
	"strings"

	"gitfield.org/fsky/gibcert/internal/config"
)

type DNSNSUpdate struct {
	Provider *config.Provider
	Out      io.Writer
}

func (d *DNSNSUpdate) Present(ctx context.Context, req Request) (func(), error) {
	if err := d.run(ctx, "add", req.FQDN, "TXT", fmt.Sprintf("%q", req.Value), 60); err != nil {
		return nil, err
	}
	return func() {
		if err := d.run(context.Background(), "delete", req.FQDN, "TXT", fmt.Sprintf("%q", req.Value), 60); err != nil && d.Out != nil {
			fmt.Fprintf(d.Out, "warning: nsupdate cleanup failed: %v\n", err)
		}
	}, nil
}

func (d *DNSNSUpdate) AddRecord(ctx context.Context, req EditRequest) error {
	ttl := req.TTL
	if ttl <= 0 {
		ttl = 60
	}
	return d.run(ctx, "add", req.Owner, req.RecordType, req.RData, ttl)
}

func (d *DNSNSUpdate) RemoveRecord(ctx context.Context, req EditRequest) error {
	return d.run(ctx, "delete", req.Owner, req.RecordType, req.RData, 0)
}

// ApplyEdits sends all ops as one nsupdate message, which an RFC 2136 server
// applies atomically. A message can only change one zone, so this needs the
// provider's zone field. Without it nsupdate derives the zone from the first
// update, and ops go out one message at a time instead.
func (d *DNSNSUpdate) ApplyEdits(ctx context.Context, ops []EditOp) error {
	if len(ops) == 0 {
		return nil
	}
	if d.Provider == nil {
		return fmt.Errorf("missing provider")
	}
	if firstField(d.Provider, "zone") == "" {
		return applyEditsSequentially(ctx, d, ops)
	}
	changes := make([]nsupdateChange, 0, len(ops))
	for _, op := range ops {
		change := nsupdateChange{op: "add", fqdn: op.Owner, recordType: op.RecordType, rdata: op.RData, ttl: op.TTL}
		if op.Remove {
			change.op = "delete"
			change.ttl = 0
		} else if change.ttl <= 0 {
			change.ttl = 60
		}
		changes = append(changes, change)
	}
	return d.send(ctx, "batch", changes)
}

type nsupdateChange struct {
	op         string
	fqdn       string
	recordType string
	rdata      string
	ttl        int
}

func (d *DNSNSUpdate) run(ctx context.Context, op, fqdn, recordType, rdata string, ttl int) error {
	return d.send(ctx, op, []nsupdateChange{{op: op, fqdn: fqdn, recordType: recordType, rdata: rdata, ttl: ttl}})
}

func (d *DNSNSUpdate) send(ctx context.Context, label string, changes []nsupdateChange) error {
	if d.Provider == nil {
		return fmt.Errorf("missing provider")
	}
	command := firstField(d.Provider, "command")
	if command == "" {
		command = "nsupdate"
	}
	args := []string{}
	if keyFile := firstSecretFile(d.Provider); keyFile != "" {
		args = append(args, "-k", keyFile)
	}
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Stdin = strings.NewReader(d.script(changes))
	cmd.Stdout = d.Out
	cmd.Stderr = d.Out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nsupdate %s: %w", label, err)
	}
	return nil
}

func (d *DNSNSUpdate) script(changes []nsupdateChange) string {
	var b strings.Builder
	if server := firstField(d.Provider, "server"); server != "" {
		fmt.Fprintf(&b, "server %s\n", server)
	}
	if zone := firstField(d.Provider, "zone"); zone != "" {
		fmt.Fprintf(&b, "zone %s\n", ensureDot(zone))
	}
	for _, c := range changes {
		switch c.op {
		case "add":
			fmt.Fprintf(&b, "update add %s %d %s %s\n", ensureDot(c.fqdn), c.ttl, c.recordType, c.rdata)
		case "delete":
			fmt.Fprintf(&b, "update delete %s %s %s\n", ensureDot(c.fqdn), c.recordType, c.rdata)
		}
	}
	b.WriteString("send\n")
	return b.String()
}

func firstSecretFile(p *config.Provider) string {
	for _, s := range p.Secrets {
		if s.File != "" {
			return s.File
		}
	}
	return ""
}
