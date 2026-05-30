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

	"foundry.fsky.io/fsky/gibcert/internal/config"
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

func (d *DNSNSUpdate) run(ctx context.Context, op, fqdn, recordType, rdata string, ttl int) error {
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
	cmd.Stdin = strings.NewReader(d.script(op, fqdn, recordType, rdata, ttl))
	cmd.Stdout = d.Out
	cmd.Stderr = d.Out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nsupdate %s: %w", op, err)
	}
	return nil
}

func (d *DNSNSUpdate) script(op, fqdn, recordType, rdata string, ttl int) string {
	var b strings.Builder
	if server := firstField(d.Provider, "server"); server != "" {
		fmt.Fprintf(&b, "server %s\n", server)
	}
	if zone := firstField(d.Provider, "zone"); zone != "" {
		fmt.Fprintf(&b, "zone %s\n", ensureDot(zone))
	}
	switch op {
	case "add":
		fmt.Fprintf(&b, "update add %s %d %s %s\n", ensureDot(fqdn), ttl, recordType, rdata)
	case "delete":
		fmt.Fprintf(&b, "update delete %s %s %s\n", ensureDot(fqdn), recordType, rdata)
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
