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
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"foundry.fsky.io/fsky/gibcert/internal/config"
)

type DNSExec struct {
	Provider *config.Provider
	Out      io.Writer

	mu     sync.Mutex
	client *gibDNSClient
}

const (
	defaultDNSExecCleanupWait = 30 * time.Second
)

func (d *DNSExec) Present(ctx context.Context, req Request) (func(), error) {
	timeout := gibDNSOperationTimeout
	if req.Timeout > 0 && req.Timeout < timeout {
		timeout = req.Timeout
	}
	pctx, cancel := contextWithTimeout(ctx, timeout)
	defer cancel()
	params := gibDNSPatchParams{
		Key:  gibDNSKey{Owner: ensureDot(req.FQDN), Type: "TXT"},
		Add:  []string{quoteGibDNSTXT(req.Value)},
		Zone: d.zone(),
	}
	if err := d.gibDNSClient().patch(pctx, params); err != nil {
		return nil, err
	}
	return func() {
		cctx, cancel := context.WithTimeout(context.Background(), dnsExecCleanupTimeout(req.Timeout))
		defer cancel()
		params := gibDNSPatchParams{
			Key:    gibDNSKey{Owner: ensureDot(req.FQDN), Type: "TXT"},
			Remove: []string{quoteGibDNSTXT(req.Value)},
			Zone:   d.zone(),
		}
		if err := d.gibDNSClient().patch(cctx, params); err != nil && d.Out != nil {
			fmt.Fprintf(d.Out, "warning: dns exec cleanup failed: %v\n", err)
		}
	}, nil
}

func (d *DNSExec) Capabilities(ctx context.Context) (GibDNSCapabilities, error) {
	return d.gibDNSClient().capabilities(ctx)
}

func (d *DNSExec) AddRecord(ctx context.Context, req EditRequest) error {
	ctx, cancel := contextWithTimeout(ctx, gibDNSOperationTimeout)
	defer cancel()
	params := gibDNSPatchParams{
		Key:  gibDNSKey{Owner: ensureDot(req.Owner), Type: req.RecordType},
		Add:  []string{req.RData},
		Zone: d.zone(),
	}
	if req.TTL > 0 {
		params.TTL = &req.TTL
		params.TTLPolicy = "exact"
	}
	return d.gibDNSClient().patch(ctx, params)
}

func (d *DNSExec) RemoveRecord(ctx context.Context, req EditRequest) error {
	ctx, cancel := contextWithTimeout(ctx, gibDNSOperationTimeout)
	defer cancel()
	return d.gibDNSClient().patch(ctx, gibDNSPatchParams{
		Key:    gibDNSKey{Owner: ensureDot(req.Owner), Type: req.RecordType},
		Remove: []string{req.RData},
		Zone:   d.zone(),
	})
}

func (d *DNSExec) gibDNSClient() *gibDNSClient {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.client == nil {
		d.client = &gibDNSClient{provider: d.Provider, out: d.Out}
	}
	return d.client
}

func (d *DNSExec) zone() string {
	if d.Provider == nil {
		return ""
	}
	zone := firstField(d.Provider, "zone")
	if zone == "" {
		return ""
	}
	return ensureDot(zone)
}

func dnsExecCleanupTimeout(timeout time.Duration) time.Duration {
	if timeout > 0 && timeout < defaultDNSExecCleanupWait {
		return timeout
	}
	return defaultDNSExecCleanupWait
}

type limitedOutput struct {
	Limit     int
	Truncated bool
	buf       bytes.Buffer
}

func (l *limitedOutput) Write(p []byte) (int, error) {
	if l.Limit <= 0 {
		return len(p), nil
	}
	remaining := l.Limit - l.buf.Len()
	if remaining <= 0 {
		l.Truncated = true
		return len(p), nil
	}
	if len(p) > remaining {
		_, _ = l.buf.Write(p[:remaining])
		l.Truncated = true
		return len(p), nil
	}
	_, _ = l.buf.Write(p)
	return len(p), nil
}

func (l *limitedOutput) String() string {
	out := strings.TrimSpace(l.buf.String())
	if l.Truncated {
		if out != "" {
			out += "\n"
		}
		out += "... output truncated ..."
	}
	return out
}

func firstField(p *config.Provider, name string) string {
	vals := p.Fields[name]
	if len(vals) == 0 {
		return ""
	}
	return strings.Join(vals, " ")
}

func ensureDot(s string) string {
	if strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}
