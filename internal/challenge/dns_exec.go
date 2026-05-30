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
	"os"
	"os/exec"
	"strings"
	"time"

	"foundry.fsky.io/fsky/gibcert/internal/config"
)

type DNSExec struct {
	Provider *config.Provider
	Out      io.Writer
}

const (
	// DNSRecProtocolVersion is the DNS record provider protocol version
	// exported as DNSREC_PROTOCOL. See docs/dns-record-protocol.md.
	DNSRecProtocolVersion     = "1"
	dnsExecOutputLimit        = 32 * 1024
	defaultDNSExecCleanupWait = 30 * time.Second
)

func (d *DNSExec) Present(ctx context.Context, req Request) (func(), error) {
	if err := d.runChallenge(ctx, "present", req); err != nil {
		return nil, err
	}
	return func() {
		cctx, cancel := context.WithTimeout(context.Background(), dnsExecCleanupTimeout(req.Timeout))
		defer cancel()
		if err := d.runChallenge(cctx, "cleanup", req); err != nil && d.Out != nil {
			fmt.Fprintf(d.Out, "warning: dns exec cleanup failed: %v\n", err)
		}
	}, nil
}

// Capabilities runs the optional capabilities operation and parses its
// line-oriented output. An error means the provider could not report
// capabilities (for example it does not implement the operation); callers
// should treat that as "unknown" rather than "unsupported".
func (d *DNSExec) Capabilities(ctx context.Context) (Capabilities, error) {
	cmd, err := d.command(ctx, "capabilities")
	if err != nil {
		return Capabilities{}, err
	}
	prepareCommand(cmd)
	providerEnv, err := d.providerEnv(ctx)
	if err != nil {
		return Capabilities{}, err
	}
	cmd.Env = append(os.Environ(), append([]string{
		"DNSREC_PROTOCOL=" + DNSRecProtocolVersion,
		"DNSREC_OPERATION=capabilities",
	}, providerEnv...)...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return Capabilities{}, fmt.Errorf("exec dns capabilities: %w", err)
	}
	return parseCapabilities(stdout.String()), nil
}

func parseCapabilities(s string) Capabilities {
	var caps Capabilities
	for _, line := range strings.Split(s, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		key, vals := fields[0], fields[1:]
		switch key {
		case "protocol":
			if len(vals) > 0 {
				caps.Protocol = vals[0]
			}
			caps.Reported = true
		case "binding":
			caps.Bindings = append(caps.Bindings, vals...)
			caps.Reported = true
		case "operations":
			caps.Operations = append(caps.Operations, vals...)
			caps.Reported = true
		case "types":
			caps.Types = append(caps.Types, vals...)
			caps.Reported = true
		}
	}
	return caps
}

func (d *DNSExec) AddRecord(ctx context.Context, req EditRequest) error {
	return d.runEdit(ctx, "add-record", req)
}

func (d *DNSExec) RemoveRecord(ctx context.Context, req EditRequest) error {
	return d.runEdit(ctx, "remove-record", req)
}

func (d *DNSExec) runChallenge(ctx context.Context, operation string, req Request) error {
	env, err := d.challengeEnv(ctx, operation, req)
	if err != nil {
		return err
	}
	return d.runCmd(ctx, operation, env)
}

func (d *DNSExec) runEdit(ctx context.Context, operation string, req EditRequest) error {
	env, err := d.editEnv(ctx, operation, req)
	if err != nil {
		return err
	}
	return d.runCmd(ctx, operation, env)
}

func (d *DNSExec) runCmd(ctx context.Context, operation string, env []string) error {
	cmd, err := d.command(ctx, operation)
	if err != nil {
		return err
	}
	prepareCommand(cmd)
	cmd.Env = append(os.Environ(), env...)
	var captured limitedOutput
	captured.Limit = dnsExecOutputLimit
	out := io.Writer(&captured)
	if d.Out != nil {
		out = io.MultiWriter(d.Out, &captured)
	}
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Run(); err != nil {
		if output := captured.String(); output != "" {
			return fmt.Errorf("exec dns %s: %w; output:\n%s", operation, err, output)
		}
		return fmt.Errorf("exec dns %s: %w", operation, err)
	}
	return nil
}

func (d *DNSExec) command(ctx context.Context, operation string) (*exec.Cmd, error) {
	if d.Provider == nil {
		return nil, fmt.Errorf("missing provider")
	}
	if command := firstField(d.Provider, "command"); command != "" {
		return exec.CommandContext(ctx, command, operation), nil
	}
	if command := firstField(d.Provider, operation); command != "" {
		return shellCommandContext(ctx, command), nil
	}
	return nil, fmt.Errorf("provider %q: exec driver requires command or %s field", d.Provider.Name, operation)
}

func (d *DNSExec) challengeEnv(ctx context.Context, operation string, req Request) ([]string, error) {
	env := []string{
		"DNSREC_PROTOCOL=" + DNSRecProtocolVersion,
		"DNSREC_OPERATION=" + operation,
		"DNSREC_RECORD_TYPE=TXT",
		"DNSREC_RECORD_OWNER=" + ensureDot(req.FQDN),
		"DNSREC_RECORD_RDATA=" + req.Value,
		"DNSREC_DOMAIN=" + req.Domain,
		"DNSREC_IDENTIFIER=" + req.Identifier,
		"DNSREC_TIMEOUT=" + fmt.Sprintf("%.0f", req.Timeout.Seconds()),
	}
	providerEnv, err := d.providerEnv(ctx)
	if err != nil {
		return nil, err
	}
	return append(env, providerEnv...), nil
}

func (d *DNSExec) editEnv(ctx context.Context, operation string, req EditRequest) ([]string, error) {
	env := []string{
		"DNSREC_PROTOCOL=" + DNSRecProtocolVersion,
		"DNSREC_OPERATION=" + operation,
		"DNSREC_RECORD_TYPE=" + req.RecordType,
		"DNSREC_RECORD_OWNER=" + ensureDot(req.Owner),
		"DNSREC_RECORD_RDATA=" + req.RData,
	}
	if req.TTL > 0 {
		env = append(env, fmt.Sprintf("DNSREC_RECORD_TTL=%d", req.TTL))
	}
	providerEnv, err := d.providerEnv(ctx)
	if err != nil {
		return nil, err
	}
	return append(env, providerEnv...), nil
}

func (d *DNSExec) providerEnv(ctx context.Context) ([]string, error) {
	var env []string
	for name, vals := range d.Provider.Fields {
		if name == "command" || name == "present" || name == "cleanup" ||
			name == "add-record" || name == "remove-record" {
			continue
		}
		env = append(env, "DNSREC_FIELD_"+envName(name)+"="+strings.Join(vals, " "))
	}
	for _, s := range d.Provider.Secrets {
		name := envName(s.Name)
		if s.File != "" {
			env = append(env, "DNSREC_SECRET_"+name+"_FILE="+s.File)
		}
		if s.Value != "" {
			env = append(env, "DNSREC_SECRET_"+name+"="+s.Value)
		}
		if s.Env != "" {
			value, err := providerSecretSource(s).Resolve(ctx)
			if err != nil {
				return nil, fmt.Errorf("secret %q: %w", s.Name, err)
			}
			env = append(env, "DNSREC_SECRET_"+name+"="+value)
		}
		if len(s.Command) > 0 {
			value, err := providerSecretSource(s).Resolve(ctx)
			if err != nil {
				return nil, fmt.Errorf("secret %q: %w", s.Name, err)
			}
			env = append(env, "DNSREC_SECRET_"+name+"="+value)
		}
		if s.SystemdCredential != "" {
			path, err := providerSecretSource(s).SystemdCredentialPath()
			if err != nil {
				return nil, fmt.Errorf("secret %q: %w", s.Name, err)
			}
			env = append(env, "DNSREC_SECRET_"+name+"_FILE="+path)
		}
	}
	return env, nil
}

func dnsExecCleanupTimeout(timeout time.Duration) time.Duration {
	if timeout > 0 {
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

func envName(name string) string {
	replacer := strings.NewReplacer("-", "_", ".", "_")
	return strings.ToUpper(replacer.Replace(name))
}

func ensureDot(s string) string {
	if strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}
