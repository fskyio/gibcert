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

// Package remote sends deploy requests to other machines by running
// "gibcert receive" there through the system ssh client. Using ssh rather than
// an embedded client keeps the user's ssh_config, agent, jump hosts, and
// hardware keys working, and adds no dependencies.
package remote

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"gitfield.org/fsky/gibcert/internal/config"
	"gitfield.org/fsky/gibcert/internal/deploy"
	"gitfield.org/fsky/gibcert/internal/receive"
)

// maxCaptureBytes bounds how much ssh output is kept per call.
const maxCaptureBytes = 1 << 20

// Client runs deploy requests on remote hosts.
type Client struct {
	// SSH is the ssh program. Empty means "ssh" found on PATH.
	SSH string
}

var _ deploy.Remote = (*Client)(nil)

// Error is a failure reported by a receiver, as opposed to a failure to reach
// one.
type Error struct {
	Host    string
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Message }

// Apply sends req to host. With dryRun the receiver stages and discards it.
// Hook output and warnings the receiver produced are written to out, one line
// at a time, prefixed with the host name.
func (c *Client) Apply(host *config.Host, req deploy.Request, dryRun bool, out io.Writer) (deploy.Result, error) {
	op := receive.OpApply
	if dryRun {
		op = receive.OpCheck
	}
	resp, stderr, err := c.call(host, receive.Envelope{Protocol: receive.ProtocolVersion, Op: op, Request: &req})
	if err != nil {
		return deploy.Result{}, err
	}
	if out != nil {
		writePrefixed(out, host.Name, stderr)
	}
	if !resp.OK {
		return deploy.Result{}, responseError(host, resp)
	}
	return deploy.Result{Target: req.Target, Host: host.Name, Changed: resp.Changed}, nil
}

// Hello asks the receiver on host to identify itself, which proves that the
// connection, the host key, the login, and the gibcert installation all work.
func (c *Client) Hello(host *config.Host) (*receive.Hello, error) {
	resp, _, err := c.call(host, receive.Envelope{Protocol: receive.ProtocolVersion, Op: receive.OpHello})
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, responseError(host, resp)
	}
	if resp.Hello == nil {
		return nil, fmt.Errorf("host %q: receiver sent no identity", host.Name)
	}
	return resp.Hello, nil
}

func responseError(host *config.Host, resp *receive.Response) error {
	if resp.Error == nil {
		return &Error{Host: host.Name, Code: receive.CodeFailed, Message: "receiver reported failure without a reason"}
	}
	return &Error{Host: host.Name, Code: resp.Error.Code, Message: resp.Error.Message}
}

// call runs one receiver round trip. It returns a nil error only when the
// receiver produced a protocol response, whether or not that response reports
// success; stderr is whatever the remote side wrote to its stderr.
func (c *Client) call(host *config.Host, env receive.Envelope) (*receive.Response, string, error) {
	payload, err := json.Marshal(env)
	if err != nil {
		return nil, "", fmt.Errorf("encode request: %w", err)
	}
	program := c.SSH
	if program == "" {
		program, err = exec.LookPath("ssh")
		if err != nil {
			return nil, "", errors.New("ssh client not found in PATH; deploying to a host requires an OpenSSH client")
		}
	}
	args, err := sshArgs(host)
	if err != nil {
		return nil, "", fmt.Errorf("host %q: %w", host.Name, err)
	}
	cmd := exec.Command(program, args...)
	cmd.Stdin = bytes.NewReader(payload)
	var stdout, stderr capture
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()

	if resp := parseResponse(stdout.buf.Bytes()); resp != nil {
		return resp, stderr.buf.String(), nil
	}
	return nil, "", unreachable(host, runErr, stderr.buf.String())
}

// sshArgs builds the ssh command line. Host key checking is always strict and
// prompts are disabled: gibcert runs unattended, so an unknown or changed key
// must fail rather than be trusted or asked about.
func sshArgs(h *config.Host) ([]string, error) {
	timeout := h.Timeout
	if timeout <= 0 {
		timeout = config.DefaultHostTimeout
	}
	seconds := int((timeout + time.Second - 1) / time.Second)
	args := []string{
		"-T",
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "ConnectTimeout=" + strconv.Itoa(seconds),
		"-o", "ServerAliveInterval=15",
		"-o", "ServerAliveCountMax=4",
	}
	if h.KnownHosts != "" {
		v, err := sshOptionValue(h.KnownHosts)
		if err != nil {
			return nil, fmt.Errorf("known-hosts: %w", err)
		}
		args = append(args, "-o", "UserKnownHostsFile="+v)
	}
	if h.IdentityFile != "" {
		args = append(args, "-i", h.IdentityFile, "-o", "IdentitiesOnly=yes")
	}
	if h.Port != 0 {
		args = append(args, "-p", strconv.Itoa(h.Port))
	}
	if h.User != "" {
		args = append(args, "-l", h.User)
	}
	command := h.RemoteCommand
	if command == "" {
		command = config.DefaultHostRemoteCommand
	}
	return append(args, "--", h.Address, command+" receive"), nil
}

// sshOptionValue quotes v for use in an ssh -o option, which is parsed like a
// line of ssh_config.
func sshOptionValue(v string) (string, error) {
	if strings.ContainsAny(v, "\"\\\r\n") {
		return "", fmt.Errorf("path %q contains an unsupported character", v)
	}
	if strings.ContainsAny(v, " \t") {
		return `"` + v + `"`, nil
	}
	return v, nil
}

// parseResponse finds the receiver's Response in stdout. A login shell may print
// to stdout before the receiver starts, so the last line that decodes as a
// response wins.
func parseResponse(stdout []byte) *receive.Response {
	lines := bytes.Split(bytes.TrimSpace(stdout), []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		var resp receive.Response
		if err := json.Unmarshal(bytes.TrimSpace(lines[i]), &resp); err == nil && resp.Protocol != 0 {
			return &resp
		}
	}
	return nil
}

// unreachable explains a call that produced no protocol response.
func unreachable(host *config.Host, runErr error, stderr string) error {
	detail := lastLines(stderr, 3)
	var exit *exec.ExitError
	msg := fmt.Sprintf("host %q (%s): ssh failed", host.Name, host.Address)
	switch {
	case errors.As(runErr, &exit) && exit.ExitCode() == 127:
		command := host.RemoteCommand
		if command == "" {
			command = config.DefaultHostRemoteCommand
		}
		msg = fmt.Sprintf("host %q (%s): %q was not found on the host; install gibcert there or set remote-command", host.Name, host.Address, command)
	case errors.As(runErr, &exit) && exit.ExitCode() != 255:
		msg = fmt.Sprintf("host %q (%s): remote command exited %d without a receiver response; the gibcert there may be too old to support \"receive\"", host.Name, host.Address, exit.ExitCode())
	case runErr != nil && !errors.As(runErr, &exit):
		msg = fmt.Sprintf("host %q (%s): run ssh: %v", host.Name, host.Address, runErr)
	}
	if detail != "" {
		return fmt.Errorf("%s: %s", msg, detail)
	}
	return errors.New(msg)
}

// lastLines returns the last n non-empty lines of s joined into one line, so
// an ssh failure reads as a single message wherever it is printed.
func lastLines(s string, n int) string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "; ")
}

// writePrefixed copies text to w, prefixing every line with "name: ".
func writePrefixed(w io.Writer, name, text string) {
	for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		if line != "" {
			fmt.Fprintf(w, "%s: %s\n", name, line)
		}
	}
}

// capture is a bounded output buffer: bytes past maxCaptureBytes are dropped.
type capture struct{ buf bytes.Buffer }

func (c *capture) Write(p []byte) (int, error) {
	if room := maxCaptureBytes - c.buf.Len(); room > 0 {
		c.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}
