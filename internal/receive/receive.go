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

// Package receive implements the remote end of cross-machine deployment. A
// controller runs "gibcert receive" on the target host over SSH, writes one
// JSON Envelope to its stdin, and reads one JSON Response from its stdout. The
// receiver applies the request with the same staging, rollback, and hook code
// as a local deploy, as the user it was started as. It never escalates: the
// files it writes are limited to what that user may write.
//
// Stdout carries only the Response. Hook output and warnings go to stderr.
package receive

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"runtime"

	"gitfield.org/fsky/gibcert/internal/buildinfo"
	"gitfield.org/fsky/gibcert/internal/deploy"
)

// ProtocolVersion is the wire protocol version. The sender and the receiver
// must agree exactly; a mismatch is reported instead of guessed around.
const ProtocolVersion = 1

// maxEnvelopeBytes bounds the request a receiver reads, so a misbehaving
// sender cannot make it buffer without limit.
const maxEnvelopeBytes = 32 << 20

// Operations.
const (
	// OpHello reports the receiver's version and identity and changes nothing.
	OpHello = "hello"
	// OpApply installs the request.
	OpApply = "apply"
	// OpCheck stages the request and discards it: nothing is installed and no
	// hook runs, but every permission the apply needs is exercised.
	OpCheck = "check"
)

// Error codes.
const (
	CodeProtocol   = "protocol"
	CodeInvalid    = "invalid"
	CodeDenied     = "denied"
	CodePermission = "permission"
	CodeFailed     = "failed"
)

// Envelope is the request a controller sends.
type Envelope struct {
	Protocol int             `json:"protocol"`
	Op       string          `json:"op"`
	Request  *deploy.Request `json:"request,omitempty"`
}

// Response is the receiver's single reply.
type Response struct {
	Protocol int      `json:"protocol"`
	OK       bool     `json:"ok"`
	Error    *Error   `json:"error,omitempty"`
	Hello    *Hello   `json:"hello,omitempty"`
	Changed  []string `json:"changed,omitempty"`
}

// Error describes why a request failed.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Message }

// Hello identifies a receiver.
type Hello struct {
	Version string `json:"version"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	UID     int    `json:"uid"`
	User    string `json:"user,omitempty"`
}

// Serve handles one request read from in, writes the Response to out, and
// returns the process exit status. Hook output and warnings go to errOut.
func Serve(in io.Reader, out, errOut io.Writer) int {
	ignoreHangup()
	resp := handle(in, errOut, os.Geteuid(), os.Getenv)
	resp.Protocol = ProtocolVersion
	if err := json.NewEncoder(out).Encode(resp); err != nil {
		fmt.Fprintf(errOut, "gibcert receive: write response: %v\n", err)
		return 1
	}
	if !resp.OK {
		return 1
	}
	return 0
}

func fail(code, format string, args ...any) Response {
	return Response{Error: &Error{Code: code, Message: fmt.Sprintf(format, args...)}}
}

func handle(in io.Reader, errOut io.Writer, euid int, getenv func(string) string) Response {
	if err := refuseEscalation(euid, getenv); err != nil {
		return fail(CodeDenied, "%v", err)
	}
	raw, err := io.ReadAll(io.LimitReader(in, maxEnvelopeBytes+1))
	if err != nil {
		return fail(CodeInvalid, "read request: %v", err)
	}
	if len(raw) > maxEnvelopeBytes {
		return fail(CodeInvalid, "request exceeds %d bytes", maxEnvelopeBytes)
	}
	var env Envelope
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return fail(CodeInvalid, "decode request: %v", err)
	}
	if env.Protocol != ProtocolVersion {
		return fail(CodeProtocol, "sender speaks protocol %d, this gibcert %s speaks %d; install a matching gibcert on this host",
			env.Protocol, buildinfo.Version, ProtocolVersion)
	}
	switch env.Op {
	case OpHello:
		return Response{OK: true, Hello: hello(euid)}
	case OpApply, OpCheck:
		return apply(env, errOut, euid)
	default:
		return fail(CodeInvalid, "unknown operation %q", env.Op)
	}
}

func apply(env Envelope, errOut io.Writer, euid int) Response {
	req := env.Request
	if req == nil {
		return fail(CodeInvalid, "%s requires a request", env.Op)
	}
	if req.Cert == "" || req.Target == "" {
		return fail(CodeInvalid, "request needs a certificate and a target name")
	}
	if err := req.Validate(); err != nil {
		return fail(CodeInvalid, "%v", err)
	}
	res, err := deploy.Apply(*req, deploy.ApplyOptions{
		Out:            errOut,
		HookStdout:     errOut,
		HookStderr:     errOut,
		DryRun:         env.Op == OpCheck,
		RefuseSymlinks: true,
	})
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return fail(CodePermission, "%v (gibcert receive runs as uid %d)", err, euid)
		}
		return fail(CodeFailed, "%v", err)
	}
	return Response{OK: true, Changed: res.Changed}
}

func hello(euid int) *Hello {
	h := &Hello{Version: buildinfo.Version, OS: runtime.GOOS, Arch: runtime.GOARCH, UID: euid}
	if u, err := user.Current(); err == nil {
		h.User = u.Username
	}
	return h
}

// refuseEscalation rejects a receiver started as root through sudo or doas.
// The receiver executes whatever hook commands the sender names, so root
// reached through a sudo rule for it would be an unrestricted root shell for
// anyone holding the deploy key. Logging in as root directly is an explicit
// decision to trust the controller with root and is allowed. This is a guard
// against a risky setup, not a security boundary: it cannot stop a user who
// already has root.
func refuseEscalation(euid int, getenv func(string) string) error {
	if euid != 0 {
		return nil
	}
	if getenv("SUDO_USER") != "" || getenv("DOAS_USER") != "" {
		return errors.New("gibcert receive does not run under sudo or doas; connect as the user that should own the deployed files, or as root directly")
	}
	return nil
}
