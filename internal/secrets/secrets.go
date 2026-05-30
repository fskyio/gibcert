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

package secrets

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	DefaultCommandTimeout = 10 * time.Second
	commandOutputLimit    = 64 * 1024
)

type Source struct {
	File              string
	Value             string
	Env               string
	Command           []string
	SystemdCredential string
}

func (s Source) Resolve(ctx context.Context) (string, error) {
	switch {
	case s.Value != "":
		return s.Value, nil
	case s.File != "":
		return readSecretFile(s.File)
	case s.Env != "":
		v, ok := os.LookupEnv(s.Env)
		if !ok {
			return "", fmt.Errorf("environment variable %q is not set", s.Env)
		}
		return v, nil
	case len(s.Command) > 0:
		return runSecretCommand(ctx, s.Command)
	case s.SystemdCredential != "":
		path, err := s.SystemdCredentialPath()
		if err != nil {
			return "", err
		}
		return readSecretFile(path)
	default:
		return "", errors.New("empty secret source")
	}
}

func (s Source) SystemdCredentialPath() (string, error) {
	if s.SystemdCredential == "" {
		return "", errors.New("empty systemd credential name")
	}
	if filepath.Base(s.SystemdCredential) != s.SystemdCredential {
		return "", fmt.Errorf("systemd credential %q must be a file name", s.SystemdCredential)
	}
	dir := os.Getenv("CREDENTIALS_DIRECTORY")
	if dir == "" {
		return "", errors.New("CREDENTIALS_DIRECTORY is not set")
	}
	return filepath.Join(dir, s.SystemdCredential), nil
}

func readSecretFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read secret file %q: %w", path, err)
	}
	return strings.TrimSpace(string(b)), nil
}

func runSecretCommand(ctx context.Context, argv []string) (string, error) {
	if len(argv) == 0 {
		return "", errors.New("empty secret command")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cctx, cancel := context.WithTimeout(ctx, DefaultCommandTimeout)
	defer cancel()

	var stdout limitedBuffer
	stdout.Limit = commandOutputLimit
	cmd := exec.CommandContext(cctx, argv[0], argv[1:]...)
	cmd.Stdout = &stdout
	cmd.Stderr = ioDiscard{}
	if err := cmd.Run(); err != nil {
		if errors.Is(cctx.Err(), context.DeadlineExceeded) {
			return "", fmt.Errorf("secret command timed out after %s", DefaultCommandTimeout)
		}
		return "", fmt.Errorf("secret command %q failed: %w", argv[0], err)
	}
	if stdout.Truncated {
		return "", fmt.Errorf("secret command %q output exceeds %d bytes", argv[0], commandOutputLimit)
	}
	return strings.TrimRight(stdout.buf.String(), "\r\n"), nil
}

type limitedBuffer struct {
	Limit     int
	Truncated bool
	buf       bytes.Buffer
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
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

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) {
	return len(p), nil
}
