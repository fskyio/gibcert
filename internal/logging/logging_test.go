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

package logging

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestLoggerJSONFormat(t *testing.T) {
	var buf bytes.Buffer
	l, err := New(Options{Format: "json", Stderr: &buf})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	l.Error("command failed", "error", "boom")

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("json log %q: %v", buf.String(), err)
	}
	if entry["level"] != "ERROR" {
		t.Fatalf("level got %v, want ERROR", entry["level"])
	}
	if entry["msg"] != "command failed" {
		t.Fatalf("msg got %v, want command failed", entry["msg"])
	}
	if entry["error"] != "boom" {
		t.Fatalf("error got %v, want boom", entry["error"])
	}
}

func TestLoggerRejectsUnknownFormat(t *testing.T) {
	_, err := New(Options{Format: "xml"})
	if err == nil {
		t.Fatal("New got nil error, want unsupported format")
	}
	if !strings.Contains(err.Error(), "unsupported log format") {
		t.Fatalf("error got %q, want unsupported log format", err)
	}
}

func TestLoggerTextInfoWarnAndClose(t *testing.T) {
	var buf bytes.Buffer
	l, err := New(Options{Format: "text", Stderr: &buf})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	l.Info("ready", "cert", "example.com")
	l.Warn("careful", "reason", "test")
	out := buf.String()
	if !strings.Contains(out, "level=INFO") || !strings.Contains(out, "msg=ready") {
		t.Fatalf("info log missing from %q", out)
	}
	if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "msg=careful") {
		t.Fatalf("warn log missing from %q", out)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := (*Logger)(nil).Close(); err != nil {
		t.Fatalf("nil Close: %v", err)
	}
}

func TestLoggerClosePropagatesCloserError(t *testing.T) {
	want := errors.New("close failed")
	l := &Logger{closer: errCloser{err: want}}
	if err := l.Close(); !errors.Is(err, want) {
		t.Fatalf("Close got %v, want %v", err, want)
	}
}

type errCloser struct {
	err error
}

func (c errCloser) Close() error {
	return c.err
}
