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
