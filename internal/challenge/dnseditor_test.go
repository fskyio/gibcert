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
	"errors"
	"slices"
	"strings"
	"testing"
)

// recordingEditor implements only DNSEditor, so ApplyEdits must fall back to
// one call per op.
type recordingEditor struct {
	calls  []string
	failOn string
}

func (e *recordingEditor) AddRecord(_ context.Context, req EditRequest) error {
	return e.record("add", req)
}

func (e *recordingEditor) RemoveRecord(_ context.Context, req EditRequest) error {
	return e.record("remove", req)
}

func (e *recordingEditor) record(verb string, req EditRequest) error {
	e.calls = append(e.calls, verb+" "+req.Owner)
	if req.Owner == e.failOn {
		return errors.New("provider refused")
	}
	return nil
}

func TestApplyEditsFallbackAppliesInOrderAndKeepsGoingAfterFailure(t *testing.T) {
	editor := &recordingEditor{failOn: "b.example.com."}
	ops := []EditOp{
		{EditRequest: EditRequest{Owner: "a.example.com.", RecordType: "TLSA"}},
		{EditRequest: EditRequest{Owner: "b.example.com.", RecordType: "TLSA"}},
		{Remove: true, EditRequest: EditRequest{Owner: "c.example.com.", RecordType: "TLSA"}},
	}
	err := ApplyEdits(context.Background(), editor, ops)
	want := []string{"add a.example.com.", "add b.example.com.", "remove c.example.com."}
	if !slices.Equal(editor.calls, want) {
		t.Fatalf("calls = %v, want %v", editor.calls, want)
	}
	if err == nil || !strings.Contains(err.Error(), "add b.example.com. TLSA: provider refused") {
		t.Fatalf("error = %v, want the failing op named", err)
	}
}
