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
	"fmt"
	"strings"
)

type EditRequest struct {
	Owner      string
	RecordType string
	RData      string
	TTL        int
}

type DNSEditor interface {
	AddRecord(ctx context.Context, req EditRequest) error
	RemoveRecord(ctx context.Context, req EditRequest) error
}

// EditOp is one record change inside a batch. A zero Remove adds the record.
type EditOp struct {
	Remove bool
	EditRequest
}

// BatchEditor is implemented by editors that can apply several record changes
// in fewer round trips than one AddRecord or RemoveRecord call per record.
type BatchEditor interface {
	// ApplyEdits applies ops in order. Ops that touch the same RRset are
	// merged, so the result matches applying them one at a time.
	ApplyEdits(ctx context.Context, ops []EditOp) error
}

// ApplyEdits applies ops through editor, using its batch support when it has
// any. Editors without it get one call per op. That fallback attempts every
// op even after a failure, so one persistently failing record cannot hide the
// rest, and returns all failures joined. Ops must be idempotent, which
// AddRecord and RemoveRecord already are.
func ApplyEdits(ctx context.Context, editor DNSEditor, ops []EditOp) error {
	if len(ops) == 0 {
		return nil
	}
	if batch, ok := editor.(BatchEditor); ok {
		return batch.ApplyEdits(ctx, ops)
	}
	return applyEditsSequentially(ctx, editor, ops)
}

func applyEditsSequentially(ctx context.Context, editor DNSEditor, ops []EditOp) error {
	var errs []error
	for _, op := range ops {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		verb := "add"
		call := editor.AddRecord
		if op.Remove {
			verb = "remove"
			call = editor.RemoveRecord
		}
		if err := call(ctx, op.EditRequest); err != nil {
			errs = append(errs, fmt.Errorf("%s %s %s: %w", verb, op.Owner, op.RecordType, err))
		}
	}
	return errors.Join(errs...)
}

// CapabilityReporter is implemented by editors that can report which operations
// and record types they support via gibdns capability discovery.
type CapabilityReporter interface {
	Capabilities(ctx context.Context) (GibDNSCapabilities, error)
}

// EnsureEditorSupports fails fast when an editor advertises a capability set
// that omits the required methods or record type. Editors without capability
// discovery, such as built-in DNS drivers, are allowed through.
func EnsureEditorSupports(ctx context.Context, editor DNSEditor, recordType string, operations ...string) error {
	reporter, ok := editor.(CapabilityReporter)
	if !ok {
		return nil
	}
	caps, err := reporter.Capabilities(ctx)
	if err != nil {
		return err
	}
	for _, op := range operations {
		if !caps.Supports(op) {
			return fmt.Errorf("provider does not support the %q operation (advertises: %s)",
				op, strings.Join(caps.Methods, " "))
		}
	}
	if recordType != "" && !caps.SupportsType(recordType) {
		return fmt.Errorf("provider does not support %s records (advertises: %s)",
			recordType, strings.Join(caps.RecordTypes, " "))
	}
	return nil
}
