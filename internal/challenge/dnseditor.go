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
	"slices"
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

// Capabilities describes what a provider reports for the DNS record provider
// protocol capabilities operation. Reported is false when the provider did not
// produce any recognized capability output (for example because it does not
// implement the operation), in which case the other fields are not meaningful.
type Capabilities struct {
	Protocol   string
	Bindings   []string
	Operations []string
	Types      []string
	Reported   bool
}

// Supports reports whether the provider advertised the named operation.
func (c Capabilities) Supports(operation string) bool {
	return slices.Contains(c.Operations, operation)
}

// SupportsType reports whether the provider advertised the named record type.
func (c Capabilities) SupportsType(recordType string) bool {
	return slices.Contains(c.Types, recordType)
}

// CapabilityReporter is implemented by editors that can report which operations
// and record types they support via the protocol capabilities operation.
type CapabilityReporter interface {
	Capabilities(ctx context.Context) (Capabilities, error)
}

// EnsureEditorSupports fails fast when an editor explicitly advertises a
// capability set that omits the required operations or record type. The
// capabilities operation is optional: editors that cannot report capabilities,
// or whose probe fails, are allowed through, and the underlying operation
// surfaces any real lack of support later.
func EnsureEditorSupports(ctx context.Context, editor DNSEditor, recordType string, operations ...string) error {
	reporter, ok := editor.(CapabilityReporter)
	if !ok {
		return nil
	}
	caps, err := reporter.Capabilities(ctx)
	if err != nil || !caps.Reported {
		return nil
	}
	for _, op := range operations {
		if !caps.Supports(op) {
			return fmt.Errorf("provider does not support the %q operation (advertises: %s)",
				op, strings.Join(caps.Operations, " "))
		}
	}
	if recordType != "" && len(caps.Types) > 0 && !caps.SupportsType(recordType) {
		return fmt.Errorf("provider does not support %s records (advertises: %s)",
			recordType, strings.Join(caps.Types, " "))
	}
	return nil
}
