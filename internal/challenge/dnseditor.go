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
