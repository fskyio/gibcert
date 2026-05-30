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
	"bufio"
	"context"
	"fmt"
	"io"
)

type DNSManual struct {
	In  io.Reader
	Out io.Writer
}

func (d *DNSManual) Present(_ context.Context, req Request) (func(), error) {
	fmt.Fprintln(d.Out)
	fmt.Fprintln(d.Out, "DNS-01 manual challenge:")
	fmt.Fprintln(d.Out, "  create this TXT record and wait for it to propagate to your authoritative nameservers:")
	fmt.Fprintln(d.Out)
	fmt.Fprintf(d.Out, "    %s.  IN TXT  %q\n", req.FQDN, req.Value)
	fmt.Fprintln(d.Out)
	fmt.Fprint(d.Out, "press enter when the record is live: ")
	r := bufio.NewReader(d.In)
	if _, err := r.ReadString('\n'); err != nil {
		return nil, fmt.Errorf("read confirmation: %w", err)
	}
	cleanup := func() {
		fmt.Fprintln(d.Out)
		fmt.Fprintln(d.Out, "DNS-01 manual challenge cleanup:")
		fmt.Fprintf(d.Out, "  you may now remove the TXT record at %s.\n", req.FQDN)
	}
	return cleanup, nil
}
