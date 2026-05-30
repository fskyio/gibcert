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

package deploy

import (
	"encoding/pem"
	"fmt"
)

// CertPEMToDER concatenates the binary DER bodies of every CERTIFICATE block in
// the supplied PEM. Non-certificate blocks are skipped so the output is clean
// DER suitable for trust-store import. A leaf cert yields a single certificate;
// a chain yields the concatenated DER bodies.
func CertPEMToDER(p []byte) ([]byte, error) {
	var out []byte
	for {
		var block *pem.Block
		block, p = pem.Decode(p)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			out = append(out, block.Bytes...)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no certificate found to convert to der")
	}
	return out, nil
}

// KeyPEMToDER returns the binary DER body of the first private-key PEM block.
// The on-disk key encoding (PKCS#8, PKCS#1, SEC1) is preserved as-is; only the
// PEM armor is removed.
func KeyPEMToDER(p []byte) ([]byte, error) {
	block, _ := pem.Decode(p)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found to convert to der")
	}
	return block.Bytes, nil
}
