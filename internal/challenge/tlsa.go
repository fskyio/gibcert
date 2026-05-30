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
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"strings"
)

// TLSARData returns the presentation-format rdata for a TLSA record, e.g.
// "3 1 1 abcdef...". data should already be the matched hash for the given
// matching type.
func TLSARData(usage, selector, matchingType int, data []byte) string {
	return fmt.Sprintf("%d %d %d %x", usage, selector, matchingType, data)
}

// TLSAOwner returns the DNS owner name for a TLSA record, with trailing dot.
// example: TLSAOwner(443, "tcp", "example.com") -> "_443._tcp.example.com."
func TLSAOwner(port int, protocol, name string) string {
	name = strings.TrimSuffix(name, ".")
	return fmt.Sprintf("_%d._%s.%s.", port, strings.ToLower(protocol), name)
}

// SPKIHash returns the hash of the SubjectPublicKeyInfo for the given public
// key. matchingType must be 1 (SHA-256) or 2 (SHA-512).
func SPKIHash(key crypto.PublicKey, matchingType int) ([]byte, error) {
	spki, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal SubjectPublicKeyInfo: %w", err)
	}
	switch matchingType {
	case 1:
		h := sha256.Sum256(spki)
		return h[:], nil
	case 2:
		h := sha512.Sum512(spki)
		return h[:], nil
	}
	return nil, fmt.Errorf("unsupported TLSA matching type %d", matchingType)
}
