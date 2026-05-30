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
	"bytes"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
)

func TestCertPEMToDER(t *testing.T) {
	key, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1)}
	der, err := x509.CreateCertificate(cryptorand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	// A single cert round-trips to its exact DER body.
	got, err := CertPEMToDER(certPEM)
	if err != nil {
		t.Fatalf("CertPEMToDER: %v", err)
	}
	if !bytes.Equal(got, der) {
		t.Fatalf("CertPEMToDER did not return the original DER bytes")
	}

	// Non-certificate blocks are skipped; a chain concatenates DER bodies.
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("ignored")})
	mixed := append(append([]byte{}, keyPEM...), certPEM...)
	mixed = append(mixed, certPEM...)
	got, err = CertPEMToDER(mixed)
	if err != nil {
		t.Fatalf("CertPEMToDER chain: %v", err)
	}
	if want := append(append([]byte{}, der...), der...); !bytes.Equal(got, want) {
		t.Fatalf("CertPEMToDER chain mismatch")
	}

	// No certificate present is an error.
	if _, err := CertPEMToDER(keyPEM); err == nil {
		t.Fatal("CertPEMToDER with no certificate: expected error, got nil")
	}
}

func TestKeyPEMToDER(t *testing.T) {
	key, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})

	got, err := KeyPEMToDER(keyPEM)
	if err != nil {
		t.Fatalf("KeyPEMToDER: %v", err)
	}
	if !bytes.Equal(got, pkcs8) {
		t.Fatalf("KeyPEMToDER did not preserve the DER key body")
	}

	if _, err := KeyPEMToDER([]byte("not pem")); err == nil {
		t.Fatal("KeyPEMToDER with no PEM block: expected error, got nil")
	}
}
