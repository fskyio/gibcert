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

package storage

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"foundry.fsky.io/fsky/gibcert/internal/config"
)

func GenerateAccountKey() (crypto.Signer, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func GenerateKey(spec config.KeySpec) (crypto.Signer, error) {
	switch spec.Type {
	case "", "ecdsa":
		curve := elliptic.P256()
		if spec.Curve == "p384" {
			curve = elliptic.P384()
		}
		return ecdsa.GenerateKey(curve, rand.Reader)
	case "rsa":
		bits := spec.Bits
		if bits == 0 {
			bits = 2048
		}
		return rsa.GenerateKey(rand.Reader, bits)
	}
	return nil, fmt.Errorf("unsupported key type %q", spec.Type)
}

func WriteKey(path string, key crypto.Signer) error {
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b})
	return writeFileAtomic(path, pemBytes, 0o600)
}

func ReadKey(path string) (crypto.Signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		k2, err2 := x509.ParseECPrivateKey(block.Bytes)
		if err2 == nil {
			return k2, nil
		}
		return nil, err
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("key does not implement crypto.Signer")
	}
	return signer, nil
}

func WriteCertChainDER(path string, chain [][]byte, mode os.FileMode) error {
	var out []byte
	for _, der := range chain {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return writeFileAtomic(path, out, mode)
}

func WriteSingleCertDER(path string, der []byte, mode os.FileMode) error {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return writeFileAtomic(path, pemBytes, mode)
}
