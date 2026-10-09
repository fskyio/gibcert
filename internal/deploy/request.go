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
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"gitfield.org/fsky/gibcert/internal/config"
	"gitfield.org/fsky/gibcert/internal/storage"
)

// fileKinds lists every kind of material a deploy target can install, in
// installation order.
var fileKinds = [6]struct {
	name        string
	defaultMode fs.FileMode
	hookEnv     string
}{
	{"cert", 0o644, "GIBCERT_CERT_PATH"},
	{"chain", 0o644, "GIBCERT_CHAIN_PATH"},
	{"fullchain", 0o644, "GIBCERT_FULLCHAIN_PATH"},
	{"key", 0o600, "GIBCERT_KEY_PATH"},
	{"cert-der", 0o644, "GIBCERT_CERT_DER_PATH"},
	{"key-der", 0o600, "GIBCERT_KEY_DER_PATH"},
}

func validKind(kind string) bool {
	for _, k := range fileKinds {
		if k.name == kind {
			return true
		}
	}
	return false
}

func privateKind(kind string) bool {
	return kind == "key" || kind == "key-der"
}

// Material is the canonical PEM material of one certificate.
type Material struct {
	Cert      []byte
	Chain     []byte
	Fullchain []byte
	Key       []byte
}

// File is one destination of a Request. A File with a Path but no Data is a
// configured destination for which there is no material; it is not written,
// but its path is still exported to hooks.
type File struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
	Data []byte `json:"data,omitempty"`
}

// Request is the complete, self-contained description of installing one deploy
// target's material on one machine. The same value is applied in-process for
// local deploys and sent to "gibcert receive" for remote ones, so both paths
// share one staging, rollback, and hook implementation.
type Request struct {
	Cert   string       `json:"cert"`
	Target string       `json:"target"`
	Files  []File       `json:"files"`
	Owner  string       `json:"owner,omitempty"`
	Group  string       `json:"group,omitempty"`
	Mode   *fs.FileMode `json:"mode,omitempty"`
	Before string       `json:"before,omitempty"`
	After  string       `json:"after,omitempty"`
	// Unseen lists the kinds the sender has no record of this target having
	// received. They count as changed when deciding whether to run the after
	// hook, which is how a hook that failed on an earlier attempt is retried.
	Unseen []string `json:"unseen,omitempty"`
}

// NewRequest builds the request that installs m for the deploy target d,
// converting to DER for any DER destinations. The returned request does not
// reference d.
func NewRequest(cert string, d *config.Deploy, m Material) (Request, error) {
	derCert, derKey, err := derVariants(d, m.Cert, m.Key)
	if err != nil {
		return Request{}, err
	}
	req := Request{
		Cert:   cert,
		Target: d.Name,
		Owner:  d.Owner,
		Group:  d.Group,
		Before: d.Before,
		After:  d.After,
	}
	if d.Mode != nil {
		mode := *d.Mode
		req.Mode = &mode
	}
	for _, f := range []File{
		{Kind: "cert", Path: d.Cert, Data: m.Cert},
		{Kind: "chain", Path: d.Chain, Data: m.Chain},
		{Kind: "fullchain", Path: d.Fullchain, Data: m.Fullchain},
		{Kind: "key", Path: d.Key, Data: m.Key},
		{Kind: "cert-der", Path: d.CertDER, Data: derCert},
		{Kind: "key-der", Path: d.KeyDER, Data: derKey},
	} {
		if f.Path != "" {
			req.Files = append(req.Files, f)
		}
	}
	return req, nil
}

// file returns the destination of the given kind, or a zero File when the
// request has none.
func (r Request) file(kind string) File {
	for _, f := range r.Files {
		if f.Kind == kind {
			return f
		}
	}
	return File{}
}

// Validate checks the structural invariants every request must satisfy before
// it touches the filesystem. It is run for local requests and, because a
// request received from another machine is not trusted, again by the receiver.
func (r Request) Validate() error {
	if r.Before != "" && r.After == "" {
		return errors.New("before hook requires an after hook for recovery")
	}
	for _, s := range []string{r.Cert, r.Target, r.Owner, r.Group, r.Before, r.After} {
		if strings.ContainsRune(s, 0) {
			return errors.New("request fields must not contain NUL")
		}
	}
	seenKind := map[string]bool{}
	seenPath := map[string]string{}
	hasKey := false
	for _, f := range r.Files {
		if !validKind(f.Kind) {
			return fmt.Errorf("unknown file kind %q", f.Kind)
		}
		if seenKind[f.Kind] {
			return fmt.Errorf("duplicate file kind %q", f.Kind)
		}
		seenKind[f.Kind] = true
		if f.Path == "" || strings.ContainsRune(f.Path, 0) || !filepath.IsAbs(f.Path) {
			return fmt.Errorf("%s: must be an absolute path, got %q", f.Kind, f.Path)
		}
		clean := filepath.Clean(f.Path)
		if other, ok := seenPath[clean]; ok {
			return fmt.Errorf("%s destination %q collides with %s", f.Kind, clean, other)
		}
		seenPath[clean] = f.Kind
		if privateKind(f.Kind) {
			hasKey = true
		}
	}
	if r.Mode != nil {
		if *r.Mode > 0o777 {
			return fmt.Errorf("mode %#o must be <= 0777", *r.Mode)
		}
		if hasKey && *r.Mode&0o117 != 0 {
			return fmt.Errorf("private-key mode must not permit other access or execution, got %#o", *r.Mode)
		}
	}
	for _, k := range r.Unseen {
		if !validKind(k) {
			return fmt.Errorf("unknown unseen kind %q", k)
		}
	}
	return nil
}

// Records returns the deploy metadata describing r as installed on host at the
// given time. Only destinations that carry material are recorded. An empty
// host means this machine.
func (r Request) Records(host string, at time.Time) []storage.CertDeployMeta {
	var records []storage.CertDeployMeta
	for _, k := range fileKinds {
		f := r.file(k.name)
		if f.Path == "" || len(f.Data) == 0 {
			continue
		}
		records = append(records, storage.CertDeployMeta{
			Target: r.Target, Host: host, Kind: f.Kind, Path: f.Path,
			SHA256: storage.SHA256Hex(f.Data), At: at,
		})
	}
	return records
}

// UnseenKinds returns the kinds of r that meta does not record as already
// installed, with identical content, on host.
func UnseenKinds(meta *storage.CertMeta, r Request, host string) []string {
	var kinds []string
	for _, rec := range r.Records(host, time.Time{}) {
		if !deployRecordCurrent(meta, rec) {
			kinds = append(kinds, rec.Kind)
		}
	}
	return kinds
}
