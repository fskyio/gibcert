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
	"os"

	"foundry.fsky.io/fsky/gibcert/internal/storage"
)

type UndeployResult struct {
	Path   string
	Kind   string
	Target string
	Status string
}

func Undeploy(certName string, store *storage.Store) ([]UndeployResult, error) {
	meta, err := store.LoadCertMeta(certName)
	if err != nil {
		return nil, fmt.Errorf("load cert metadata: %w", err)
	}

	var results []UndeployResult
	seen := map[string]bool{}
	for _, rec := range meta.Deploys {
		if rec.Path == "" || seen[rec.Path] {
			continue
		}
		seen[rec.Path] = true
		r := UndeployResult{Path: rec.Path, Kind: rec.Kind, Target: rec.Target}
		data, err := os.ReadFile(rec.Path)
		if errors.Is(err, os.ErrNotExist) {
			r.Status = "missing"
			results = append(results, r)
			continue
		}
		if err != nil {
			return results, fmt.Errorf("%s: %w", rec.Path, err)
		}
		if storage.SHA256Hex(data) != rec.SHA256 {
			r.Status = "skipped: content changed"
			results = append(results, r)
			continue
		}
		if err := os.Remove(rec.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return results, fmt.Errorf("%s: %w", rec.Path, err)
		}
		r.Status = "removed"
		results = append(results, r)
	}
	return results, nil
}
