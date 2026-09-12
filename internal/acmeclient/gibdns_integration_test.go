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

package acmeclient

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"foundry.fsky.io/fsky/gibcert/internal/challenge"
	"foundry.fsky.io/fsky/gibcert/internal/config"
)

type pebbleGibDNSRequest struct {
	Version string          `json:"version"`
	ID      string          `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type pebbleGibDNSPatch struct {
	Key struct {
		Owner string `json:"owner"`
		Type  string `json:"type"`
	} `json:"key"`
	Add    []string `json:"add"`
	Remove []string `json:"remove"`
	Zone   string   `json:"zone"`
}

func newPebbleGibDNSProvider(t *testing.T) (*config.Provider, string) {
	logPath := filepath.Join(t.TempDir(), "dns.log")
	return &config.Provider{
		Name:   "exec",
		Type:   "dns",
		Driver: "exec",
		Fields: map[string][]string{
			"command": {os.Args[0], "-test.run=TestPebbleGibDNSProviderProcess", "--", logPath},
		},
	}, logPath
}

func TestPebbleGibDNSProviderProcess(t *testing.T) {
	separator := slices.Index(os.Args, "--")
	if separator < 0 {
		return
	}
	args := os.Args[separator+1:]
	if len(args) != 1 {
		os.Exit(2)
	}
	os.Exit(runPebbleGibDNSProvider(args[0]))
}

func runPebbleGibDNSProvider(logPath string) int {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		return 2
	}
	var req pebbleGibDNSRequest
	if err := json.Unmarshal(raw, &req); err != nil || req.Version != challenge.GibDNSProtocolVersion {
		return 2
	}
	if req.Method == "capabilities" {
		return writePebbleGibDNSResponse(0, map[string]any{
			"version": challenge.GibDNSProtocolVersion,
			"id":      req.ID,
			"ok":      true,
			"result": map[string]any{
				"provider":     map[string]string{"name": "pebble-test", "version": "1"},
				"methods":      []string{"capabilities", "rrset.patch"},
				"record_types": []string{"TXT"},
				"features": map[string]any{
					"zone_discovery":        true,
					"concurrent_safe_patch": true,
					"preconditions":         map[string]any{},
				},
			},
		})
	}
	if req.Method != "rrset.patch" {
		return 1
	}
	var patch pebbleGibDNSPatch
	if err := json.Unmarshal(req.Params, &patch); err != nil {
		return 2
	}
	op := "present"
	values := patch.Add
	if len(patch.Remove) != 0 {
		op = "cleanup"
		values = patch.Remove
	}
	if err := appendPebbleGibDNSLog(logPath, op+" "+patch.Key.Owner+"\n"); err != nil {
		return 2
	}
	zone := patch.Zone
	if zone == "" {
		zone = pebbleGibDNSEffectiveZone(patch.Key.Owner)
	}
	result := map[string]any{
		"changed": true,
		"exists":  len(patch.Add) != 0,
		"zone":    zone,
	}
	if len(patch.Add) != 0 {
		result["rrset"] = map[string]any{
			"owner": patch.Key.Owner,
			"type":  patch.Key.Type,
			"ttl":   60,
			"rdata": values,
		}
	}
	return writePebbleGibDNSResponse(0, map[string]any{
		"version": challenge.GibDNSProtocolVersion,
		"id":      req.ID,
		"ok":      true,
		"result":  result,
	})
}

func appendPebbleGibDNSLog(path, line string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.WriteString(f, line)
	return err
}

func writePebbleGibDNSResponse(status int, response any) int {
	if err := json.NewEncoder(os.Stdout).Encode(response); err != nil {
		return 2
	}
	return status
}

func pebbleGibDNSEffectiveZone(owner string) string {
	labels := strings.Split(strings.TrimSuffix(owner, "."), ".")
	if len(labels) < 2 {
		return "."
	}
	return strings.Join(labels[len(labels)-2:], ".") + "."
}
