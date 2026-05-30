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

package preflight

import (
	"strings"
	"testing"

	"foundry.fsky.io/fsky/gibcert/internal/config"
)

func TestCheckHTTP01Webroot(t *testing.T) {
	cfg := &config.Config{
		Accounts: []*config.Account{{Name: "a", Directory: "https://example.invalid/directory"}},
		Certificates: []*config.Certificate{{
			Name:    "example.com",
			Account: "a",
			Names:   []string{"example.com"},
			Challenge: config.ChallengeSpec{
				Type:    "http-01",
				Webroot: t.TempDir(),
			},
			Deploys: []*config.Deploy{{Name: "d", Cert: "/tmp/cert.pem"}},
		}},
	}
	if err := Check(cfg); err != nil {
		t.Fatalf("Check: %v", err)
	}
}

func TestCheckRejectsMissingHTTP01Webroot(t *testing.T) {
	cfg := &config.Config{
		Accounts: []*config.Account{{Name: "a", Directory: "https://example.invalid/directory"}},
		Certificates: []*config.Certificate{{
			Name:    "example.com",
			Account: "a",
			Names:   []string{"example.com"},
			Challenge: config.ChallengeSpec{
				Type:    "http-01",
				Webroot: "/definitely/not/a/real/gibcert/webroot",
			},
			Deploys: []*config.Deploy{{Name: "d", Cert: "/tmp/cert.pem"}},
		}},
	}
	err := Check(cfg)
	if err == nil {
		t.Fatal("Check succeeded, want error")
	}
	if !strings.Contains(err.Error(), "webroot") {
		t.Fatalf("error %q does not mention webroot", err)
	}
}
