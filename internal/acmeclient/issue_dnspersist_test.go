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
	"context"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"gitfield.org/fsky/gibcert/internal/acme"
	"gitfield.org/fsky/gibcert/internal/challenge"
	"gitfield.org/fsky/gibcert/internal/config"
)

func TestIssueDNSPersistWildcardAuthorizationPolicy(t *testing.T) {
	const accountURI = "https://ca.example/acct/1"
	for _, alias := range []struct {
		name   string
		domain string
		fqdn   string
		owner  string
	}{
		{"base", "", "", "_validation-persist.example.com"},
		{"alias-domain", "delegate.example.", "", "_validation-persist.example.com.delegate.example"},
		{"alias-fqdn", "", "_validation-persist.custom.example.", "_validation-persist.custom.example"},
	} {
		for _, policy := range []struct {
			name     string
			wildcard bool
			policy   string
			accept   bool
		}{
			{"wildcard-missing-policy", true, "", false},
			{"wildcard-authorized", true, "wildcard", true},
			{"nonwildcard-no-policy", false, "", true},
			{"nonwildcard-wildcard-policy", false, "wildcard", true},
		} {
			t.Run(alias.name+"/"+policy.name, func(t *testing.T) {
				queries := serveIssuePersistTXT(t, challenge.DNSPersistRecordValue("ca.example", accountURI, policy.policy, ""))
				store, cert := seedIssueState(t, "reused")
				cert.Names = []string{"example.com"}
				if policy.wildcard {
					cert.Names = []string{"*.example.com"}
				}
				cert.CA = "private"
				cert.Challenge = config.ChallengeSpec{Type: challengeDNSPersist01, AliasDomain: alias.domain, AliasFQDN: alias.fqdn}
				cfg := &config.Config{CAs: []*config.CA{{Name: "private", Type: "acme", PersistIdentifier: "ca.example"}}}
				authz := &acme.Authorization{
					Identifier: acme.Identifier{Type: "dns", Value: "example.com"},
					Wildcard:   policy.wildcard,
					Status:     acme.StatusPending,
					Challenges: []acme.Challenge{{Type: challengeDNSPersist01, AccountURI: accountURI, IssuerDomainNames: []string{"ca.example"}}},
				}
				client, downloaded := fakeIssueClient(t, authz, func(csr *x509.CertificateRequest) []byte {
					return issueResponseChain(t, csr, "")
				})
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				err := Issue(ctx, client, cert, store, cfg, IssueOptions{Out: io.Discard})
				if policy.accept {
					if err != nil || !*downloaded {
						t.Fatalf("authorized standing record rejected: %v (downloaded=%v)", err, *downloaded)
					}
				} else if err == nil || !strings.Contains(err.Error(), "does not authorize account") || *downloaded {
					t.Fatalf("wildcard accepted without wildcard policy: %v (downloaded=%v)", err, *downloaded)
				}
				select {
				case owner := <-queries:
					if owner != alias.owner {
						t.Fatalf("DNS lookup owner = %q, want %q", owner, alias.owner)
					}
				default:
					t.Fatal("standing record was not looked up")
				}
			})
		}
	}
}

// serveIssuePersistTXT installs a local UDP resolver for the actual public
// verifier used by Issue. It answers one TXT question per packet and reports
// the queried owner, without network access or changes to resolver files.
func serveIssuePersistTXT(t *testing.T, txt string) <-chan string {
	t.Helper()
	if len(txt) > 255 {
		t.Fatal("fixture TXT exceeds one DNS character string")
	}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	queries := make(chan string, 32)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 17 || binary.BigEndian.Uint16(buf[4:6]) != 1 {
				continue
			}
			offset := 12
			var labels []string
			for offset < n && buf[offset] != 0 {
				length := int(buf[offset])
				offset++
				if length > 63 || offset+length >= n {
					break
				}
				labels = append(labels, string(buf[offset:offset+length]))
				offset += length
			}
			if offset+5 > n || buf[offset] != 0 {
				continue
			}
			offset++
			if binary.BigEndian.Uint16(buf[offset:offset+2]) != 16 {
				continue
			}
			select {
			case queries <- strings.Join(labels, "."):
			default:
			}
			response := []byte{buf[0], buf[1], 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}
			response = append(response, buf[12:offset+4]...)
			// Compressed owner, TXT, IN, TTL 60, and one TXT character string.
			response = append(response, 0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 60, byte((len(txt)+1)>>8), byte(len(txt)+1), byte(len(txt)))
			response = append(response, txt...)
			_, _ = conn.WriteTo(response, addr)
		}
	}()
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "udp", conn.LocalAddr().String())
		},
	}
	t.Cleanup(func() {
		net.DefaultResolver = previous
		_ = conn.Close()
		<-done
	})
	return queries
}
