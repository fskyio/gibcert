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

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"gitfield.org/fsky/gibcert/internal/storage"
)

// fakeCA is an ACME server that only implements account deactivation.
type fakeCA struct {
	srv   *httptest.Server
	reply func(w http.ResponseWriter)

	mu    sync.Mutex
	posts []string
}

func newFakeCA(t *testing.T, reply func(w http.ResponseWriter)) *fakeCA {
	t.Helper()
	ca := &fakeCA{reply: reply}
	ca.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce-value")
		switch {
		case r.URL.Path == "/directory":
			w.Header().Set("Content-Type", "application/json")
			u := ca.srv.URL
			io.WriteString(w, `{"newNonce":"`+u+`/nonce","newAccount":"`+u+`/new-account","newOrder":"`+u+`/new-order","revokeCert":"`+u+`/revoke","keyChange":"`+u+`/key-change"}`)
		case r.URL.Path == "/nonce":
			w.WriteHeader(http.StatusOK)
		case strings.HasPrefix(r.URL.Path, "/acct/"):
			ca.mu.Lock()
			ca.posts = append(ca.posts, strings.TrimPrefix(r.URL.Path, "/acct/"))
			ca.mu.Unlock()
			ca.reply(w)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ca.srv.Close)
	return ca
}

func (ca *fakeCA) accepted() func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"status":"deactivated"}`)
	}
}

func refused(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusForbidden)
	io.WriteString(w, `{"type":"urn:ietf:params:acme:error:unauthorized","detail":"not allowed"}`)
}

func (ca *fakeCA) accountPosts() []string {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return append([]string(nil), ca.posts...)
}

// saveLiveAccount stores an account registered at the fake CA, with a real key.
func saveLiveAccount(t *testing.T, store *storage.Store, ca *fakeCA, name string) {
	t.Helper()
	key, err := storage.GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(store.AccountDir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := storage.WriteKey(store.AccountKeyPath(name), key); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAccountMeta(name, storage.AccountMeta{
		URL:       ca.srv.URL + "/acct/" + name,
		Directory: ca.srv.URL + "/directory",
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
}

func accountDirExists(store *storage.Store, name string) bool {
	_, err := os.Stat(store.AccountDir(name))
	return err == nil
}

func TestAccountDeactivateDeactivatesThenDeletesLocalState(t *testing.T) {
	p, store := pruneFixture(t)
	ca := newFakeCA(t, nil)
	ca.reply = ca.accepted()
	saveLiveAccount(t, store, ca, "ca:google")

	out, errOut, code := captureCommand(t, func() int {
		return cmdAccount(p, []string{"deactivate", "--yes", "ca:google"})
	})
	if code != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	if got := ca.accountPosts(); len(got) != 1 || got[0] != "ca:google" {
		t.Fatalf("CA saw account POSTs %v, want one for ca:google", got)
	}
	if accountDirExists(store, "ca:google") {
		t.Error("local state of the deactivated account was kept")
	}
	if !accountDirExists(store, "ca:zerossl") || !accountDirExists(store, "custom") {
		t.Error("another account was removed")
	}
	if !strings.Contains(out, "deactivated at") || !strings.Contains(out, "local state deleted") {
		t.Errorf("output missing confirmation:\n%s", out)
	}
}

func TestAccountDeactivateRefusesWhatIsStillNeeded(t *testing.T) {
	p, store := pruneFixture(t)
	ca := newFakeCA(t, nil)
	ca.reply = ca.accepted()
	for _, name := range []string{"custom", "ca:buypass"} {
		saveLiveAccount(t, store, ca, name)
	}

	for _, tc := range []struct {
		account  string
		wantCode int
		wantErr  string
	}{
		{"custom", 1, "declared in config"},                  // the config uses it
		{"ca:buypass", 1, "needed by cert/valid.example"},    // a stored certificate records it
		{"missing", 1, "has no local state"},                 // nothing to deactivate
		{"../custom", 2, "must not contain path separators"}, // not a state name
	} {
		_, errOut, code := captureCommand(t, func() int {
			return cmdAccount(p, []string{"deactivate", "--yes", tc.account})
		})
		if code != tc.wantCode || !strings.Contains(errOut, tc.wantErr) {
			t.Errorf("%s: code=%d stderr=%q, want code %d containing %q", tc.account, code, errOut, tc.wantCode, tc.wantErr)
		}
	}
	if got := ca.accountPosts(); len(got) != 0 {
		t.Fatalf("CA was contacted for refused accounts: %v", got)
	}
	if !accountDirExists(store, "custom") || !accountDirExists(store, "ca:buypass") {
		t.Fatal("local state of a refused account was removed")
	}
}

func TestAccountDeactivateKeepsLocalStateUnlessTheCAConfirms(t *testing.T) {
	p, store := pruneFixture(t)
	ca := newFakeCA(t, refused)
	saveLiveAccount(t, store, ca, "ca:google")

	_, errOut, code := captureCommand(t, func() int {
		return cmdAccount(p, []string{"deactivate", "--yes", "ca:google"})
	})
	if code != 1 || !strings.Contains(errOut, "local state kept") {
		t.Fatalf("refusal: code=%d stderr=%q", code, errOut)
	}
	if !accountDirExists(store, "ca:google") {
		t.Fatal("local state removed although the CA refused")
	}

	// A reply that does not say "deactivated" is not trusted either.
	ca.reply = func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"status":"valid"}`)
	}
	_, errOut, code = captureCommand(t, func() int {
		return cmdAccount(p, []string{"deactivate", "--yes", "ca:google"})
	})
	if code != 1 || !strings.Contains(errOut, "CA reported status") || !accountDirExists(store, "ca:google") {
		t.Fatalf("unexpected status: code=%d stderr=%q kept=%v", code, errOut, accountDirExists(store, "ca:google"))
	}
}

func TestAccountDeactivateWithoutConfirmationDoesNothing(t *testing.T) {
	p, store := pruneFixture(t)
	ca := newFakeCA(t, nil)
	ca.reply = ca.accepted()
	saveLiveAccount(t, store, ca, "ca:google")
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	oldStdin := os.Stdin
	os.Stdin = devNull
	defer func() { os.Stdin = oldStdin }()

	_, _, code := captureCommand(t, func() int { return cmdAccount(p, []string{"deactivate", "ca:google"}) })
	if code != 1 || len(ca.accountPosts()) != 0 || !accountDirExists(store, "ca:google") {
		t.Fatalf("code=%d posts=%v kept=%v", code, ca.accountPosts(), accountDirExists(store, "ca:google"))
	}
}

func TestPruneDeactivateContactsTheCAForRemovedAccountsOnly(t *testing.T) {
	p, store := pruneFixture(t)
	ca := newFakeCA(t, nil)
	ca.reply = ca.accepted()
	saveLiveAccount(t, store, ca, "ca:google")

	// A dry run describes the deactivation without contacting the CA.
	out, errOut, code := captureCommand(t, func() int {
		return cmdPrune(p, []string{"--accounts", "--deactivate", "--dry-run"})
	})
	if code != 0 || !strings.Contains(out, "deactivated at the CA first") || !strings.Contains(out, "1 account(s) will be deactivated") {
		t.Fatalf("dry run: code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	if len(ca.accountPosts()) != 0 || !accountDirExists(store, "ca:google") {
		t.Fatal("dry run contacted the CA or removed state")
	}

	out, errOut, code = captureCommand(t, func() int {
		return cmdPrune(p, []string{"--accounts", "--deactivate", "--yes"})
	})
	if code != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	// Only the account nothing uses is deactivated; the others are in use.
	if got := ca.accountPosts(); len(got) != 1 || got[0] != "ca:google" {
		t.Fatalf("CA saw account POSTs %v, want one for ca:google", got)
	}
	if accountDirExists(store, "ca:google") {
		t.Error("deactivated account kept its local state")
	}
	for _, name := range []string{"custom", "ca:zerossl", "ca:buypass"} {
		if !accountDirExists(store, name) {
			t.Errorf("account %s was removed", name)
		}
	}
}

func TestPruneDeactivateFailureKeepsThatAccountAndContinues(t *testing.T) {
	p, store := pruneFixture(t)
	ca := newFakeCA(t, nil)
	ca.reply = ca.accepted()
	// ca:google is live. ca:zerossl, freed once the expired certificate goes,
	// has no key, so it cannot be deactivated.
	saveLiveAccount(t, store, ca, "ca:google")

	_, errOut, code := captureCommand(t, func() int {
		return cmdPrune(p, []string{"--certs", "--accounts", "--deactivate", "--yes"})
	})
	if code != 1 || !strings.Contains(errOut, "account/ca:zerossl") || !strings.Contains(errOut, "local state kept") {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
	if !accountDirExists(store, "ca:zerossl") {
		t.Error("account that could not be deactivated lost its local state")
	}
	if accountDirExists(store, "ca:google") {
		t.Error("the failure held back the deactivation of another account")
	}
	if _, err := os.Stat(store.CertDir("old.example")); !os.IsNotExist(err) {
		t.Error("the failure held back removal of the expired certificate")
	}
}

func TestPruneDeactivateNeedsAccounts(t *testing.T) {
	p, store := pruneFixture(t)
	_, errOut, code := captureCommand(t, func() int {
		return cmdPrune(p, []string{"--certs", "--deactivate", "--yes"})
	})
	if code != 2 || !strings.Contains(errOut, "--deactivate requires --accounts") {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
	assertPruneState(t, store, map[string]bool{"cert/old.example": true})
}
