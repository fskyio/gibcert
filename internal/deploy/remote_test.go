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
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"gitfield.org/fsky/gibcert/internal/config"
	"gitfield.org/fsky/gibcert/internal/storage"
)

type fakeRemote struct {
	fail  map[string]error
	calls []string
	reqs  []Request
}

func (f *fakeRemote) Apply(h *config.Host, req Request, dryRun bool, out io.Writer) (Result, error) {
	f.calls = append(f.calls, h.Name)
	f.reqs = append(f.reqs, req)
	if err := f.fail[h.Name]; err != nil {
		return Result{}, err
	}
	return Result{Target: req.Target, Host: h.Name, Changed: []string{"fullchain"}}, nil
}

func remoteCert(root string, hosts ...string) *config.Certificate {
	mode := os.FileMode(0o600)
	return &config.Certificate{
		Name: "example.com",
		Deploys: []*config.Deploy{{
			Name: "web", Hosts: hosts, Mode: &mode,
			Fullchain: "/etc/tls/fullchain.pem", Key: "/etc/tls/privkey.pem",
			After: "systemctl reload nginx",
		}},
	}
}

func hostsNamed(names ...string) []*config.Host {
	var hosts []*config.Host
	for _, n := range names {
		hosts = append(hosts, &config.Host{Name: n, Address: n + ".example.net"})
	}
	return hosts
}

func TestDeployKeepsGoingAfterRemoteFailureAndRetriesOnlyThatHost(t *testing.T) {
	root := t.TempDir()
	store := storage.New(filepath.Join(root, "state"))
	writeCanonical(t, store, "example.com")
	cert := remoteCert(root, "web1", "web2", "web3")
	remote := &fakeRemote{fail: map[string]error{"web2": errors.New("ssh: connect timed out")}}

	results, err := Deploy(cert, store, io.Discard, WithRemote(remote, hostsNamed("web1", "web2", "web3")))
	if err == nil || !strings.Contains(err.Error(), `host "web2"`) || !strings.Contains(err.Error(), "connect timed out") {
		t.Fatalf("err = %v, want the web2 failure", err)
	}
	if !slices.Equal(remote.calls, []string{"web1", "web2", "web3"}) {
		t.Fatalf("calls = %v, want every host attempted", remote.calls)
	}
	var labels []string
	for _, r := range results {
		labels = append(labels, r.Label())
	}
	if !slices.Equal(labels, []string{"web@web1", "web@web3"}) {
		t.Fatalf("results = %v", labels)
	}

	meta, err := store.LoadCertMeta("example.com")
	if err != nil {
		t.Fatal(err)
	}
	hosts := map[string]bool{}
	for _, rec := range meta.Deploys {
		hosts[rec.Host] = true
	}
	if !hosts["web1"] || !hosts["web3"] || hosts["web2"] {
		t.Fatalf("deploy records for hosts %v, want web1 and web3 only", hosts)
	}
	if len(meta.DeployFailures) != 1 || meta.DeployFailures[0].Host != "web2" || meta.DeployFailures[0].Target != "web" {
		t.Fatalf("failures = %+v, want one for web2", meta.DeployFailures)
	}
	firstFailure := meta.DeployFailures[0].Since

	// The next run: web1 and web3 are known to be current, web2 still is not,
	// and the hook obligation travels with the request to web2 only.
	remote.calls, remote.reqs = nil, nil
	time.Sleep(time.Millisecond)
	if _, err := Deploy(cert, store, io.Discard, WithRemote(remote, hostsNamed("web1", "web2", "web3"))); err == nil {
		t.Fatal("retry succeeded while web2 still fails")
	}
	for i, req := range remote.reqs {
		wantUnseen := remote.calls[i] == "web2"
		if got := len(req.Unseen) != 0; got != wantUnseen {
			t.Errorf("%s: unseen = %v, want unseen kinds %v", remote.calls[i], req.Unseen, wantUnseen)
		}
	}
	meta, _ = store.LoadCertMeta("example.com")
	if !meta.DeployFailures[0].Since.Equal(firstFailure) || !meta.DeployFailures[0].At.After(firstFailure) {
		t.Fatalf("failure streak = %+v, want Since kept at %v and At advanced", meta.DeployFailures[0], firstFailure)
	}

	remote.fail = nil
	if _, err := Deploy(cert, store, io.Discard, WithRemote(remote, hostsNamed("web1", "web2", "web3"))); err != nil {
		t.Fatalf("Deploy after recovery: %v", err)
	}
	meta, _ = store.LoadCertMeta("example.com")
	if len(meta.DeployFailures) != 0 {
		t.Fatalf("failures = %+v, want cleared after success", meta.DeployFailures)
	}
}

func TestDeployRequestCarriesCompleteInstruction(t *testing.T) {
	root := t.TempDir()
	store := storage.New(filepath.Join(root, "state"))
	writeCanonical(t, store, "example.com")
	cert := remoteCert(root, "web1")
	cert.Deploys[0].Owner, cert.Deploys[0].Group = "root", "ssl-cert"
	remote := &fakeRemote{}
	if _, err := Deploy(cert, store, io.Discard, WithRemote(remote, hostsNamed("web1"))); err != nil {
		t.Fatal(err)
	}
	req := remote.reqs[0]
	if req.Cert != "example.com" || req.Target != "web" || req.Owner != "root" || req.Group != "ssl-cert" ||
		req.After != "systemctl reload nginx" || req.Mode == nil || *req.Mode != 0o600 {
		t.Fatalf("request = %+v", req)
	}
	if len(req.Files) != 2 || req.Files[1].Kind != "key" || req.Files[1].Path != "/etc/tls/privkey.pem" || len(req.Files[1].Data) == 0 {
		t.Fatalf("files = %+v", req.Files)
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("request does not validate: %v", err)
	}
}

func TestDeployWithoutRemoteRefusesHostTargets(t *testing.T) {
	root := t.TempDir()
	store := storage.New(filepath.Join(root, "state"))
	writeCanonical(t, store, "example.com")
	if _, err := Deploy(remoteCert(root, "web1"), store, io.Discard); err == nil || !strings.Contains(err.Error(), `host "web1"`) {
		t.Fatalf("err = %v, want refusal for host web1", err)
	}
	if _, err := Deploy(remoteCert(root, "web1"), store, io.Discard, WithRemote(&fakeRemote{}, hostsNamed("other"))); err == nil {
		t.Fatal("deploy to an unconfigured host succeeded")
	}
}

func TestDeployOnlyHostSkipsEverythingElse(t *testing.T) {
	root := t.TempDir()
	store := storage.New(filepath.Join(root, "state"))
	writeCanonical(t, store, "example.com")
	localDst := filepath.Join(root, "local", "fullchain.pem")
	cert := remoteCert(root, "web1", "web2")
	cert.Deploys = append(cert.Deploys, &config.Deploy{Name: "local", Fullchain: localDst})
	remote := &fakeRemote{}

	results, err := Deploy(cert, store, io.Discard, WithRemote(remote, hostsNamed("web1", "web2")), OnlyHost("web2"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(remote.calls, []string{"web2"}) || len(results) != 1 || results[0].Label() != "web@web2" {
		t.Fatalf("calls %v, results %+v; want only web2", remote.calls, results)
	}
	if _, err := os.Stat(localDst); !os.IsNotExist(err) {
		t.Fatalf("local target was deployed despite OnlyHost: %v", err)
	}
}

func TestSameTargetOnLocalAndRemoteKeepsSeparateRecords(t *testing.T) {
	root := t.TempDir()
	store := storage.New(filepath.Join(root, "state"))
	writeCanonical(t, store, "example.com")
	dst := filepath.Join(root, "fullchain.pem")
	mode := os.FileMode(0o600)
	local := &config.Deploy{Name: "web", Fullchain: dst, Mode: &mode}
	remoteDeploy := &config.Deploy{Name: "web", Hosts: []string{"web1"}, Fullchain: dst, Mode: &mode}
	cert := &config.Certificate{Name: "example.com", Deploys: []*config.Deploy{local, remoteDeploy}}

	if _, err := Deploy(cert, store, io.Discard, WithRemote(&fakeRemote{}, hostsNamed("web1"))); err != nil {
		t.Fatal(err)
	}
	meta, _ := store.LoadCertMeta("example.com")
	if len(meta.Deploys) != 2 {
		t.Fatalf("records = %+v, want one local and one for web1", meta.Deploys)
	}
}

func TestUndeploySkipsRemoteRecords(t *testing.T) {
	root := t.TempDir()
	store := storage.New(filepath.Join(root, "state"))
	path := filepath.Join(root, "fullchain.pem")
	data := []byte("material")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	// A local file that happens to match a record installed on another host
	// must survive: the record's path means nothing on this machine.
	meta := storage.CertMeta{Name: "example.com", Deploys: []storage.CertDeployMeta{
		{Target: "web", Host: "web1", Kind: "fullchain", Path: path, SHA256: storage.SHA256Hex(data)},
	}}
	if err := store.SaveCertMeta("example.com", meta); err != nil {
		t.Fatal(err)
	}
	results, err := Undeploy("example.com", store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("local file removed for a remote record: %v", err)
	}
	if len(results) != 1 || results[0].Host != "web1" || !strings.HasPrefix(results[0].Status, "skipped") {
		t.Fatalf("results = %+v", results)
	}
}
