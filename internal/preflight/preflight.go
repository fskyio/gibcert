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
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"foundry.fsky.io/fsky/gibcert/internal/config"
)

func Check(cfg *config.Config) error {
	var errs []error
	if os.Geteuid() != 0 {
		for _, cert := range cfg.Certificates {
			for _, d := range cert.Deploys {
				if d.Owner != "" {
					errs = append(errs, fmt.Errorf("certificate %q deploy %q: owner %q requires root", cert.Name, d.Name, d.Owner))
				}
				if d.Group != "" {
					errs = append(errs, fmt.Errorf("certificate %q deploy %q: group %q requires root", cert.Name, d.Name, d.Group))
				}
			}
		}
	}

	cas := config.CAProfiles(cfg.CAs)
	for _, cert := range cfg.Certificates {
		if cert.CA != "" {
			if ca := cas[cert.CA]; ca != nil && ca.Type == "local" {
				continue
			}
		}
		switch challengeType(cfg, cert) {
		case "http-01":
			listen := cert.Challenge.Listen
			webroot := cert.Challenge.Webroot
			if listen == "" && webroot == "" && cfg.GlobalChallenge != nil {
				listen = cfg.GlobalChallenge.Listen
				webroot = cfg.GlobalChallenge.Webroot
			}
			if listen != "" {
				if err := checkListen(cert.Name, "http-01", listen); err != nil {
					errs = append(errs, err)
				}
				continue
			}
			if err := checkWebroot(cert.Name, webroot); err != nil {
				errs = append(errs, err)
			}
		case "tls-alpn-01":
			if err := checkListen(cert.Name, "tls-alpn-01", cert.Challenge.Listen); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func checkListen(certName, chType, listen string) error {
	if _, _, err := net.SplitHostPort(listen); err != nil {
		return fmt.Errorf("certificate %q: %s listen %q: %w", certName, chType, listen, err)
	}
	return nil
}

func challengeType(cfg *config.Config, cert *config.Certificate) string {
	if cert.Challenge.Type != "" {
		return cert.Challenge.Type
	}
	if cfg.GlobalChallenge != nil {
		return cfg.GlobalChallenge.Type
	}
	return ""
}

func checkWebroot(certName, webroot string) error {
	info, err := os.Stat(webroot)
	if err != nil {
		return fmt.Errorf("certificate %q: http-01 webroot %q: %w", certName, webroot, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("certificate %q: http-01 webroot %q is not a directory", certName, webroot)
	}
	challengeDir := filepath.Join(webroot, ".well-known", "acme-challenge")
	if err := os.MkdirAll(challengeDir, 0o755); err != nil {
		return fmt.Errorf("certificate %q: create http-01 challenge dir %q: %w", certName, challengeDir, err)
	}
	tmp, err := os.CreateTemp(challengeDir, ".gibcert-check-*")
	if err != nil {
		return fmt.Errorf("certificate %q: http-01 challenge dir %q is not writable: %w", certName, challengeDir, err)
	}
	name := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("certificate %q: close http-01 preflight file %q: %w", certName, name, err)
	}
	if err := os.Remove(name); err != nil {
		return fmt.Errorf("certificate %q: remove http-01 preflight file %q: %w", certName, name, err)
	}
	return nil
}
