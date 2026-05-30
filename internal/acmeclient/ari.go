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
	"errors"
	"time"

	"foundry.fsky.io/fsky/gibcert/internal/acme"
)

// ErrARIUnsupported is returned by RenewalInfo when the ACME server does not
// advertise ACME Renewal Information (RFC 9773) support.
var ErrARIUnsupported = errors.New("acme server does not support renewal information")

// RenewalInfo is the ACME Renewal Information (ARI) for a certificate, reduced
// to the fields gibcert acts on. WindowStart and WindowEnd bound the CA's
// suggested renewal window; SelectedTime is a uniformly random instant the
// server (via the underlying client) picked within that window for this query.
// RetryAfter, if set, is the earliest the client should query again.
type RenewalInfo struct {
	WindowStart    time.Time
	WindowEnd      time.Time
	SelectedTime   time.Time
	RetryAfter     *time.Time
	ExplanationURL string
}

// RenewalInfo fetches the ACME Renewal Information for leaf. The request is an
// unauthenticated GET. If the server does not support ARI, the returned error
// wraps ErrARIUnsupported so callers can treat it as a benign fallback.
func (c *Client) RenewalInfo(ctx context.Context, leaf *x509.Certificate) (RenewalInfo, error) {
	ari, err := c.acme.GetRenewalInfo(ctx, leaf)
	if err != nil {
		if errors.Is(err, acme.ErrUnsupported) {
			return RenewalInfo{}, ErrARIUnsupported
		}
		return RenewalInfo{}, err
	}
	return RenewalInfo{
		WindowStart:    ari.SuggestedWindow.Start,
		WindowEnd:      ari.SuggestedWindow.End,
		SelectedTime:   ari.SelectedTime,
		RetryAfter:     ari.RetryAfter,
		ExplanationURL: ari.ExplanationURL,
	}, nil
}
