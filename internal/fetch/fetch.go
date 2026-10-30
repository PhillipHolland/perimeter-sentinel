// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package fetch performs a single GET that has already passed the egress
// allowlist. Redirects are limited to the same host. Bodies are capped.
package fetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/egress"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/scope"
)

const maxBody = 2 << 20

// Get fetches rawURL. parent is the in-scope page when rawURL is a referenced
// script. A declared page passes an empty parent.
func Get(ctx context.Context, sc *scope.Store, rawURL, parent string) (int, map[string]string, []byte, error) {
	if err := egress.Require(sc, http.MethodGet, rawURL, parent); err != nil {
		return 0, nil, nil, err
	}
	originHost := host(rawURL)
	client := &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			if !sameHost(req.URL.Hostname(), originHost) {
				return fmt.Errorf("redirect left %s", originHost)
			}
			return egress.Require(sc, http.MethodGet, req.URL.String(), parent)
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("User-Agent", "perimeterctl/0.1 (+https://github.com/perimeter-sentinel/perimeter-sentinel)")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return resp.StatusCode, nil, nil, err
	}
	if len(body) > maxBody {
		return resp.StatusCode, nil, nil, errors.New("response exceeds 2MiB cap")
	}
	hdr := map[string]string{}
	for k, v := range resp.Header {
		if len(v) > 0 {
			hdr[k] = v[0]
		}
	}
	return resp.StatusCode, hdr, body, nil
}

func host(raw string) string {
	// Avoid importing net/url failure modes twice: egress already parsed it.
	req, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil || req.URL == nil {
		return ""
	}
	return req.URL.Hostname()
}

func sameHost(a, b string) bool { return a == b }
