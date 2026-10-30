// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package cloudflare is a GET-only zone reader. It never calls the live API
// from tests and it refuses every write method.
package cloudflare

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
)

const TokenEnv = "PERIMETER_CLOUDFLARE_TOKEN"

// Client talks to a base URL the caller supplies (httptest in v0.4).
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// Zone is a hostname the API listed.
type Zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type apiList struct {
	Success bool   `json:"success"`
	Result  []Zone `json:"result"`
}

// ListZones GETs zones filtered by name. Missing token, 401, and parse errors
// are needs_human. A name outside affirmed scope is a finding.
func (c Client) ListZones(name string, affirmed map[string]bool) failsafe.Result {
	const watcher = "cloudflare-readonly"
	if strings.TrimSpace(c.Token) == "" {
		return failsafe.NeedsHuman(watcher, "PERIMETER_CLOUDFLARE_TOKEN is unset", fmt.Errorf("missing token"))
	}
	if strings.TrimSpace(c.BaseURL) == "" {
		return failsafe.NeedsHuman(watcher, "cloudflare base url is empty", fmt.Errorf("no base url"))
	}
	u, err := url.Parse(strings.TrimRight(c.BaseURL, "/") + "/client/v4/zones")
	if err != nil {
		return failsafe.FromError(watcher, err)
	}
	q := u.Query()
	q.Set("name", name)
	u.RawQuery = q.Encode()
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return failsafe.FromError(watcher, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	res, err := hc.Do(req)
	if err != nil {
		return failsafe.NeedsHuman(watcher, "cloudflare read failed", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return failsafe.NeedsHuman(watcher, "cloudflare body unreadable", err)
	}
	if res.StatusCode == http.StatusUnauthorized {
		return failsafe.NeedsHuman(watcher, "cloudflare token rejected", fmt.Errorf("401"))
	}
	if res.StatusCode != http.StatusOK {
		return failsafe.NeedsHuman(watcher, "cloudflare status "+res.Status, fmt.Errorf("status %d", res.StatusCode))
	}
	var parsed apiList
	if err := json.Unmarshal(body, &parsed); err != nil || !parsed.Success {
		return failsafe.NeedsHuman(watcher, "cloudflare payload did not parse", fmt.Errorf("parse"))
	}
	var findings []failsafe.Finding
	for _, z := range parsed.Result {
		if !affirmed[strings.ToLower(z.Name)] {
			findings = append(findings, failsafe.Finding{
				ID: "zone-outside-scope", Watcher: watcher, Title: "zone not in affirmed scope",
				Severity: "high", Asset: z.Name,
				Evidence: []failsafe.Evidence{{Key: "zone_id", Value: z.ID}},
			})
		}
	}
	if len(findings) > 0 {
		return failsafe.FromFindings(watcher, "cloudflare zone mismatch", findings, nil)
	}
	return failsafe.JustOK(watcher, "cloudflare zones match affirmed scope")
}

// RefuseWrite is the only answer to a non-GET method.
func RefuseWrite(method string) error {
	switch method {
	case http.MethodGet, http.MethodHead:
		return nil
	default:
		return fmt.Errorf("cloudflare adapter refuses %s", method)
	}
}
