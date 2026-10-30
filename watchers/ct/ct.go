// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package ct ingests Certificate Transparency observations the operator
// already collected (for example certspotter JSON). It does not vendor
// certspotter and it does not run that binary. An unexpected issuer is a
// finding. A read error is needs_human.
package ct

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/govern"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/scope"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/state"
)

// Entry is one observed certificate. Issuer is the operator-visible CA name.
type Entry struct {
	DNSNames []string `json:"dns_names"`
	Issuer   string   `json:"issuer"`
	Error    string   `json:"error,omitempty"`
}

// Diff compares names in scope to the operator's expected issuer set.
func Diff(cfg state.Config, sc *scope.Store, ros state.Roster, host string, allowedIssuers []string, entries []Entry) failsafe.Result {
	const watcher = "ct"
	if res, ok := govern.Result(watcher, govern.Ready(cfg, sc, ros, scope.KindHTTPS, host)); !ok {
		return res
	}
	if len(allowedIssuers) == 0 {
		return failsafe.NeedsHuman(watcher, "no expected issuer list; a CT feed alone is not a verdict", fmt.Errorf("issuers"))
	}
	if len(entries) == 0 {
		return failsafe.NeedsHuman(watcher, "no CT entries supplied", fmt.Errorf("empty"))
	}
	allow := map[string]bool{}
	for _, a := range allowedIssuers {
		allow[strings.ToLower(strings.TrimSpace(a))] = true
	}
	var findings []failsafe.Finding
	for _, e := range entries {
		if e.Error != "" {
			return failsafe.NeedsHuman(watcher, "ct source failed", fmt.Errorf("%s", e.Error))
		}
		if !namesMatch(host, e.DNSNames) {
			continue
		}
		if !allow[strings.ToLower(strings.TrimSpace(e.Issuer))] {
			findings = append(findings, failsafe.Finding{
				ID: "ct-issuer", Watcher: watcher, Title: "CT entry from an issuer that is not on the expected list",
				Summary: "Issuer " + e.Issuer + " issued for " + host,
				CIA:     "integrity", Lesson: "module 9 CT", Severity: "high", Asset: host,
				Detection: "det-ct-issuer",
				Evidence:  []failsafe.Evidence{{Key: "issuer", Value: e.Issuer}},
			})
		}
	}
	if len(findings) == 0 {
		return failsafe.JustOK(watcher, "in-scope CT entries use an expected issuer")
	}
	return failsafe.FromFindings(watcher, "unexpected CT issuer", findings, nil)
}

func namesMatch(host string, names []string) bool {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	for _, n := range names {
		n = strings.TrimSuffix(strings.ToLower(n), ".")
		if n == h || (strings.HasPrefix(n, "*.") && strings.HasSuffix(h, n[1:])) {
			return true
		}
	}
	return false
}

// ParseJSONL reads one JSON object per line. Malformed input fails closed.
func ParseJSONL(raw string) ([]Entry, error) {
	var out []Entry
	for i, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		out = append(out, e)
	}
	return out, nil
}
