// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package csp accepts Content-Security-Policy reports for pages in scope.
// The handler is original. It is not a vendored copy of go-csp-collector.
// Reports for hosts the operator did not declare are dropped, not stored.
package csp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/scope"
)

// Report is the subset of a CSP report this sink keeps.
type Report struct {
	DocumentURI       string `json:"document-uri"`
	ViolatedDirective string `json:"violated-directive"`
	BlockedURI        string `json:"blocked-uri"`
}

type envelope struct {
	CSPReport Report `json:"csp-report"`
}

// Parse accepts a legacy report-uri object or a Reporting API array.
func Parse(body []byte) ([]Report, error) {
	body = bytesTrim(body)
	if len(body) == 0 {
		return nil, fmt.Errorf("empty csp report")
	}
	if body[0] == '[' {
		var arr []struct {
			Body Report `json:"body"`
		}
		if err := json.Unmarshal(body, &arr); err != nil {
			return nil, err
		}
		out := make([]Report, 0, len(arr))
		for _, a := range arr {
			out = append(out, a.Body)
		}
		return out, nil
	}
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, err
	}
	if env.CSPReport.DocumentURI == "" {
		var one Report
		if err := json.Unmarshal(body, &one); err != nil {
			return nil, err
		}
		return []Report{one}, nil
	}
	return []Report{env.CSPReport}, nil
}

func bytesTrim(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}

// Classify turns reports into findings. Out-of-scope documents are a denial,
// not a finding about that third party.
func Classify(sc *scope.Store, reports []Report) failsafe.Result {
	const watcher = "csp"
	if sc == nil || !sc.Affirmed() {
		return failsafe.NeedsHuman(watcher, "scope is not affirmed", fmt.Errorf("scope"))
	}
	var findings []failsafe.Finding
	var dropped int
	for _, rep := range reports {
		if strings.TrimSpace(rep.DocumentURI) == "" {
			return failsafe.NeedsHuman(watcher, "csp report missing document-uri", fmt.Errorf("document-uri"))
		}
		if err := sc.Check(scope.KindPage, rep.DocumentURI); err != nil {
			dropped++
			continue
		}
		findings = append(findings, failsafe.Finding{
			ID: "csp-violation", Watcher: watcher,
			Title:   "CSP violation on an in-scope page",
			Summary: rep.ViolatedDirective + " blocked " + rep.BlockedURI,
			CIA:     "integrity", Lesson: "L7 third-party browser scripts are supply chain",
			Severity: "medium", Asset: rep.DocumentURI, Detection: "det-csp-violation",
			Evidence: []failsafe.Evidence{
				{Key: "violated_directive", Value: rep.ViolatedDirective},
				{Key: "blocked_uri", Value: rep.BlockedURI},
			},
		})
	}
	if len(findings) == 0 && dropped > 0 {
		return failsafe.NeedsHuman(watcher, "csp reports were for pages outside scope and were dropped", fmt.Errorf("dropped %d", dropped))
	}
	if len(findings) == 0 {
		return failsafe.NeedsHuman(watcher, "csp report contained no usable in-scope violation", fmt.Errorf("empty"))
	}
	return failsafe.FromFindings(watcher, "csp violation recorded", findings, nil)
}

// Handler is a localhost sink. The CLI refuses non-loopback binds.
func Handler(sc *scope.Store, sink func(failsafe.Result)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "read", http.StatusBadRequest)
			return
		}
		reps, err := Parse(body)
		if err != nil {
			sink(failsafe.FromError("csp", err))
			http.Error(w, "bad report", http.StatusBadRequest)
			return
		}
		sink(Classify(sc, reps))
		w.WriteHeader(http.StatusNoContent)
	})
}
