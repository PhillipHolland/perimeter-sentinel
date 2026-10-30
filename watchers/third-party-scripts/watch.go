// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package thirdparty inventories script origins on a page the operator runs
// and hashes vendor-hosted scripts that the page referenced.
//
// PCI DSS v4.0.1 requirements 6.4.3 and 11.6.1 are the evidence target:
// an inventory with a justification, and a tamper check on script bytes as
// received. The report is evidence. A QSA decides. This is not "the only"
// control and it does not block in the browser.
//
// A page that mixes a third-party script with a session or a signing surface
// is flagged on first inventory. That is the Polymarket Oct 29 shape:
// a vendor script beside an authenticated trading page. Sentinel does not
// claim it would have stopped the loss. It claims the drift is visible.
package thirdparty

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/govern"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/scope"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/state"
	servedjs "github.com/perimeter-sentinel/perimeter-sentinel/watchers/served-js"
)

// Entry is one script origin on one page.
type Entry struct {
	Page           string `json:"page"`
	Src            string `json:"src"`
	Origin         string `json:"origin"`
	Vendor         string `json:"vendor"`
	SHA256         string `json:"sha256,omitempty"`
	Justification  string `json:"justification,omitempty"`
	ThirdParty     bool   `json:"third_party"`
	TouchesSession bool   `json:"touches_session"`
	TouchesSigning bool   `json:"touches_signing"`
	Red            bool   `json:"red"`
}

// Baseline is the last approved hash per script URL.
type Baseline struct {
	Page    string            `json:"page"`
	Hashes  map[string]string `json:"hashes"`
	Vendors map[string]string `json:"vendors,omitempty"`
	Justify map[string]string `json:"justify,omitempty"`
}

// Observation is one vantage.
type Observation struct {
	Vantage      string            `json:"vantage"`
	Body         string            `json:"body"`
	ScriptBodies map[string]string `json:"script_bodies,omitempty"`
	CSP          string            `json:"csp,omitempty"`
	Error        string            `json:"error,omitempty"`
	At           time.Time         `json:"at,omitempty"`
}

// Check is the govern-aware entry. Every call hits the scope gate.
func Check(cfg state.Config, sc *scope.Store, ros state.Roster, page scope.Asset, base Baseline, vendors map[string]string, obs []Observation, changedAt time.Time) failsafe.Result {
	const watcher = "third-party-scripts"
	if res, ok := govern.Result(watcher, govern.Ready(cfg, sc, ros, scope.KindPage, page.Name)); !ok {
		return res
	}
	if len(obs) == 0 {
		return failsafe.NeedsHuman(watcher, "no page observation", fmt.Errorf("no observations"))
	}
	pageHost := hostOf(page.Name)
	var findings []failsafe.Finding
	hard := false
	hardErr := ""
	for _, o := range obs {
		if o.Error != "" {
			hard = true
			hardErr = o.Vantage + ": " + o.Error
			continue
		}
		refs, _ := servedjs.ParseHTML(o.Body)
		for _, ref := range refs {
			if ref.Inline {
				continue
			}
			if err := sc.AllowReferenced(scope.KindPage, page.Name, ref.Src); err != nil {
				return failsafe.FromError(watcher, err)
			}
			origin := originOf(ref.Src)
			third := !sameHost(origin, pageHost)
			vendor := vendorName(ref.Src, vendors, base)
			body, ok := bodyFor(o.ScriptBodies, ref.Src)
			entry := Entry{
				Page: page.Name, Src: ref.Src, Origin: origin, Vendor: vendor, ThirdParty: third,
				TouchesSession: page.TouchesSession, TouchesSigning: page.TouchesSigning,
				Justification: justify(ref.Src, base),
			}
			entry.Red = third && (page.TouchesSession || page.TouchesSigning || page.PaymentPage)
			if !ok {
				hard = true
				hardErr = "missing bytes for " + ref.Src
				continue
			}
			sum := servedjs.SHA256Hex([]byte(body))
			entry.SHA256 = sum
			if entry.Red && entry.Justification == "" {
				findings = append(findings, driftFinding("unjustified", "Third-party script on a session or signing page has no justification", entry, o.Vantage))
			}
			if entry.Red && vendor == "unlisted" {
				findings = append(findings, driftFinding("unlisted-vendor", "Third-party script on a sensitive page has no vendor name", entry, o.Vantage))
			}
			if prev, ok := base.Hashes[ref.Src]; ok {
				if !strings.EqualFold(prev, sum) {
					f := driftFinding("vendor-hash-drift", "Vendor-hosted script hash changed", entry, o.Vantage)
					f.Severity = "critical"
					f.Evidence = append(f.Evidence,
						failsafe.Evidence{Key: "approved_sha256", Value: prev},
						failsafe.Evidence{Key: "served_sha256", Value: sum},
						failsafe.Evidence{Key: "vendor", Value: vendor},
					)
					if !changedAt.IsZero() && !o.At.IsZero() {
						delta := int64(o.At.Sub(changedAt).Seconds())
						f.Evidence = append(f.Evidence, failsafe.Evidence{Key: "notice_seconds", Value: fmt.Sprintf("%d", delta)})
					}
					findings = append(findings, f)
				}
			} else if third {
				findings = append(findings, driftFinding("new-script", "Third-party script is not in the approved baseline", entry, o.Vantage))
			}
		}
	}
	if hard {
		res := failsafe.NeedsHuman(watcher, "third-party script hash incomplete", fmt.Errorf("%s", hardErr))
		res.Findings = dedupe(findings)
		res.Lesson = "L7 third-party browser scripts are supply chain"
		return res
	}
	if len(findings) == 0 {
		return failsafe.JustOK(watcher, "third-party script hashes match the approved baseline")
	}
	res := failsafe.FromFindings(watcher, "third-party script inventory needs a human", dedupe(findings), nil)
	res.Lesson = "L7 third-party browser scripts are supply chain"
	return res
}

func bodyFor(m map[string]string, src string) (string, bool) {
	if m == nil {
		return "", false
	}
	if b, ok := m[src]; ok {
		return b, true
	}
	return "", false
}

func driftFinding(id, title string, e Entry, vantage string) failsafe.Finding {
	sev := "high"
	if e.Red {
		sev = "critical"
	}
	return failsafe.Finding{
		ID: id, Watcher: "third-party-scripts", Title: title, Summary: title,
		CIA: "integrity", Attack: "T1195.001", Lesson: "L7 third-party browser scripts are supply chain",
		Severity: sev, Asset: e.Page, Detection: "det-vendor-script-drift",
		Envelope: "vendor-script-compromise",
		Evidence: []failsafe.Evidence{
			{Key: "vendor", Value: e.Vendor},
			{Key: "src", Value: e.Src},
			{Key: "origin", Value: e.Origin},
			{Key: "vantage", Value: vantage},
			{Key: "sha256", Value: e.SHA256},
			{Key: "red", Value: fmt.Sprintf("%t", e.Red)},
		},
	}
}

func vendorName(src string, vendors map[string]string, base Baseline) string {
	host := hostOf(src)
	if vendors != nil {
		if v, ok := vendors[host]; ok && v != "" {
			return v
		}
	}
	if base.Vendors != nil {
		if v, ok := base.Vendors[src]; ok && v != "" {
			return v
		}
		if v, ok := base.Vendors[host]; ok && v != "" {
			return v
		}
	}
	return "unlisted"
}

func justify(src string, base Baseline) string {
	if base.Justify == nil {
		return ""
	}
	return base.Justify[src]
}

func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return strings.ToLower(raw)
	}
	return strings.ToLower(u.Hostname())
}

func sameHost(origin, pageHost string) bool {
	return hostOf(origin) == pageHost
}

func dedupe(in []failsafe.Finding) []failsafe.Finding {
	seen := map[string]bool{}
	type pair struct {
		k string
		f failsafe.Finding
	}
	var pairs []pair
	for _, f := range in {
		k := f.ID + "|" + f.Asset
		for _, e := range f.Evidence {
			if e.Key == "src" {
				k += "|" + e.Value
			}
		}
		if seen[k] {
			continue
		}
		seen[k] = true
		pairs = append(pairs, pair{k, f})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].k < pairs[j].k })
	out := make([]failsafe.Finding, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, p.f)
	}
	return out
}
