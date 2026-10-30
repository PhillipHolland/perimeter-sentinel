// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package dns diffs live or replayed DNS against the operator's desired
// state. It does not chase CNAME targets outside scope: that would be a
// lookup against a name the operator did not declare. A CNAME that leaves
// scope is reported as a blind spot, and a changed CNAME is a finding.
package dns

import (
	"fmt"
	"sort"
	"strings"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/govern"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/scope"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/state"
)

// Record is one RRSET. Values are compared as a set.
type Record struct {
	Type   string   `json:"type"`
	Values []string `json:"values"`
}

// Snapshot is desired state or one vantage's answer.
type Snapshot struct {
	Name    string   `json:"name"`
	Vantage string   `json:"vantage,omitempty"`
	Records []Record `json:"records"`
	Error   string   `json:"error,omitempty"`
}

// Diff compares desired to observed. Both must already be in hand.
// Live resolvers are the caller's job, and only after RequireVerified.
func Diff(cfg state.Config, sc *scope.Store, ros state.Roster, desired Snapshot, observed []Snapshot) failsafe.Result {
	const watcher = "dns"
	name := desired.Name
	if name == "" && len(observed) > 0 {
		name = observed[0].Name
	}
	if res, ok := govern.Result(watcher, govern.Ready(cfg, sc, ros, scope.KindDNS, name)); !ok {
		return res
	}
	if len(observed) == 0 {
		return failsafe.NeedsHuman(watcher, "no DNS observation; refusing to report the name clean", fmt.Errorf("no observations"))
	}
	var findings []failsafe.Finding
	var blind []string
	for _, obs := range observed {
		if obs.Error != "" {
			return failsafe.NeedsHuman(watcher, "dns lookup failed", fmt.Errorf("vantage %s: %s", obs.Vantage, obs.Error))
		}
		findings = append(findings, compareSet(name, obs, desired)...)
		for _, rec := range obs.Records {
			if strings.EqualFold(rec.Type, "CNAME") {
				for _, v := range rec.Values {
					host := strings.TrimSuffix(strings.ToLower(v), ".")
					if host == "" {
						findings = append(findings, one("cname-empty", "CNAME has an empty target", name, "high", obs.Vantage))
						continue
					}
					if err := sc.Check(scope.KindDNS, host); err != nil {
						blind = append(blind, "CNAME target "+host+" is outside scope; it was not resolved")
					}
				}
			}
		}
	}
	if len(findings) == 0 {
		return failsafe.JustOK(watcher, "DNS matches desired state for the compared RRSETs").WithBlind(unique(blind))
	}
	res := failsafe.FromFindings(watcher, "DNS drifted from desired state", findings, unique(blind))
	res.Lesson = "L9 dns and certificates"
	return res
}

func compareSet(name string, obs, desired Snapshot) []failsafe.Finding {
	want := index(desired.Records)
	got := index(obs.Records)
	var out []failsafe.Finding
	keys := map[string]struct{}{}
	for k := range want {
		keys[k] = struct{}{}
	}
	for k := range got {
		keys[k] = struct{}{}
	}
	for typ := range keys {
		w, wok := want[typ]
		g, gok := got[typ]
		if wok && !gok {
			out = append(out, one("dns-missing", "Desired "+typ+" is absent", name, "high", obs.Vantage))
			continue
		}
		if gok && !wok {
			out = append(out, one("dns-unexpected", "Unexpected "+typ+" is present", name, "high", obs.Vantage))
			continue
		}
		if strings.Join(w, ",") != strings.Join(g, ",") {
			f := one("dns-changed", typ+" values changed", name, "high", obs.Vantage)
			f.Evidence = append(f.Evidence,
				failsafe.Evidence{Key: "desired", Value: strings.Join(w, ",")},
				failsafe.Evidence{Key: "observed", Value: strings.Join(g, ",")},
			)
			out = append(out, f)
		}
	}
	return out
}

func index(recs []Record) map[string][]string {
	out := map[string][]string{}
	for _, r := range recs {
		typ := strings.ToUpper(strings.TrimSpace(r.Type))
		vals := append([]string{}, r.Values...)
		for i, v := range vals {
			vals[i] = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(v)), ".")
		}
		sort.Strings(vals)
		out[typ] = vals
	}
	return out
}

func one(id, title, asset, sev, vantage string) failsafe.Finding {
	return failsafe.Finding{
		ID: id, Watcher: "dns", Title: title, Summary: title, CIA: "integrity",
		Attack: "T1584.002", Lesson: "module 9 DNS", Severity: sev, Asset: asset,
		Detection: "det-dns-drift",
		Evidence:  []failsafe.Evidence{{Key: "vantage", Value: vantage}},
	}
}

func unique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
