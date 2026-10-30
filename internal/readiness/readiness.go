// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package readiness scores whether the operator can support a claim.
// The tiers follow the shape of OMB M-21-31 (EL0–EL3) and the CISA guidance
// to keep at least a year of logs. A missing source is a blind spot.
// Sentinel does not invent coverage.
package readiness

import (
	"encoding/json"
	"os"
	"time"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/state"
)

// Source is one log the operator says they have. Sentinel does not collect it.
type Source struct {
	Name          string `json:"name"`
	Present       bool   `json:"present"`
	RetentionDays int    `json:"retention_days"`
	Centralized   bool   `json:"centralized"`
	CanReverse    bool   `json:"can_reverse"`
}

// Report is the score shown on every brief.
type Report struct {
	Tier    string   `json:"tier"`
	Score   int      `json:"score"`
	Covered []string `json:"covered"`
	Blind   []string `json:"blind"`
	Notes   []string `json:"notes"`
}

// DefaultSources are the questions init asks. All start absent.
func DefaultSources() []Source {
	names := []string{"edge", "application", "idp", "dns", "wallet-rpc"}
	out := make([]Source, 0, len(names))
	for _, n := range names {
		out = append(out, Source{Name: n})
	}
	return out
}

// Score applies the tier rules. Retention under 365 days cannot clear EL2.
func Score(sources []Source) Report {
	r := Report{Tier: "EL0", Notes: []string{
		"Tiers are M-21-31-shaped labels for the operator's own answers, not an authorization.",
	}}
	var present, centralized, year, reverse int
	for _, s := range sources {
		if !s.Present {
			r.Blind = append(r.Blind, s.Name+": not present")
			continue
		}
		present++
		if s.RetentionDays < 365 {
			r.Blind = append(r.Blind, s.Name+": retention under 365 days")
		} else {
			year++
		}
		if s.Centralized {
			centralized++
		} else {
			r.Blind = append(r.Blind, s.Name+": not centralized")
		}
		if s.CanReverse {
			reverse++
		}
		r.Covered = append(r.Covered, s.Name)
	}
	r.Score = present
	switch {
	case present == 0:
		r.Tier = "EL0"
	case year >= 2 && centralized >= 2 && reverse >= 1 && has(sources, "edge") && has(sources, "application") && has(sources, "idp"):
		r.Tier = "EL3"
	case year >= 2 && centralized >= 2 && has(sources, "edge") && has(sources, "application"):
		r.Tier = "EL2"
	default:
		r.Tier = "EL1"
	}
	if len(r.Blind) > 0 {
		r.Notes = append(r.Notes, "No logs, no claim: blind sources stay on the brief.")
	}
	return r
}

func has(sources []Source, name string) bool {
	for _, s := range sources {
		if s.Name == name && s.Present && s.RetentionDays >= 365 && s.Centralized {
			return true
		}
	}
	return false
}

// File is the on-disk readiness document.
type File struct {
	Sources []Source  `json:"sources"`
	Updated time.Time `json:"updated"`
}

func Load(path string) (File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return File{}, err
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return File{}, err
	}
	return f, nil
}

func Save(path string, f File) error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, state.FilePerm)
}

// Verdict is needs_human whenever any declared source is blind.
// An empty source list is also needs_human: silence is not coverage.
func Verdict(rep Report) failsafe.Result {
	if len(rep.Covered) == 0 || len(rep.Blind) > 0 {
		r := failsafe.NeedsHuman("readiness", "log readiness is incomplete ("+rep.Tier+")", nil)
		r.BlindSpots = rep.Blind
		r.Lesson = "L5 no logs, no claim"
		if len(rep.Blind) == 0 {
			r.BlindSpots = []string{"no log sources declared"}
		}
		return r
	}
	return failsafe.JustOK("readiness", "declared sources meet the recorded tier "+rep.Tier).WithBlind(nil)
}
