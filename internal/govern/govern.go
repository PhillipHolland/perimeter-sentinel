// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package govern enforces "govern before detect" (NIST CSF 2.0, lesson 2).
// Watchers do not run until the owner, the affirmation, the risk appetite,
// and a human incident commander exist. Sentinel is scribe, never commander.
package govern

import (
	"fmt"
	"strings"
	"time"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/scope"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/state"
)

// Gap is one missing governance fact.
type Gap struct {
	Code   string
	Detail string
}

func (g Gap) Error() string { return g.Code + ": " + g.Detail }

// Ready reports whether a watcher may read this asset.
func Ready(cfg state.Config, sc *scope.Store, ros state.Roster, kind scope.Kind, name string) []Gap {
	var gaps []Gap
	if strings.TrimSpace(cfg.Owner) == "" {
		gaps = append(gaps, Gap{"owner", "owner is not set"})
	}
	switch cfg.RiskAppetite {
	case "low", "medium", "high":
	default:
		gaps = append(gaps, Gap{"risk-appetite", "risk appetite is not set"})
	}
	if cfg.Profile == state.ProfileCivic && cfg.BehavioralTelemetry {
		gaps = append(gaps, Gap{"privacy", "civic profile forbids behavioral telemetry"})
	}
	if sc == nil || !sc.Affirmed() {
		gaps = append(gaps, Gap{"affirmation", "owner has not affirmed \"I operate these\""})
	}
	if _, ok := ros.Commander(); !ok {
		gaps = append(gaps, Gap{"roster", "freeze roster needs a human incident commander and an out-of-band channel"})
	}
	if sc != nil && sc.Affirmed() {
		if err := sc.Check(kind, name); err != nil {
			gaps = append(gaps, Gap{"scope", err.Error()})
		}
	}
	return gaps
}

// Result turns gaps into a fail-closed watcher result. ok is true when the
// watcher may proceed.
func Result(watcher string, gaps []Gap) (failsafe.Result, bool) {
	if len(gaps) == 0 {
		return failsafe.Result{}, true
	}
	parts := make([]string, 0, len(gaps))
	for _, g := range gaps {
		parts = append(parts, g.Error())
	}
	return failsafe.NeedsHuman(watcher, "govern before detect: "+strings.Join(parts, "; "), fmt.Errorf("%s", strings.Join(parts, "; "))), false
}

// IntervalStatus flags probe intervals that are looser than the Oct 29 bar.
// A loose interval is a blind spot, not a silent OK.
func IntervalStatus(cfg state.Config) []string {
	var blind []string
	checks := []struct {
		name string
		raw  string
		max  time.Duration
	}{
		{"served script and third-party probe", cfg.ProbeInterval, 5 * time.Minute},
		{"external intake", cfg.IntakeInterval, 2 * time.Minute},
		{"on-chain tier-0 watch", cfg.OnchainInterval, 60 * time.Second},
	}
	for _, c := range checks {
		d, err := time.ParseDuration(c.raw)
		if err != nil || d <= 0 {
			blind = append(blind, c.name+": interval missing or unparsable")
			continue
		}
		if d > c.max {
			blind = append(blind, fmt.Sprintf("%s interval %s exceeds the Oct 29 bar of %s", c.name, d, c.max))
		}
	}
	return blind
}
