// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package readiness

import (
	"testing"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
)

func TestNoLogsNoClaim(t *testing.T) {
	rep := Score(DefaultSources())
	if rep.Tier != "EL0" {
		t.Fatal(rep.Tier)
	}
	r := Verdict(rep)
	if r.Status != failsafe.StatusNeedsHuman {
		t.Fatal(r.Status)
	}
}

func TestEL3RequiresYearAndIDP(t *testing.T) {
	src := []Source{
		{Name: "edge", Present: true, RetentionDays: 400, Centralized: true, CanReverse: true},
		{Name: "application", Present: true, RetentionDays: 400, Centralized: true, CanReverse: true},
		{Name: "idp", Present: true, RetentionDays: 400, Centralized: true, CanReverse: true},
	}
	rep := Score(src)
	if rep.Tier != "EL3" {
		t.Fatalf("tier %s blind %v", rep.Tier, rep.Blind)
	}
	if Verdict(rep).Status != failsafe.StatusOK {
		t.Fatal(Verdict(rep).Status)
	}
	src[0].RetentionDays = 30
	rep = Score(src)
	if rep.Tier == "EL3" {
		t.Fatal("short retention must not be EL3")
	}
	if Verdict(rep).Status != failsafe.StatusNeedsHuman {
		t.Fatal("short retention must fail closed")
	}
}
