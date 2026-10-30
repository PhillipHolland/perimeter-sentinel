// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package osv

import (
	"testing"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
	"github.com/perimeter-sentinel/perimeter-sentinel/watchers/kev"
)

func TestMatchNeedsHumanWhenBlind(t *testing.T) {
	r := Match([]kev.Component{{Name: "widget", PURL: "pkg:npm/widget@1"}}, nil)
	if r.Status != failsafe.StatusNeedsHuman {
		t.Fatal(r.Status)
	}
}

func TestMatchFinding(t *testing.T) {
	r := Match(
		[]kev.Component{{Name: "widget", PURL: "pkg:npm/widget@1"}},
		[]Item{{ID: "OSV-2026-1", PURL: "pkg:npm/widget@1"}},
	)
	if r.Status != failsafe.StatusFinding || r.Findings[0].Detection != "det-osv-sbom" {
		t.Fatalf("%s", r)
	}
}
