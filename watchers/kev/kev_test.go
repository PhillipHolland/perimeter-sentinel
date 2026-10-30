// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package kev

import (
	"testing"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
)

func TestMatchNeedsHumanWhenBlind(t *testing.T) {
	r := Match(nil, []Item{{CVE: "CVE-2026-0001", Product: "widget", Version: "1"}})
	if r.Status != failsafe.StatusNeedsHuman {
		t.Fatal(r.Status)
	}
}

func TestMatchFinding(t *testing.T) {
	sbom := []Component{{Name: "widget", Version: "1.2.3", PURL: "pkg:npm/widget@1.2.3"}}
	items := []Item{{CVE: "CVE-2026-0001", PURL: "pkg:npm/widget@1.2.3"}}
	r := Match(sbom, items)
	if r.Status != failsafe.StatusFinding || r.Findings[0].Detection != "det-kev-sbom" {
		t.Fatalf("%s", r)
	}
}
