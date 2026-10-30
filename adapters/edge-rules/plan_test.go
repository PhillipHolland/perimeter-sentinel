// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package edgerules

import (
	"strings"
	"testing"
)

func TestPlanRefusesApply(t *testing.T) {
	c := Change{Vendor: "cloudflare", Resource: "csp", Diff: "deny vendor.example", Rollback: "restore previous CSP"}
	body, err := Plan(c)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "apply: refused") {
		t.Fatalf("body %s", body)
	}
	if err := Apply(c); err == nil || !strings.Contains(err.Error(), "refuses") {
		t.Fatalf("apply %v", err)
	}
}
