// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package csp

import (
	"testing"
	"time"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/scope"
)

func TestInScopeViolation(t *testing.T) {
	sc := &scope.Store{}
	_ = sc.Affirm("Ada", scope.Affirmation, time.Now())
	_, _ = sc.Add(scope.KindPage, "https://owned.example/trade", "", true, true, false)
	body := []byte(`{"csp-report":{"document-uri":"https://owned.example/trade","violated-directive":"script-src","blocked-uri":"https://cdn.evil.example/a.js"}}`)
	reps, err := Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	r := Classify(sc, reps)
	if r.Status != failsafe.StatusFinding {
		t.Fatalf("%s", r)
	}
}

func TestDropsOutOfScope(t *testing.T) {
	sc := &scope.Store{}
	_ = sc.Affirm("Ada", scope.Affirmation, time.Now())
	_, _ = sc.Add(scope.KindPage, "https://owned.example/trade", "", false, false, false)
	r := Classify(sc, []Report{{DocumentURI: "https://other.example/", ViolatedDirective: "script-src", BlockedURI: "https://x"}})
	if r.Status != failsafe.StatusNeedsHuman {
		t.Fatal(r.Status)
	}
}
