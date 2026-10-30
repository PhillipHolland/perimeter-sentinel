// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"testing"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
)

func TestAccessibilityReject(t *testing.T) {
	r := Evaluate(Input{Friction: &Friction{Enabled: true}})
	if r.Status != failsafe.StatusFinding {
		t.Fatal(r.Status)
	}
}

func TestCivicTelemetryOff(t *testing.T) {
	r := Evaluate(Input{Telemetry: &Telemetry{Enabled: true, OptIn: true, Profile: "civic", Aggregated: true, RetentionDays: 7}})
	if r.Status != failsafe.StatusFinding {
		t.Fatal(r.Status)
	}
}

func TestVerifiedAgentDoesNotRelax(t *testing.T) {
	r := Evaluate(Input{Agent: &AgentLane{VerifiedAgent: true, RelaxChecks: true}})
	if r.Status != failsafe.StatusFinding {
		t.Fatal(r.Status)
	}
	ok := Evaluate(Input{Agent: &AgentLane{VerifiedAgent: true, FraudSignal: true, RelaxChecks: false}})
	if ok.Status != failsafe.StatusOK {
		t.Fatalf("keeping checks should be ok, got %s", ok.Status)
	}
}
