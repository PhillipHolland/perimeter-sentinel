// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package lanes

import "testing"

func TestVerifiedAgentKeepsStepUp(t *testing.T) {
	d := Assign(Input{RFC9421Verified: true, FraudSignal: true, RelaxFraudChecks: true})
	if d.Lane != VerifiedAgent {
		t.Fatal(d.Lane)
	}
	if !d.StepUp {
		t.Fatal("fraud checks must stay")
	}
	if d.Apply {
		t.Fatal("v0.1 must not apply")
	}
}

func TestTripwireQuarantineOnly(t *testing.T) {
	d := Assign(Input{Tripwire: true, RFC9421Verified: true})
	if d.Lane != Quarantine {
		t.Fatal(d.Lane)
	}
	if d.Reason == "" {
		t.Fatal("missing reason")
	}
}
