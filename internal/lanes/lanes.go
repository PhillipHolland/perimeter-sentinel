// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package lanes is the operator's traffic policy vocabulary.
//
// Sentinel is an operator console across edge vendors, not a bot detector.
// It does not score a request inline and it does not block one. It names the
// lane an edge should already be enforcing, and it notices when a proposal
// would treat a verified agent as trusted. Identity is not intent.
//
// Lanes: human, verified-agent, declared-automation, unknown-automation, quarantine.
// A verified signature never relaxes fraud checks.
package lanes

import "strings"

// Lane is a budget class, not a moral category.
type Lane string

const (
	Human              Lane = "human"
	VerifiedAgent      Lane = "verified-agent"
	DeclaredAutomation Lane = "declared-automation"
	UnknownAutomation  Lane = "unknown-automation"
	Quarantine         Lane = "quarantine"
)

// Input is what the operator already knows. Raw visitor identifiers are not required.
type Input struct {
	SessionProven    bool
	RFC9421Verified  bool
	DeclaredBot      bool
	Tripwire         bool
	FraudSignal      bool
	RelaxFraudChecks bool
}

// Decision is advisory. The edge enforces. Apply is always false in v0.1.
type Decision struct {
	Lane   Lane
	Apply  bool
	Reason string
	// StepUp stays true when a fraud signal is present, including for verified agents.
	StepUp bool
}

// Assign picks a lane. It never returns a direction to execute code.
func Assign(in Input) Decision {
	d := Decision{Apply: false}
	switch {
	case in.Tripwire:
		d.Lane = Quarantine
		d.Reason = "tripwire hit moves the session to the quarantine lane; no code is served to the agent"
		d.StepUp = true
	case in.SessionProven && !in.DeclaredBot:
		d.Lane = Human
		d.Reason = "session-proven human lane"
	case in.RFC9421Verified:
		d.Lane = VerifiedAgent
		d.Reason = "signature verified against a pinned directory; fraud checks stay on"
	case in.DeclaredBot:
		d.Lane = DeclaredAutomation
		d.Reason = "unsigned automation claim; treat as unverified"
	default:
		d.Lane = UnknownAutomation
		d.Reason = "no proof of a human session and no verified signature"
	}
	if in.FraudSignal || in.RelaxFraudChecks {
		d.StepUp = true
		if in.RelaxFraudChecks {
			d.Reason = d.Reason + "; proposal to relax fraud checks was ignored"
		}
	}
	return d
}

// All returns the lane names in ladder order.
func All() []Lane {
	return []Lane{Human, VerifiedAgent, DeclaredAutomation, UnknownAutomation, Quarantine}
}

// Valid reports whether s is a known lane.
func Valid(s string) bool {
	for _, l := range All() {
		if string(l) == s {
			return true
		}
	}
	return false
}

// Note is the one-line product statement.
func Note() string {
	return strings.TrimSpace(`
Perimeter Sentinel names lanes and budgets. The owner's edge enforces them.
This package is not a bot detector and it does not claim a detection rate.
`)
}
