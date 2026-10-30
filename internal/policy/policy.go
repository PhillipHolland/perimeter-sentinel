// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package policy is the v0.1 guardrail evaluator. The same rules are written
// in policy/*.rego for a later conftest job. This package does not shell out
// to OPA, so a missing OPA binary cannot turn a decision into an all-clear.
//
// Lesson 10: friction needs an accessible fallback, behavioral telemetry is
// opt-in and off for civic, and a verified agent is not trusted intent.
package policy

import (
	"strings"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
)

// Friction is one proposed rung on the ladder.
type Friction struct {
	Enabled             bool
	AccessibleFallback  bool
	FallbackDescription string
}

// Telemetry is proposed visitor-behavior collection.
type Telemetry struct {
	Enabled       bool
	OptIn         bool
	Profile       string
	Aggregated    bool
	RetentionDays int
}

// AgentLane is a lane decision. Verified identity must not relax fraud checks.
type AgentLane struct {
	VerifiedAgent bool
	FraudSignal   bool
	RelaxChecks   bool
}

// Evaluate returns findings for rule breaks. No breaks is OK only when the
// caller passed a complete input. Empty input is needs_human.
type Input struct {
	Friction  *Friction
	Telemetry *Telemetry
	Agent     *AgentLane
}

// Evaluate applies the guardrails.
func Evaluate(in Input) failsafe.Result {
	if in.Friction == nil && in.Telemetry == nil && in.Agent == nil {
		return failsafe.NeedsHuman("policy", "no policy input", nil)
	}
	var findings []failsafe.Finding
	if f := in.Friction; f != nil && f.Enabled && (!f.AccessibleFallback || strings.TrimSpace(f.FallbackDescription) == "") {
		findings = append(findings, failsafe.Finding{
			ID: "policy-accessibility", Watcher: "policy",
			Title:   "Friction has no accessible fallback",
			Summary: "A friction rung needs a non-visual, non-JS path the operator can describe.",
			Lesson:  "L10 friction must be accessible", CIA: "availability", Severity: "high",
			Detection: "policy-accessibility",
		})
	}
	if t := in.Telemetry; t != nil && t.Enabled {
		if t.Profile == "civic" || !t.OptIn || !t.Aggregated || t.RetentionDays <= 0 || t.RetentionDays > 14 {
			findings = append(findings, failsafe.Finding{
				ID: "policy-privacy", Watcher: "policy",
				Title:   "Behavioral telemetry is not allowed on these terms",
				Summary: "Telemetry must be opt-in, aggregated, retained at most 14 days, and off for the civic profile.",
				Lesson:  "L10 friction must be accessible and private", CIA: "confidentiality", Severity: "high",
				Detection: "policy-privacy",
			})
		}
	}
	if a := in.Agent; a != nil && a.VerifiedAgent && (a.RelaxChecks || a.FraudSignal) {
		// A fraud signal on a verified agent must keep checks. RelaxChecks is always a finding.
		if a.RelaxChecks {
			findings = append(findings, failsafe.Finding{
				ID: "policy-identity-intent", Watcher: "policy",
				Title:   "Verified-agent lane must not relax fraud checks",
				Summary: "A signature proves identity. It does not prove intent.",
				Lesson:  "L10 identity is not intent", CIA: "integrity", Severity: "high",
				Detection: "policy-identity",
			})
		}
	}
	if len(findings) == 0 {
		return failsafe.JustOK("policy", "guardrails accepted the proposal")
	}
	return failsafe.FromFindings("policy", "guardrails rejected the proposal", findings, nil)
}
