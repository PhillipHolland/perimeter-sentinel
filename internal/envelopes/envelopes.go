// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package envelopes describes a pre-approved, expiring action class.
// v0.1 does not execute envelopes. Execute returns an error on purpose.
package envelopes

import (
	"errors"
	"time"
)

// Envelope is one class a human pre-authorized.
type Envelope struct {
	Class              string    `json:"class"`
	ExpiresAt          time.Time `json:"expires_at"`
	PreApprovedBy      string    `json:"pre_approved_by"`
	SecondApprover     string    `json:"second_approver"`
	Rollback           string    `json:"rollback"`
	AccessibleFallback string    `json:"accessible_fallback,omitempty"`
}

// Active reports whether the envelope is still inside its window.
func Active(e Envelope, now time.Time) bool {
	if e.Class == "" || e.PreApprovedBy == "" || e.Rollback == "" {
		return false
	}
	if e.ExpiresAt.IsZero() || !e.ExpiresAt.After(now) {
		return false
	}
	return true
}

// Execute is refused. The operator's systems perform the action.
func Execute(e Envelope) error {
	return errors.New("v0.1 does not execute envelopes; the operator executes, and this envelope is a checklist")
}
