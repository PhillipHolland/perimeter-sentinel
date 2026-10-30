// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package approve records that a human approval was claimed. It does not hold
// a signing key and it does not check a WebAuthn assertion in v0.1.
// A receipt without a human fingerprint is needs_human, not an approval.
package approve

import (
	"errors"
	"strings"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
)

// Receipt is what the operator says they signed, somewhere else.
type Receipt struct {
	CardID              string
	ApproverFingerprint string
	SecondFingerprint   string
	Statement           string
}

// Accept checks the shape of a receipt. It does not verify a signature.
func Accept(r Receipt) failsafe.Result {
	if strings.TrimSpace(r.CardID) == "" {
		return failsafe.NeedsHuman("approve", "receipt has no card id", errors.New("card"))
	}
	if strings.TrimSpace(r.ApproverFingerprint) == "" {
		return failsafe.NeedsHuman("approve", "receipt has no approver fingerprint", errors.New("fingerprint"))
	}
	if self(r.ApproverFingerprint) || self(r.SecondFingerprint) {
		return failsafe.NeedsHuman("approve", "sentinel cannot be an approver", errors.New("self-approval"))
	}
	if strings.TrimSpace(r.SecondFingerprint) == "" {
		return failsafe.NeedsHuman("approve", "high-risk classes need a second human fingerprint; v0.1 does not assume this one is low risk", errors.New("second"))
	}
	if r.ApproverFingerprint == r.SecondFingerprint {
		return failsafe.NeedsHuman("approve", "the two fingerprints match; that is one person", errors.New("same"))
	}
	res := failsafe.JustOK("approve", "receipt shape is stored; signature was not verified in v0.1")
	res.Lesson = "separation of privilege"
	return res.WithBlind([]string{"signature verification is not implemented; this is not an authorization to apply"})
}

func self(s string) bool {
	l := strings.ToLower(strings.TrimSpace(s))
	return l == "sentinel" || l == "perimeterctl" || l == "perimeter-sentinel"
}
