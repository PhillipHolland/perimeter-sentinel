// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package failsafe is the shared result type for every watcher and command.
//
// Graduation lesson 1 (Saltzer & Schroeder fail-safe defaults; OWASP A10:2025):
// a result is ok, finding, or needs_human. Errors, timeouts, and refusals are
// needs_human. They are never an all-clear.
package failsafe

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Status is the only verdict a Sentinel check is allowed to return.
type Status string

const (
	// StatusOK means the check ran, the inputs were sufficient, and nothing
	// in scope drifted. It is forbidden when any input was missing or any
	// call failed.
	StatusOK Status = "ok"
	// StatusFinding means the check ran and observed a defensive condition
	// the operator should review. It is not a claim that an intrusion succeeded.
	StatusFinding Status = "finding"
	// StatusNeedsHuman means Sentinel cannot decide. The operator must look.
	// This is the fail-closed state.
	StatusNeedsHuman Status = "needs_human"
)

// Evidence is a string pair so ledger payloads stay canonical.
type Evidence struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Finding is one observed condition. Detections describe behavior and drift.
// They do not include reproduction steps.
type Finding struct {
	ID         string     `json:"id"`
	Watcher    string     `json:"watcher"`
	Title      string     `json:"title"`
	Summary    string     `json:"summary"`
	CIA        string     `json:"cia,omitempty"`
	Attack     string     `json:"attack,omitempty"`
	Lesson     string     `json:"lesson,omitempty"`
	Severity   string     `json:"severity,omitempty"`
	Asset      string     `json:"asset,omitempty"`
	Detection  string     `json:"detection,omitempty"`
	Envelope   string     `json:"envelope,omitempty"`
	Evidence   []Evidence `json:"evidence,omitempty"`
	BlindSpots []string   `json:"blind_spots,omitempty"`
}

// Result is the fail-closed verdict of one check.
type Result struct {
	Status     Status    `json:"status"`
	Watcher    string    `json:"watcher"`
	Summary    string    `json:"summary"`
	Findings   []Finding `json:"findings,omitempty"`
	BlindSpots []string  `json:"blind_spots,omitempty"`
	Lesson     string    `json:"lesson,omitempty"`
	Err        string    `json:"error,omitempty"`
}

// NeedsHuman builds the fail-closed verdict. err may be nil.
func NeedsHuman(watcher, summary string, err error) Result {
	r := Result{
		Status:  StatusNeedsHuman,
		Watcher: watcher,
		Summary: summary,
		Lesson:  "L1 fail closed",
	}
	if err != nil {
		r.Err = err.Error()
		if summary == "" {
			r.Summary = "check could not be completed"
		}
	}
	if r.Summary == "" {
		r.Summary = "needs human"
	}
	return r
}

// FromError maps any non-nil error to needs_human. A nil error is a programming
// mistake and still does not return OK.
func FromError(watcher string, err error) Result {
	if err == nil {
		return NeedsHuman(watcher, "error path called without an error; refusing to report ok", errors.New("nil error"))
	}
	return NeedsHuman(watcher, "check failed", err)
}

// JustOK is a clean verdict. Callers must not use it after a partial failure.
func JustOK(watcher, summary string) Result {
	return Result{Status: StatusOK, Watcher: watcher, Summary: summary}
}

// FromFindings returns finding when there is at least one finding.
// With none, it returns needs_human: an empty finding list is not an all-clear.
// Call JustOK only from a watcher that positively compared a full baseline.
func FromFindings(watcher, summary string, findings []Finding, blind []string) Result {
	if len(findings) == 0 {
		return NeedsHuman(watcher, "no findings were produced; refusing to infer ok", errors.New("empty findings"))
	}
	return Result{
		Status:     StatusFinding,
		Watcher:    watcher,
		Summary:    summary,
		Findings:   findings,
		BlindSpots: blind,
	}
}

// WithBlind keeps a positive OK only when the caller asserts coverage.
// If blind spots are present, OK is downgraded to needs_human so a brief
// cannot say the asset is clear where telemetry is missing.
// Existing findings stay findings and keep the blind spots attached.
func (r Result) WithBlind(spots []string) Result {
	if len(spots) == 0 {
		return r
	}
	r.BlindSpots = append(append([]string{}, r.BlindSpots...), spots...)
	if r.Status == StatusOK {
		r.Status = StatusNeedsHuman
		r.Lesson = "L5 no logs, no claim"
		if r.Summary == "" {
			r.Summary = "coverage is incomplete"
		} else {
			r.Summary = r.Summary + "; coverage is incomplete"
		}
	}
	return r
}

// ExitCode maps a verdict to a process status. Usage errors are not a Result.
func (r Result) ExitCode() int {
	switch r.Status {
	case StatusOK:
		return 0
	case StatusFinding:
		return 2
	default:
		return 3
	}
}

// Normalize forces unknown statuses to needs_human.
func (r Result) Normalize() Result {
	switch r.Status {
	case StatusOK, StatusFinding, StatusNeedsHuman:
		return r
	default:
		r.Status = StatusNeedsHuman
		if r.Err == "" {
			r.Err = "unknown status coerced to needs_human"
		}
		return r
	}
}

// JSON returns the canonical encoding of the result.
func (r Result) JSON() ([]byte, error) {
	r = r.Normalize()
	return json.Marshal(r)
}

// String is a one-line operator summary.
func (r Result) String() string {
	r = r.Normalize()
	var b strings.Builder
	fmt.Fprintf(&b, "%s watcher=%s %s", r.Status, r.Watcher, r.Summary)
	if r.Err != "" {
		fmt.Fprintf(&b, " error=%s", r.Err)
	}
	if len(r.Findings) > 0 {
		fmt.Fprintf(&b, " findings=%d", len(r.Findings))
	}
	if len(r.BlindSpots) > 0 {
		fmt.Fprintf(&b, " blind=%d", len(r.BlindSpots))
	}
	return b.String()
}
