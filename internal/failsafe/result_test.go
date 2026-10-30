// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package failsafe

import (
	"errors"
	"testing"
)

func TestFromErrorNeverOK(t *testing.T) {
	cases := []error{nil, errors.New("timeout"), errors.New("parse")}
	for _, err := range cases {
		r := FromError("dns", err).Normalize()
		if r.Status != StatusNeedsHuman {
			t.Fatalf("err %v status %s, want needs_human", err, r.Status)
		}
		if r.ExitCode() == 0 {
			t.Fatal("needs_human must not exit 0")
		}
	}
}

func TestWithBlindDowngradesOK(t *testing.T) {
	r := JustOK("brief", "no drift in watched sources").WithBlind([]string{"idp logs absent"})
	if r.Status != StatusNeedsHuman {
		t.Fatalf("status %s", r.Status)
	}
	if r.Lesson != "L5 no logs, no claim" {
		t.Fatalf("lesson %s", r.Lesson)
	}
}

func TestFindingStaysFindingWhenBlind(t *testing.T) {
	r := FromFindings("dns", "drift", []Finding{{ID: "1", Title: "A changed"}}, nil)
	r = r.WithBlind([]string{"cname chase skipped"})
	if r.Status != StatusFinding {
		t.Fatalf("status %s", r.Status)
	}
	if len(r.BlindSpots) != 1 {
		t.Fatalf("blind %+v", r.BlindSpots)
	}
}

func TestUnknownStatusCoerced(t *testing.T) {
	r := Result{Status: "all-clear", Watcher: "x"}.Normalize()
	if r.Status != StatusNeedsHuman {
		t.Fatalf("status %s", r.Status)
	}
}
