// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package oct29

import (
	"strings"
	"testing"
	"time"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/drill"
)

func TestOct29Acceptance(t *testing.T) {
	reps, err := drill.RunAll(t.TempDir(), time.Date(2026, 10, 29, 18, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(reps) != len(drill.Specs()) {
		t.Fatalf("got %d reports", len(reps))
	}
	for _, r := range reps {
		if !r.Pass {
			t.Errorf("%s FAIL: %s", r.ID, r.Detail)
		}
	}
	joined := ""
	for _, r := range reps {
		joined += r.Detail + "\n"
	}
	if strings.Contains(joined, "private key was accepted") {
		t.Fatal(joined)
	}
}
