// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package flags

import (
	"strings"
	"testing"
	"time"
)

func TestArmDoesNotApply(t *testing.T) {
	rec, err := Arm(t.TempDir(), "cancel-only", "operator intent only", time.Date(2026, 10, 29, 18, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != "armed" {
		t.Fatalf("state %s", rec.State)
	}
	err = Apply(rec)
	if err == nil || !strings.Contains(err.Error(), "does not apply") {
		t.Fatalf("apply err %v", err)
	}
}

func TestRejectsPathID(t *testing.T) {
	if _, err := Arm(t.TempDir(), "../x", "note", time.Now()); err == nil {
		t.Fatal("path id accepted")
	}
}
