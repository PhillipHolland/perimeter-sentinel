// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package gitops

import (
	"strings"
	"testing"
)

func TestRenderIsUnapplied(t *testing.T) {
	body, err := Render(Card{
		ID: "card-1", Title: "Deny vendor origin", Diff: "csp: remove demo-vendor",
		Rollback: "restore previous CSP", Expiry: "2026-10-29T22:00:00Z", Lesson: "L7",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "did not push") || !strings.Contains(body, "Apply: false") || !strings.Contains(body, "demo-vendor") {
		t.Fatalf("body %s", body)
	}
	if _, err := Render(Card{}); err == nil {
		t.Fatal("empty card rendered")
	}
}
