// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package correlate

import (
	"testing"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
)

func TestRepeatedPathIsFinding(t *testing.T) {
	var reqs []Request
	for i := 0; i < 6; i++ {
		base := int64(i) // same second-ish, spread by client but span 0 if all second 0
		reqs = append(reqs,
			Request{ClientKey: string(rune('a' + i)), Path: "/login", Second: base % 5},
			Request{ClientKey: string(rune('a' + i)), Path: "/login", Second: base % 5},
		)
	}
	// Force identical sequences and a tight span.
	reqs = nil
	for i := 0; i < 6; i++ {
		key := string(rune('a' + i))
		reqs = append(reqs,
			Request{ClientKey: key, Path: "/a", Second: 1},
			Request{ClientKey: key, Path: "/b", Second: 2},
		)
	}
	r := Score(reqs)
	if r.Status != failsafe.StatusFinding {
		t.Fatalf("%s", r)
	}
}

func TestIPOnlyRejected(t *testing.T) {
	r := RejectIPOnly(IPOnly{Addresses: []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}})
	if r.Status != failsafe.StatusNeedsHuman {
		t.Fatal(r.Status)
	}
}

func TestOrdinaryTrafficOK(t *testing.T) {
	reqs := []Request{
		{ClientKey: "h1", Path: "/results", Second: 10},
		{ClientKey: "h2", Path: "/about", Second: 80},
	}
	r := Score(reqs)
	if r.Status != failsafe.StatusOK {
		t.Fatalf("%s", r)
	}
}
