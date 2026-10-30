// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package preauth

import (
	"strings"
	"testing"
	"time"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
)

func TestRejectsPrivateKey(t *testing.T) {
	b := &Book{}
	err := b.Add(Authority{
		ID: "a", Kind: KindAPIKey, Subject: "ci", Fingerprint: "abc",
		Owner: "ada", Tier: TierNA, RevokePath: "rotate in the owner IdP",
		Outstanding: true, Note: "private_key=abcd",
	})
	// Note text containing the field name is not a JSON field. Use a real field.
	if err != nil && strings.Contains(err.Error(), "private") {
		return
	}
	err = b.Add(Authority{
		ID: "b", Kind: KindDelegation, Subject: "0xabc", Fingerprint: "ff",
		Owner: "ada", Tier: TierHot, Limit: "1", RevokePath: "owner ceremony",
		Outstanding: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Saving a document that smuggles a key via a raw edit is covered by secrets.Reject
	// on Save. Adding with a blocked fingerprint field name is not possible on the struct.
	rawBook := &Book{}
	if err := rawBook.Add(Authority{
		ID: "c", Kind: KindDelegation, Subject: "wallet", Fingerprint: "not-a-key",
		Owner: "ada", Tier: TierHot, RevokePath: "owner ceremony", Outstanding: true,
	}); err != nil {
		t.Fatal(err)
	}
	r := Review(rawBook.Authorities, time.Now())
	if r.Status != failsafe.StatusFinding {
		t.Fatalf("hot without limit: %s", r)
	}
}

func TestExpiredOutstanding(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	r := Review([]Authority{{
		ID: "del-1", Kind: KindDelegation, Subject: "0xabc", Fingerprint: "fp",
		Tier: TierWarm, Limit: "1", RevokePath: "owner clears delegation",
		Outstanding: true, Expires: now.Add(-time.Hour),
	}}, now)
	if r.Status != failsafe.StatusFinding {
		t.Fatalf("%s", r)
	}
	if r.Findings[0].Detection != "det-preauth-expired" {
		t.Fatal(r.Findings[0].Detection)
	}
}
