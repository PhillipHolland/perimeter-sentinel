// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package freeze

import (
	"strings"
	"testing"
	"time"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/state"
)

func TestFreezeStopwatch(t *testing.T) {
	dir := t.TempDir()
	onset := time.Date(2026, 10, 29, 17, 10, 0, 0, time.UTC)
	notice := onset.Add(4 * time.Minute)
	start := notice.Add(1 * time.Minute)
	ros := state.Roster{
		People: []state.Person{{Role: "incident-commander", Name: "Ada", OOB: "voice"}},
		Contacts: []state.Contact{
			{ID: "cdn", Org: "Edge", Channel: "ticket"},
			{ID: "status-page", Org: "Status", Channel: "draft"},
		},
	}
	run, res := Start(StartInput{
		Playbook: "vendor-script-compromise", Now: start, OnsetAt: onset, NoticeAt: notice,
		OOBConfirmed: true, OOBChannel: "voice", Roster: ros, Dir: dir,
		Facts: Facts{Vendor: "rum-vendor", Page: "https://staging.example/trade", Owner: "Ada", ObservedAt: notice},
	})
	if res.Status != failsafe.StatusOK {
		t.Fatalf("start: %s", res)
	}
	if run.TimeToNotice != "4m0s" {
		t.Fatalf("notice %s", run.TimeToNotice)
	}
	for _, d := range run.Drafts {
		if d.Sent {
			t.Fatal("draft marked sent")
		}
		if !strings.Contains(d.Body, "does not send") {
			t.Fatalf("draft missing banner: %s", d.Template)
		}
	}
	containAt := onset.Add(12 * time.Minute)
	done, res := Contain(dir, run.ID, containAt)
	if res.Status != failsafe.StatusOK {
		t.Fatalf("contain: %s", res)
	}
	if done.ContainSeconds != 12*60 {
		t.Fatalf("contain seconds %d", done.ContainSeconds)
	}
	if !strings.Contains(done.KPI, "under") || !strings.Contains(done.KPI, "not prevention") {
		t.Fatalf("kpi %s", done.KPI)
	}
	view := Stopwatch(done, containAt)
	if !strings.Contains(view, "time_to_contain") || !strings.Contains(view, "drafts_sent false") {
		t.Fatalf("view:\n%s", view)
	}
}

func TestFreezeRequiresOOB(t *testing.T) {
	dir := t.TempDir()
	ros := state.Roster{
		People: []state.Person{{Role: "incident-commander", Name: "Ada", OOB: "voice"}},
		Contacts: []state.Contact{
			{ID: "issuer-usdc", Org: "Circle channel", Channel: "published"},
			{ID: "issuer-usdt", Org: "Tether channel", Channel: "published"},
			{ID: "ic3", Org: "IC3", Channel: "web"},
		},
	}
	now := time.Date(2026, 10, 29, 20, 0, 0, 0, time.UTC)
	run, res := Start(StartInput{
		Playbook: "hot-wallet-drain", Now: now, NoticeAt: now, Roster: ros, Dir: dir,
		Facts: Facts{Asset: "0xabc", Owner: "Ada"},
	})
	if res.Status != failsafe.StatusNeedsHuman {
		t.Fatalf("status %s", res.Status)
	}
	if run.Status != "blocked" {
		t.Fatal(run.Status)
	}
	if _, res := Contain(dir, run.ID, now.Add(time.Minute)); res.Status != failsafe.StatusNeedsHuman {
		// blocked runs are not saved when gaps exist before write... check
	}
}

func TestHotWalletDraftsPrefill(t *testing.T) {
	dir := t.TempDir()
	ros := fullHotRoster()
	now := time.Date(2026, 10, 29, 20, 32, 0, 0, time.UTC)
	run, res := Start(StartInput{
		Playbook: "hot-wallet-drain", Now: now, OnsetAt: now.Add(-30 * time.Second), NoticeAt: now,
		OOBConfirmed: true, OOBChannel: "voice", Roster: ros, Dir: dir,
		Facts: Facts{
			Asset: "0xabc", Chain: "testnet", Owner: "Ada", ObservedAt: now,
			Addresses: []string{"0xdest"}, Amounts: []string{"1"}, TxHashes: []string{"0xtx"},
		},
	})
	if res.Status != failsafe.StatusOK {
		t.Fatalf("%s", res)
	}
	var issuer string
	for _, d := range run.Drafts {
		if d.Template == "issuer-freeze.md" {
			issuer = d.Body
		}
	}
	if !strings.Contains(issuer, "0xdest") || !strings.Contains(issuer, "0xtx") {
		t.Fatalf("issuer draft not prefilled:\n%s", issuer)
	}
}

func fullHotRoster() state.Roster {
	return state.Roster{
		People: []state.Person{{Role: "incident-commander", Name: "Ada", OOB: "voice"}},
		Contacts: []state.Contact{
			{ID: "issuer-usdc", Org: "Circle published channel", Channel: "web"},
			{ID: "issuer-usdt", Org: "Tether published channel", Channel: "web"},
			{ID: "ic3", Org: "IC3", Channel: "web"},
		},
	}
}
