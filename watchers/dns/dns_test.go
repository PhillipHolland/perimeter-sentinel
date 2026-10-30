// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"testing"
	"time"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/scope"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/state"
)

func TestDrift(t *testing.T) {
	cfg, sc, ros := gov(t, "owned.example")
	desired := Snapshot{Name: "owned.example", Records: []Record{{Type: "A", Values: []string{"192.0.2.10"}}}}
	obs := []Snapshot{{Name: "owned.example", Vantage: "local", Records: []Record{{Type: "A", Values: []string{"192.0.2.99"}}}}}
	r := Diff(cfg, sc, ros, desired, obs)
	if r.Status != failsafe.StatusFinding {
		t.Fatalf("%s", r)
	}
}

func TestMatch(t *testing.T) {
	cfg, sc, ros := gov(t, "owned.example")
	snap := Snapshot{Name: "owned.example", Records: []Record{{Type: "A", Values: []string{"192.0.2.10"}}}}
	r := Diff(cfg, sc, ros, snap, []Snapshot{snap})
	if r.Status != failsafe.StatusOK {
		t.Fatalf("%s", r)
	}
}

func TestScopeDeny(t *testing.T) {
	cfg, sc, ros := gov(t, "owned.example")
	r := Diff(cfg, sc, ros, Snapshot{Name: "other.example"}, nil)
	if r.Status != failsafe.StatusNeedsHuman {
		t.Fatal(r.Status)
	}
}

func TestLookupErrorIsNeedsHuman(t *testing.T) {
	cfg, sc, ros := gov(t, "owned.example")
	r := Diff(cfg, sc, ros, Snapshot{Name: "owned.example", Records: []Record{{Type: "A", Values: []string{"192.0.2.10"}}}},
		[]Snapshot{{Name: "owned.example", Error: "timeout"}})
	if r.Status != failsafe.StatusNeedsHuman {
		t.Fatal(r.Status)
	}
}

func TestCNAMEOutsideScopeIsBlindNotChased(t *testing.T) {
	cfg, sc, ros := gov(t, "owned.example")
	desired := Snapshot{Name: "owned.example", Records: []Record{{Type: "CNAME", Values: []string{"cdn.vendor.example"}}}}
	r := Diff(cfg, sc, ros, desired, []Snapshot{{Name: "owned.example", Vantage: "local", Records: desired.Records}})
	if r.Status != failsafe.StatusNeedsHuman {
		t.Fatalf("status %s", r.Status)
	}
	if len(r.BlindSpots) == 0 {
		t.Fatal("expected blind spot")
	}
}

func gov(t *testing.T, name string) (state.Config, *scope.Store, state.Roster) {
	t.Helper()
	cfg := state.Config{Owner: "Ada", Profile: state.ProfileEnterprise, Timezone: "UTC", RiskAppetite: "low",
		ProbeInterval: "1m", IntakeInterval: "1m", OnchainInterval: "30s"}
	sc := &scope.Store{}
	_ = sc.Affirm("Ada", scope.Affirmation, time.Now())
	if _, err := sc.Add(scope.KindDNS, name, "", false, false, false); err != nil {
		t.Fatal(err)
	}
	ros := state.Roster{People: []state.Person{{Role: "incident-commander", Name: "Ada", OOB: "voice"}}}
	return cfg, sc, ros
}
