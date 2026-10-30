// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package tls

import (
	"testing"
	"time"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/scope"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/state"
)

func TestFingerprintDrift(t *testing.T) {
	cfg, sc, ros := gov(t)
	now := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	base := Snapshot{Host: "owned.example", Fingerprint: "aa", Issuer: "CN=Test", NotAfter: now.Add(90 * 24 * time.Hour)}
	obs := base
	obs.Fingerprint = "bb"
	obs.Vantage = "local"
	r := Diff(cfg, sc, ros, base, []Snapshot{obs}, now, 14*24*time.Hour)
	if r.Status != failsafe.StatusFinding {
		t.Fatalf("%s", r)
	}
}

func TestExpiryAndError(t *testing.T) {
	cfg, sc, ros := gov(t)
	now := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	base := Snapshot{Host: "owned.example", Fingerprint: "aa", Issuer: "CN=Test", NotAfter: now.Add(48 * time.Hour)}
	r := Diff(cfg, sc, ros, base, []Snapshot{base}, now, 14*24*time.Hour)
	if r.Status != failsafe.StatusFinding {
		t.Fatalf("expiry: %s", r)
	}
	bad := base
	bad.Error = "handshake timeout"
	bad.NotAfter = now.Add(90 * 24 * time.Hour)
	r = Diff(cfg, sc, ros, base, []Snapshot{bad}, now, 0)
	if r.Status != failsafe.StatusNeedsHuman {
		t.Fatal(r.Status)
	}
}

func TestScopeDeny(t *testing.T) {
	cfg, sc, ros := gov(t)
	r := Diff(cfg, sc, ros, Snapshot{Host: "other.example", Fingerprint: "aa"}, nil, time.Now(), 0)
	if r.Status != failsafe.StatusNeedsHuman {
		t.Fatal(r.Status)
	}
}

func gov(t *testing.T) (state.Config, *scope.Store, state.Roster) {
	t.Helper()
	cfg := state.Config{Owner: "Ada", Profile: state.ProfileEnterprise, Timezone: "UTC", RiskAppetite: "low",
		ProbeInterval: "1m", IntakeInterval: "1m", OnchainInterval: "30s"}
	sc := &scope.Store{}
	_ = sc.Affirm("Ada", scope.Affirmation, time.Now())
	if _, err := sc.Add(scope.KindHTTPS, "owned.example", "", false, false, false); err != nil {
		t.Fatal(err)
	}
	ros := state.Roster{People: []state.Person{{Role: "incident-commander", Name: "Ada", OOB: "voice"}}}
	return cfg, sc, ros
}
