// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package thirdparty

import (
	"testing"
	"time"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/scope"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/state"
	servedjs "github.com/perimeter-sentinel/perimeter-sentinel/watchers/served-js"
)

func TestVendorDriftNamesVendorAndEnvelope(t *testing.T) {
	cfg, sc, ros, page := gov(t)
	approved := "var rum=1;\n"
	served := "var rum=2;\n"
	src := "https://cdn.vendor.example/rum.js"
	base := Baseline{
		Page:    page.Name,
		Hashes:  map[string]string{src: servedjs.SHA256Hex([]byte(approved))},
		Vendors: map[string]string{"cdn.vendor.example": "rum-vendor"},
		Justify: map[string]string{src: "RUM on the trading page, accepted risk, drill fixture"},
	}
	changed := time.Date(2026, 10, 29, 17, 10, 0, 0, time.UTC)
	obs := []Observation{{
		Vantage:      "us-central",
		At:           changed.Add(4 * time.Minute),
		Body:         `<script src="` + src + `"></script>`,
		ScriptBodies: map[string]string{src: served},
	}}
	r := Check(cfg, sc, ros, page, base, base.Vendors, obs, changed)
	if r.Status != failsafe.StatusFinding {
		t.Fatalf("%s", r)
	}
	var found bool
	for _, f := range r.Findings {
		if f.ID != "vendor-hash-drift" {
			continue
		}
		found = true
		if f.Envelope != "vendor-script-compromise" {
			t.Fatal(f.Envelope)
		}
		if ev(f, "vendor") != "rum-vendor" {
			t.Fatal(ev(f, "vendor"))
		}
		if ev(f, "notice_seconds") != "240" {
			t.Fatal(ev(f, "notice_seconds"))
		}
	}
	if !found {
		t.Fatalf("%+v", r.Findings)
	}
}

func TestScopeDeny(t *testing.T) {
	cfg, sc, ros, _ := gov(t)
	page := scope.Asset{Kind: scope.KindPage, Name: "https://other.example/trade", TouchesSigning: true}
	r := Check(cfg, sc, ros, page, Baseline{}, nil, nil, time.Time{})
	if r.Status != failsafe.StatusNeedsHuman {
		t.Fatal(r.Status)
	}
}

func gov(t *testing.T) (state.Config, *scope.Store, state.Roster, scope.Asset) {
	t.Helper()
	cfg := state.Config{Owner: "Ada", Profile: state.ProfileCustody, Timezone: "America/Chicago", RiskAppetite: "low",
		ProbeInterval: "1m", IntakeInterval: "1m", OnchainInterval: "30s"}
	sc := &scope.Store{}
	_ = sc.Affirm("Ada", scope.Affirmation, time.Now())
	a, err := sc.Add(scope.KindPage, "https://staging.example/trade", "", true, true, false)
	if err != nil {
		t.Fatal(err)
	}
	ros := state.Roster{People: []state.Person{{Role: "incident-commander", Name: "Ada", OOB: "voice"}}}
	return cfg, sc, ros, a
}

func ev(f failsafe.Finding, k string) string {
	for _, e := range f.Evidence {
		if e.Key == k {
			return e.Value
		}
	}
	return ""
}
