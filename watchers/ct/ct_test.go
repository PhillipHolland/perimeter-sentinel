// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package ct

import (
	"testing"
	"time"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/scope"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/state"
)

func TestUnexpectedIssuer(t *testing.T) {
	cfg, sc, ros := gov(t)
	r := Diff(cfg, sc, ros, "owned.example", []string{"Expected CA"}, []Entry{{
		DNSNames: []string{"owned.example"}, Issuer: "Other CA",
	}})
	if r.Status != failsafe.StatusFinding || r.Findings[0].Detection != "det-ct-issuer" {
		t.Fatalf("%s", r)
	}
}

func TestEmptyFeedIsNeedsHuman(t *testing.T) {
	cfg, sc, ros := gov(t)
	r := Diff(cfg, sc, ros, "owned.example", []string{"Expected CA"}, nil)
	if r.Status != failsafe.StatusNeedsHuman {
		t.Fatal(r.Status)
	}
}

func TestOutOfScopeNameIsIgnored(t *testing.T) {
	cfg, sc, ros := gov(t)
	r := Diff(cfg, sc, ros, "owned.example", []string{"Expected CA"}, []Entry{{
		DNSNames: []string{"other.example"}, Issuer: "Other CA",
	}})
	if r.Status != failsafe.StatusOK {
		t.Fatalf("%s", r)
	}
}

func gov(t *testing.T) (state.Config, *scope.Store, state.Roster) {
	t.Helper()
	cfg := state.Config{Owner: "Ada", Profile: state.ProfileEnterprise, Timezone: "UTC", RiskAppetite: "low",
		ProbeInterval: "1m", IntakeInterval: "1m", OnchainInterval: "30s"}
	sc := &scope.Store{}
	if err := sc.Affirm("Ada", scope.Affirmation, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := sc.Add(scope.KindHTTPS, "owned.example", "", false, false, false); err != nil {
		t.Fatal(err)
	}
	ros := state.Roster{People: []state.Person{{Role: "incident-commander", Name: "Ada", OOB: "voice"}}}
	return cfg, sc, ros
}
