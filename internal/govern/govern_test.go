// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package govern

import (
	"testing"
	"time"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/scope"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/state"
)

func TestGovernBlocksUnaffirmed(t *testing.T) {
	cfg := state.Config{Owner: "Ada", Profile: state.ProfileEnterprise, RiskAppetite: "low", Timezone: "UTC"}
	sc := &scope.Store{}
	ros := state.Roster{People: []state.Person{{Role: "incident-commander", Name: "Ada", OOB: "voice"}}}
	gaps := Ready(cfg, sc, ros, scope.KindDNS, "owned.example")
	r, ok := Result("dns", gaps)
	if ok || r.Status != failsafe.StatusNeedsHuman {
		t.Fatalf("ok=%v result=%s", ok, r)
	}
}

func TestSentinelIsNotCommander(t *testing.T) {
	cfg := state.Config{Owner: "Ada", Profile: state.ProfileEnterprise, RiskAppetite: "low"}
	sc := &scope.Store{}
	_ = sc.Affirm("Ada", scope.Affirmation, time.Now())
	_, _ = sc.Add(scope.KindDNS, "owned.example", "", false, false, false)
	ros := state.Roster{People: []state.Person{{Role: "incident-commander", Name: "Perimeter Sentinel", OOB: "ledger"}}}
	gaps := Ready(cfg, sc, ros, scope.KindDNS, "owned.example")
	if len(gaps) == 0 {
		t.Fatal("sentinel must not satisfy the commander role")
	}
}

func TestLooseIntervalIsBlind(t *testing.T) {
	cfg := state.Config{ProbeInterval: "1h", IntakeInterval: "1m", OnchainInterval: "30s"}
	blind := IntervalStatus(cfg)
	if len(blind) != 1 {
		t.Fatalf("%v", blind)
	}
}
