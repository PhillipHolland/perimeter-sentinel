// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package onchain

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/scope"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/state"
)

func TestDelegationChangeTier0(t *testing.T) {
	cfg, sc, ros := gov(t)
	addr := "0x1111111111111111111111111111111111111111"
	deleg := "0x2222222222222222222222222222222222222222"
	changed := time.Date(2026, 10, 29, 20, 24, 0, 0, time.UTC)
	fake := Fake{Code: map[string]string{addr: "0xef0100" + deleg[2:]}}
	obs := Observe(context.Background(), fake, addr, []Transfer{{
		To: "0x3333333333333333333333333333333333333333", ValueWei: "10", TxHash: "0xtx", At: changed,
	}}, changed.Add(20*time.Second))
	decl := Declaration{
		Address: addr, Chain: "testnet", Tier: "hot", LimitWei: "1000",
		KnownDestinations: []string{"0x3333333333333333333333333333333333333333"},
		KnownCode:         "0x",
	}
	r := Inspect(cfg, sc, ros, decl, obs, changed)
	if r.Status != failsafe.StatusFinding {
		t.Fatalf("%s", r)
	}
	var found bool
	for _, f := range r.Findings {
		if f.ID == "delegation-change" {
			found = true
			if f.Severity != "tier-0" || f.Envelope != "hot-wallet-drain" {
				t.Fatalf("%+v", f)
			}
			if ev(f, "notice_seconds") != "20" {
				t.Fatal(ev(f, "notice_seconds"))
			}
		}
	}
	if !found {
		t.Fatalf("%+v", r.Findings)
	}
}

func TestFakeRPCErrorIsNeedsHuman(t *testing.T) {
	cfg, sc, ros := gov(t)
	addr := "0x1111111111111111111111111111111111111111"
	fake := Fake{Err: context.DeadlineExceeded}
	obs := Observe(context.Background(), fake, addr, nil, time.Now())
	r := Inspect(cfg, sc, ros, Declaration{Address: addr, Chain: "testnet", Tier: "hot", LimitWei: "1", KnownCode: "0x"}, obs, time.Time{})
	if r.Status != failsafe.StatusNeedsHuman {
		t.Fatal(r.Status)
	}
}

func TestForbiddenMethodNeverSent(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "eth_send") || strings.Contains(string(body), "eth_sign") {
			t.Errorf("forbidden body reached the server: %s", body)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": "0x"})
	}))
	defer srv.Close()

	sc := &scope.Store{}
	_ = sc.Affirm("Ada", scope.Affirmation, time.Now())
	if _, err := sc.Add(scope.KindRPC, srv.URL, "", false, false, false); err != nil {
		t.Fatal(err)
	}
	// Mark verified without a TXT lookup: test fixture on localhost.
	for i := range sc.Data.Assets {
		sc.Data.Assets[i].Verified = true
		sc.Data.Assets[i].VerifyBy = "test"
	}
	c := &Client{URL: srv.URL, HTTP: srv.Client(), Scope: sc}
	if _, err := c.Call(context.Background(), "eth_sendRawTransaction", []any{"0xdead"}); err == nil {
		t.Fatal("send must be refused")
	}
	if hits != 0 {
		t.Fatalf("server was hit %d times", hits)
	}
	if _, err := c.Call(context.Background(), "personal_sign", []any{"0x"}); err == nil {
		t.Fatal("sign must be refused")
	}
	if _, err := c.GetCode(context.Background(), "0x1111111111111111111111111111111111111111"); err != nil {
		t.Fatal(err)
	}
	if hits != 1 {
		t.Fatalf("hits %d", hits)
	}
}

func TestNewDestination(t *testing.T) {
	cfg, sc, ros := gov(t)
	addr := "0x1111111111111111111111111111111111111111"
	obs := Observation{Code: "0x", At: time.Now(), Transfers: []Transfer{{
		To: "0x9999999999999999999999999999999999999999", ValueWei: "1", TxHash: "0xa",
	}}}
	r := Inspect(cfg, sc, ros, Declaration{Address: addr, Chain: "testnet", Tier: "hot", LimitWei: "100", KnownCode: "0x"}, obs, time.Time{})
	if r.Status != failsafe.StatusFinding {
		t.Fatalf("%s", r)
	}
}

func gov(t *testing.T) (state.Config, *scope.Store, state.Roster) {
	t.Helper()
	cfg := state.Config{Owner: "Ada", Profile: state.ProfileCustody, Timezone: "UTC", RiskAppetite: "low",
		ProbeInterval: "1m", IntakeInterval: "1m", OnchainInterval: "30s"}
	sc := &scope.Store{}
	_ = sc.Affirm("Ada", scope.Affirmation, time.Now())
	if _, err := sc.Add(scope.KindWallet, "0x1111111111111111111111111111111111111111", "", false, true, false); err != nil {
		t.Fatal(err)
	}
	ros := state.Roster{People: []state.Person{{Role: "incident-commander", Name: "Ada", OOB: "voice"}}}
	return cfg, sc, ros
}

func ev(f failsafe.Finding, k string) string {
	for _, e := range f.Evidence {
		if e.Key == k {
			return e.Value
		}
	}
	return ""
}
