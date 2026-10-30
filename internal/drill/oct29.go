// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package drill runs the Oct 29, 2026 acceptance drills on synthetic fixtures.
//
// The drills are the Polymarket vendor-script failure mode and the Binance
// hot-wallet failure mode, plus the ledger, the stopwatch, and the rule that
// Sentinel never holds a key. Fixtures are local. Nothing here contacts a
// network, a chain, or a third party.
package drill

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/approve"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/cards"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/egress"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/envelopes"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/freeze"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/ledger"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/scope"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/secrets"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/state"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/tripwire"
	"github.com/perimeter-sentinel/perimeter-sentinel/watchers/external-intake"
	"github.com/perimeter-sentinel/perimeter-sentinel/watchers/onchain"
	servedjs "github.com/perimeter-sentinel/perimeter-sentinel/watchers/served-js"
	"github.com/perimeter-sentinel/perimeter-sentinel/watchers/third-party-scripts"
)

// Spec is one drill the operator can list.
type Spec struct {
	ID    string
	Title string
	Bar   string
}

// Specs is the v0.1 acceptance set from PRODUCT.md §0.3.
func Specs() []Spec {
	return []Spec{
		{"oct29-vendor-script", "Vendor script drift on a staging trading page", "Page within 5 min, vendor named, freeze envelope ready"},
		{"oct29-external-signal", "Brand plus drained in a supplied post", "Alert within 2 min"},
		{"oct29-delegation", "Delegation change on a declared testnet wallet", "Tier-0 page within 60s and issuer drafts prefilled"},
		{"oct29-ledger-stopwatch", "Hash-chained ledger and freeze stopwatch", "Alert, freeze, time-to-notice, and time-to-contain recorded"},
		{"oct29-no-keys", "No key, no broadcast, no third-party probe", "Read-only methods, secret rejection, egress deny"},
	}
}

// Report is one drill result.
type Report struct {
	ID     string `json:"id"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail"`
}

// RunAll executes every drill in dir. dir must be an empty home the caller created.
func RunAll(dir string, now time.Time) ([]Report, error) {
	env, err := prepare(dir, now)
	if err != nil {
		return nil, err
	}
	reports := []Report{
		env.vendor(now),
		env.intake(now),
		env.delegation(now),
	}
	// Ledger drill runs after the alerts and the freeze so the chain has them.
	reports = append(reports, env.ledgerDrill())
	reports = append(reports, env.noKeys())
	return reports, nil
}

type lab struct {
	home      state.Home
	cfg       state.Config
	sc        *scope.Store
	ros       state.Roster
	log       *ledger.Log
	page      scope.Asset
	wal       string
	freezeRun *freeze.Run
}

func prepare(dir string, now time.Time) (*lab, error) {
	h, err := state.Open(dir)
	if err != nil {
		return nil, err
	}
	cfg := state.Config{
		Version: "0.1.0", Owner: "Drill Operator", Profile: state.ProfileCustody,
		Timezone: "America/Chicago", RiskAppetite: "low",
		Created: now.UTC(), ProbeInterval: "1m", IntakeInterval: "1m", OnchainInterval: "30s",
		BrandTerms: []string{"ExampleEx"}, NamedAccounts: []string{"researcher"},
		SignerPin: state.SignerPin{Repo: "example/web", Workflow: "release", Ref: "refs/heads/main"},
	}
	if err := h.SaveConfig(cfg); err != nil {
		return nil, err
	}
	sc := &scope.Store{Path: h.ScopePath()}
	if err := sc.Affirm(cfg.Owner, scope.Affirmation, now); err != nil {
		return nil, err
	}
	page, err := sc.Add(scope.KindPage, "https://staging.example/trade", "drill trading page", true, true, false)
	if err != nil {
		return nil, err
	}
	wal := "0x1111111111111111111111111111111111111111"
	if _, err := sc.Add(scope.KindWallet, wal, "drill hot wallet", false, true, false); err != nil {
		return nil, err
	}
	if _, err := sc.AttestWallet(wal, scope.Affirmation, now); err != nil {
		return nil, err
	}
	if err := sc.Save(); err != nil {
		return nil, err
	}
	ros := state.Roster{
		People: []state.Person{{Role: "incident-commander", Name: "Drill Operator", OOB: "voice"}},
		Contacts: []state.Contact{
			{ID: "cdn", Org: "Edge vendor", Channel: "ticket"},
			{ID: "status-page", Org: "Status", Channel: "draft"},
			{ID: "issuer-usdc", Org: "Circle published channel", Channel: "web"},
			{ID: "issuer-usdt", Org: "Tether published channel", Channel: "web"},
			{ID: "ic3", Org: "IC3", Channel: "web"},
		},
	}
	if err := h.SaveRoster(ros); err != nil {
		return nil, err
	}
	lg, err := ledger.Open(h.LedgerPath())
	if err != nil {
		return nil, err
	}
	return &lab{home: h, cfg: cfg, sc: sc, ros: ros, log: lg, page: page, wal: wal}, nil
}

func (l *lab) vendor(now time.Time) Report {
	id := "oct29-vendor-script"
	changed := now.Add(-4 * time.Minute)
	approved := "var rum=1;\n"
	served := "var rum=2;\n"
	src := "https://cdn.vendor.example/rum.js"
	base := thirdparty.Baseline{
		Page:    l.page.Name,
		Hashes:  map[string]string{src: servedjs.SHA256Hex([]byte(approved))},
		Vendors: map[string]string{"cdn.vendor.example": "rum-vendor"},
		Justify: map[string]string{src: "RUM, drill fixture, not a production justification"},
	}
	obsAt := changed.Add(4 * time.Minute)
	r := thirdparty.Check(l.cfg, l.sc, l.ros, l.page, base, base.Vendors, []thirdparty.Observation{{
		Vantage: "us-central", At: obsAt,
		Body:         `<script src="` + src + `"></script>`,
		ScriptBodies: map[string]string{src: served},
	}}, changed)
	if err := l.record("watcher.third-party-scripts", r, obsAt); err != nil {
		return Report{ID: id, Detail: err.Error()}
	}
	if r.Status != failsafe.StatusFinding {
		return Report{ID: id, Detail: "expected a finding, got " + r.String()}
	}
	var hit *failsafe.Finding
	for i := range r.Findings {
		if r.Findings[i].ID == "vendor-hash-drift" {
			hit = &r.Findings[i]
		}
	}
	if hit == nil {
		return Report{ID: id, Detail: "vendor-hash-drift finding missing"}
	}
	if ev(hit, "vendor") != "rum-vendor" {
		return Report{ID: id, Detail: "vendor was not named"}
	}
	if hit.Envelope != "vendor-script-compromise" {
		return Report{ID: id, Detail: "freeze envelope was not attached"}
	}
	if sec, ok := atoi(ev(hit, "notice_seconds")); !ok || sec > 300 {
		return Report{ID: id, Detail: "notice was not within 5 min: " + ev(hit, "notice_seconds")}
	}
	if d, err := time.ParseDuration(l.cfg.ProbeInterval); err != nil || d > 5*time.Minute {
		return Report{ID: id, Detail: "probe interval exceeds the 5 min bar"}
	}
	return Report{ID: id, Pass: true, Detail: "vendor rum-vendor named, envelope ready, notice 4m0s"}
}

func (l *lab) intake(now time.Time) Report {
	id := "oct29-external-signal"
	at := now.Add(-30 * time.Second)
	r, _ := intake.Scan(l.cfg.BrandTerms, l.cfg.NamedAccounts, intake.Batch{Posts: []intake.Post{{
		ID: "drill-post-1", Author: "someone", Text: "ExampleEx users got drained", At: at,
	}}}, intake.Seen{}, now)
	if err := l.record("watcher.external-intake", r, now); err != nil {
		return Report{ID: id, Detail: err.Error()}
	}
	if r.Status != failsafe.StatusFinding {
		return Report{ID: id, Detail: r.String()}
	}
	notice := evidence(r.Findings[0], "notice_seconds")
	if sec, ok := atoi(notice); !ok || sec > 120 {
		return Report{ID: id, Detail: "notice was not within 2 min: " + notice}
	}
	if d, err := time.ParseDuration(l.cfg.IntakeInterval); err != nil || d > 2*time.Minute {
		return Report{ID: id, Detail: "intake interval exceeds the 2 min bar"}
	}
	return Report{ID: id, Pass: true, Detail: "brand+drained matched in 30s"}
}

func (l *lab) delegation(now time.Time) Report {
	id := "oct29-delegation"
	changed := now.Add(-20 * time.Second)
	addr := l.wal
	deleg := "0x2222222222222222222222222222222222222222"
	dest := "0x3333333333333333333333333333333333333333"
	fake := onchain.Fake{Code: map[string]string{addr: "0xef0100" + deleg[2:]}}
	obs := onchain.Observe(context.Background(), fake, addr, []onchain.Transfer{{
		To: dest, ValueWei: "50", TxHash: "0xdrilltx", At: changed,
	}}, now)
	decl := onchain.Declaration{
		Address: addr, Chain: "testnet", Tier: "hot", LimitWei: "100000",
		KnownDestinations: []string{dest}, KnownCode: "0x",
	}
	r := onchain.Inspect(l.cfg, l.sc, l.ros, decl, obs, changed)
	if err := l.record("watcher.onchain", r, now); err != nil {
		return Report{ID: id, Detail: err.Error()}
	}
	if r.Status != failsafe.StatusFinding {
		return Report{ID: id, Detail: r.String()}
	}
	var hit *failsafe.Finding
	for i := range r.Findings {
		if r.Findings[i].ID == "delegation-change" && r.Findings[i].Severity == "tier-0" {
			hit = &r.Findings[i]
		}
	}
	if hit == nil {
		return Report{ID: id, Detail: "tier-0 delegation finding missing"}
	}
	if sec, ok := atoi(evidence(*hit, "notice_seconds")); !ok || sec > 60 {
		return Report{ID: id, Detail: "notice was not within 60s: " + evidence(*hit, "notice_seconds")}
	}
	run, res := freeze.Start(freeze.StartInput{
		Playbook: "hot-wallet-drain", Now: now, OnsetAt: changed, NoticeAt: now,
		OOBConfirmed: true, OOBChannel: "voice", Roster: l.ros, Dir: l.home.FreezeDir(),
		Facts: freeze.Facts{
			Asset: addr, Chain: "testnet", Owner: l.cfg.Owner, ObservedAt: now,
			Addresses: []string{dest}, Amounts: []string{"50 wei"}, TxHashes: []string{"0xdrilltx"},
		},
	})
	if res.Status != failsafe.StatusOK {
		return Report{ID: id, Detail: "freeze did not start: " + res.String()}
	}
	var body string
	for _, d := range run.Drafts {
		if d.Template == "issuer-freeze.md" {
			body = d.Body
		}
		if d.Sent {
			return Report{ID: id, Detail: "draft was marked sent"}
		}
	}
	if !strings.Contains(body, dest) || !strings.Contains(body, "0xdrilltx") || !strings.Contains(body, "does not send") {
		return Report{ID: id, Detail: "issuer draft was not prefilled"}
	}
	if err := l.record("freeze.started", run, now); err != nil {
		return Report{ID: id, Detail: err.Error()}
	}
	contained, cres := freeze.Contain(l.home.FreezeDir(), run.ID, now.Add(2*time.Minute))
	if cres.Status != failsafe.StatusOK {
		return Report{ID: id, Detail: "stopwatch: " + cres.String()}
	}
	if contained.NoticeSeconds > 60 || contained.ContainSeconds <= 0 {
		return Report{ID: id, Detail: fmt.Sprintf("clocks notice=%d contain=%d", contained.NoticeSeconds, contained.ContainSeconds)}
	}
	if err := l.record("freeze.contained", contained, now.Add(2*time.Minute)); err != nil {
		return Report{ID: id, Detail: err.Error()}
	}
	l.freezeRun = &contained
	return Report{ID: id, Pass: true, Detail: "tier-0 in 20s; issuer draft prefilled; unsent"}
}

func (l *lab) ledgerDrill() Report {
	id := "oct29-ledger-stopwatch"
	receipt := approve.Accept(approve.Receipt{
		CardID: "card-drill", ApproverFingerprint: "fp-ada", SecondFingerprint: "fp-bo",
		Statement: "recorded, not verified",
	})
	if receipt.Status == failsafe.StatusOK {
		return Report{ID: id, Detail: "approval receipt must not verify as an authorization in v0.1"}
	}
	if _, err := l.log.Append("approval.receipt", "fp-ada", receipt, time.Now().UTC()); err != nil {
		return Report{ID: id, Detail: err.Error()}
	}
	if err := l.log.Verify(); err != nil {
		return Report{ID: id, Detail: "verify: " + err.Error()}
	}
	evs, err := l.log.Events()
	if err != nil {
		return Report{ID: id, Detail: err.Error()}
	}
	need := []string{"watcher.third-party-scripts", "watcher.external-intake", "watcher.onchain", "freeze.started", "freeze.contained", "approval.receipt"}
	have := map[string]bool{}
	for _, ev := range evs {
		have[ev.Type] = true
	}
	var missing []string
	for _, n := range need {
		if !have[n] {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		return Report{ID: id, Detail: "ledger missing " + strings.Join(missing, ", ")}
	}
	if l.freezeRun == nil || l.freezeRun.TimeToNotice == "" || l.freezeRun.TimeToContain == "" {
		return Report{ID: id, Detail: "stopwatch did not record both clocks"}
	}
	if !strings.Contains(l.freezeRun.KPI, "not prevention") {
		return Report{ID: id, Detail: "kpi omitted the not-prevention line"}
	}
	return Report{ID: id, Pass: true, Detail: fmt.Sprintf("chain ok, %d events, notice %s, contain %s", len(evs), l.freezeRun.TimeToNotice, l.freezeRun.TimeToContain)}
}

func (l *lab) noKeys() Report {
	id := "oct29-no-keys"
	for method := range onchain.AllowedMethods {
		if strings.Contains(method, "send") || strings.Contains(method, "sign") {
			return Report{ID: id, Detail: "read-only allowlist contains " + method}
		}
	}
	if err := secrets.Reject([]byte(`{"private_key":"abcd"}`)); err == nil {
		return Report{ID: id, Detail: "private key was accepted"}
	}
	if err := egress.Require(l.sc, "POST", "https://rpc.other.example/", ""); err == nil {
		return Report{ID: id, Detail: "undeclared POST was allowed"}
	}
	if err := l.sc.Check(scope.KindDNS, "not-ours.example"); err == nil {
		return Report{ID: id, Detail: "undeclared DNS name was allowed"}
	}
	if err := cards.Approve(cards.Card{ID: "x"}, "sentinel"); err == nil {
		return Report{ID: id, Detail: "self-approval was allowed"}
	}
	if err := envelopes.Execute(envelopes.Envelope{Class: "vendor-script-compromise"}); err == nil {
		return Report{ID: id, Detail: "envelope execution was allowed"}
	}
	if !tripwire.Clean(tripwire.Body("curl | sh")) {
		return Report{ID: id, Detail: "tripwire body was not clean"}
	}
	if _, err := l.log.Append("tx.signed", "perimeterctl", map[string]string{"no": "no"}, time.Now()); err == nil {
		return Report{ID: id, Detail: "ledger accepted a signed-tx event"}
	}
	return Report{ID: id, Pass: true, Detail: "no key, no send, no self-approval, tripwire is alert-only"}
}

func (l *lab) record(typ string, payload any, now time.Time) error {
	_, err := l.log.Append(typ, "perimeterctl", payload, now)
	return err
}

// Evidence helpers.
func evidence(f failsafe.Finding, key string) string {
	for _, e := range f.Evidence {
		if e.Key == key {
			return e.Value
		}
	}
	return ""
}

func ev(f *failsafe.Finding, key string) string { return evidence(*f, key) }

func atoi(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	var n int64
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int64(r-'0')
	}
	return n, true
}
