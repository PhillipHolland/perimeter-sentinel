// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package brief builds the daily brief. It is organized by NIST CSF 2.0
// function. Missing governance or missing logs make the status needs_human.
// The brief never says the site is clear where a source is blind.
package brief

import (
	"fmt"
	"strings"
	"time"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/freeze"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/govern"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/ledger"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/readiness"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/scope"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/state"
)

// Document is the brief and its verdict.
type Document struct {
	Markdown string
	Result   failsafe.Result
}

// Build reads the home directory. A broken ledger is reported, not skipped.
func Build(h state.Home, now time.Time) (Document, error) {
	cfg, cfgErr := h.LoadConfig()
	sc, scErr := scope.Load(h.ScopePath())
	ros, rosErr := h.LoadRoster()
	readyFile, readyErr := readiness.Load(h.ReadinessPath())
	var rep readiness.Report
	if readyErr == nil {
		rep = readiness.Score(readyFile.Sources)
	}
	lg, logErr := ledger.Open(h.LedgerPath())
	var events []ledger.Event
	var chainErr error
	if logErr == nil {
		events, chainErr = lg.Events()
	}

	loc := time.UTC
	zone := "UTC"
	if cfgErr == nil && cfg.Timezone != "" {
		if l, err := time.LoadLocation(cfg.Timezone); err == nil {
			loc = l
			zone = cfg.Timezone
		}
	}
	local := now.In(loc).Format("2006-01-02 15:04:05 MST")

	var b strings.Builder
	fmt.Fprintf(&b, "# Perimeter Sentinel brief\n\n")
	fmt.Fprintf(&b, "Time: %s (%s)\n\n", local, zone)
	b.WriteString("This brief is decision support. It does not prevent incidents, replace a WAF, or decide fraud.\n\n")

	status := failsafe.StatusOK
	var reasons []string
	fail := func(msg string) {
		status = failsafe.StatusNeedsHuman
		reasons = append(reasons, msg)
	}

	b.WriteString("## Govern (GV)\n\n")
	if cfgErr != nil {
		fail("config unreadable")
		fmt.Fprintf(&b, "- Config: unreadable (%s)\n", cfgErr)
	} else {
		fmt.Fprintf(&b, "- Owner: %s\n- Profile: %s\n- Risk appetite: %s\n- Behavioral telemetry: %t\n",
			cfg.Owner, cfg.Profile, cfg.RiskAppetite, cfg.BehavioralTelemetry)
		if cfg.Profile == state.ProfileCivic && cfg.BehavioralTelemetry {
			fail("civic profile has behavioral telemetry on")
		}
	}
	if scErr != nil {
		fail("scope unreadable")
		fmt.Fprintf(&b, "- Scope: unreadable (%s)\n", scErr)
	} else if !sc.Affirmed() {
		fail("owner has not affirmed scope")
		b.WriteString("- Affirmation: missing. Watchers stay closed.\n")
	} else {
		fmt.Fprintf(&b, "- Affirmation: present (%s)\n- Declared assets: %d\n", sc.Data.AffirmedAt.UTC().Format(time.RFC3339), len(sc.Data.Assets))
		var unverified int
		for _, a := range sc.Data.Assets {
			if !a.Verified {
				unverified++
			}
			if a.Kind == scope.KindWallet && a.VerifyBy == "operator-attestation" {
				b.WriteString("- Wallet " + a.Name + " is operator-attested only. That is not cryptographic proof.\n")
			}
		}
		if unverified > 0 {
			fmt.Fprintf(&b, "- Unverified assets: %d. Live checks stay closed for them.\n", unverified)
		}
	}
	if rosErr != nil {
		fail("roster unreadable")
		fmt.Fprintf(&b, "- Roster: unreadable (%s)\n", rosErr)
	} else if _, ok := ros.Commander(); !ok {
		fail("freeze roster has no human incident commander")
		b.WriteString("- Incident commander: missing. Sentinel remains scribe only.\n")
	} else {
		p, _ := ros.Commander()
		fmt.Fprintf(&b, "- Incident commander: %s (out-of-band channel label: %s)\n", p.Name, p.OOB)
		b.WriteString("- Sentinel role: scribe. Not commander.\n")
	}
	if cfgErr == nil {
		for _, blind := range govern.IntervalStatus(cfg) {
			fail(blind)
			b.WriteString("- Interval: " + blind + "\n")
		}
	}

	b.WriteString("\n## Identify (ID)\n\n")
	if scErr == nil {
		red := 0
		for _, a := range sc.Data.Assets {
			if a.Kind == scope.KindPage && (a.TouchesSession || a.TouchesSigning || a.PaymentPage) {
				red++
				fmt.Fprintf(&b, "- Sensitive page: %s (session=%t signing=%t payment=%t)\n", a.Name, a.TouchesSession, a.TouchesSigning, a.PaymentPage)
			}
		}
		if red == 0 {
			b.WriteString("- No page is flagged as session, signing, or payment. That may be true, or the inventory may be incomplete.\n")
		}
	}
	b.WriteString("- Pre-authorization records live in preauth/authorities.json. Fingerprints only.\n")

	b.WriteString("\n## Protect (PR)\n\n")
	b.WriteString("- v0.1 drafts change cards and does not apply them.\n")
	b.WriteString("- Envelopes are checklists. This process does not execute them.\n")
	if cfgErr == nil {
		if cfg.SignerPin.Repo == "" {
			fail("signer pin is empty; signed is not safe")
			b.WriteString("- Signer pin: empty.\n")
		} else {
			fmt.Fprintf(&b, "- Signer pin: %s %s %s\n", cfg.SignerPin.Repo, cfg.SignerPin.Workflow, cfg.SignerPin.Ref)
		}
	}

	b.WriteString("\n## Detect (DE)\n\n")
	if readyErr != nil {
		fail("readiness file unreadable")
		fmt.Fprintf(&b, "- Log readiness: unreadable (%s)\n", readyErr)
	} else {
		fmt.Fprintf(&b, "- Log readiness tier: %s (operator's own answers, not an authorization)\n", rep.Tier)
		if len(rep.Covered) > 0 {
			fmt.Fprintf(&b, "- Covered: %s\n", strings.Join(rep.Covered, ", "))
		}
		if len(rep.Blind) > 0 {
			fail("log readiness has blind spots")
			b.WriteString("- Blind:\n")
			for _, s := range rep.Blind {
				b.WriteString("  - " + s + "\n")
			}
		}
	}
	b.WriteString("- Recent ledger events:\n")
	if logErr != nil {
		fail("ledger unreadable")
		fmt.Fprintf(&b, "  - unreadable (%s)\n", logErr)
	} else if chainErr != nil {
		fail("ledger chain does not verify")
		fmt.Fprintf(&b, "  - chain broken: %s\n", chainErr)
	} else if len(events) == 0 {
		b.WriteString("  - none\n")
	} else {
		start := 0
		if len(events) > 8 {
			start = len(events) - 8
		}
		for _, ev := range events[start:] {
			fmt.Fprintf(&b, "  - seq %d %s %s\n", ev.Seq, ev.Type, ev.TS)
		}
	}

	b.WriteString("\n## Respond (RS)\n\n")
	runs, runErr := freeze.List(h.FreezeDir())
	if runErr != nil {
		fail("freeze directory unreadable")
		fmt.Fprintf(&b, "- Freezes: unreadable (%s)\n", runErr)
	} else if len(runs) == 0 {
		b.WriteString("- No freeze runs on disk.\n")
	} else {
		for _, run := range runs {
			fmt.Fprintf(&b, "- %s %s status=%s notice=%s contain=%s\n", run.ID, run.Playbook, run.Status, run.TimeToNotice, run.TimeToContain)
		}
	}
	b.WriteString("- Drafts are unsent. The operator sends them.\n")

	b.WriteString("\n## Recover (RC)\n\n")
	b.WriteString("- Thaw is a checklist on the freeze run. A freeze that never thaws is an outage.\n")
	b.WriteString("- Root-cause cards are drafts. Sentinel does not close an incident.\n")

	b.WriteString("\n## Verdict\n\n")
	summary := "brief assembled"
	if status != failsafe.StatusOK {
		summary = "needs human: " + strings.Join(reasons, "; ")
	} else {
		summary = "governed inputs present and no blind spot was recorded in this brief"
	}
	fmt.Fprintf(&b, "Status: %s. %s\n", status, summary)
	res := failsafe.Result{Status: status, Watcher: "brief", Summary: summary, Lesson: "L2 govern before detect"}
	if status != failsafe.StatusOK {
		res.Err = summary
		res.BlindSpots = reasons
	}
	return Document{Markdown: b.String(), Result: res.Normalize()}, nil
}
