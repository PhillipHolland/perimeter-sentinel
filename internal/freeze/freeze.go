// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package freeze is the Freeze Desk. It drafts containment checklists and
// times them. It does not send messages, change edge config, sign, or move
// funds. The operator executes every step on their own systems.
//
// Lesson 9: a freeze expires, thaw is a checklist, and out-of-band confirmation
// comes before action. Sentinel is the scribe. The incident commander is human.
//
// The stopwatch records time-to-notice and time-to-contain. Benchmarks from
// the Oct 29, 2026 Polymarket and Binance incidents are labeled provisional.
// Beating a benchmark is not prevention.
package freeze

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/state"
)

// Benchmark is a published, provisional comparison point. Sources live in
// RESEARCH.md §0 and are not treated as final loss figures.
type Benchmark struct {
	Notice  time.Duration
	Contain time.Duration
	Label   string
	Source  string
}

// Benchmarks are the v0.1 KPI reference. Times are provisional.
var Benchmarks = map[string]Benchmark{
	"vendor-script-compromise": {
		Notice:  35 * time.Minute,
		Contain: 55 * time.Minute,
		Label:   "Polymarket Oct 29 2026, provisional",
		Source:  "Defiprime reconstruction: about 35 min to first public victim post, about 55 min to cancel-only. Status page is the primary halt time. RESEARCH.md §0.1.",
	},
	"hot-wallet-drain": {
		Notice:  8 * time.Minute,
		Contain: 24 * time.Minute,
		Label:   "Binance Oct 29 2026, provisional",
		Source:  "First public flag about 3:32 PM CT; USDC issuer freeze about 24 min and USDT about 37 min after first inflow (practitioner tally). Root cause undisclosed. RESEARCH.md §0.2.",
	},
}

// Step is one operator action. Sentinel does not perform it.
type Step struct {
	ID     string `json:"id"`
	Text   string `json:"text"`
	Owner  string `json:"owner"`
	Lesson string `json:"lesson"`
}

// Playbook is a rehearsed containment script.
type Playbook struct {
	ID               string   `json:"id"`
	Title            string   `json:"title"`
	Summary          string   `json:"summary"`
	Lesson           string   `json:"lesson"`
	BreaksLink       string   `json:"breaks_link"`
	RequiresOOB      bool     `json:"requires_oob"`
	ExpiresAfter     string   `json:"expires_after"`
	RequiredContacts []string `json:"required_contacts"`
	Steps            []Step   `json:"steps"`
	Drafts           []string `json:"drafts"`
	Thaw             []string `json:"thaw"`
	EnvelopeClass    string   `json:"envelope_class"`
}

// Catalog is the v0.1 pair. More playbooks are a later release.
func Catalog() []Playbook {
	return []Playbook{vendorScript(), hotWallet()}
}

// Get returns one playbook by id.
func Get(id string) (Playbook, bool) {
	for _, p := range Catalog() {
		if p.ID == id {
			return p, true
		}
	}
	return Playbook{}, false
}

func vendorScript() Playbook {
	return Playbook{
		ID:               "vendor-script-compromise",
		Title:            "Vendor script compromise",
		Summary:          "A third-party script on a page the operator runs no longer matches the approved hash, or a new script appeared beside a session.",
		Lesson:           "L7 third-party browser scripts are supply chain",
		BreaksLink:       "actions on objectives, by cancel-only and a session refresh; delivery, by a CSP denial of the vendor origin at the operator's own edge",
		RequiresOOB:      true,
		ExpiresAfter:     "4h",
		RequiredContacts: []string{"cdn", "status-page"},
		EnvelopeClass:    "vendor-script-compromise",
		Drafts:           []string{"vendor.md", "status-page.md", "users.md", "law-enforcement.md"},
		Steps: []Step{
			{ID: "oob", Owner: "incident-commander", Lesson: "L9 freezes thaw and are verified out of band", Text: "Confirm on a second channel that this freeze was requested by a human you already trust. Sentinel did not place this call."},
			{ID: "name-vendor", Owner: "ops", Lesson: "L7 third-party browser scripts are supply chain", Text: "Read the finding. Name the page, the vendor, and the script URL. Do not paste script bodies into chat."},
			{ID: "cancel-only", Owner: "ops", Lesson: "L9 freezes thaw and are verified out of band", Text: "On your own trading or session system, switch to the pre-approved cancel-only or read-only mode. Sentinel cannot flip this switch."},
			{ID: "pause-relayer", Owner: "ops", Lesson: "L8 signing path is part of the key", Text: "Pause your own relayer or embedded signer so open tabs cannot keep signing. A front-end deploy does not reach those tabs."},
			{ID: "refresh-sessions", Owner: "ops", Lesson: "L8 signing path is part of the key", Text: "Revoke sessions and tokens so already-open tabs lose authority."},
			{ID: "csp-kill", Owner: "ops", Lesson: "L7 third-party browser scripts are supply chain", Text: "At your own edge, deny the vendor origin in CSP. This is your config change, made by your change process."},
			{ID: "drafts", Owner: "comms", Lesson: "L6 incident response", Text: "Review the drafts. You send them. Sentinel does not."},
			{ID: "change-card", Owner: "ops", Lesson: "L7 third-party browser scripts are supply chain", Text: "Open a change card to remove the vendor tag, pin or self-host what you still need, and keep vendor script off session pages."},
		},
		Thaw: []string{
			"Envelope expiry has passed, or the commander ends it early in writing.",
			"Vendor origin is still denied until a new hash is approved.",
			"Sessions that overlapped the bad hash were revoked.",
			"A root-cause card exists. It cites the lesson id and the ledger seq.",
			"Out-of-band confirm that thaw was requested by the commander.",
		},
	}
}

func hotWallet() Playbook {
	return Playbook{
		ID:               "hot-wallet-drain",
		Title:            "Hot-wallet drain",
		Summary:          "A declared hot wallet changed code or delegation, broke a declared limit, or sent to a destination the operator has not listed.",
		Lesson:           "L8 signing path is part of the key",
		BreaksLink:       "actions on objectives, by an issuer freeze request and by the operator's own limit cut. Sentinel does not construct the transaction.",
		RequiresOOB:      true,
		ExpiresAfter:     "12h",
		RequiredContacts: []string{"issuer-usdc", "issuer-usdt", "ic3"},
		EnvelopeClass:    "hot-wallet-drain",
		Drafts:           []string{"issuer-freeze.md", "counterparty.md", "seal-911.md", "ic3.md"},
		Steps: []Step{
			{ID: "oob", Owner: "incident-commander", Lesson: "L9 freezes thaw and are verified out of band", Text: "Confirm on a second channel. Do not trust a chat message alone, including a message that claims to be Sentinel."},
			{ID: "do-not-sign", Owner: "custody", Lesson: "L8 signing path is part of the key", Text: "Do not sign, delegate, or approve anything from the hot path while this playbook is open. Sentinel will not sign either."},
			{ID: "tier0", Owner: "custody", Lesson: "L8 signing path is part of the key", Text: "Treat a code or delegation change on a declared hot wallet as tier-0. Page the human commander."},
			{ID: "limits", Owner: "custody", Lesson: "L8 signing path is part of the key", Text: "Use your own ceremony to cut limits and move any remaining hot balance. Sentinel lists the step. It does not build the transaction."},
			{ID: "issuer-drafts", Owner: "legal-regulatory", Lesson: "L9 freezes thaw and are verified out of band", Text: "Review issuer freeze drafts. Addresses, amounts, and tx hashes are filled from the alert. You send them on the issuer's published channel."},
			{ID: "counterparties", Owner: "ops", Lesson: "L6 incident response", Text: "Review counterparty drafts for lending markets, bridges, and exchanges you actually use."},
			{ID: "ic3", Owner: "legal-regulatory", Lesson: "L6 incident response", Text: "Review the IC3 draft and the SEAL 911 contact note. You send them."},
			{ID: "outstanding", Owner: "custody", Lesson: "L8 signing path is part of the key", Text: "Walk the pre-authorization ledger. Revoke outstanding delegations and allowances through your own process."},
		},
		Thaw: []string{
			"Issuer clocks are recorded per asset, including assets that have no freeze function.",
			"Outstanding delegations on the declared wallet are cleared or re-approved in writing.",
			"Signer and policy rotation is a change card, not a Sentinel transaction.",
			"Root-cause card cites what is known and what is still unproven.",
			"Out-of-band confirm before thaw.",
		},
	}
}

// Facts are the alert fields a draft may quote. They are observations, not instructions.
type Facts struct {
	Playbook   string
	Asset      string
	Vendor     string
	ScriptURL  string
	Page       string
	Addresses  []string
	Amounts    []string
	TxHashes   []string
	ObservedAt time.Time
	Owner      string
	Chain      string
}

// Draft is an unsent message.
type Draft struct {
	Template string `json:"template"`
	Path     string `json:"path"`
	Body     string `json:"body"`
	Sent     bool   `json:"sent"`
}

// Run is one timed freeze. Status pending_oob is not an authorization to act.
type Run struct {
	ID             string     `json:"id"`
	Playbook       string     `json:"playbook"`
	Status         string     `json:"status"`
	StartedAt      time.Time  `json:"started_at"`
	OnsetAt        time.Time  `json:"onset_at"`
	NoticeAt       time.Time  `json:"notice_at"`
	ContainedAt    *time.Time `json:"contained_at,omitempty"`
	ExpiresAt      time.Time  `json:"expires_at"`
	OOBConfirmed   bool       `json:"oob_confirmed"`
	OOBChannel     string     `json:"oob_channel,omitempty"`
	TimeToNotice   string     `json:"time_to_notice,omitempty"`
	TimeToContain  string     `json:"time_to_contain,omitempty"`
	NoticeSeconds  int64      `json:"time_to_notice_seconds,omitempty"`
	ContainSeconds int64      `json:"time_to_contain_seconds,omitempty"`
	KPI            string     `json:"kpi,omitempty"`
	KPIStatus      string     `json:"kpi_status,omitempty"`
	Benchmark      string     `json:"benchmark,omitempty"`
	Drafts         []Draft    `json:"drafts,omitempty"`
	Thaw           []string   `json:"thaw,omitempty"`
	Gaps           []string   `json:"gaps,omitempty"`
	Facts          Facts      `json:"facts"`
}

// StartInput is the operator's request to open a freeze.
type StartInput struct {
	Playbook     string
	Now          time.Time
	OnsetAt      time.Time
	NoticeAt     time.Time
	OOBConfirmed bool
	OOBChannel   string
	Roster       state.Roster
	Facts        Facts
	Dir          string
}

// Start opens a freeze or refuses it. A refusal is needs_human and is still
// returned so the caller can write it to the ledger. The run status is
// "blocked" in that case and the stopwatch has not started.
func Start(in StartInput) (Run, failsafe.Result) {
	pb, ok := Get(in.Playbook)
	if !ok {
		return Run{}, failsafe.NeedsHuman("freeze", "unknown playbook", fmt.Errorf("unknown playbook %q", in.Playbook))
	}
	now := in.Now.UTC()
	if now.IsZero() {
		return Run{}, failsafe.NeedsHuman("freeze", "clock is missing", errors.New("now is zero"))
	}
	run := Run{
		ID:        newID(now),
		Playbook:  pb.ID,
		StartedAt: now,
		OnsetAt:   in.OnsetAt.UTC(),
		NoticeAt:  in.NoticeAt.UTC(),
		Facts:     in.Facts,
		Thaw:      append([]string{}, pb.Thaw...),
	}
	run.Facts.Playbook = pb.ID
	var gaps []string
	if _, ok := in.Roster.Commander(); !ok {
		gaps = append(gaps, "roster has no human incident commander")
	}
	for _, id := range pb.RequiredContacts {
		if _, ok := in.Roster.Contact(id); !ok {
			gaps = append(gaps, "roster contact "+id+" is empty")
		}
	}
	if pb.RequiresOOB && (!in.OOBConfirmed || strings.TrimSpace(in.OOBChannel) == "") {
		gaps = append(gaps, "out-of-band confirmation is missing")
	}
	if in.NoticeAt.IsZero() {
		gaps = append(gaps, "notice time is missing")
	}
	exp, err := time.ParseDuration(pb.ExpiresAfter)
	if err != nil {
		gaps = append(gaps, "playbook expiry is unparsable")
		exp = 0
	}
	run.ExpiresAt = now.Add(exp)
	run.Gaps = gaps
	if len(gaps) > 0 {
		run.Status = "blocked"
		res := failsafe.NeedsHuman("freeze", "freeze not started: "+strings.Join(gaps, "; "), errors.New(strings.Join(gaps, "; ")))
		res.Lesson = "L9 freezes thaw and are verified out of band"
		return run, res
	}
	run.Status = "running"
	run.OOBConfirmed = true
	run.OOBChannel = in.OOBChannel
	if !in.OnsetAt.IsZero() && !in.NoticeAt.Before(in.OnsetAt) {
		d := in.NoticeAt.Sub(in.OnsetAt)
		run.NoticeSeconds = int64(d.Seconds())
		run.TimeToNotice = d.Truncate(time.Second).String()
	}
	drafts, err := writeDrafts(in.Dir, run, pb)
	if err != nil {
		run.Status = "blocked"
		return run, failsafe.FromError("freeze", err)
	}
	run.Drafts = drafts
	if err := saveRun(in.Dir, run); err != nil {
		return run, failsafe.FromError("freeze", err)
	}
	res := failsafe.JustOK("freeze", "freeze clock started; drafts are unsent; operator executes")
	res.Lesson = pb.Lesson
	return run, res
}

// Contain stops the clock. It does not thaw and it does not send.
func Contain(dir, id string, now time.Time) (Run, failsafe.Result) {
	run, err := Load(dir, id)
	if err != nil {
		return Run{}, failsafe.FromError("freeze", err)
	}
	if run.Status == "blocked" {
		return run, failsafe.NeedsHuman("freeze", "this freeze never started", errors.New(run.Status))
	}
	if run.Status == "contained" {
		return run, failsafe.NeedsHuman("freeze", "stopwatch already stopped", errors.New("already contained"))
	}
	now = now.UTC()
	if now.Before(run.StartedAt) {
		return run, failsafe.NeedsHuman("freeze", "contain time is before start", errors.New("clock went backwards"))
	}
	run.ContainedAt = &now
	run.Status = "contained"
	if run.OnsetAt.IsZero() {
		run.KPIStatus = string(failsafe.StatusNeedsHuman)
		run.KPI = "onset unknown; time-to-contain is not certified"
		res := failsafe.NeedsHuman("freeze", run.KPI, errors.New("onset unknown"))
		_ = saveRun(dir, run)
		return run, res
	}
	d := now.Sub(run.OnsetAt)
	run.ContainSeconds = int64(d.Seconds())
	run.TimeToContain = d.Truncate(time.Second).String()
	run.KPI, run.Benchmark, run.KPIStatus = kpi(run.Playbook, d)
	if err := saveRun(dir, run); err != nil {
		return run, failsafe.FromError("freeze", err)
	}
	res := failsafe.JustOK("freeze", run.KPI)
	res.Lesson = "L9 freezes thaw and are verified out of band"
	// A KPI that we could not compare is not ok.
	if run.KPIStatus == string(failsafe.StatusNeedsHuman) {
		return run, failsafe.NeedsHuman("freeze", run.KPI, errors.New(run.KPI))
	}
	return run, res
}

func kpi(playbook string, contain time.Duration) (text, benchmark, status string) {
	b, ok := Benchmarks[playbook]
	if !ok {
		return "no provisional benchmark for this playbook", "", string(failsafe.StatusNeedsHuman)
	}
	benchmark = b.Label + ". " + b.Source
	status = string(failsafe.StatusOK)
	rel := "at or over"
	if contain < b.Contain {
		rel = "under"
	}
	text = fmt.Sprintf("time-to-contain %s is %s the provisional benchmark %s (%s). This is a clock comparison, not prevention.",
		contain.Truncate(time.Second), rel, b.Contain, b.Label)
	return text, benchmark, status
}

// Stopwatch is the operator view of a running or finished clock.
func Stopwatch(run Run, now time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "freeze %s playbook=%s status=%s\n", run.ID, run.Playbook, run.Status)
	if run.Status == "running" {
		fmt.Fprintf(&b, "elapsed_since_start %s\n", now.Sub(run.StartedAt).Truncate(time.Second))
	}
	if run.TimeToNotice != "" {
		fmt.Fprintf(&b, "time_to_notice %s\n", run.TimeToNotice)
	}
	if run.TimeToContain != "" {
		fmt.Fprintf(&b, "time_to_contain %s\n", run.TimeToContain)
	}
	if run.KPI != "" {
		fmt.Fprintf(&b, "kpi %s\n", run.KPI)
	}
	fmt.Fprintf(&b, "drafts_sent %t\n", false)
	if !run.ExpiresAt.IsZero() {
		fmt.Fprintf(&b, "expires %s\n", run.ExpiresAt.Format(time.RFC3339))
	}
	return b.String()
}

func writeDrafts(dir string, run Run, pb Playbook) ([]Draft, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("freeze directory is empty")
	}
	d := filepath.Join(dir, run.ID)
	if err := os.MkdirAll(d, state.DirPerm); err != nil {
		return nil, err
	}
	var out []Draft
	for _, name := range pb.Drafts {
		body := "SENT: false\n" + render(name, run.Facts)
		path := filepath.Join(d, name)
		if err := os.WriteFile(path, []byte(body), state.FilePerm); err != nil {
			return nil, err
		}
		out = append(out, Draft{Template: name, Path: path, Body: body, Sent: false})
	}
	return out, nil
}

func render(name string, f Facts) string {
	var b strings.Builder
	b.WriteString("DRAFT — the operator sends this. Perimeter Sentinel does not send it.\n")
	b.WriteString("Do not add exploit detail, payloads, or reproduction steps.\n\n")
	fmt.Fprintf(&b, "Template: %s\nPlaybook: %s\nOwner: %s\n", name, f.Playbook, f.Owner)
	if !f.ObservedAt.IsZero() {
		fmt.Fprintf(&b, "Observed at (UTC): %s\n", f.ObservedAt.UTC().Format(time.RFC3339))
	}
	if f.Page != "" {
		fmt.Fprintf(&b, "Page: %s\n", f.Page)
	}
	if f.Vendor != "" {
		fmt.Fprintf(&b, "Vendor: %s\n", f.Vendor)
	}
	if f.ScriptURL != "" {
		fmt.Fprintf(&b, "Script URL: %s\n", f.ScriptURL)
	}
	if f.Asset != "" {
		fmt.Fprintf(&b, "Asset: %s\n", f.Asset)
	}
	if f.Chain != "" {
		fmt.Fprintf(&b, "Chain: %s\n", f.Chain)
	}
	if len(f.Addresses) > 0 {
		fmt.Fprintf(&b, "Addresses: %s\n", strings.Join(f.Addresses, ", "))
	}
	if len(f.Amounts) > 0 {
		fmt.Fprintf(&b, "Amounts (operator-supplied observation): %s\n", strings.Join(f.Amounts, ", "))
	}
	if len(f.TxHashes) > 0 {
		fmt.Fprintf(&b, "Transaction hashes: %s\n", strings.Join(f.TxHashes, ", "))
	}
	b.WriteString("\n")
	switch name {
	case "vendor.md":
		b.WriteString("We operate the page named above. A script we loaded from your origin changed relative to our approved hash. Please confirm whether you published that change. We have not included script contents.\n")
	case "status-page.md":
		b.WriteString("We are investigating a third-party script change on a page we operate. Trading or sign-in may be limited while we confirm integrity. We will update this notice. We are not claiming the cause beyond the hash change.\n")
	case "users.md":
		b.WriteString("A script on a page we operate changed unexpectedly. If you have that page open, close it. We have paused new privileged actions where we can. This note does not ask you to install anything or to paste a seed phrase.\n")
	case "law-enforcement.md":
		b.WriteString("We are reporting a suspected compromise of a third-party script on a site we operate. Facts we have are listed above. Facts we do not have are omitted. We are not requesting that you take action on systems we do not operate, beyond your own intake process.\n")
	case "issuer-freeze.md":
		b.WriteString("Please review a freeze request under your published compliance channel. Observed addresses, amounts, and transaction hashes are above. We do not ask you to accept this draft as a completed legal request. Root cause may still be unknown.\n")
	case "counterparty.md":
		b.WriteString("We are notifying you because you are on our declared counterparty list. A declared hot wallet showed an unexpected change. Please use your own process. We are not asking you to run software from us.\n")
	case "seal-911.md":
		b.WriteString("Contact note for SEAL 911. We have not sent this. Include only the facts above and your own reach-back channel.\n")
	case "ic3.md":
		b.WriteString("Draft for IC3 intake. Include the facts above. Do not attach keys, seeds, or exploit material. Sentinel did not file this.\n")
	default:
		b.WriteString("Operator-owned draft.\n")
	}
	b.WriteString("\nUnsent: true\n")
	return b.String()
}

func saveRun(dir string, run Run) error {
	if err := os.MkdirAll(filepath.Join(dir, run.ID), state.DirPerm); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(run, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(filepath.Join(dir, run.ID, "run.json"), raw, state.FilePerm)
}

// Load reads one run.
func Load(dir, id string) (Run, error) {
	if strings.Contains(id, "..") || strings.ContainsAny(id, `/\`) {
		return Run{}, errors.New("bad freeze id")
	}
	raw, err := os.ReadFile(filepath.Join(dir, id, "run.json"))
	if err != nil {
		return Run{}, err
	}
	var run Run
	if err := json.Unmarshal(raw, &run); err != nil {
		return Run{}, err
	}
	return run, nil
}

// List returns runs under dir. A missing directory is an empty list.
func List(dir string) ([]Run, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Run
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		run, err := Load(dir, e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, run)
	}
	return out, nil
}

func newID(now time.Time) string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return now.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b[:])
}
