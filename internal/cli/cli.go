// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package cli is perimeterctl, the operator console.
//
// It is a console across the edge the operator already runs, not a bot
// detector and not an inline control. Watchers are read-only. Freezes draft
// and time. Nothing in this process holds a key, signs, or sends a message.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/brief"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/drill"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/freeze"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/ledger"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/preauth"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/readiness"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/scope"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/state"
	"github.com/perimeter-sentinel/perimeter-sentinel/watchers/dns"
	"github.com/perimeter-sentinel/perimeter-sentinel/watchers/external-intake"
	"github.com/perimeter-sentinel/perimeter-sentinel/watchers/onchain"
	servedjs "github.com/perimeter-sentinel/perimeter-sentinel/watchers/served-js"
	"github.com/perimeter-sentinel/perimeter-sentinel/watchers/third-party-scripts"
	"github.com/perimeter-sentinel/perimeter-sentinel/watchers/tls"
)

const Version = "0.1.0"

// Run executes one invocation. args excludes the program name.
func Run(args []string, stdout, stderr io.Writer) int {
	home := os.Getenv("PERIMETER_HOME")
	if home == "" {
		home = ".perimeter"
	}
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--home":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "--home needs a path")
				return 1
			}
			i++
			home = args[i]
		case strings.HasPrefix(a, "--home="):
			home = strings.TrimPrefix(a, "--home=")
		case a == "--help" || a == "-h":
			rest = append(rest, a)
		default:
			rest = append(rest, a)
		}
	}
	if len(rest) == 0 {
		usage(stderr)
		return 1
	}
	cmd := rest[0]
	sub := rest[1:]
	switch cmd {
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	case "version":
		fmt.Fprintln(stdout, "perimeterctl", Version)
		return 0
	case "init":
		return cmdInit(home, sub, stdout, stderr)
	case "scope":
		return cmdScope(home, sub, stdout, stderr)
	case "roster":
		return cmdRoster(home, sub, stdout, stderr)
	case "ledger":
		return cmdLedger(home, sub, stdout, stderr)
	case "brief":
		return cmdBrief(home, stdout, stderr)
	case "watch":
		return cmdWatch(home, sub, stdout, stderr)
	case "freeze":
		return cmdFreeze(home, sub, stdout, stderr)
	case "drill":
		return cmdDrill(home, sub, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", cmd)
		usage(stderr)
		return 1
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `perimeterctl is the Perimeter Sentinel operator console.
It watches assets you declare, keeps a hash-chained ledger, and drafts freezes.
It does not hold keys, move funds, sign, or contact undeclared systems.

Usage:
  perimeterctl [--home DIR] <command>

Commands:
  init                          create a home directory
  scope affirm|add|list|verify  declare assets (deny by default)
  roster set|contact|show       human commander and draft contacts
  ledger append|verify|export   hash-chained evidence
  brief                         CSF 2.0 daily brief
  watch dns|tls|served-js|third-party-scripts|onchain|intake
  freeze list|start|stopwatch  draft and time a freeze (never sends)
  drill list|run                Oct 29 acceptance drills (synthetic)
  version

Exit codes: 0 ok, 1 usage, 2 finding, 3 needs-human.
A needs-human result is not an all-clear.
`)
}

type env struct {
	home state.Home
	cfg  state.Config
	sc   *scope.Store
	ros  state.Roster
	log  *ledger.Log
}

func openEnv(path string) (env, error) {
	h, err := state.Open(path)
	if err != nil {
		return env{}, err
	}
	cfg, err := h.LoadConfig()
	if err != nil {
		return env{}, fmt.Errorf("config: %w (did you run init?)", err)
	}
	sc, err := scope.Load(h.ScopePath())
	if err != nil {
		return env{}, fmt.Errorf("scope: %w", err)
	}
	ros, err := h.LoadRoster()
	if err != nil {
		return env{}, fmt.Errorf("roster: %w", err)
	}
	lg, err := ledger.Open(h.LedgerPath())
	if err != nil {
		return env{}, err
	}
	return env{home: h, cfg: cfg, sc: sc, ros: ros, log: lg}, nil
}

func cmdInit(path string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	owner := fs.String("owner", "", "operator name")
	profile := fs.String("profile", "enterprise", "civic, enterprise, or custody-ops")
	tz := fs.String("timezone", "America/Chicago", "IANA timezone")
	appetite := fs.String("appetite", "low", "low, medium, or high")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if strings.TrimSpace(*owner) == "" {
		fmt.Fprintln(stderr, "init requires --owner")
		return 1
	}
	h, err := state.Open(path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := os.MkdirAll(h.Root, state.DirPerm); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	now := time.Now().UTC()
	cfg := state.Config{
		Version: Version, Owner: *owner, Profile: *profile, Timezone: *tz,
		RiskAppetite: *appetite, Created: now,
		ProbeInterval: "1m", IntakeInterval: "1m", OnchainInterval: "30s",
	}
	if err := h.SaveConfig(cfg); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	sc := &scope.Store{Path: h.ScopePath(), Data: scope.File{Owner: *owner}}
	if err := sc.Save(); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	ros := state.Roster{
		People: []state.Person{
			{Role: "incident-commander"},
			{Role: "scribe", Name: "Perimeter Sentinel", OOB: "ledger"},
		},
		Contacts: []state.Contact{
			{ID: "cdn", Template: "vendor.md"},
			{ID: "status-page", Template: "status-page.md"},
			{ID: "registrar", Template: "vendor.md"},
			{ID: "idp", Template: "vendor.md"},
			{ID: "issuer-usdc", Template: "issuer-freeze.md"},
			{ID: "issuer-usdt", Template: "issuer-freeze.md"},
			{ID: "ic3", Template: "ic3.md"},
			{ID: "seal-911", Template: "seal-911.md"},
			{ID: "cisa-region", Template: "law-enforcement.md"},
		},
	}
	if err := h.SaveRoster(ros); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	rf := readiness.File{Sources: readiness.DefaultSources(), Updated: now}
	if err := os.MkdirAll(h.Root, state.DirPerm); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := readiness.Save(h.ReadinessPath(), rf); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := os.MkdirAll(h.FreezeDir(), state.DirPerm); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	book := &preauth.Book{Path: h.PreauthPath()}
	if err := book.Save(); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if _, err := ledger.Open(h.LedgerPath()); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "initialized %s\nprofile %s\nnext: scope affirm --statement %q\n", h.Root, cfg.Profile, scope.Affirmation)
	return 0
}

func cmdScope(path string, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "scope needs affirm, add, list, or verify")
		return 1
	}
	e, err := openEnv(path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	switch args[0] {
	case "list":
		if !e.sc.Affirmed() {
			fmt.Fprintln(stdout, "affirmed: no")
		} else {
			fmt.Fprintf(stdout, "affirmed: yes (%s)\n", e.sc.Data.AffirmedAt.UTC().Format(time.RFC3339))
		}
		if len(e.sc.Data.Assets) == 0 {
			fmt.Fprintln(stdout, "assets: none")
			return 0
		}
		for _, a := range e.sc.Data.Assets {
			fmt.Fprintf(stdout, "%s\t%s\tverified=%t\tby=%s\tsession=%t\tsigning=%t\n", a.Kind, a.Name, a.Verified, a.VerifyBy, a.TouchesSession, a.TouchesSigning)
			if a.TXTToken != "" && !a.Verified {
				fmt.Fprintf(stdout, "  publish TXT %s%s = %s%s\n", scope.TXTPrefix, hostForAsset(a), scope.TXTMarker, a.TXTToken)
			}
		}
		return 0
	case "affirm":
		fs := flag.NewFlagSet("scope affirm", flag.ContinueOnError)
		fs.SetOutput(stderr)
		statement := fs.String("statement", "", "must be exactly: I operate these")
		if err := fs.Parse(args[1:]); err != nil {
			return 1
		}
		if err := e.sc.Affirm(e.cfg.Owner, *statement, time.Now()); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if err := e.sc.Save(); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if _, err := e.log.Append("scope.affirmed", "operator", map[string]string{"owner": e.cfg.Owner}, time.Now()); err != nil {
			fmt.Fprintln(stderr, err)
			return 3
		}
		fmt.Fprintln(stdout, "affirmed")
		return 0
	case "add":
		fs := flag.NewFlagSet("scope add", flag.ContinueOnError)
		fs.SetOutput(stderr)
		kind := fs.String("kind", "", "dns, https, page, wallet, or rpc")
		name := fs.String("name", "", "asset name")
		note := fs.String("note", "", "why it is in scope")
		session := fs.Bool("session", false, "page touches a session")
		signing := fs.Bool("signing", false, "page or wallet touches signing")
		payment := fs.Bool("payment", false, "page is a payment page")
		if err := fs.Parse(args[1:]); err != nil {
			return 1
		}
		a, err := e.sc.Add(scope.Kind(*kind), *name, *note, *session, *signing, *payment)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if err := e.sc.Save(); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if _, err := e.log.Append("scope.added", "operator", a, time.Now()); err != nil {
			fmt.Fprintln(stderr, err)
			return 3
		}
		fmt.Fprintf(stdout, "added %s %s\n", a.Kind, a.Name)
		return 0
	case "verify":
		return cmdScopeVerify(e, args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown scope command %q\n", args[0])
		return 1
	}
}

func cmdScopeVerify(e env, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scope verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	kind := fs.String("kind", "", "asset kind")
	name := fs.String("name", "", "asset name")
	live := fs.Bool("live", false, "query DNS TXT (refused unless you mean it)")
	attest := fs.Bool("attest", false, "operator attestation for a wallet; not cryptographic")
	statement := fs.String("statement", "", "required with --attest")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	k := scope.Kind(*kind)
	if k == scope.KindWallet {
		if !*attest {
			fmt.Fprintln(stderr, "wallets are operator-attested; pass --attest and --statement. Sentinel will not ask you to sign.")
			return 3
		}
		a, err := e.sc.AttestWallet(*name, *statement, time.Now())
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 3
		}
		if err := e.sc.Save(); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintf(stdout, "attested %s by %s; this is not cryptographic proof\n", a.Name, a.VerifyBy)
		return 0
	}
	if !*live {
		res := failsafe.NeedsHuman("scope", "refusing a live TXT lookup without --live", errors.New("not live"))
		fmt.Fprintln(stdout, res.String())
		return res.ExitCode()
	}
	if err := e.sc.Check(k, *name); err != nil {
		res := failsafe.FromError("scope", err)
		fmt.Fprintln(stdout, res.String())
		return res.ExitCode()
	}
	a, err := e.sc.VerifyDNS(context.Background(), k, *name, scope.NetResolver{}, time.Now())
	if err != nil {
		res := failsafe.FromError("scope", err)
		fmt.Fprintln(stdout, res.String())
		return res.ExitCode()
	}
	if err := e.sc.Save(); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "verified %s by %s\n", a.Name, a.VerifyBy)
	return 0
}

func hostForAsset(a scope.Asset) string {
	if a.Kind == scope.KindPage || a.Kind == scope.KindRPC {
		// Stored URL. The TXT name is the host, printed in full by the caller via asset name when it is a host.
		return a.Name
	}
	return a.Name
}

func cmdRoster(path string, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "roster needs set, contact, or show")
		return 1
	}
	e, err := openEnv(path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	switch args[0] {
	case "show":
		raw, _ := json.MarshalIndent(e.ros, "", "  ")
		fmt.Fprintln(stdout, string(raw))
		return 0
	case "set":
		fs := flag.NewFlagSet("roster set", flag.ContinueOnError)
		fs.SetOutput(stderr)
		role := fs.String("role", "incident-commander", "role")
		name := fs.String("name", "", "human name")
		oob := fs.String("oob", "", "out-of-band channel label, not a secret")
		if err := fs.Parse(args[1:]); err != nil {
			return 1
		}
		if strings.TrimSpace(*name) == "" || strings.TrimSpace(*oob) == "" {
			fmt.Fprintln(stderr, "roster set needs --name and --oob")
			return 1
		}
		if strings.EqualFold(*name, "sentinel") || strings.EqualFold(*name, "perimeter sentinel") {
			fmt.Fprintln(stderr, "sentinel cannot be the incident commander")
			return 1
		}
		replaced := false
		for i := range e.ros.People {
			if e.ros.People[i].Role == *role {
				e.ros.People[i].Name = *name
				e.ros.People[i].OOB = *oob
				replaced = true
			}
		}
		if !replaced {
			e.ros.People = append(e.ros.People, state.Person{Role: *role, Name: *name, OOB: *oob})
		}
		if err := e.home.SaveRoster(e.ros); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintf(stdout, "roster %s set\n", *role)
		return 0
	case "contact":
		fs := flag.NewFlagSet("roster contact", flag.ContinueOnError)
		fs.SetOutput(stderr)
		id := fs.String("id", "", "contact id")
		org := fs.String("org", "", "organization label")
		channel := fs.String("channel", "", "channel label")
		if err := fs.Parse(args[1:]); err != nil {
			return 1
		}
		if *id == "" || *org == "" {
			fmt.Fprintln(stderr, "roster contact needs --id and --org")
			return 1
		}
		found := false
		for i := range e.ros.Contacts {
			if e.ros.Contacts[i].ID == *id {
				e.ros.Contacts[i].Org = *org
				if *channel != "" {
					e.ros.Contacts[i].Channel = *channel
				}
				found = true
			}
		}
		if !found {
			e.ros.Contacts = append(e.ros.Contacts, state.Contact{ID: *id, Org: *org, Channel: *channel})
		}
		if err := e.home.SaveRoster(e.ros); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintf(stdout, "contact %s set\n", *id)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown roster command %q\n", args[0])
		return 1
	}
}

func cmdLedger(path string, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "ledger needs verify, append, or export")
		return 1
	}
	e, err := openEnv(path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	switch args[0] {
	case "verify":
		if err := e.log.Verify(); err != nil {
			res := failsafe.FromError("ledger", err)
			fmt.Fprintln(stdout, res.String())
			return res.ExitCode()
		}
		evs, _ := e.log.Events()
		fmt.Fprintf(stdout, "ok events=%d\n", len(evs))
		return 0
	case "append":
		fs := flag.NewFlagSet("ledger append", flag.ContinueOnError)
		fs.SetOutput(stderr)
		typ := fs.String("type", "", "event type")
		actor := fs.String("actor", "operator", "who recorded it")
		payload := fs.String("payload", "{}", "JSON object")
		if err := fs.Parse(args[1:]); err != nil {
			return 1
		}
		var body any
		if err := json.Unmarshal([]byte(*payload), &body); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		ev, err := e.log.Append(*typ, *actor, body, time.Now())
		if err != nil {
			res := failsafe.FromError("ledger", err)
			fmt.Fprintln(stdout, res.String())
			return res.ExitCode()
		}
		fmt.Fprintf(stdout, "appended seq=%d hash=%s\n", ev.Seq, ev.Hash)
		return 0
	case "export":
		md, err := e.log.ExportMarkdown()
		if err != nil {
			res := failsafe.FromError("ledger", err)
			fmt.Fprintln(stdout, res.String())
			return res.ExitCode()
		}
		fmt.Fprint(stdout, md)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown ledger command %q\n", args[0])
		return 1
	}
}

func cmdBrief(path string, stdout, stderr io.Writer) int {
	h, err := state.Open(path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	doc, err := brief.Build(h, time.Now())
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 3
	}
	fmt.Fprint(stdout, doc.Markdown)
	return doc.Result.ExitCode()
}

func cmdWatch(path string, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "watch needs a watcher name")
		return 1
	}
	e, err := openEnv(path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	switch args[0] {
	case "dns":
		return watchDNS(e, args[1:], stdout, stderr)
	case "tls":
		return watchTLS(e, args[1:], stdout, stderr)
	case "served-js":
		return watchServed(e, args[1:], stdout, stderr)
	case "third-party-scripts":
		return watchThird(e, args[1:], stdout, stderr)
	case "onchain":
		return watchChain(e, args[1:], stdout, stderr)
	case "intake":
		return watchIntake(e, args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown watcher %q\n", args[0])
		return 1
	}
}

func emit(e env, stdout io.Writer, res failsafe.Result, typ string) int {
	res = res.Normalize()
	if _, err := e.log.Append(typ, "perimeterctl", res, time.Now().UTC()); err != nil {
		fmt.Fprintln(stdout, failsafe.FromError(res.Watcher, err).String())
		return 3
	}
	fmt.Fprintln(stdout, res.String())
	for _, f := range res.Findings {
		fmt.Fprintf(stdout, "  finding %s severity=%s asset=%s\n", f.ID, f.Severity, f.Asset)
		if f.Envelope != "" {
			fmt.Fprintf(stdout, "    envelope %s\n", f.Envelope)
		}
	}
	for _, b := range res.BlindSpots {
		fmt.Fprintf(stdout, "  blind %s\n", b)
	}
	return res.ExitCode()
}

func watchDNS(e env, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("watch dns", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "declared DNS name")
	desiredPath := fs.String("desired", "", "desired snapshot JSON")
	obsPath := fs.String("observation", "", "observation JSON")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *name == "" {
		fmt.Fprintln(stderr, "--name is required")
		return 1
	}
	if *desiredPath == "" || *obsPath == "" {
		res := failsafe.NeedsHuman("dns", "pass --desired and --observation; refusing to invent a clean answer", errors.New("no observation"))
		return emit(e, stdout, res, "watcher.dns")
	}
	var desired dns.Snapshot
	obs, err := readSnapshots(*desiredPath, *obsPath, &desired)
	if err != nil {
		return emit(e, stdout, failsafe.FromError("dns", err), "watcher.dns")
	}
	desired.Name = *name
	return emit(e, stdout, dns.Diff(e.cfg, e.sc, e.ros, desired, obs), "watcher.dns")
}

func readSnapshots(desiredPath, obsPath string, desired *dns.Snapshot) ([]dns.Snapshot, error) {
	b, err := os.ReadFile(desiredPath)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, desired); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(obsPath)
	if err != nil {
		return nil, err
	}
	return decodeList[dns.Snapshot](raw)
}

func watchTLS(e env, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("watch tls", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "declared https host")
	basePath := fs.String("baseline", "", "baseline snapshot JSON")
	obsPath := fs.String("observation", "", "observation JSON")
	live := fs.Bool("live", false, "dial TLS on this host")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *name == "" {
		fmt.Fprintln(stderr, "--name is required")
		return 1
	}
	var base tls.Snapshot
	var obs []tls.Snapshot
	if *live {
		if err := e.sc.RequireVerified(scope.KindHTTPS, *name); err != nil {
			return emit(e, stdout, failsafe.FromError("tls", err), "watcher.tls")
		}
		snap, err := tls.Dial(*name)
		if err != nil {
			return emit(e, stdout, failsafe.FromError("tls", err), "watcher.tls")
		}
		snap.Vantage = "local"
		obs = []tls.Snapshot{snap}
		if *basePath == "" {
			return emit(e, stdout, failsafe.NeedsHuman("tls", "live leaf was read; pass --baseline before treating it as a comparison", errors.New("no baseline")), "watcher.tls")
		}
	}
	if *basePath == "" || (len(obs) == 0 && *obsPath == "") {
		return emit(e, stdout, failsafe.NeedsHuman("tls", "pass --baseline and --observation, or --live with --baseline", errors.New("no observation")), "watcher.tls")
	}
	b, err := os.ReadFile(*basePath)
	if err != nil {
		return emit(e, stdout, failsafe.FromError("tls", err), "watcher.tls")
	}
	if err := json.Unmarshal(b, &base); err != nil {
		return emit(e, stdout, failsafe.FromError("tls", err), "watcher.tls")
	}
	base.Host = *name
	if len(obs) == 0 {
		raw, err := os.ReadFile(*obsPath)
		if err != nil {
			return emit(e, stdout, failsafe.FromError("tls", err), "watcher.tls")
		}
		obs, err = decodeList[tls.Snapshot](raw)
		if err != nil {
			return emit(e, stdout, failsafe.FromError("tls", err), "watcher.tls")
		}
	}
	return emit(e, stdout, tls.Diff(e.cfg, e.sc, e.ros, base, obs, time.Now(), 14*24*time.Hour), "watcher.tls")
}

func watchServed(e env, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("watch served-js", flag.ContinueOnError)
	fs.SetOutput(stderr)
	page := fs.String("page", "", "declared page URL")
	manifestPath := fs.String("manifest", "", "signed build manifest JSON")
	obsPath := fs.String("observation", "", "observations JSON")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *page == "" || *manifestPath == "" || *obsPath == "" {
		return emit(e, stdout, failsafe.NeedsHuman("served-js", "pass --page, --manifest, and --observation", errors.New("incomplete")), "watcher.served-js")
	}
	var manifest servedjs.Manifest
	if err := readJSON(*manifestPath, &manifest); err != nil {
		return emit(e, stdout, failsafe.FromError("served-js", err), "watcher.served-js")
	}
	raw, err := os.ReadFile(*obsPath)
	if err != nil {
		return emit(e, stdout, failsafe.FromError("served-js", err), "watcher.served-js")
	}
	obs, err := decodeList[servedjs.Observation](raw)
	if err != nil {
		return emit(e, stdout, failsafe.FromError("served-js", err), "watcher.served-js")
	}
	return emit(e, stdout, servedjs.Compare(e.cfg, e.sc, e.ros, *page, &manifest, e.cfg.SignerPin, obs), "watcher.served-js")
}

func watchThird(e env, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("watch third-party-scripts", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pageName := fs.String("page", "", "declared page URL")
	basePath := fs.String("baseline", "", "approved hash baseline JSON")
	obsPath := fs.String("observation", "", "observations JSON")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *pageName == "" || *basePath == "" || *obsPath == "" {
		return emit(e, stdout, failsafe.NeedsHuman("third-party-scripts", "pass --page, --baseline, and --observation", errors.New("incomplete")), "watcher.third-party-scripts")
	}
	asset, err := e.sc.Get(scope.KindPage, *pageName)
	if err != nil {
		return emit(e, stdout, failsafe.FromError("third-party-scripts", err), "watcher.third-party-scripts")
	}
	var base thirdparty.Baseline
	if err := readJSON(*basePath, &base); err != nil {
		return emit(e, stdout, failsafe.FromError("third-party-scripts", err), "watcher.third-party-scripts")
	}
	raw, err := os.ReadFile(*obsPath)
	if err != nil {
		return emit(e, stdout, failsafe.FromError("third-party-scripts", err), "watcher.third-party-scripts")
	}
	obs, err := decodeList[thirdparty.Observation](raw)
	if err != nil {
		return emit(e, stdout, failsafe.FromError("third-party-scripts", err), "watcher.third-party-scripts")
	}
	return emit(e, stdout, thirdparty.Check(e.cfg, e.sc, e.ros, asset, base, base.Vendors, obs, time.Time{}), "watcher.third-party-scripts")
}

func watchChain(e env, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("watch onchain", flag.ContinueOnError)
	fs.SetOutput(stderr)
	declPath := fs.String("declaration", "", "wallet declaration JSON")
	obsPath := fs.String("observation", "", "read-only observation JSON")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *declPath == "" || *obsPath == "" {
		return emit(e, stdout, failsafe.NeedsHuman("onchain", "pass --declaration and --observation; this watcher does not broadcast", errors.New("incomplete")), "watcher.onchain")
	}
	var decl onchain.Declaration
	var obs onchain.Observation
	if err := readJSON(*declPath, &decl); err != nil {
		return emit(e, stdout, failsafe.FromError("onchain", err), "watcher.onchain")
	}
	if err := readJSON(*obsPath, &obs); err != nil {
		return emit(e, stdout, failsafe.FromError("onchain", err), "watcher.onchain")
	}
	return emit(e, stdout, onchain.Inspect(e.cfg, e.sc, e.ros, decl, obs, time.Time{}), "watcher.onchain")
}

func watchIntake(e env, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("watch intake", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "posts JSON")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *file == "" {
		return emit(e, stdout, failsafe.NeedsHuman("external-intake", "pass --file; v0.1 does not call the X API", errors.New("no file")), "watcher.external-intake")
	}
	var batch intake.Batch
	if err := readJSON(*file, &batch); err != nil {
		return emit(e, stdout, failsafe.FromError("external-intake", err), "watcher.external-intake")
	}
	seen, err := intake.LoadSeen(e.home.IntakeSeenPath())
	if err != nil {
		return emit(e, stdout, failsafe.FromError("external-intake", err), "watcher.external-intake")
	}
	res, seen := intake.Scan(e.cfg.BrandTerms, e.cfg.NamedAccounts, batch, seen, time.Now())
	if err := intake.SaveSeen(e.home.IntakeSeenPath(), seen); err != nil {
		return emit(e, stdout, failsafe.FromError("external-intake", err), "watcher.external-intake")
	}
	return emit(e, stdout, res, "watcher.external-intake")
}

func cmdFreeze(path string, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "freeze needs list, start, or stopwatch")
		return 1
	}
	switch args[0] {
	case "list":
		for _, p := range freeze.Catalog() {
			fmt.Fprintf(stdout, "%s\t%s\n", p.ID, p.Title)
		}
		return 0
	case "start":
		return freezeStart(path, args[1:], stdout, stderr)
	case "stopwatch":
		return freezeStop(path, args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown freeze command %q\n", args[0])
		return 1
	}
}

func freezeStart(path string, args []string, stdout, stderr io.Writer) int {
	e, err := openEnv(path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fs := flag.NewFlagSet("freeze start", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pb := fs.String("playbook", "", "playbook id")
	oob := fs.Bool("oob-confirmed", false, "a human confirmed on a second channel")
	channel := fs.String("oob-channel", "", "channel label")
	notice := fs.String("notice-at", "", "RFC3339 notice time")
	onset := fs.String("onset-at", "", "RFC3339 onset time")
	asset := fs.String("asset", "", "asset")
	vendor := fs.String("vendor", "", "vendor name")
	page := fs.String("page", "", "page url")
	chain := fs.String("chain", "", "chain label")
	tx := fs.String("tx", "", "comma-separated tx hashes")
	addr := fs.String("address", "", "comma-separated addresses")
	amount := fs.String("amount", "", "comma-separated amounts")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	now := time.Now().UTC()
	noticeAt := now
	onsetAt := time.Time{}
	if *notice != "" {
		t, err := time.Parse(time.RFC3339, *notice)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		noticeAt = t
	}
	if *onset != "" {
		t, err := time.Parse(time.RFC3339, *onset)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		onsetAt = t
	}
	run, res := freeze.Start(freeze.StartInput{
		Playbook: *pb, Now: now, OnsetAt: onsetAt, NoticeAt: noticeAt,
		OOBConfirmed: *oob, OOBChannel: *channel, Roster: e.ros, Dir: e.home.FreezeDir(),
		Facts: freeze.Facts{
			Asset: *asset, Vendor: *vendor, Page: *page, Chain: *chain, Owner: e.cfg.Owner,
			ObservedAt: noticeAt,
			TxHashes:   splitComma(*tx), Addresses: splitComma(*addr), Amounts: splitComma(*amount),
		},
	})
	typ := "freeze.started"
	if res.Status != failsafe.StatusOK {
		typ = "freeze.blocked"
	}
	if _, err := e.log.Append(typ, "perimeterctl", run, now); err != nil {
		fmt.Fprintln(stderr, err)
		return 3
	}
	fmt.Fprintln(stdout, res.String())
	if run.ID != "" {
		fmt.Fprintf(stdout, "id %s\n", run.ID)
	}
	for _, d := range run.Drafts {
		fmt.Fprintf(stdout, "draft %s sent=%t\n", d.Path, d.Sent)
	}
	fmt.Fprint(stdout, freeze.Stopwatch(run, now))
	return res.ExitCode()
}

func freezeStop(path string, args []string, stdout, stderr io.Writer) int {
	e, err := openEnv(path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fs := flag.NewFlagSet("freeze stopwatch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	id := fs.String("id", "", "freeze id")
	contain := fs.Bool("contain", false, "stop the clock")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	fid := *id
	if fid == "" {
		runs, err := freeze.List(e.home.FreezeDir())
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 3
		}
		if len(runs) == 1 {
			fid = runs[0].ID
		} else {
			fmt.Fprintln(stderr, "--id is required")
			return 1
		}
	}
	now := time.Now().UTC()
	if !*contain {
		run, err := freeze.Load(e.home.FreezeDir(), fid)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 3
		}
		fmt.Fprint(stdout, freeze.Stopwatch(run, now))
		return 0
	}
	run, res := freeze.Contain(e.home.FreezeDir(), fid, now)
	if _, err := e.log.Append("freeze.contained", "perimeterctl", run, now); err != nil {
		fmt.Fprintln(stderr, err)
		return 3
	}
	fmt.Fprintln(stdout, res.String())
	fmt.Fprint(stdout, freeze.Stopwatch(run, now))
	if len(run.Thaw) > 0 {
		fmt.Fprintln(stdout, "thaw checklist:")
		for _, step := range run.Thaw {
			fmt.Fprintf(stdout, "  - %s\n", step)
		}
	}
	return res.ExitCode()
}

func cmdDrill(path string, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "list" {
		for _, s := range drill.Specs() {
			fmt.Fprintf(stdout, "%s\t%s\n  %s\n", s.ID, s.Title, s.Bar)
		}
		return 0
	}
	if args[0] != "run" {
		fmt.Fprintf(stderr, "unknown drill command %q\n", args[0])
		return 1
	}
	dir, err := os.MkdirTemp("", "perimeter-drill-")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer os.RemoveAll(dir)
	reps, err := drill.RunAll(dir, time.Now().UTC())
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 3
	}
	code := 0
	for _, r := range reps {
		mark := "PASS"
		if !r.Pass {
			mark = "FAIL"
			code = 2
		}
		fmt.Fprintf(stdout, "%s %s %s\n", mark, r.ID, r.Detail)
	}
	_ = path
	return code
}

func splitComma(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func readJSON(path string, dst any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}

func decodeList[T any](raw []byte) ([]T, error) {
	raw = []byte(strings.TrimSpace(string(raw)))
	if len(raw) == 0 {
		return nil, errors.New("empty observation")
	}
	if raw[0] == '[' {
		var out []T
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, err
		}
		return out, nil
	}
	var wrap struct {
		Observations []T `json:"observations"`
	}
	if err := json.Unmarshal(raw, &wrap); err == nil && wrap.Observations != nil {
		return wrap.Observations, nil
	}
	var one T
	if err := json.Unmarshal(raw, &one); err != nil {
		return nil, err
	}
	return []T{one}, nil
}
