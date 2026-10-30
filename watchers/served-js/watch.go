// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package servedjs is the what-the-world-sees integrity check.
//
// It compares scripts and CSP on a page the operator runs with the signed
// build manifest. A match is not "safe": the signer identity is pinned, and
// a signature from any other repo, workflow, or ref is a finding
// (signed ≠ safe). Host file integrity can be blind to a swapped edge file.
// This watcher looks at the bytes a vantage actually received.
//
// It fetches only through the scope gate. It does not instrument visitors
// and it does not rewrite the page.
package servedjs

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/govern"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/scope"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/state"
)

// Signer is the identity that produced the build.
type Signer struct {
	Repo     string `json:"repo"`
	Workflow string `json:"workflow"`
	Ref      string `json:"ref"`
}

// ScriptDecl is one approved script.
type ScriptDecl struct {
	Src           string `json:"src,omitempty"`
	Inline        bool   `json:"inline,omitempty"`
	SHA256        string `json:"sha256"`
	Vendor        string `json:"vendor,omitempty"`
	Justification string `json:"justification,omitempty"`
}

// Manifest is the signed build's account of one page.
type Manifest struct {
	Page    string       `json:"page"`
	BuildID string       `json:"build_id"`
	Signer  Signer       `json:"signer"`
	Scripts []ScriptDecl `json:"scripts"`
	CSP     string       `json:"csp"`
}

// Observation is one vantage's copy of the page and of referenced script bytes.
type Observation struct {
	Vantage      string            `json:"vantage"`
	Status       int               `json:"status"`
	Headers      map[string]string `json:"headers,omitempty"`
	Body         string            `json:"body"`
	ScriptBodies map[string]string `json:"script_bodies,omitempty"`
	Error        string            `json:"error,omitempty"`
	At           time.Time         `json:"at,omitempty"`
}

// Compare checks observations against the manifest.
func Compare(cfg state.Config, sc *scope.Store, ros state.Roster, page string, manifest *Manifest, pin state.SignerPin, obs []Observation) failsafe.Result {
	const watcher = "served-js"
	if res, ok := govern.Result(watcher, govern.Ready(cfg, sc, ros, scope.KindPage, page)); !ok {
		return res
	}
	asset, err := sc.Get(scope.KindPage, page)
	if err != nil {
		return failsafe.FromError(watcher, err)
	}
	if manifest == nil {
		return failsafe.NeedsHuman(watcher, "no signed build manifest; refusing to call the page clean", fmt.Errorf("manifest missing"))
	}
	if len(obs) == 0 {
		return failsafe.NeedsHuman(watcher, "no vantage returned a page", fmt.Errorf("no observations"))
	}
	var blind []string
	var findings []failsafe.Finding
	hardFail := false
	var hardErr string

	normPage, _ := scope.Normalize(scope.KindPage, page)
	if mp, err := scope.Normalize(scope.KindPage, manifest.Page); err != nil || mp != normPage {
		findings = append(findings, finding("manifest-page", "Manifest page does not match the declared page", asset.Name, "high",
			ev("manifest_page", manifest.Page)))
	}

	pinFinding, pinBlind := checkPin(manifest.Signer, pin)
	if pinFinding != nil {
		findings = append(findings, *pinFinding)
	}
	if pinBlind != "" {
		blind = append(blind, pinBlind)
	}

	perVantage := map[string][]string{}
	for _, o := range obs {
		if o.Error != "" || o.Status >= 400 || o.Status == 0 {
			hardFail = true
			hardErr = fmt.Sprintf("vantage %s: %s status %d", o.Vantage, o.Error, o.Status)
			continue
		}
		refs, metaCSP := ParseHTML(o.Body)
		headerCSP := headerCSP(o.Headers)
		if headerCSP != "" && manifest.CSP != "" && normalizeCSP(headerCSP) != normalizeCSP(manifest.CSP) {
			findings = append(findings, finding("csp-header", "Served CSP header differs from the signed manifest", asset.Name, "high",
				ev("vantage", o.Vantage), ev("served", headerCSP), ev("manifest", manifest.CSP)))
		}
		if metaCSP != "" && manifest.CSP != "" && normalizeCSP(metaCSP) != normalizeCSP(manifest.CSP) {
			findings = append(findings, finding("csp-meta", "CSP meta differs from the signed manifest", asset.Name, "medium",
				ev("vantage", o.Vantage)))
		}
		var sums []string
		for _, ref := range refs {
			sum := ref.SHA256
			body := ""
			if !ref.Inline {
				var ok bool
				body, ok = lookupBody(o.ScriptBodies, ref.Src)
				if !ok {
					hardFail = true
					hardErr = "script body missing for " + ref.Src
					continue
				}
				sum = SHA256Hex([]byte(body))
				if ref.Integrity != "" && !sriMatches(ref.Integrity, []byte(body)) {
					findings = append(findings, finding("sri-mismatch", "Integrity attribute does not match served bytes", ref.Src, "high",
						ev("vantage", o.Vantage), ev("integrity", ref.Integrity)))
				}
				if ref.Integrity == "" && (asset.TouchesSession || asset.TouchesSigning || asset.PaymentPage) {
					findings = append(findings, finding("sri-missing", "External script on a session, signing, or payment page has no SRI", ref.Src, "high",
						ev("vantage", o.Vantage)))
				}
			}
			sums = append(sums, ref.Src+"@"+sum)
			decl, ok := matchDecl(manifest.Scripts, ref, sum)
			if !ok {
				findings = append(findings, finding("served-drift", "Served script is not in the signed build manifest", firstNonEmpty(ref.Src, "inline:"+sum[:12]), "high",
					ev("vantage", o.Vantage), ev("sha256", sum), ev("vendor", decl.Vendor)))
				continue
			}
			if !strings.EqualFold(decl.SHA256, sum) {
				findings = append(findings, finding("served-drift", "Served script hash differs from the signed build", firstNonEmpty(ref.Src, "inline"), "critical",
					ev("vantage", o.Vantage), ev("served_sha256", sum), ev("manifest_sha256", decl.SHA256), ev("vendor", decl.Vendor)))
			}
		}
		// Scripts in the manifest that the page did not serve.
		for _, d := range manifest.Scripts {
			if !served(refs, d) {
				label := d.Src
				if label == "" {
					label = "inline"
					if len(d.SHA256) >= 12 {
						label = "inline:" + d.SHA256[:12]
					}
				}
				findings = append(findings, finding("served-missing", "Signed script was not on the served page", label, "high",
					ev("vantage", o.Vantage), ev("sha256", d.SHA256)))
			}
		}
		perVantage[o.Vantage] = sums
	}
	if split(perVantage) {
		findings = append(findings, finding("split-view", "Vantages disagree on served script hashes", asset.Name, "critical",
			ev("vantages", fmt.Sprint(len(perVantage)))))
	}

	if hardFail {
		res := failsafe.NeedsHuman(watcher, "served-script check incomplete", fmt.Errorf("%s", hardErr))
		res.Findings = findings
		res.BlindSpots = blind
		res.Lesson = "L7 third-party browser scripts are supply chain"
		return res
	}
	if pinBlind != "" && len(findings) == 0 {
		res := failsafe.NeedsHuman(watcher, "hashes match and signer pin is missing; signed is not safe", fmt.Errorf("signer pin missing"))
		res.BlindSpots = blind
		res.Lesson = "L6 signed is not safe"
		return res
	}
	if len(findings) == 0 {
		return failsafe.JustOK(watcher, "served scripts match the signed manifest and the pinned signer").WithBlind(blind)
	}
	res := failsafe.FromFindings(watcher, "what-the-world-sees differs from the signed build", dedupe(findings), blind)
	res.Lesson = "L7 third-party browser scripts are supply chain"
	return res
}

func checkPin(got Signer, pin state.SignerPin) (*failsafe.Finding, string) {
	if pin.Repo == "" || pin.Workflow == "" || pin.Ref == "" {
		return nil, "signer pin is incomplete; a matching hash is not a clean bill"
	}
	if got.Repo != pin.Repo || got.Workflow != pin.Workflow || got.Ref != pin.Ref {
		f := finding("signer", "Build signer does not match the pinned repo, workflow, and ref", got.Repo, "critical",
			ev("got_repo", got.Repo), ev("got_workflow", got.Workflow), ev("got_ref", got.Ref),
			ev("pin_repo", pin.Repo), ev("pin_workflow", pin.Workflow), ev("pin_ref", pin.Ref))
		f.Lesson = "L6 signed is not safe"
		f.Detection = "det-signer-identity"
		return &f, ""
	}
	return nil, ""
}

func matchDecl(decls []ScriptDecl, ref Ref, sum string) (ScriptDecl, bool) {
	for _, d := range decls {
		if ref.Inline && d.Inline && strings.EqualFold(d.SHA256, sum) {
			return d, true
		}
		if !ref.Inline && d.Src != "" && sameResource(d.Src, ref.Src) {
			return d, true
		}
	}
	// Fall through: still return a zero decl so evidence can show vendor blank.
	return ScriptDecl{}, false
}

func served(refs []Ref, d ScriptDecl) bool {
	for _, ref := range refs {
		if d.Inline && ref.Inline && strings.EqualFold(ref.SHA256, d.SHA256) {
			return true
		}
		if d.Src != "" && sameResource(d.Src, ref.Src) {
			return true
		}
	}
	return false
}

func sameResource(a, b string) bool {
	aa, ea := url.Parse(a)
	bb, eb := url.Parse(b)
	if ea != nil || eb != nil {
		return a == b
	}
	aa.Fragment = ""
	bb.Fragment = ""
	return aa.String() == bb.String() || a == b
}

func lookupBody(m map[string]string, src string) (string, bool) {
	if m == nil {
		return "", false
	}
	if b, ok := m[src]; ok {
		return b, true
	}
	for k, b := range m {
		if sameResource(k, src) {
			return b, true
		}
	}
	return "", false
}

func sriMatches(integrity string, body []byte) bool {
	want := SRIValue(body)
	for _, part := range strings.Fields(integrity) {
		if part == want {
			return true
		}
	}
	return false
}

func headerCSP(h map[string]string) string {
	for k, v := range h {
		if strings.EqualFold(k, "content-security-policy") {
			return v
		}
	}
	return ""
}

func normalizeCSP(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func split(v map[string][]string) bool {
	var prev string
	first := true
	for _, sums := range v {
		s := strings.Join(sums, "|")
		if first {
			prev = s
			first = false
			continue
		}
		if s != prev {
			return true
		}
	}
	return false
}

func finding(id, title, asset, sev string, evidence ...failsafe.Evidence) failsafe.Finding {
	return failsafe.Finding{
		ID: id, Watcher: "served-js", Title: title, Summary: title,
		CIA: "integrity", Attack: "T1195.001", Lesson: "L7 third-party browser scripts are supply chain",
		Severity: sev, Asset: asset, Detection: "det-served-js-drift", Evidence: evidence,
		Envelope: "vendor-script-compromise",
	}
}

func ev(k, v string) failsafe.Evidence { return failsafe.Evidence{Key: k, Value: v} }

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func dedupe(in []failsafe.Finding) []failsafe.Finding {
	seen := map[string]bool{}
	var out []failsafe.Finding
	for _, f := range in {
		k := f.ID + "|" + f.Asset + "|" + evJoin(f.Evidence)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, f)
	}
	return out
}

func evJoin(e []failsafe.Evidence) string {
	var b strings.Builder
	for _, x := range e {
		b.WriteString(x.Key)
		b.WriteString("=")
		b.WriteString(x.Value)
		b.WriteString(";")
	}
	return b.String()
}
