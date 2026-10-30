// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package servedjs

import (
	"testing"
	"time"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/scope"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/state"
)

func TestServedJSDrift(t *testing.T) {
	cfg, sc, ros := fixture(t)
	page := "https://staging.example/trade"
	good := "console.log('ok');\n"
	bad := "console.log('drift');\n"
	manifest := &Manifest{
		Page: page, BuildID: "b1",
		Signer: Signer{Repo: "example/web", Workflow: "release", Ref: "refs/heads/main"},
		CSP:    "script-src 'self' https://cdn.vendor.example",
		Scripts: []ScriptDecl{{
			Src: "https://cdn.vendor.example/rum.js", SHA256: SHA256Hex([]byte(good)),
			Vendor: "rum-vendor", Justification: "performance, not on by default after drill",
		}},
	}
	html := `<html><head><script src="https://cdn.vendor.example/rum.js" integrity="` + SRIValue([]byte(bad)) + `"></script></head></html>`
	obs := []Observation{{
		Vantage: "us-central", Status: 200, At: time.Now(),
		Headers:      map[string]string{"Content-Security-Policy": manifest.CSP},
		Body:         html,
		ScriptBodies: map[string]string{"https://cdn.vendor.example/rum.js": bad},
	}}
	r := Compare(cfg, sc, ros, page, manifest, cfg.SignerPin, obs)
	if r.Status != failsafe.StatusFinding {
		t.Fatalf("status %s err %s summary %s", r.Status, r.Err, r.Summary)
	}
	if !hasEvidence(r, "vendor", "rum-vendor") {
		t.Fatalf("vendor missing: %+v", r.Findings)
	}
	if r.Findings[0].Envelope != "vendor-script-compromise" {
		t.Fatal(r.Findings[0].Envelope)
	}
}

func TestMatchWithoutPinIsNeedsHuman(t *testing.T) {
	cfg, sc, ros := fixture(t)
	cfg.SignerPin = state.SignerPin{}
	page := "https://staging.example/trade"
	body := "console.log('ok');\n"
	manifest := &Manifest{
		Page: page, BuildID: "b1",
		Signer: Signer{Repo: "example/web", Workflow: "release", Ref: "refs/heads/main"},
		Scripts: []ScriptDecl{{
			Src: "https://cdn.vendor.example/rum.js", SHA256: SHA256Hex([]byte(body)), Vendor: "rum-vendor",
		}},
	}
	html := `<script src="https://cdn.vendor.example/rum.js" integrity="` + SRIValue([]byte(body)) + `"></script>`
	r := Compare(cfg, sc, ros, page, manifest, cfg.SignerPin, []Observation{{
		Vantage: "eu-west", Status: 200,
		Body: html, ScriptBodies: map[string]string{"https://cdn.vendor.example/rum.js": body},
	}})
	if r.Status != failsafe.StatusNeedsHuman {
		t.Fatalf("status %s (%s)", r.Status, r.Summary)
	}
}

func TestScopeDeny(t *testing.T) {
	cfg, sc, ros := fixture(t)
	r := Compare(cfg, sc, ros, "https://other.example/", &Manifest{Page: "https://other.example/"}, cfg.SignerPin, nil)
	if r.Status != failsafe.StatusNeedsHuman {
		t.Fatal(r.Status)
	}
	if r.Err == "" || !contains(r.Err, "scope deny") && !contains(r.Summary, "scope deny") {
		t.Fatalf("%s", r)
	}
}

func fixture(t *testing.T) (state.Config, *scope.Store, state.Roster) {
	t.Helper()
	cfg := state.Config{
		Owner: "Ada", Profile: state.ProfileCustody, Timezone: "America/Chicago",
		RiskAppetite: "low", ProbeInterval: "1m", IntakeInterval: "1m", OnchainInterval: "30s",
		SignerPin: state.SignerPin{Repo: "example/web", Workflow: "release", Ref: "refs/heads/main"},
	}
	sc := &scope.Store{}
	if err := sc.Affirm("Ada", scope.Affirmation, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := sc.Add(scope.KindPage, "https://staging.example/trade", "", true, true, false); err != nil {
		t.Fatal(err)
	}
	ros := state.Roster{People: []state.Person{{Role: "incident-commander", Name: "Ada", OOB: "voice"}}}
	return cfg, sc, ros
}

func hasEvidence(r failsafe.Result, k, v string) bool {
	for _, f := range r.Findings {
		for _, e := range f.Evidence {
			if e.Key == k && e.Value == v {
				return true
			}
		}
	}
	return false
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0))
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
