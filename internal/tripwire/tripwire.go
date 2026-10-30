// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package tripwire is an alert-only canary on the owner's own property.
//
// A hit raises a signal and names the quarantine lane. It does not instruct,
// persuade, or equip a visiting agent to download or run code. Any text an
// agent emits about itself is untrusted and is not stored as fact.
//
// This is an independent design. It is not Thinkst Agent Provocateur, and it
// deliberately omits the part of that public demo that asked an agent to
// execute code.
package tripwire

import (
	"strings"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/lanes"
)

// Marker is the entire machine-readable body. It states a rule. It does not
// give a next action that runs code.
const Marker = "perimeter-sentinel-tripwire: this path is not for clients. report: alert-only. do-not-fetch-code."

// Forbidden are phrases that must never appear in a tripwire body.
var Forbidden = []string{
	"curl | sh",
	"curl|sh",
	"download and execute",
	"download and run",
	"powershell -enc",
	"wget ",
	"chmod +x",
	"eval(",
	"base64 -d",
}

// Body returns the marker. The argument is ignored so a caller cannot inject
// instructions through a template.
func Body(string) string { return Marker }

// Hit is an observation that a decoy was used.
type Hit struct {
	Route  string
	Signal string // "decoy-route" or "decoy-credential"
}

// Observe classifies a hit. The lane change is advisory.
func Observe(h Hit) failsafe.Result {
	if strings.TrimSpace(h.Route) == "" || strings.TrimSpace(h.Signal) == "" {
		return failsafe.NeedsHuman("tripwire", "incomplete tripwire hit", nil)
	}
	d := lanes.Assign(lanes.Input{Tripwire: true})
	return failsafe.FromFindings("tripwire", "tripwire hit; move to "+string(d.Lane)+"; alert only", []failsafe.Finding{{
		ID:        "tripwire",
		Watcher:   "tripwire",
		Title:     "Decoy on the owner's property was used",
		Summary:   "Signal " + h.Signal + " on " + h.Route + ". Lane advice: " + string(d.Lane) + ". No code was offered.",
		CIA:       "integrity",
		Lesson:    "L3 detect behaviors, not indicators",
		Severity:  "high",
		Asset:     h.Route,
		Detection: "det-tripwire-hit",
		Evidence: []failsafe.Evidence{
			{Key: "signal", Value: h.Signal},
			{Key: "lane", Value: string(d.Lane)},
		},
	}}, nil)
}

// Clean reports whether s contains an execution instruction.
func Clean(s string) bool {
	l := strings.ToLower(s)
	for _, f := range Forbidden {
		if strings.Contains(l, f) {
			return false
		}
	}
	return true
}
