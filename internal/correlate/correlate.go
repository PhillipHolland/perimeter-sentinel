// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package correlate scores swarm-shaped behavior from features the operator
// already collected. IP reputation is not an input. A list of addresses with
// no behavior is needs_human: indicators at the bottom of the Pyramid of Pain
// are not a detection.
//
// The score is advisory. It does not block, and it is not a bot-detection rate.
package correlate

import (
	"fmt"
	"math"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
)

// Request is one sanitized event. ClientKey is a pseudonym the operator minted.
type Request struct {
	ClientKey  string
	Path       string
	Second     int64
	NewAccount bool
}

// IPOnly is rejected. Pass behavior or pass nothing.
type IPOnly struct {
	Addresses []string
}

// Score returns a finding when the same path set repeats across many client
// keys inside a tight time span, or when new-account creation bursts.
func Score(reqs []Request) failsafe.Result {
	const watcher = "correlate"
	if len(reqs) == 0 {
		return failsafe.NeedsHuman(watcher, "no behavioral events; refusing to score", fmt.Errorf("empty"))
	}
	byClient := map[string][]Request{}
	var accountBurst int
	var minS, maxS int64
	first := true
	for _, r := range reqs {
		if r.ClientKey == "" || r.Path == "" {
			return failsafe.NeedsHuman(watcher, "event missing a client key or a path", fmt.Errorf("incomplete"))
		}
		byClient[r.ClientKey] = append(byClient[r.ClientKey], r)
		if r.NewAccount {
			accountBurst++
		}
		if first || r.Second < minS {
			minS = r.Second
		}
		if first || r.Second > maxS {
			maxS = r.Second
		}
		first = false
	}
	// Identical path sequence across clients.
	sigCount := map[string]int{}
	for _, rs := range byClient {
		sig := ""
		for _, r := range rs {
			sig += r.Path + ">"
		}
		sigCount[sig]++
	}
	var repeated int
	for _, n := range sigCount {
		if n > repeated {
			repeated = n
		}
	}
	span := maxS - minS
	var findings []failsafe.Finding
	if repeated >= 5 && span >= 0 && span <= 30 {
		findings = append(findings, failsafe.Finding{
			ID: "swarm-path", Watcher: watcher,
			Title:   "Same path sequence repeated across many clients in a short span",
			Summary: fmt.Sprintf("%d clients shared a path sequence inside %d seconds", repeated, span),
			CIA:     "availability", Attack: "T1498", Lesson: "L3 detect behaviors, not indicators",
			Severity: "high", Detection: "det-swarm-behavior",
			Evidence: []failsafe.Evidence{
				{Key: "clients", Value: fmt.Sprintf("%d", repeated)},
				{Key: "span_seconds", Value: fmt.Sprintf("%d", span)},
			},
		})
	}
	if accountBurst >= 10 && span <= 60 {
		findings = append(findings, failsafe.Finding{
			ID: "swarm-accounts", Watcher: watcher,
			Title:   "New-account creation clustered in a short span",
			Summary: fmt.Sprintf("%d new-account events inside %d seconds", accountBurst, span),
			CIA:     "integrity", Lesson: "L3 detect behaviors, not indicators",
			Severity: "medium", Detection: "det-swarm-behavior",
		})
	}
	entropy := timingEntropy(reqs)
	if len(reqs) >= 20 && entropy >= 0 && entropy < 0.4 && repeated >= 3 {
		findings = append(findings, failsafe.Finding{
			ID: "swarm-timing", Watcher: watcher,
			Title:   "Request timing is unusually regular across clients",
			Summary: fmt.Sprintf("timing entropy %.2f across %d events", entropy, len(reqs)),
			CIA:     "availability", Lesson: "L3 detect behaviors, not indicators",
			Severity: "medium", Detection: "det-swarm-behavior",
			Evidence: []failsafe.Evidence{{Key: "entropy", Value: fmt.Sprintf("%.2f", entropy)}},
		})
	}
	if len(findings) == 0 {
		return failsafe.JustOK(watcher, "no swarm-shaped behavior in the supplied events")
	}
	return failsafe.FromFindings(watcher, "swarm-shaped behavior needs a human", findings, nil)
}

// RejectIPOnly is the Pyramid-of-Pain gate.
func RejectIPOnly(in IPOnly) failsafe.Result {
	if len(in.Addresses) == 0 {
		return failsafe.NeedsHuman("correlate", "no input", fmt.Errorf("empty"))
	}
	return failsafe.NeedsHuman("correlate", "IP-only input is not a detection", fmt.Errorf("%d addresses and no behavior", len(in.Addresses)))
}

func timingEntropy(reqs []Request) float64 {
	if len(reqs) < 2 {
		return -1
	}
	gaps := map[int64]int{}
	var prev int64
	sorted := append([]Request{}, reqs...)
	// tiny insertion by second
	for i := 1; i < len(sorted); i++ {
		j := i
		for j > 0 && sorted[j].Second < sorted[j-1].Second {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
			j--
		}
	}
	for i, r := range sorted {
		if i == 0 {
			prev = r.Second
			continue
		}
		g := r.Second - prev
		if g < 0 {
			g = 0
		}
		gaps[g]++
		prev = r.Second
	}
	total := 0
	for _, n := range gaps {
		total += n
	}
	if total == 0 {
		return -1
	}
	var h float64
	for _, n := range gaps {
		p := float64(n) / float64(total)
		h -= p * math.Log2(p)
	}
	// Normalize by a small cap so a single repeated gap scores near 0.
	if h > 4 {
		return 1
	}
	return h / 4
}
