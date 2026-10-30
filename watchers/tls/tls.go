// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package tls compares a presented certificate to the operator's baseline.
// Live dials use the system verifier. InsecureSkipVerify is not a mode.
// A dial error is needs_human, not a clean certificate.
package tls

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/govern"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/scope"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/state"
)

// Snapshot is one leaf certificate observation.
type Snapshot struct {
	Host        string    `json:"host"`
	Vantage     string    `json:"vantage,omitempty"`
	Fingerprint string    `json:"fingerprint"`
	Issuer      string    `json:"issuer"`
	Subject     string    `json:"subject"`
	NotAfter    time.Time `json:"not_after"`
	SANs        []string  `json:"sans,omitempty"`
	Error       string    `json:"error,omitempty"`
}

// Diff compares a baseline snapshot to later observations.
func Diff(cfg state.Config, sc *scope.Store, ros state.Roster, baseline Snapshot, observed []Snapshot, now time.Time, horizon time.Duration) failsafe.Result {
	const watcher = "tls"
	host := baseline.Host
	if host == "" && len(observed) > 0 {
		host = observed[0].Host
	}
	if res, ok := govern.Result(watcher, govern.Ready(cfg, sc, ros, scope.KindHTTPS, host)); !ok {
		return res
	}
	if baseline.Fingerprint == "" {
		return failsafe.NeedsHuman(watcher, "no TLS baseline; the first look is not an all-clear", fmt.Errorf("baseline missing"))
	}
	if len(observed) == 0 {
		return failsafe.NeedsHuman(watcher, "no TLS observation", fmt.Errorf("no observations"))
	}
	if horizon <= 0 {
		horizon = 14 * 24 * time.Hour
	}
	var findings []failsafe.Finding
	for _, obs := range observed {
		if obs.Error != "" {
			return failsafe.NeedsHuman(watcher, "tls observation failed", fmt.Errorf("vantage %s: %s", obs.Vantage, obs.Error))
		}
		if !strings.EqualFold(obs.Fingerprint, baseline.Fingerprint) {
			findings = append(findings, one("cert-fingerprint", "Leaf fingerprint changed", host, "high", obs))
		}
		if obs.Issuer != "" && baseline.Issuer != "" && obs.Issuer != baseline.Issuer {
			findings = append(findings, one("cert-issuer", "Issuer changed", host, "high", obs))
		}
		if !obs.NotAfter.IsZero() && !obs.NotAfter.After(now) {
			findings = append(findings, one("cert-expired", "Certificate is expired", host, "critical", obs))
		} else if !obs.NotAfter.IsZero() && obs.NotAfter.Before(now.Add(horizon)) {
			findings = append(findings, one("cert-expiry", "Certificate expires inside the horizon", host, "medium", obs))
		}
	}
	if len(findings) == 0 {
		return failsafe.JustOK(watcher, "TLS leaf matches the baseline and is outside the expiry horizon")
	}
	res := failsafe.FromFindings(watcher, "TLS drifted from the baseline", findings, nil)
	res.Lesson = "module 9 DNS and TLS"
	return res
}

func one(id, title, asset, sev string, obs Snapshot) failsafe.Finding {
	return failsafe.Finding{
		ID: id, Watcher: "tls", Title: title, Summary: title, CIA: "integrity",
		Attack: "T1587.003", Lesson: "module 9 TLS", Severity: sev, Asset: asset,
		Detection: "det-tls-drift",
		Evidence: []failsafe.Evidence{
			{Key: "vantage", Value: obs.Vantage},
			{Key: "fingerprint", Value: obs.Fingerprint},
			{Key: "issuer", Value: obs.Issuer},
		},
	}
}

// Dial reads the verified leaf. It never skips verification.
func Dial(host string) (Snapshot, error) {
	d := &tls.Dialer{Config: &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}}
	conn, err := d.Dial("tcp", host+":443")
	if err != nil {
		return Snapshot{Host: host, Error: err.Error()}, err
	}
	defer conn.Close()
	cs := conn.(*tls.Conn).ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		err := fmt.Errorf("no peer certificate")
		return Snapshot{Host: host, Error: err.Error()}, err
	}
	return FromCert(host, cs.PeerCertificates[0]), nil
}

// FromCert fills a snapshot from a verified leaf.
func FromCert(host string, cert *x509.Certificate) Snapshot {
	sum := sha256.Sum256(cert.Raw)
	return Snapshot{
		Host:        host,
		Fingerprint: hex.EncodeToString(sum[:]),
		Issuer:      cert.Issuer.String(),
		Subject:     cert.Subject.String(),
		NotAfter:    cert.NotAfter.UTC(),
		SANs:        append([]string{}, cert.DNSNames...),
	}
}
