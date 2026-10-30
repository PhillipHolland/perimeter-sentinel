// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package preauth is the pre-authorization ledger: long-lived authority the
// operator has already granted. Delegations, allowances, OAuth refresh
// tokens, CI tokens, and admin sessions are latent liability.
//
// Records store a fingerprint and a revocation path. They never store the
// secret, and Sentinel never signs, rotates, or broadcasts on the operator's
// behalf. This is the Oct 29 Binance lesson at inventory level: outstanding
// authority should be visible before it is used. The root cause of that
// incident is undisclosed; the control does not depend on a single cause.
package preauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/secrets"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/state"
)

// Kind classifies an outstanding authority.
type Kind string

const (
	KindDelegation   Kind = "delegation"
	KindAllowance    Kind = "allowance"
	KindApproval     Kind = "approval"
	KindOAuthRefresh Kind = "oauth-refresh"
	KindAPIKey       Kind = "api-key"
	KindCIToken      Kind = "ci-token"
	KindAdminSession Kind = "admin-session"
	KindSignedPermit Kind = "signed-permit"
)

// Tier is hot, warm, or cold for key-like authority. Other kinds use "n/a".
type Tier string

const (
	TierHot  Tier = "hot"
	TierWarm Tier = "warm"
	TierCold Tier = "cold"
	TierNA   Tier = "n/a"
)

// Authority is one outstanding grant.
type Authority struct {
	ID           string    `json:"id"`
	Kind         Kind      `json:"kind"`
	Subject      string    `json:"subject"`
	Fingerprint  string    `json:"fingerprint"`
	Owner        string    `json:"owner"`
	Tier         Tier      `json:"tier"`
	Limit        string    `json:"limit,omitempty"`
	Destinations []string  `json:"destinations,omitempty"`
	Expires      time.Time `json:"expires,omitempty"`
	RevokePath   string    `json:"revoke_path"`
	Outstanding  bool      `json:"outstanding"`
	Chain        string    `json:"chain,omitempty"`
	Note         string    `json:"note,omitempty"`
}

// Book is the on-disk list.
type Book struct {
	Path        string      `json:"-"`
	Authorities []Authority `json:"authorities"`
}

func Load(path string) (*Book, error) {
	b := &Book{Path: path}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return b, nil
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return b, nil
	}
	if err := json.Unmarshal(raw, b); err != nil {
		return nil, err
	}
	b.Path = path
	return b, nil
}

func (b *Book) Save() error {
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	if err := secrets.Reject(raw); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(b.Path), state.DirPerm); err != nil {
		return err
	}
	out, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	tmp := b.Path + ".tmp"
	if err := os.WriteFile(tmp, out, state.FilePerm); err != nil {
		return err
	}
	return os.Rename(tmp, b.Path)
}

// Add validates and stores. Duplicate IDs are refused.
func (b *Book) Add(a Authority) error {
	if err := validate(a); err != nil {
		return err
	}
	for _, have := range b.Authorities {
		if have.ID == a.ID {
			return fmt.Errorf("authority %s already recorded", a.ID)
		}
	}
	b.Authorities = append(b.Authorities, a)
	return nil
}

func validate(a Authority) error {
	if strings.TrimSpace(a.ID) == "" || strings.TrimSpace(a.Subject) == "" {
		return errors.New("id and subject are required")
	}
	if strings.TrimSpace(a.Fingerprint) == "" {
		return errors.New("fingerprint is required; do not paste the secret")
	}
	if strings.TrimSpace(a.RevokePath) == "" {
		return errors.New("revoke path is required")
	}
	switch a.Kind {
	case KindDelegation, KindAllowance, KindApproval, KindOAuthRefresh, KindAPIKey, KindCIToken, KindAdminSession, KindSignedPermit:
	default:
		return fmt.Errorf("unknown authority kind %q", a.Kind)
	}
	switch a.Tier {
	case TierHot, TierWarm, TierCold, TierNA:
	default:
		return fmt.Errorf("unknown tier %q", a.Tier)
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return secrets.Reject(raw)
}

// Review flags expired outstanding authority and hot-tier records with no limit.
// It does not declare the set safe.
func Review(list []Authority, now time.Time) failsafe.Result {
	var findings []failsafe.Finding
	for _, a := range list {
		if !a.Outstanding {
			continue
		}
		if !a.Expires.IsZero() && !a.Expires.After(now) {
			findings = append(findings, failsafe.Finding{
				ID:        "preauth-expired-" + a.ID,
				Watcher:   "preauth",
				Title:     "Outstanding authority is past its expiry",
				Summary:   string(a.Kind) + " " + a.ID + " is still marked outstanding after expiry",
				CIA:       "integrity",
				Attack:    "T1550",
				Lesson:    "L8 signing path is part of the key",
				Severity:  "high",
				Asset:     a.Subject,
				Detection: "det-preauth-expired",
				Evidence: []failsafe.Evidence{
					{Key: "kind", Value: string(a.Kind)},
					{Key: "fingerprint", Value: a.Fingerprint},
					{Key: "revoke_path", Value: a.RevokePath},
				},
			})
		}
		if a.Tier == TierHot && strings.TrimSpace(a.Limit) == "" {
			findings = append(findings, failsafe.Finding{
				ID:        "preauth-hot-nolimit-" + a.ID,
				Watcher:   "preauth",
				Title:     "Hot-tier authority has no declared limit",
				Summary:   a.ID + " is hot and has no operator-declared cap",
				CIA:       "integrity",
				Lesson:    "L8 signing path is part of the key",
				Severity:  "high",
				Asset:     a.Subject,
				Detection: "det-preauth-expired",
				Evidence:  []failsafe.Evidence{{Key: "tier", Value: string(a.Tier)}},
			})
		}
	}
	if len(findings) == 0 {
		return failsafe.JustOK("preauth", "no expired outstanding authority and no unlimited hot-tier record in the declared set")
	}
	return failsafe.FromFindings("preauth", "pre-authorization review needs a human", findings, nil)
}
