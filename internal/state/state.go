// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package state is the on-disk home for one operator: config, roster, and paths.
// Secrets are rejected before write. Sentinel stores types, locations, and
// fingerprints, never keys.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/secrets"
)

const (
	DirPerm  = 0o700
	FilePerm = 0o600
)

// Profiles the v0.1 tree knows.
const (
	ProfileCivic      = "civic"
	ProfileEnterprise = "enterprise"
	ProfileCustody    = "custody-ops"
)

// Config is operator governance. It is not a claim of coverage.
type Config struct {
	Version             string    `json:"version"`
	Owner               string    `json:"owner"`
	Profile             string    `json:"profile"`
	Timezone            string    `json:"timezone"`
	RiskAppetite        string    `json:"risk_appetite"`
	BehavioralTelemetry bool      `json:"behavioral_telemetry"`
	Created             time.Time `json:"created"`
	ProbeInterval       string    `json:"probe_interval"`
	IntakeInterval      string    `json:"intake_interval"`
	OnchainInterval     string    `json:"onchain_interval"`
	SignerPin           SignerPin `json:"signer_pin"`
	BrandTerms          []string  `json:"brand_terms,omitempty"`
	NamedAccounts       []string  `json:"named_accounts,omitempty"`
	RekorURL            string    `json:"rekor_url,omitempty"`
}

// SignerPin is who may sign the owner's build. A signature from anyone else
// is not treated as safe (lesson: signed ≠ safe).
type SignerPin struct {
	Repo     string `json:"repo,omitempty"`
	Workflow string `json:"workflow,omitempty"`
	Ref      string `json:"ref,omitempty"`
}

// Person is a human role. Sentinel never fills incident commander.
type Person struct {
	Role        string `json:"role"`
	Name        string `json:"name"`
	OOB         string `json:"oob"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// Contact is a draft destination. Channel is a label, not a credential.
type Contact struct {
	ID       string `json:"id"`
	Org      string `json:"org"`
	Channel  string `json:"channel"`
	Template string `json:"template"`
	Notes    string `json:"notes,omitempty"`
}

// Roster is the freeze desk phone tree. Empty slots are gaps, not defaults.
type Roster struct {
	People   []Person  `json:"people"`
	Contacts []Contact `json:"contacts"`
}

// Home is the state directory.
type Home struct {
	Root string
}

func Open(root string) (Home, error) {
	if strings.TrimSpace(root) == "" {
		return Home{}, errors.New("home path is empty")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return Home{}, err
	}
	return Home{Root: abs}, nil
}

func (h Home) ConfigPath() string { return filepath.Join(h.Root, "config.json") }
func (h Home) ScopePath() string  { return filepath.Join(h.Root, "scope.json") }
func (h Home) RosterPath() string { return filepath.Join(h.Root, "roster.json") }
func (h Home) LedgerPath() string { return filepath.Join(h.Root, "ledger", "events.jsonl") }
func (h Home) ReadinessPath() string {
	return filepath.Join(h.Root, "readiness.json")
}
func (h Home) PreauthPath() string { return filepath.Join(h.Root, "preauth", "authorities.json") }
func (h Home) FreezeDir() string   { return filepath.Join(h.Root, "freezes") }
func (h Home) BaselineDir() string { return filepath.Join(h.Root, "baselines") }
func (h Home) IntakeSeenPath() string {
	return filepath.Join(h.Root, "intake", "seen.json")
}

func (h Home) LoadConfig() (Config, error) {
	var c Config
	if err := load(h.ConfigPath(), &c); err != nil {
		return Config{}, err
	}
	return c, nil
}

func (h Home) SaveConfig(c Config) error {
	if err := validateConfig(c); err != nil {
		return err
	}
	return save(h.ConfigPath(), c)
}

func validateConfig(c Config) error {
	switch c.Profile {
	case ProfileCivic, ProfileEnterprise, ProfileCustody:
	default:
		return fmt.Errorf("unknown profile %q", c.Profile)
	}
	switch c.RiskAppetite {
	case "low", "medium", "high":
	default:
		return fmt.Errorf("risk appetite must be low, medium, or high")
	}
	if strings.TrimSpace(c.Owner) == "" {
		return errors.New("owner is required")
	}
	if c.Profile == ProfileCivic && c.BehavioralTelemetry {
		return errors.New("civic profile keeps behavioral telemetry off")
	}
	if _, err := time.LoadLocation(c.Timezone); err != nil {
		return fmt.Errorf("timezone: %w", err)
	}
	return nil
}

func (h Home) LoadRoster() (Roster, error) {
	var r Roster
	if err := load(h.RosterPath(), &r); err != nil {
		return Roster{}, err
	}
	return r, nil
}

func (h Home) SaveRoster(r Roster) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if err := secrets.Reject(b); err != nil {
		return err
	}
	return save(h.RosterPath(), r)
}

// Commander returns the named human incident commander, if the roster has one.
func (r Roster) Commander() (Person, bool) {
	for _, p := range r.People {
		if p.Role == "incident-commander" && strings.TrimSpace(p.Name) != "" && strings.TrimSpace(p.OOB) != "" {
			if strings.EqualFold(p.Name, "sentinel") || strings.EqualFold(p.Name, "perimeter sentinel") {
				continue
			}
			return p, true
		}
	}
	return Person{}, false
}

func (r Roster) Contact(id string) (Contact, bool) {
	for _, c := range r.Contacts {
		if c.ID == id && strings.TrimSpace(c.Org) != "" {
			return c, true
		}
	}
	return Contact{}, false
}

func load(path string, dst any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, dst); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func save(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), DirPerm); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, FilePerm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

var safeName = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// SafeFile turns an asset name into a single path segment.
func SafeFile(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	s = strings.ReplaceAll(s, "https://", "")
	s = strings.ReplaceAll(s, "http://", "")
	s = safeName.ReplaceAllString(s, "_")
	s = strings.Trim(s, "._")
	if s == "" {
		return "unnamed"
	}
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}
