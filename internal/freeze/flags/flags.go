// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package flags records a local kill-switch intent.
// Arm writes a file. Apply does not call a CDN, an issuer, or any other vendor.
// The operator's own edge is where a switch becomes real.
package flags

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/state"
)

// Record is the operator's intent. State stays "armed" inside this process.
type Record struct {
	ID    string    `json:"id"`
	State string    `json:"state"`
	Note  string    `json:"note"`
	At    time.Time `json:"at"`
}

// Arm writes one switch under dir. It does not contact a network.
func Arm(dir, id, note string, now time.Time) (Record, error) {
	id = strings.TrimSpace(id)
	if id == "" || strings.Contains(id, "..") || strings.ContainsAny(id, `/\`) {
		return Record{}, errors.New("kill-switch id must be a single path segment")
	}
	if strings.TrimSpace(note) == "" {
		return Record{}, errors.New("kill-switch note is required")
	}
	rec := Record{ID: id, State: "armed", Note: note, At: now.UTC()}
	if err := os.MkdirAll(dir, state.DirPerm); err != nil {
		return Record{}, err
	}
	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return Record{}, err
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(filepath.Join(dir, id+".json"), raw, state.FilePerm); err != nil {
		return Record{}, err
	}
	return rec, nil
}

// Apply is refused. v0.1 does not call a vendor API.
func Apply(Record) error {
	return errors.New("v0.1 does not apply a kill switch to a vendor; the operator changes their own edge")
}
