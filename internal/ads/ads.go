// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package ads reads Palantir-ADS-style detection records.
// The format is line-oriented so CI does not need a YAML library.
// A detection without a goal, a blind spot, and a validation path is rejected.
package ads

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Record is one detection. Playbook may be "none" when v0.1 has no freeze for it.
type Record struct {
	ID             string
	Goal           string
	Attack         string
	DataSources    []string
	BlindSpots     []string
	FalsePositives []string
	Validation     string
	Playbook       string
	Lesson         string
	CIA            string
}

var allowedPlaybooks = map[string]bool{
	"none":                     true,
	"vendor-script-compromise": true,
	"hot-wallet-drain":         true,
}

// Parse reads one record. Lists are "  - item" lines under a bare key.
func Parse(text string) (Record, error) {
	var rec Record
	var list *[]string
	saw := map[string]bool{}
	for i, line := range strings.Split(text, "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		if strings.HasPrefix(line, "  - ") {
			if list == nil {
				return Record{}, fmt.Errorf("line %d: list item without a key", i+1)
			}
			item := strings.TrimSpace(strings.TrimPrefix(line, "  - "))
			if item == "" {
				return Record{}, fmt.Errorf("line %d: empty list item", i+1)
			}
			*list = append(*list, item)
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok || strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			return Record{}, fmt.Errorf("line %d: want key: value", i+1)
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if saw[key] {
			return Record{}, fmt.Errorf("duplicate key %s", key)
		}
		saw[key] = true
		list = nil
		switch key {
		case "id":
			rec.ID = val
		case "goal":
			rec.Goal = val
		case "attack":
			rec.Attack = val
		case "validation":
			rec.Validation = val
		case "playbook":
			rec.Playbook = val
		case "lesson":
			rec.Lesson = val
		case "cia":
			rec.CIA = val
		case "data_sources":
			if val != "" {
				return Record{}, fmt.Errorf("data_sources is a list")
			}
			list = &rec.DataSources
		case "blind_spots":
			if val != "" {
				return Record{}, fmt.Errorf("blind_spots is a list")
			}
			list = &rec.BlindSpots
		case "false_positives":
			if val != "" {
				return Record{}, fmt.Errorf("false_positives is a list")
			}
			list = &rec.FalsePositives
		default:
			return Record{}, fmt.Errorf("unknown key %s", key)
		}
	}
	if !strings.HasPrefix(rec.ID, "det-") {
		return Record{}, fmt.Errorf("id %q must start with det-", rec.ID)
	}
	for _, pair := range []struct{ k, v string }{
		{"goal", rec.Goal}, {"attack", rec.Attack}, {"validation", rec.Validation},
		{"playbook", rec.Playbook}, {"lesson", rec.Lesson}, {"cia", rec.CIA},
	} {
		if strings.TrimSpace(pair.v) == "" {
			return Record{}, fmt.Errorf("%s is empty", pair.k)
		}
	}
	if len(rec.DataSources) == 0 || len(rec.BlindSpots) == 0 || len(rec.FalsePositives) == 0 {
		return Record{}, fmt.Errorf("%s needs data_sources, blind_spots, and false_positives", rec.ID)
	}
	for _, p := range strings.Split(rec.Playbook, ",") {
		if !allowedPlaybooks[strings.TrimSpace(p)] {
			return Record{}, fmt.Errorf("%s playbook %q is not in the v0.1 catalog", rec.ID, p)
		}
	}
	return rec, nil
}

// LoadDir reads every *.ads.yaml file in dir.
func LoadDir(dir string) ([]Record, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []Record
	seen := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".ads.yaml") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		rec, err := Parse(string(raw))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		if !strings.HasPrefix(e.Name(), rec.ID+".") {
			return nil, fmt.Errorf("%s: file name does not match id %s", e.Name(), rec.ID)
		}
		if prev, ok := seen[rec.ID]; ok {
			return nil, fmt.Errorf("duplicate id %s in %s and %s", rec.ID, prev, e.Name())
		}
		seen[rec.ID] = e.Name()
		out = append(out, rec)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no detection records in %s", dir)
	}
	return out, nil
}
