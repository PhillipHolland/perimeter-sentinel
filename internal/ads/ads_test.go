// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package ads

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestRecordsCoverCode(t *testing.T) {
	root := repoRoot(t)
	recs, err := LoadDir(filepath.Join(root, "detections"))
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, r := range recs {
		have[r.ID] = true
		if !strings.Contains(r.Validation, "go test") && !strings.Contains(r.Validation, "drills/oct29") {
			t.Errorf("%s validation %q does not name a test", r.ID, r.Validation)
		}
	}
	ids := detectionIDs(t, root)
	if len(ids) == 0 {
		t.Fatal("no detection ids in Go source")
	}
	for id := range ids {
		if !have[id] {
			t.Errorf("code uses %s with no detections record", id)
		}
	}
	for id := range have {
		if !ids[id] {
			t.Errorf("detections record %s is not referenced by Go", id)
		}
	}
}

func TestRejectsIncomplete(t *testing.T) {
	_, err := Parse("id: det-x\ngoal: g\n")
	if err == nil {
		t.Fatal("incomplete record was accepted")
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

var detRE = regexp.MustCompile(`det-[a-z0-9-]+`)

func detectionIDs(t *testing.T, root string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "bin", "dist", ".perimeter":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.Contains(path, string(filepath.Separator)+"internal"+string(filepath.Separator)+"ads"+string(filepath.Separator)) {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range detRE.FindAll(raw, -1) {
			out[string(m)] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
