// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package scriptdrift_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestScriptDriftDemo(t *testing.T) {
	root := findRoot(t)
	bin := filepath.Join(t.TempDir(), "perimeterctl")
	build := exec.Command("go", "build", "-o", bin, "./cmd/perimeterctl")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	home := filepath.Join(t.TempDir(), "demo-home")
	cmd := exec.Command(bin, "--home", home, "demo", "script-drift", "--port", "0")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "PERIMETER_ROOT="+root)
	timer := time.AfterFunc(60*time.Second, func() { _ = cmd.Process.Kill() })
	defer timer.Stop()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("demo: %v\n%s", err, out)
	}
	text := string(out)
	for _, needle := range []string{"finding", "demo-vendor", "SENT: false", "ledger verify", "time-to-notice"} {
		if !strings.Contains(text, needle) {
			t.Fatalf("missing %q in\n%s", needle, text)
		}
	}
	err = filepath.Walk(home, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		s := string(b)
		for _, scheme := range []string{"https://", "http://"} {
			idx := 0
			for {
				i := strings.Index(s[idx:], scheme)
				if i < 0 {
					break
				}
				abs := idx + i
				rest := s[abs:]
				if strings.HasPrefix(rest, "http://") && !strings.HasPrefix(rest, "http://127.0.0.1") {
					t.Errorf("%s contains non-loopback url %q", path, rest[:min(80, len(rest))])
				}
				if strings.HasPrefix(rest, "https://") {
					t.Errorf("%s contains https url", path)
				}
				idx = abs + len(scheme)
				if idx >= len(s) {
					break
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func findRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
