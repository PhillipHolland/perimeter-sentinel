// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLedgerChainVerify(t *testing.T) {
	l := openTest(t)
	now := time.Date(2026, 10, 29, 18, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		if _, err := l.Append("note", "operator", map[string]any{"n": i}, now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Verify(); err != nil {
		t.Fatal(err)
	}
	evs, err := l.Events()
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 3 || evs[0].Prev != ZeroPrev || evs[1].Prev != evs[0].Hash || evs[2].Seq != 3 {
		t.Fatalf("%+v", evs)
	}

	// Flip one payload byte.
	raw, err := os.ReadFile(l.Path)
	if err != nil {
		t.Fatal(err)
	}
	broken := strings.Replace(string(raw), `"n":0`, `"n":9`, 1)
	if broken == string(raw) {
		t.Fatal("fixture did not change")
	}
	if err := os.WriteFile(l.Path, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := l.Verify(); err == nil {
		t.Fatal("tampered chain verified")
	}

	// Restore and delete the middle line.
	if err := os.WriteFile(l.Path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines %d", len(lines))
	}
	cut := lines[0] + "\n" + lines[2] + "\n"
	if err := os.WriteFile(l.Path, []byte(cut), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := l.Verify(); err == nil {
		t.Fatal("deleted middle verified")
	}
}

func TestAppendRefusesBrokenChain(t *testing.T) {
	l := openTest(t)
	if _, err := l.Append("note", "operator", map[string]string{"a": "b"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(l.Path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append("note", "operator", map[string]string{"a": "c"}, time.Now()); err == nil {
		t.Fatal("append extended a broken chain")
	}
}

func TestSentinelCannotAppendApproval(t *testing.T) {
	l := openTest(t)
	_, err := l.Append("approval.granted", "sentinel", map[string]string{"ok": "yes"}, time.Now())
	if err == nil {
		t.Fatal("expected refusal")
	}
}

func TestRejectsKeyMaterial(t *testing.T) {
	l := openTest(t)
	_, err := l.Append("note", "operator", map[string]string{"private_key": "abcd"}, time.Now())
	if err == nil {
		t.Fatal("expected refusal")
	}
}

func TestExportMarkdown(t *testing.T) {
	l := openTest(t)
	if _, err := l.Append("note", "operator", map[string]string{"text": "hi"}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	md, err := l.ExportMarkdown()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(md, "note") || !strings.Contains(md, "Hash-chained") {
		t.Fatalf("%s", md)
	}
}

func openTest(t *testing.T) *Log {
	t.Helper()
	l, err := Open(filepath.Join(t.TempDir(), "ledger", "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return l
}
