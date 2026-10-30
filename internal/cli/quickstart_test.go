// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestQuickstart(t *testing.T) {
	home := t.TempDir()
	steps := []struct {
		args []string
		code int
		want string
	}{
		{[]string{"--home", home, "init", "--owner", "Example Operator", "--profile", "enterprise", "--timezone", "America/Chicago", "--appetite", "low"}, 0, "initialized"},
		{[]string{"--home", home, "scope", "affirm", "--statement", "I operate these"}, 0, "affirmed"},
		{[]string{"--home", home, "roster", "set", "--role", "incident-commander", "--name", "Example Operator", "--oob", "voice"}, 0, "roster"},
		{[]string{"--home", home, "scope", "add", "--kind", "dns", "--name", "example.com"}, 0, "added"},
		{[]string{"--home", home, "scope", "list"}, 0, "example.com"},
		{[]string{"--home", home, "ledger", "append", "--type", "note", "--actor", "operator", "--payload", `{"text":"quickstart"}`}, 0, "appended"},
		{[]string{"--home", home, "ledger", "verify"}, 0, "ok events="},
		{[]string{"--home", home, "brief"}, 3, "Govern (GV)"},
		{[]string{"--home", home, "freeze", "list"}, 0, "vendor-script-compromise"},
		{[]string{"--home", home, "freeze", "list"}, 0, "hot-wallet-drain"},
		{[]string{"--home", home, "drill", "list"}, 0, "oct29-delegation"},
		{[]string{"--home", home, "watch", "dns", "--name", "example.com"}, 3, "needs_human"},
		{[]string{"--home", home, "drill", "run"}, 0, "PASS oct29-no-keys"},
	}
	for _, s := range steps {
		var out, errb bytes.Buffer
		code := Run(s.args, &out, &errb)
		if code != s.code {
			t.Fatalf("args %v code %d want %d\nstdout:\n%s\nstderr:\n%s", s.args, code, s.code, out.String(), errb.String())
		}
		if !strings.Contains(out.String(), s.want) {
			t.Fatalf("args %v missing %q\n%s", s.args, s.want, out.String())
		}
	}
}

func TestScopeDenyFromWatch(t *testing.T) {
	home := t.TempDir()
	var out, errb bytes.Buffer
	if code := Run([]string{"--home", home, "init", "--owner", "Ada", "--profile", "enterprise", "--timezone", "UTC", "--appetite", "low"}, &out, &errb); code != 0 {
		t.Fatal(out.String(), errb.String())
	}
	out.Reset()
	code := Run([]string{"--home", home, "watch", "dns", "--name", "example.com", "--desired", "nope", "--observation", "nope"}, &out, &errb)
	if code != 3 {
		t.Fatalf("code %d %s %s", code, out.String(), errb.String())
	}
}
