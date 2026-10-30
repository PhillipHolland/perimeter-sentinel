// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"testing"
	"time"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/scope"
)

func TestDeniesUndeclaredPost(t *testing.T) {
	sc := affirmed(t)
	d := AllowFetch(sc, "POST", "https://rpc.other.example/", "")
	if d.Allowed {
		t.Fatal("post to undeclared host must be denied")
	}
}

func TestAllowsReferencedScript(t *testing.T) {
	sc := affirmed(t)
	if _, err := sc.Add(scope.KindPage, "https://owned.example/trade", "", true, true, false); err != nil {
		t.Fatal(err)
	}
	if err := Require(sc, "GET", "https://cdn.vendor.example/rum.js", "https://owned.example/trade"); err != nil {
		t.Fatal(err)
	}
	if err := Require(sc, "GET", "https://cdn.vendor.example/rum.js", ""); err == nil {
		t.Fatal("script without a parent page must be denied")
	}
}

func TestAllowsDeclaredRPCOnly(t *testing.T) {
	sc := affirmed(t)
	if _, err := sc.Add(scope.KindRPC, "https://rpc.owned.example/read", "", false, false, false); err != nil {
		t.Fatal(err)
	}
	if err := Require(sc, "POST", "https://rpc.owned.example/read", ""); err != nil {
		t.Fatal(err)
	}
	if err := Require(sc, "PUT", "https://rpc.owned.example/read", ""); err == nil {
		t.Fatal("put must be denied")
	}
}

func affirmed(t *testing.T) *scope.Store {
	t.Helper()
	sc := &scope.Store{}
	if err := sc.Affirm("Ada", scope.Affirmation, time.Now()); err != nil {
		t.Fatal(err)
	}
	return sc
}
