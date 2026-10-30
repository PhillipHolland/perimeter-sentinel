// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package egress is the allowlist for outbound calls. Correlation and watcher
// code may GET an in-scope page, GET a script that page referenced, resolve
// DNS for an in-scope name, or POST a read-only JSON-RPC method to a declared
// RPC URL. Everything else is refused. There is no general webhook sender.
package egress

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/scope"
)

// Decision is one allow or deny.
type Decision struct {
	Allowed bool
	Reason  string
}

// AllowFetch decides a single HTTP call. parentPage is required for any host
// that is not itself declared. method POST is only legal for a declared RPC.
func AllowFetch(sc *scope.Store, method, rawURL, parentPage string) Decision {
	method = strings.ToUpper(strings.TrimSpace(method))
	u, err := url.Parse(rawURL)
	if err != nil {
		return Decision{Reason: "url did not parse"}
	}
	if u.User != nil {
		return Decision{Reason: "userinfo is refused"}
	}
	switch method {
	case "GET", "HEAD":
	case "POST":
		if err := sc.Check(scope.KindRPC, rawURL); err != nil {
			// Normalize may differ by trailing slash. Try the stored form via Check on parsed URL.
			return Decision{Reason: "POST is refused except to a declared read-only RPC: " + err.Error()}
		}
		return Decision{Allowed: true, Reason: "declared rpc"}
	default:
		return Decision{Reason: "method " + method + " is refused"}
	}
	if u.Scheme != "https" && !localHTTP(u) {
		return Decision{Reason: "scheme is refused"}
	}
	// Declared page or https host: GET of that exact asset, or GET of its origin.
	if sc != nil && sc.Affirmed() {
		if err := sc.Check(scope.KindPage, rawURL); err == nil {
			return Decision{Allowed: true, Reason: "declared page"}
		}
		if host := u.Hostname(); host != "" {
			if err := sc.Check(scope.KindHTTPS, host); err == nil && (u.Path == "" || u.Path == "/") {
				return Decision{Allowed: true, Reason: "declared https origin"}
			}
		}
	}
	if parentPage == "" {
		return Decision{Reason: "target is not a declared page and has no in-scope parent"}
	}
	if err := sc.AllowReferenced(scope.KindPage, parentPage, rawURL); err != nil {
		return Decision{Reason: err.Error()}
	}
	return Decision{Allowed: true, Reason: "referenced by an in-scope page"}
}

func localHTTP(u *url.URL) bool {
	if u.Scheme != "http" {
		return false
	}
	h := u.Hostname()
	return h == "127.0.0.1" || h == "localhost" || h == "::1"
}

// Require returns an error when the call is not allowed.
func Require(sc *scope.Store, method, rawURL, parentPage string) error {
	d := AllowFetch(sc, method, rawURL, parentPage)
	if !d.Allowed {
		return fmt.Errorf("egress deny: %s", d.Reason)
	}
	return nil
}
