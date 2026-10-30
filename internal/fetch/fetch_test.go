// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package fetch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/scope"
)

func TestGetDeclaredPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "script-src 'self'")
		_, _ = w.Write([]byte("<html>ok</html>"))
	}))
	defer srv.Close()
	sc := &scope.Store{}
	_ = sc.Affirm("Ada", scope.Affirmation, time.Now())
	if _, err := sc.Add(scope.KindPage, srv.URL, "", false, false, false); err != nil {
		t.Fatal(err)
	}
	// Add stores a normalized URL that may add a slash. Fetch the stored name.
	page := sc.Data.Assets[0].Name
	code, hdr, body, err := Get(context.Background(), sc, page, "")
	if err != nil {
		t.Fatal(err)
	}
	if code != 200 || len(body) == 0 || hdr["Content-Security-Policy"] == "" {
		t.Fatalf("code %d hdr %v body %s", code, hdr, body)
	}
}

func TestRejectsUndeclared(t *testing.T) {
	sc := &scope.Store{}
	_ = sc.Affirm("Ada", scope.Affirmation, time.Now())
	if _, _, _, err := Get(context.Background(), sc, "https://not-ours.example/", ""); err == nil {
		t.Fatal("expected deny")
	}
}
