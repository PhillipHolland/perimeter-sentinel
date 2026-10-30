// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package cloudflare

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
)

func TestListZonesFixture(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method %s", r.Method)
		}
		if r.URL.Path != "/client/v4/zones" {
			t.Errorf("path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"z1","name":"other.example"}]}`))
	}))
	defer srv.Close()
	c := Client{BaseURL: srv.URL, Token: "test-token", HTTP: srv.Client()}
	res := c.ListZones("owned.example", map[string]bool{"owned.example": true})
	if res.Status != failsafe.StatusFinding {
		t.Fatalf("status %s %s", res.Status, res.Summary)
	}
}

func TestMissingTokenNoNetwork(t *testing.T) {
	c := Client{BaseURL: "http://127.0.0.1:1", Token: ""}
	res := c.ListZones("owned.example", nil)
	if res.Status != failsafe.StatusNeedsHuman {
		t.Fatal(res.Status)
	}
}

func TestUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	res := Client{BaseURL: srv.URL, Token: "bad", HTTP: srv.Client()}.ListZones("a.example", nil)
	if res.Status != failsafe.StatusNeedsHuman {
		t.Fatal(res.Status)
	}
}

func TestParseError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not-json`))
	}))
	defer srv.Close()
	res := Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}.ListZones("a.example", nil)
	if res.Status != failsafe.StatusNeedsHuman {
		t.Fatal(res.Status)
	}
}

func TestNoWriteVerbsInPackage(t *testing.T) {
	dir := "."
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		for _, verb := range []string{"MethodPut", "MethodPatch", "MethodDelete", "MethodPost", `"` + "PUT" + `"`, `"` + "POST" + `"`, `"` + "PATCH" + `"`, `"` + "DELETE" + `"`} {
			if strings.Contains(s, verb) {
				t.Fatalf("%s contains write verb %s", e.Name(), verb)
			}
		}
	}
	for _, m := range []string{http.MethodPut, http.MethodPost, http.MethodPatch, http.MethodDelete} {
		if err := RefuseWrite(m); err == nil {
			t.Fatal(m)
		}
	}
}
