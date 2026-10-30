// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package intake

import (
	"testing"
	"time"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
)

func TestBrandAndDrained(t *testing.T) {
	at := time.Date(2026, 10, 29, 17, 45, 0, 0, time.UTC)
	batch := Batch{Posts: []Post{{
		ID: "p1", Author: "someone", Text: "ExampleEx users just got drained", At: at,
	}}}
	r, seen := Scan([]string{"ExampleEx"}, nil, batch, Seen{}, at.Add(30*time.Second))
	if r.Status != failsafe.StatusFinding {
		t.Fatalf("%s", r)
	}
	if r.Findings[0].Evidence[2].Value != "30" {
		t.Fatalf("%+v", r.Findings[0].Evidence)
	}
	r2, _ := Scan([]string{"ExampleEx"}, nil, batch, seen, at.Add(time.Minute))
	if r2.Status != failsafe.StatusOK {
		t.Fatalf("duplicate should not re-alert: %s", r2)
	}
}

func TestBrandAloneIsNotAFinding(t *testing.T) {
	batch := Batch{Posts: []Post{{ID: "p2", Author: "someone", Text: "ExampleEx status is green", At: time.Now()}}}
	r, _ := Scan([]string{"ExampleEx"}, nil, batch, Seen{}, time.Now())
	if r.Status != failsafe.StatusOK {
		t.Fatalf("%s", r)
	}
}

func TestSourceError(t *testing.T) {
	r, _ := Scan([]string{"ExampleEx"}, nil, Batch{Error: "timeout"}, Seen{}, time.Now())
	if r.Status != failsafe.StatusNeedsHuman {
		t.Fatal(r.Status)
	}
}

func TestNamedAccount(t *testing.T) {
	batch := Batch{Posts: []Post{{ID: "p3", Author: "@researcher", Text: "hot wallet looks compromised", At: time.Now()}}}
	r, _ := Scan(nil, []string{"researcher"}, batch, Seen{}, time.Now())
	if r.Status != failsafe.StatusFinding {
		t.Fatalf("%s", r)
	}
}
