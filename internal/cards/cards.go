// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package cards is the change-card schema. v0.1 drafts cards and stops.
// Sentinel cannot approve a card. The default later apply path is a pull
// request, not a direct write.
package cards

import (
	"errors"
	"fmt"
	"time"
)

// Card is one proposed change. Status stays "draft" inside this process.
type Card struct {
	ID       string    `json:"id"`
	Lesson   string    `json:"lesson"`
	Summary  string    `json:"summary"`
	Diff     string    `json:"diff"`
	Scope    string    `json:"scope"`
	Expires  time.Time `json:"expires"`
	Rollback string    `json:"rollback"`
	Status   string    `json:"status"`
}

// Draft builds a card. It does not approve it.
func Draft(id, lesson, summary, diff, scope, rollback string, expires time.Time) (Card, error) {
	if id == "" || lesson == "" || summary == "" || diff == "" || rollback == "" {
		return Card{}, errors.New("a card needs an id, a lesson, a summary, a diff, and a rollback")
	}
	if !expires.After(time.Now().Add(-time.Minute)) && expires.IsZero() {
		return Card{}, errors.New("expiry is required")
	}
	if expires.IsZero() {
		return Card{}, errors.New("expiry is required")
	}
	return Card{
		ID: id, Lesson: lesson, Summary: summary, Diff: diff, Scope: scope,
		Expires: expires, Rollback: rollback, Status: "draft",
	}, nil
}

// Approve is refused. Humans approve on their own device.
func Approve(c Card, actor string) error {
	return fmt.Errorf("sentinel cannot approve card %s (actor %s)", c.ID, actor)
}
