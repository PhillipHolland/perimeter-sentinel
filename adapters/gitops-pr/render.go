// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package gitops renders a pull-request body. It does not open a pull request,
// push a branch, or talk to a forge. The operator pastes or commits the text.
package gitops

import (
	"fmt"
	"strings"
)

// Card is the text of one proposed change.
type Card struct {
	ID       string
	Title    string
	Diff     string
	Rollback string
	Expiry   string
	Lesson   string
}

// Render returns Markdown. The body says the change is unapplied.
func Render(c Card) (string, error) {
	for _, pair := range []struct{ name, v string }{
		{"id", c.ID}, {"title", c.Title}, {"diff", c.Diff},
		{"rollback", c.Rollback}, {"expiry", c.Expiry}, {"lesson", c.Lesson},
	} {
		if strings.TrimSpace(pair.v) == "" {
			return "", fmt.Errorf("gitops card needs %s", pair.name)
		}
	}
	return fmt.Sprintf(`# %s

Status: draft. This file is not a merged change.
Lesson: %s
Expires: %s

## Diff

%s

## Rollback

%s

Perimeter Sentinel did not push this branch and did not approve this card.
`, c.Title, c.Lesson, c.Expiry, c.Diff, c.Rollback), nil
}
