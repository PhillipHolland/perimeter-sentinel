// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package edgerules is a plan-only change card for the operator's edge.
// The shape is original. It is not a copy of octorules. Apply is refused in
// v0.1 so a plan cannot become a live vendor call from this process.
package edgerules

import (
	"errors"
	"fmt"
	"strings"
)

// Change is a desired diff. Vendor is a label the operator already uses.
type Change struct {
	Vendor   string
	Resource string
	Diff     string
	Rollback string
}

// Plan renders a review document. It does not contact the vendor.
func Plan(c Change) (string, error) {
	if strings.TrimSpace(c.Vendor) == "" || strings.TrimSpace(c.Resource) == "" {
		return "", errors.New("plan needs a vendor label and a resource")
	}
	if strings.TrimSpace(c.Diff) == "" || strings.TrimSpace(c.Rollback) == "" {
		return "", errors.New("plan needs a diff and a rollback")
	}
	return fmt.Sprintf("plan-only\nvendor: %s\nresource: %s\napply: refused\nrollback: %s\n\n%s\n", c.Vendor, c.Resource, c.Rollback, c.Diff), nil
}

// Apply is refused. The operator applies through their own change process.
func Apply(Change) error {
	return errors.New("v0.1 refuses edge apply; open the plan as a change card")
}
