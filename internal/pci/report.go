// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package pci renders a QSA-friendly evidence note for script inventory and
// tamper checks. It is not a compliance determination and not an attestation.
package pci

import (
	"fmt"
	"strings"
	"time"
)

// Row is one script on one page.
type Row struct {
	Page          string
	Src           string
	Vendor        string
	Justification string
	ApprovedSHA   string
	ObservedSHA   string
	SRI           string
}

// Report is the evidence document.
type Report struct {
	Generated time.Time
	Rows      []Row
	HeaderCSP string
	Blind     []string
}

// Markdown renders the note.
func (r Report) Markdown() string {
	var b strings.Builder
	b.WriteString("# Script integrity evidence (PCI DSS v4.0.1 6.4.3 / 11.6.1 shaped)\n\n")
	b.WriteString("This is evidence for a qualified security assessor. It is not a finding that the operator complies, and it is not the only way to meet those requirements.\n\n")
	fmt.Fprintf(&b, "Generated (UTC): %s\n\n", r.Generated.UTC().Format(time.RFC3339))
	if r.HeaderCSP != "" {
		fmt.Fprintf(&b, "CSP observed: `%s`\n\n", r.HeaderCSP)
	}
	b.WriteString("| Page | Script | Vendor | Justification | Approved SHA-256 | Observed SHA-256 |\n")
	b.WriteString("|------|--------|--------|---------------|------------------|------------------|\n")
	for _, row := range r.Rows {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n",
			tick(row.Page), tick(row.Src), tick(row.Vendor), tick(row.Justification), tick(row.ApprovedSHA), tick(row.ObservedSHA))
	}
	if len(r.Blind) > 0 {
		b.WriteString("\n## Blind spots\n\n")
		for _, s := range r.Blind {
			b.WriteString("- " + s + "\n")
		}
	}
	b.WriteString("\nSentinel did not block a script in the browser. The operator's edge does that, if they choose to.\n")
	return b.String()
}

func tick(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}
