// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package servedjs

import "testing"

func TestParseExternalAndInline(t *testing.T) {
	doc := `<html><head>
<meta http-equiv="Content-Security-Policy" content="script-src 'self'">
<script src="https://cdn.example/app.js" integrity="sha256-abc"></script>
<script type="application/ld+json">{"@x":1}</script>
<script>var a=1;</script>
</head></html>`
	refs, csp := ParseHTML(doc)
	if csp != "script-src 'self'" {
		t.Fatal(csp)
	}
	if len(refs) != 2 {
		t.Fatalf("%+v", refs)
	}
	if refs[0].Src != "https://cdn.example/app.js" || refs[0].Integrity == "" {
		t.Fatalf("%+v", refs[0])
	}
	if !refs[1].Inline || refs[1].SHA256 == "" {
		t.Fatalf("%+v", refs[1])
	}
}
