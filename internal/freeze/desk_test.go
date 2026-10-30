// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package freeze

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDeskFilesMatchCatalog(t *testing.T) {
	for _, p := range Catalog() {
		raw, err := os.ReadFile(filepath.Join("..", "..", "freeze-desk", "playbooks", p.ID+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var got Playbook
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		canon, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		var want Playbook
		if err := json.Unmarshal(canon, &want); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("%s on disk drifted from Catalog()", p.ID)
		}
	}
}
