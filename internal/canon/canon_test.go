// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package canon

import "testing"

func TestKeyOrderStable(t *testing.T) {
	a, err := Bytes([]byte(`{"b":1,"a":{"d":2,"c":3}}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Bytes([]byte(`{"a":{"c":3,"d":2},"b":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("%s vs %s", a, b)
	}
	if string(a) != `{"a":{"c":3,"d":2},"b":1}` {
		t.Fatalf("got %s", a)
	}
}

func TestRejectsTrailing(t *testing.T) {
	if _, err := Bytes([]byte(`{}{}`)); err == nil {
		t.Fatal("expected error")
	}
}
