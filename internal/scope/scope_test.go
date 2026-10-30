// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestScopeDeny(t *testing.T) {
	s := &Store{Data: File{Owner: "Ada", Affirmation: Affirmation, AffirmedAt: time.Now()}}
	err := s.Check(KindDNS, "not-declared.example")
	if err == nil {
		t.Fatal("expected deny")
	}
	var d *DenyError
	if !asDeny(err, &d) {
		t.Fatalf("got %T %v", err, err)
	}
	if d.Reason == "" || !contains(err.Error(), "deny") {
		t.Fatalf("error %v", err)
	}

	// Unaffirmed scope denies even a listed name.
	if _, err := s.Add(KindDNS, "owned.example", "", false, false, false); err != nil {
		t.Fatal(err)
	}
	s.Data.Affirmation = ""
	if err := s.Check(KindDNS, "owned.example"); err == nil {
		t.Fatal("unaffirmed scope must deny")
	}
}

func TestScopeAllowAfterAffirm(t *testing.T) {
	s := &Store{}
	if err := s.Affirm("Ada", Affirmation, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add(KindHTTPS, "Owned.Example", "", false, false, false); err != nil {
		t.Fatal(err)
	}
	if err := s.Check(KindHTTPS, "owned.example"); err != nil {
		t.Fatal(err)
	}
	if err := s.RequireVerified(KindHTTPS, "owned.example"); err == nil {
		t.Fatal("unverified live check must deny")
	}
}

func TestTXTVerify(t *testing.T) {
	dir := t.TempDir()
	s := &Store{Path: filepath.Join(dir, "scope.json")}
	if err := s.Affirm("Ada", Affirmation, time.Now()); err != nil {
		t.Fatal(err)
	}
	a, err := s.Add(KindDNS, "owned.example", "", false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	r := fakeTXT{name: TXTPrefix + "owned.example", values: []string{TXTMarker + a.TXTToken}}
	got, err := s.VerifyDNS(context.Background(), KindDNS, "owned.example", r, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !got.Verified || got.VerifyBy != "dns-txt" {
		t.Fatalf("%+v", got)
	}
	if err := s.RequireVerified(KindDNS, "owned.example"); err != nil {
		t.Fatal(err)
	}
}

func TestTXTMismatchStaysClosed(t *testing.T) {
	s := &Store{}
	_ = s.Affirm("Ada", Affirmation, time.Now())
	if _, err := s.Add(KindDNS, "owned.example", "", false, false, false); err != nil {
		t.Fatal(err)
	}
	r := fakeTXT{name: TXTPrefix + "owned.example", values: []string{"perimeter-sentinel-verify=nope"}}
	if _, err := s.VerifyDNS(context.Background(), KindDNS, "owned.example", r, time.Now()); err == nil {
		t.Fatal("expected mismatch")
	}
}

func TestWalletAttestDoesNotSign(t *testing.T) {
	s := &Store{}
	_ = s.Affirm("Ada", Affirmation, time.Now())
	if _, err := s.Add(KindWallet, "0xABcd00000000000000000000000000000000abcd", "", false, false, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifyDNS(context.Background(), KindWallet, "0xabcd00000000000000000000000000000000abcd", fakeTXT{}, time.Now()); err == nil {
		t.Fatal("wallet dns verify must refuse")
	}
	a, err := s.AttestWallet("0xabcd00000000000000000000000000000000abcd", Affirmation, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if a.VerifyBy != "operator-attestation" {
		t.Fatal(a.VerifyBy)
	}
}

func TestRejectsNonASCIIAndUserinfo(t *testing.T) {
	if _, err := Normalize(KindDNS, "exámple.com"); err == nil {
		t.Fatal("non-ascii should fail")
	}
	if _, err := Normalize(KindPage, "https://user:pass@owned.example/a"); err == nil {
		t.Fatal("userinfo should fail")
	}
	if _, err := Normalize(KindPage, "http://owned.example/a"); err == nil {
		t.Fatal("remote http should fail")
	}
}

func TestReferencedScriptRequiresParentPage(t *testing.T) {
	s := &Store{}
	_ = s.Affirm("Ada", Affirmation, time.Now())
	if _, err := s.Add(KindPage, "https://owned.example/trade", "", true, true, false); err != nil {
		t.Fatal(err)
	}
	if err := s.AllowReferenced(KindPage, "https://owned.example/trade", "https://cdn.vendor.example/rum.js"); err != nil {
		t.Fatal(err)
	}
	if err := s.AllowReferenced(KindPage, "https://other.example/trade", "https://cdn.vendor.example/rum.js"); err == nil {
		t.Fatal("undeclared parent must deny the reference")
	}
}

type fakeTXT struct {
	name   string
	values []string
	err    error
}

func (f fakeTXT) LookupTXT(_ context.Context, name string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	if name != f.name {
		return nil, nil
	}
	return f.values, nil
}

func asDeny(err error, dst **DenyError) bool {
	d, ok := err.(*DenyError)
	if !ok {
		return false
	}
	*dst = d
	return true
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})())
}
