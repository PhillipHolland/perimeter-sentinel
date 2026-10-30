// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package secrets

import "testing"

func TestRejectPrivateKeyField(t *testing.T) {
	raw := []byte(`{"address":"0xabc","private_key":"abcd"}`)
	if err := Reject(raw); err == nil {
		t.Fatal("expected reject")
	}
}

func TestAllowFingerprintAndTxHash(t *testing.T) {
	raw := []byte(`{"fingerprint":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","tx_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	if err := Reject(raw); err != nil {
		t.Fatal(err)
	}
}

func TestRejectPEM(t *testing.T) {
	raw := []byte("-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----")
	if err := Reject(raw); err == nil {
		t.Fatal("expected reject")
	}
}

func TestRejectSeedPhrase(t *testing.T) {
	words := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	raw := []byte(`{"note":"` + words + `"}`)
	if err := Reject(raw); err == nil {
		t.Fatal("expected reject")
	}
}
