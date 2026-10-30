// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package secrets rejects material Sentinel must never store: private keys,
// seed phrases, keystores, and PEM blocks. Fingerprints and tx hashes are
// allowed only under explicit field names.
package secrets

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// BlockedField are names that must not carry secret material.
var blockedFields = []string{
	"private_key",
	"privatekey",
	"seed",
	"seed_phrase",
	"mnemonic",
	"keystore",
	"signing_key",
	"secret_key",
	"raw_key",
	"withdrawal_key",
}

var pem = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)

// Reject walks JSON and returns an error if it looks like key material.
// The error never echoes the secret bytes.
func Reject(raw []byte) error {
	if pem.Match(raw) {
		return fmt.Errorf("refusing to store a private key block")
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		// Non-JSON text is scanned only for PEM, already done.
		return nil
	}
	if err := walk("", v); err != nil {
		return err
	}
	return nil
}

func walk(name string, v any) error {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			lk := strings.ToLower(k)
			if blockedName(lk) {
				if s, ok := child.(string); ok && strings.TrimSpace(s) != "" {
					return fmt.Errorf("refusing field %q: sentinel never holds keys", k)
				}
				if child != nil {
					if _, ok := child.(string); !ok {
						return fmt.Errorf("refusing field %q: sentinel never holds keys", k)
					}
				}
			}
			if err := walk(k, child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range t {
			if err := walk(name, child); err != nil {
				return err
			}
		}
	case string:
		if pem.MatchString(t) {
			return fmt.Errorf("refusing to store a private key block")
		}
		if looksLikeSeedPhrase(t) {
			return fmt.Errorf("refusing field %q: value looks like a seed phrase", name)
		}
	}
	return nil
}

func blockedName(k string) bool {
	k = strings.ReplaceAll(k, "-", "_")
	for _, b := range blockedFields {
		if k == b || strings.HasSuffix(k, "_"+b) || strings.Contains(k, b) {
			return true
		}
	}
	return false
}

func looksLikeSeedPhrase(s string) bool {
	parts := strings.Fields(s)
	if len(parts) != 12 && len(parts) != 24 {
		return false
	}
	for _, p := range parts {
		if len(p) < 3 || len(p) > 8 {
			return false
		}
		for _, r := range p {
			if r < 'a' || r > 'z' {
				return false
			}
		}
	}
	return true
}
