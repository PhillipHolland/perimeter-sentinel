// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package canon writes JSON with sorted object keys and no insignificant
// whitespace, so ledger hashes do not depend on map iteration order.
package canon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

// Bytes re-encodes JSON. Empty input becomes null.
func Bytes(raw []byte) ([]byte, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return []byte("null"), nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("canon: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("canon: trailing json")
		}
		return nil, fmt.Errorf("canon: %w", err)
	}
	return Value(v)
}

// Value encodes v in canonical form.
func Value(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := write(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func write(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return err
			}
			buf.Write(kb)
			buf.WriteByte(':')
			if err := write(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, el := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := write(buf, el); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case json.Number:
		if t.String() == "" {
			return fmt.Errorf("canon: empty number")
		}
		buf.WriteString(t.String())
	case string, bool:
		b, err := json.Marshal(t)
		if err != nil {
			return err
		}
		buf.Write(b)
	case float64:
		return fmt.Errorf("canon: float64 is not allowed; use json.Number")
	default:
		// Structs and other typed values go through encoding/json once, then
		// back through the canonical walker so key order is stable.
		b, err := json.Marshal(t)
		if err != nil {
			return err
		}
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.UseNumber()
		var parsed any
		if err := dec.Decode(&parsed); err != nil {
			return err
		}
		return write(buf, parsed)
	}
	return nil
}
