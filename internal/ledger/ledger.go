// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package ledger is an append-only hash-chained JSONL evidence log.
//
// The chain detects a flipped byte, a deleted line, and a rewritten middle.
// Someone who can rewrite the whole file can recompute a fresh chain. That
// residual is why a later release anchors the head in Rekor. v0.1 keeps the
// anchor interface and does not call a public log unless the operator points
// at one they run. Sentinel never treats a local verify as proof against a
// privileged editor of the file.
package ledger

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/canon"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/secrets"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/state"
)

// ZeroPrev is the genesis previous-hash.
const ZeroPrev = "0000000000000000000000000000000000000000000000000000000000000000"

// Event is one ledger line. Hash is sha256 of the canonical body without Hash.
type Event struct {
	Seq     int64           `json:"seq"`
	Prev    string          `json:"prev"`
	TS      string          `json:"ts"`
	Type    string          `json:"type"`
	Actor   string          `json:"actor"`
	Payload json.RawMessage `json:"payload"`
	Hash    string          `json:"hash"`
}

// Log is the JSONL file.
type Log struct {
	Path string
}

func Open(path string) (*Log, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("ledger path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), state.DirPerm); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, state.FilePerm)
	if err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return &Log{Path: path}, nil
}

// Verify walks the chain. An empty file is a valid empty chain.
// A missing file is an error, not an empty chain.
func (l *Log) Verify() error {
	events, err := l.read()
	if err != nil {
		return err
	}
	prev := ZeroPrev
	for i, ev := range events {
		wantSeq := int64(i + 1)
		if ev.Seq != wantSeq {
			return fmt.Errorf("ledger: seq %d at line %d, want %d", ev.Seq, i+1, wantSeq)
		}
		if ev.Prev != prev {
			return fmt.Errorf("ledger: prev mismatch at seq %d", ev.Seq)
		}
		got, err := hashEvent(ev)
		if err != nil {
			return fmt.Errorf("ledger: seq %d: %w", ev.Seq, err)
		}
		if got != ev.Hash {
			return fmt.Errorf("ledger: hash mismatch at seq %d", ev.Seq)
		}
		prev = ev.Hash
	}
	return nil
}

// Append adds one event. It refuses to extend a broken chain.
func (l *Log) Append(typ, actor string, payload any, now time.Time) (Event, error) {
	if err := validateType(typ, actor); err != nil {
		return Event{}, err
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return Event{}, err
	}
	if err := secrets.Reject(raw); err != nil {
		return Event{}, err
	}
	canonPayload, err := canon.Bytes(raw)
	if err != nil {
		return Event{}, err
	}
	unlock, err := lockFile(l.Path)
	if err != nil {
		return Event{}, err
	}
	defer unlock()

	if err := l.Verify(); err != nil {
		return Event{}, fmt.Errorf("refusing to append to a broken chain: %w", err)
	}
	events, err := l.read()
	if err != nil {
		return Event{}, err
	}
	prev := ZeroPrev
	seq := int64(1)
	if n := len(events); n > 0 {
		prev = events[n-1].Hash
		seq = events[n-1].Seq + 1
	}
	ev := Event{
		Seq:     seq,
		Prev:    prev,
		TS:      now.UTC().Format(time.RFC3339Nano),
		Type:    typ,
		Actor:   actor,
		Payload: canonPayload,
	}
	h, err := hashEvent(ev)
	if err != nil {
		return Event{}, err
	}
	ev.Hash = h
	line, err := json.Marshal(ev)
	if err != nil {
		return Event{}, err
	}
	f, err := os.OpenFile(l.Path, os.O_APPEND|os.O_WRONLY, state.FilePerm)
	if err != nil {
		return Event{}, err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return Event{}, err
	}
	return ev, nil
}

// Events returns the chain after a successful verify.
func (l *Log) Events() ([]Event, error) {
	if err := l.Verify(); err != nil {
		return nil, err
	}
	return l.read()
}

// ExportMarkdown renders the chain for an auditor. It is not a PDF.
func (l *Log) ExportMarkdown() (string, error) {
	evs, err := l.Events()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("# Perimeter Sentinel evidence ledger\n\n")
	b.WriteString("Hash-chained JSONL. Local verify detects edits. It does not replace an external timestamp.\n\n")
	if len(evs) == 0 {
		b.WriteString("No events.\n")
		return b.String(), nil
	}
	b.WriteString("| Seq | Time (UTC) | Type | Actor | Hash |\n")
	b.WriteString("|-----|------------|------|-------|------|\n")
	for _, ev := range evs {
		fmt.Fprintf(&b, "| %d | %s | %s | %s | `%s` |\n", ev.Seq, ev.TS, ev.Type, ev.Actor, ev.Hash[:16])
	}
	b.WriteString("\n")
	return b.String(), nil
}

func (l *Log) read() ([]Event, error) {
	f, err := os.Open(l.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			return nil, fmt.Errorf("ledger: line %d: %w", lineNo, err)
		}
		out = append(out, ev)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func hashEvent(ev Event) (string, error) {
	payload, err := canon.Bytes(ev.Payload)
	if err != nil {
		return "", err
	}
	body := map[string]any{
		"seq":     ev.Seq,
		"prev":    ev.Prev,
		"ts":      ev.TS,
		"type":    ev.Type,
		"actor":   ev.Actor,
		"payload": json.RawMessage(payload),
	}
	// json.RawMessage inside map[string]any does not walk as raw JSON in canon.Value
	// because the default branch re-marshals it. Build the canonical bytes directly.
	_ = body
	sumInput := fmt.Sprintf("{\"actor\":%s,\"payload\":%s,\"prev\":%s,\"seq\":%d,\"ts\":%s,\"type\":%s}",
		mustJSONString(ev.Actor),
		payload,
		mustJSONString(ev.Prev),
		ev.Seq,
		mustJSONString(ev.TS),
		mustJSONString(ev.Type),
	)
	sum := sha256.Sum256([]byte(sumInput))
	return hex.EncodeToString(sum[:]), nil
}

func mustJSONString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return "\"\""
	}
	return string(b)
}

func validateType(typ, actor string) error {
	if strings.TrimSpace(typ) == "" {
		return errors.New("event type is required")
	}
	if strings.TrimSpace(actor) == "" {
		return errors.New("actor is required")
	}
	if strings.ContainsAny(typ, " \n\t") {
		return errors.New("event type must be a single token")
	}
	switch typ {
	case "tx.signed", "tx.broadcast", "freeze.execute", "approval.granted":
		return fmt.Errorf("event type %s is refused; sentinel does not approve, sign, or broadcast", typ)
	}
	lowerActor := strings.ToLower(actor)
	self := lowerActor == "sentinel" || lowerActor == "perimeterctl" || lowerActor == "perimeter-sentinel"
	if self && strings.HasPrefix(typ, "approval") {
		return errors.New("sentinel cannot approve, sign, or broadcast")
	}
	return nil
}

func lockFile(path string) (func(), error) {
	lp := path + ".lock"
	f, err := os.OpenFile(lp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, state.FilePerm)
	if err != nil {
		return nil, fmt.Errorf("ledger lock held or unwritable: %w", err)
	}
	fmt.Fprintf(f, "%d\n", os.Getpid())
	_ = f.Close()
	return func() { _ = os.Remove(lp) }, nil
}
