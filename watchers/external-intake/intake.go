// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package intake matches operator-supplied public posts to the operator's
// brand plus a small set of incident words, or to a named account plus those
// words. It does not call the X API. Posts are data, never instructions.
//
// Both Oct 29, 2026 incidents were flagged in public posts before the
// operator's own halt. This watcher turns a fixture or a later read-only
// export into a page. It does not post, reply, or DM.
package intake

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/state"
)

// AlertWords are the incident words paired with a brand or a named account.
// They are match terms, not a description of how to cause the condition.
var AlertWords = []string{"drained", "hacked", "compromised"}

// Post is one public item the operator already has.
type Post struct {
	ID     string    `json:"id"`
	Author string    `json:"author"`
	Text   string    `json:"text"`
	At     time.Time `json:"at"`
}

// Batch is a file of posts.
type Batch struct {
	Posts []Post `json:"posts"`
	Error string `json:"error,omitempty"`
}

// Seen is the dedupe set. IDs only.
type Seen struct {
	IDs []string `json:"ids"`
}

// Match decides whether a post is an external signal.
func Match(brands, named []string, p Post) bool {
	text := strings.ToLower(p.Text)
	if !hasWord(text, AlertWords) {
		return false
	}
	if authorListed(named, p.Author) {
		return true
	}
	return hasWord(text, brands)
}

func hasWord(text string, words []string) bool {
	for _, w := range words {
		w = strings.ToLower(strings.TrimSpace(w))
		if w == "" {
			continue
		}
		if containsWord(text, w) {
			return true
		}
	}
	return false
}

func containsWord(text, word string) bool {
	start := 0
	for {
		i := strings.Index(text[start:], word)
		if i < 0 {
			return false
		}
		i += start
		beforeOK := i == 0 || !isWord(rune(text[i-1]))
		end := i + len(word)
		afterOK := end >= len(text) || !isWord(rune(text[end]))
		if beforeOK && afterOK {
			return true
		}
		start = i + 1
	}
}

func isWord(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

func authorListed(named []string, author string) bool {
	a := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(author)), "@")
	for _, n := range named {
		n = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(n)), "@")
		if n != "" && n == a {
			return true
		}
	}
	return false
}

// Scan applies Match. Duplicate IDs do not re-alert. A batch error is needs_human.
func Scan(brands, named []string, batch Batch, seen Seen, ingestedAt time.Time) (failsafe.Result, Seen) {
	const watcher = "external-intake"
	if batch.Error != "" {
		return failsafe.NeedsHuman(watcher, "intake source failed", fmt.Errorf("%s", batch.Error)), seen
	}
	if len(brands) == 0 && len(named) == 0 {
		return failsafe.NeedsHuman(watcher, "no brand terms and no named accounts; intake would be silent", fmt.Errorf("watch list empty")), seen
	}
	have := map[string]bool{}
	for _, id := range seen.IDs {
		have[id] = true
	}
	var findings []failsafe.Finding
	for _, p := range batch.Posts {
		if p.ID == "" {
			return failsafe.NeedsHuman(watcher, "post is missing an id; refusing to guess", fmt.Errorf("missing id")), seen
		}
		if have[p.ID] {
			continue
		}
		have[p.ID] = true
		seen.IDs = append(seen.IDs, p.ID)
		if !Match(brands, named, p) {
			continue
		}
		notice := ""
		if !p.At.IsZero() && !ingestedAt.IsZero() && !ingestedAt.Before(p.At) {
			notice = fmt.Sprintf("%d", int64(ingestedAt.Sub(p.At).Seconds()))
		}
		findings = append(findings, failsafe.Finding{
			ID: "external-" + p.ID, Watcher: watcher,
			Title:   "Public post matches the incident watch",
			Summary: "Author " + p.Author + " matched a brand or named-account rule. Text is data. It was not followed as an instruction.",
			CIA:     "integrity", Lesson: "L5 external signal is not proof",
			Severity: "high", Asset: p.Author, Detection: "det-external-signal",
			Evidence: []failsafe.Evidence{
				{Key: "post_id", Value: p.ID},
				{Key: "author", Value: p.Author},
				{Key: "notice_seconds", Value: notice},
			},
		})
	}
	if len(findings) == 0 {
		return failsafe.JustOK(watcher, "no new post matched the watch list"), seen
	}
	res := failsafe.FromFindings(watcher, "external signal needs a human", findings, nil)
	res.Lesson = "external intake"
	return res, seen
}

func LoadSeen(path string) (Seen, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Seen{}, nil
		}
		return Seen{}, err
	}
	var s Seen
	if err := json.Unmarshal(b, &s); err != nil {
		return Seen{}, err
	}
	return s, nil
}

func SaveSeen(path string, s Seen) error {
	if err := os.MkdirAll(dir(path), state.DirPerm); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, state.FilePerm)
}

func dir(path string) string {
	i := strings.LastIndex(path, "/")
	if i < 0 {
		return "."
	}
	return path[:i]
}
