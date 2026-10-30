// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package servedjs

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// Ref is one script tag. Inline bodies are not retained, only their hash.
type Ref struct {
	Src       string
	Integrity string
	Inline    bool
	SHA256    string
}

// ParseHTML lists script tags and the first CSP meta content.
// It is a scanner, not a browser. Unusual markup fails closed at the caller
// when a later hash step cannot account for every tag.
func ParseHTML(doc string) (refs []Ref, metaCSP string) {
	lower := strings.ToLower(doc)
	metaCSP = metaContent(doc, lower)
	i := 0
	for {
		j := strings.Index(lower[i:], "<script")
		if j < 0 {
			return refs, metaCSP
		}
		j += i
		if j+7 < len(doc) {
			next := doc[j+7]
			if next != ' ' && next != '\t' && next != '\n' && next != '\r' && next != '>' && next != '/' {
				i = j + 7
				continue
			}
		}
		gt := strings.IndexByte(doc[j:], '>')
		if gt < 0 {
			return refs, metaCSP
		}
		tag := doc[j : j+gt]
		selfClose := strings.HasSuffix(strings.TrimSpace(tag), "/")
		attr := parseAttrs(tag)
		typ := strings.ToLower(strings.TrimSpace(attr["type"]))
		advance := j + gt + 1
		if skipType(typ) {
			if !selfClose {
				if end := indexClose(lower, advance); end >= 0 {
					advance = end + len("</script>")
				}
			}
			i = advance
			continue
		}
		if src := strings.TrimSpace(attr["src"]); src != "" {
			refs = append(refs, Ref{Src: src, Integrity: strings.TrimSpace(attr["integrity"])})
			i = advance
			continue
		}
		if selfClose {
			i = advance
			continue
		}
		end := indexClose(lower, advance)
		if end < 0 {
			return refs, metaCSP
		}
		inner := doc[advance:end]
		sum := sha256.Sum256([]byte(inner))
		refs = append(refs, Ref{
			Inline:    true,
			Integrity: strings.TrimSpace(attr["integrity"]),
			SHA256:    hex.EncodeToString(sum[:]),
		})
		i = end + len("</script>")
	}
}

func indexClose(lower string, from int) int {
	k := strings.Index(lower[from:], "</script>")
	if k < 0 {
		return -1
	}
	return from + k
}

func skipType(typ string) bool {
	switch typ {
	case "application/json", "application/ld+json", "importmap", "speculationrules":
		return true
	default:
		return false
	}
}

func metaContent(doc, lower string) string {
	i := 0
	for {
		j := strings.Index(lower[i:], "<meta")
		if j < 0 {
			return ""
		}
		j += i
		gt := strings.IndexByte(doc[j:], '>')
		if gt < 0 {
			return ""
		}
		tag := doc[j : j+gt]
		attr := parseAttrs(tag)
		equiv := strings.ToLower(attr["http-equiv"])
		if equiv == "content-security-policy" {
			return attr["content"]
		}
		i = j + gt + 1
	}
}

func parseAttrs(tag string) map[string]string {
	out := map[string]string{}
	// Drop the tag name.
	k := 0
	for k < len(tag) && tag[k] != ' ' && tag[k] != '\t' && tag[k] != '\n' {
		k++
	}
	rest := tag[k:]
	for {
		rest = strings.TrimLeft(rest, " \t\r\n/")
		if rest == "" || rest == ">" {
			return out
		}
		eq := strings.IndexAny(rest, "= \t\r\n")
		if eq < 0 {
			out[strings.ToLower(rest)] = ""
			return out
		}
		name := strings.ToLower(rest[:eq])
		rest = rest[eq:]
		rest = strings.TrimLeft(rest, " \t\r\n")
		if !strings.HasPrefix(rest, "=") {
			out[name] = ""
			continue
		}
		rest = strings.TrimLeft(rest[1:], " \t\r\n")
		if rest == "" {
			out[name] = ""
			return out
		}
		switch rest[0] {
		case '"', '\'':
			q := rest[0]
			rest = rest[1:]
			end := strings.IndexByte(rest, q)
			if end < 0 {
				out[name] = rest
				return out
			}
			out[name] = rest[:end]
			rest = rest[end+1:]
		default:
			end := strings.IndexAny(rest, " \t\r\n>")
			if end < 0 {
				out[name] = rest
				return out
			}
			out[name] = rest[:end]
			rest = rest[end:]
		}
	}
}

// SHA256Hex hashes bytes.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// SRIValue is the integrity attribute value for a sha256 hash of b.
func SRIValue(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}
