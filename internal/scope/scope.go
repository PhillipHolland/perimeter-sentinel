// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package scope is the deny-by-default gate. Every watcher calls Check before
// it reads an asset. A target that was not declared and affirmed is refused.
// Refusal is not an all-clear.
package scope

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/state"
)

// Kind is the class of declared asset.
type Kind string

const (
	KindDNS    Kind = "dns"
	KindHTTPS  Kind = "https"
	KindPage   Kind = "page"
	KindWallet Kind = "wallet"
	KindRPC    Kind = "rpc"
)

const Affirmation = "I operate these"

// TXTPrefix is the DNS label the operator publishes.
const TXTPrefix = "_perimeter-sentinel."

// TXTMarker is the left-hand side of the verification record.
const TXTMarker = "perimeter-sentinel-verify="

// Asset is one thing the operator says they run.
type Asset struct {
	Kind       Kind      `json:"kind"`
	Name       string    `json:"name"`
	Note       string    `json:"note,omitempty"`
	Verified   bool      `json:"verified"`
	VerifyBy   string    `json:"verify_by,omitempty"`
	TXTToken   string    `json:"txt_token,omitempty"`
	VerifiedAt time.Time `json:"verified_at,omitempty"`
	// Page flags. A page that loads vendor script beside a session is red.
	TouchesSession bool `json:"touches_session,omitempty"`
	TouchesSigning bool `json:"touches_signing,omitempty"`
	PaymentPage    bool `json:"payment_page,omitempty"`
}

// File is the scope document.
type File struct {
	Owner       string    `json:"owner"`
	Affirmation string    `json:"affirmation,omitempty"`
	AffirmedAt  time.Time `json:"affirmed_at,omitempty"`
	Assets      []Asset   `json:"assets"`
}

// Store loads and saves scope.json.
type Store struct {
	Path string
	Data File
}

func Load(path string) (*Store, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("scope: %w", err)
	}
	return &Store{Path: path, Data: f}, nil
}

func (s *Store) Save() error {
	b, err := json.MarshalIndent(s.Data, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp := s.Path + ".tmp"
	if err := os.MkdirAll(dirOf(s.Path), state.DirPerm); err != nil {
		return err
	}
	if err := os.WriteFile(tmp, b, state.FilePerm); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path)
}

func dirOf(path string) string {
	i := strings.LastIndex(path, string(os.PathSeparator))
	if i <= 0 {
		return "."
	}
	return path[:i]
}

// Affirmed reports whether the owner has said they operate this scope.
func (s *Store) Affirmed() bool {
	return s != nil && s.Data.Affirmation == Affirmation && strings.TrimSpace(s.Data.Owner) != ""
}

// DenyError is a hard refusal. Watchers turn it into needs_human.
type DenyError struct {
	Target string
	Reason string
}

func (e *DenyError) Error() string {
	return "scope deny: " + e.Target + ": " + e.Reason
}

// Check refuses anything not declared. Verification is a separate, stricter
// gate for live network calls (see RequireVerified).
func (s *Store) Check(kind Kind, name string) error {
	norm, err := Normalize(kind, name)
	if err != nil {
		return &DenyError{Target: name, Reason: err.Error()}
	}
	if s == nil {
		return &DenyError{Target: norm, Reason: "scope is not loaded"}
	}
	if !s.Affirmed() {
		return &DenyError{Target: norm, Reason: "owner has not affirmed \"I operate these\""}
	}
	if _, ok := s.lookup(kind, norm); !ok {
		return &DenyError{Target: norm, Reason: "not in the declared scope (deny by default)"}
	}
	return nil
}

// RequireVerified is the live-network gate. Fixture replay still uses Check.
func (s *Store) RequireVerified(kind Kind, name string) error {
	if err := s.Check(kind, name); err != nil {
		return err
	}
	norm, err := Normalize(kind, name)
	if err != nil {
		return &DenyError{Target: name, Reason: err.Error()}
	}
	a, _ := s.lookup(kind, norm)
	if !a.Verified {
		return &DenyError{Target: norm, Reason: "ownership is not verified; live checks stay closed"}
	}
	return nil
}

func (s *Store) lookup(kind Kind, norm string) (Asset, bool) {
	for _, a := range s.Data.Assets {
		if a.Kind == kind && a.Name == norm {
			return a, true
		}
	}
	return Asset{}, false
}

// Get returns the declared asset.
func (s *Store) Get(kind Kind, name string) (Asset, error) {
	norm, err := Normalize(kind, name)
	if err != nil {
		return Asset{}, err
	}
	a, ok := s.lookup(kind, norm)
	if !ok {
		return Asset{}, &DenyError{Target: norm, Reason: "not in the declared scope (deny by default)"}
	}
	return a, nil
}

// Add declares an asset and returns it. Tokens are generated for DNS-verifiable kinds.
func (s *Store) Add(kind Kind, name, note string, session, signing, payment bool) (Asset, error) {
	norm, err := Normalize(kind, name)
	if err != nil {
		return Asset{}, err
	}
	if _, ok := s.lookup(kind, norm); ok {
		return Asset{}, fmt.Errorf("already in scope: %s %s", kind, norm)
	}
	a := Asset{
		Kind:           kind,
		Name:           norm,
		Note:           note,
		TouchesSession: session,
		TouchesSigning: signing,
		PaymentPage:    payment,
	}
	if kind == KindDNS || kind == KindHTTPS || kind == KindPage || kind == KindRPC {
		tok, err := newToken()
		if err != nil {
			return Asset{}, err
		}
		a.TXTToken = tok
	}
	s.Data.Assets = append(s.Data.Assets, a)
	return a, nil
}

// Affirm records the owner statement. Any other statement is refused.
func (s *Store) Affirm(owner, statement string, now time.Time) error {
	if strings.TrimSpace(owner) == "" {
		return errors.New("owner is required")
	}
	if statement != Affirmation {
		return fmt.Errorf("affirmation must be exactly %q", Affirmation)
	}
	s.Data.Owner = owner
	s.Data.Affirmation = statement
	s.Data.AffirmedAt = now.UTC()
	return nil
}

// Resolver looks up TXT records. Tests inject a fake. Live code uses net.Resolver.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// NetResolver adapts net.Resolver.
type NetResolver struct{ R *net.Resolver }

func (n NetResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	r := n.R
	if r == nil {
		r = net.DefaultResolver
	}
	return r.LookupTXT(ctx, name)
}

// VerifyDNS checks the operator-published TXT record and marks the asset verified.
// Wallet assets cannot be verified this way: Sentinel must not ask the operator to sign.
func (s *Store) VerifyDNS(ctx context.Context, kind Kind, name string, r Resolver, now time.Time) (Asset, error) {
	if kind == KindWallet {
		return Asset{}, errors.New("wallets are operator-attested; sentinel does not request a signature")
	}
	norm, err := Normalize(kind, name)
	if err != nil {
		return Asset{}, err
	}
	idx := -1
	for i, a := range s.Data.Assets {
		if a.Kind == kind && a.Name == norm {
			idx = i
			break
		}
	}
	if idx < 0 {
		return Asset{}, &DenyError{Target: norm, Reason: "not in the declared scope (deny by default)"}
	}
	if r == nil {
		return Asset{}, errors.New("dns resolver is not configured")
	}
	host := hostFor(kind, norm)
	qname := TXTPrefix + host
	txts, err := r.LookupTXT(ctx, qname)
	if err != nil {
		return Asset{}, fmt.Errorf("txt lookup %s: %w", qname, err)
	}
	want := TXTMarker + s.Data.Assets[idx].TXTToken
	ok := false
	for _, t := range txts {
		if strings.TrimSpace(t) == want {
			ok = true
			break
		}
	}
	if !ok {
		return Asset{}, fmt.Errorf("txt record at %s does not match the scope token", qname)
	}
	s.Data.Assets[idx].Verified = true
	s.Data.Assets[idx].VerifyBy = "dns-txt"
	s.Data.Assets[idx].VerifiedAt = now.UTC()
	return s.Data.Assets[idx], nil
}

// AttestWallet records a second human affirmation for a wallet.
// This is not cryptographic proof. Briefs must say so.
func (s *Store) AttestWallet(name, statement string, now time.Time) (Asset, error) {
	if statement != Affirmation {
		return Asset{}, fmt.Errorf("affirmation must be exactly %q", Affirmation)
	}
	norm, err := Normalize(KindWallet, name)
	if err != nil {
		return Asset{}, err
	}
	for i, a := range s.Data.Assets {
		if a.Kind == KindWallet && a.Name == norm {
			s.Data.Assets[i].Verified = true
			s.Data.Assets[i].VerifyBy = "operator-attestation"
			s.Data.Assets[i].VerifiedAt = now.UTC()
			return s.Data.Assets[i], nil
		}
	}
	return Asset{}, &DenyError{Target: norm, Reason: "not in the declared scope (deny by default)"}
}

func hostFor(kind Kind, norm string) string {
	switch kind {
	case KindPage, KindRPC:
		u, err := url.Parse(norm)
		if err != nil {
			return norm
		}
		return u.Hostname()
	default:
		return norm
	}
}

// Normalize applies the deny-by-default name rules.
func Normalize(kind Kind, name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("name is empty")
	}
	if strings.Contains(name, "://") && kind != KindPage && kind != KindRPC {
		return "", errors.New("pass a host, not a URL, for this kind")
	}
	switch kind {
	case KindDNS, KindHTTPS:
		return normalizeHost(name)
	case KindPage, KindRPC:
		return normalizeURL(kind, name)
	case KindWallet:
		return normalizeWallet(name)
	default:
		return "", fmt.Errorf("unknown kind %q", kind)
	}
}

func normalizeHost(name string) (string, error) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if _, _, err := net.SplitHostPort(name); err == nil {
		return "", errors.New("do not include a port")
	}
	if strings.Contains(name, "/") || strings.Contains(name, " ") || strings.Contains(name, "@") {
		return "", errors.New("host contains illegal characters")
	}
	if err := asciiHost(name); err != nil {
		return "", err
	}
	if name == "localhost" {
		return name, nil
	}
	if ip := net.ParseIP(name); ip != nil {
		return "", errors.New("bare IP addresses are not a scope name; declare the hostname you operate")
	}
	if !strings.Contains(name, ".") {
		return "", errors.New("host must be a fully qualified name")
	}
	return name, nil
}

func asciiHost(name string) error {
	for _, r := range name {
		if r > unicode.MaxASCII {
			return errors.New("enter the punycode (ACE) form; non-ASCII names are refused")
		}
	}
	return nil
}

func normalizeURL(kind Kind, name string) (string, error) {
	u, err := url.Parse(name)
	if err != nil {
		return "", fmt.Errorf("url: %w", err)
	}
	if u.User != nil {
		return "", errors.New("urls with userinfo are refused")
	}
	if u.Fragment != "" {
		return "", errors.New("strip the fragment before declaring the url")
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if err := asciiHost(host); err != nil {
		return "", err
	}
	if host == "" {
		return "", errors.New("url has no host")
	}
	switch scheme {
	case "https":
	case "http":
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			return "", errors.New("http is allowed only for localhost fixtures")
		}
	default:
		return "", fmt.Errorf("scheme %q is refused", u.Scheme)
	}
	if kind == KindRPC && u.Path == "" {
		u.Path = "/"
	}
	u.Scheme = scheme
	u.Host = strings.ToLower(u.Host)
	return u.String(), nil
}

func normalizeWallet(name string) (string, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	if !strings.HasPrefix(n, "0x") || len(n) != 42 {
		return "", errors.New("wallet must be 0x plus 40 hex characters")
	}
	for _, r := range n[2:] {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return "", errors.New("wallet must be 0x plus 40 hex characters")
		}
	}
	return n, nil
}

func newToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// AllowReferenced permits a GET of a script or stylesheet URL only because an
// in-scope page referenced it. The script host is not added to scope and is
// not a license to probe arbitrary third parties.
func (s *Store) AllowReferenced(pageKind Kind, pageName, resource string) error {
	if err := s.Check(pageKind, pageName); err != nil {
		return err
	}
	if strings.TrimSpace(resource) == "" {
		return &DenyError{Target: resource, Reason: "empty referenced url"}
	}
	u, err := url.Parse(resource)
	if err != nil {
		return &DenyError{Target: resource, Reason: "referenced url did not parse"}
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost")) {
		return &DenyError{Target: resource, Reason: "referenced url scheme is refused"}
	}
	if u.User != nil {
		return &DenyError{Target: resource, Reason: "referenced url userinfo is refused"}
	}
	return nil
}
