// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package onchain is a read-only watcher for wallets the operator declared.
//
// It alerts on a code or delegation change (tier-0), a limit breach, or a
// destination the operator has not listed. EIP-7702 delegation, when present,
// shows up as the published account-code prefix 0xef0100 plus an address.
// Detecting that prefix is a read of public chain state. This package does
// not build, sign, or broadcast a transaction, and it has no key field.
//
// The Oct 29, 2026 Binance failure mode is the drill: a hot wallet's
// delegation changed, and issuer freezes were the containment that existed.
// Root cause is undisclosed. The watcher does not assume one.
package onchain

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/egress"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/govern"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/scope"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/state"
)

// AllowedMethods are the only JSON-RPC methods this process will encode.
var AllowedMethods = map[string]bool{
	"eth_chainId":             true,
	"eth_getBalance":          true,
	"eth_getCode":             true,
	"eth_getTransactionCount": true,
}

// Transfer is an operator-supplied observation of an outgoing movement.
// The read-only RPC surface above does not enumerate history.
type Transfer struct {
	To       string    `json:"to"`
	ValueWei string    `json:"value_wei"`
	TxHash   string    `json:"tx_hash"`
	At       time.Time `json:"at"`
}

// Declaration is the operator's record of one hot wallet.
type Declaration struct {
	Address           string   `json:"address"`
	Chain             string   `json:"chain"`
	Tier              string   `json:"tier"`
	LimitWei          string   `json:"limit_wei"`
	KnownDestinations []string `json:"known_destinations,omitempty"`
	KnownCode         string   `json:"known_code"`
	KnownDelegation   string   `json:"known_delegation,omitempty"`
}

// Observation is one read.
type Observation struct {
	Code      string     `json:"code"`
	Balance   string     `json:"balance_wei,omitempty"`
	Transfers []Transfer `json:"transfers,omitempty"`
	Error     string     `json:"error,omitempty"`
	At        time.Time  `json:"at"`
}

// Reader is the read-only RPC surface. There is no Send and no Sign.
type Reader interface {
	GetCode(ctx context.Context, address string) (string, error)
	GetBalance(ctx context.Context, address string) (string, error)
	GetTransactionCount(ctx context.Context, address string) (uint64, error)
}

// Inspect compares a declaration to an observation.
func Inspect(cfg state.Config, sc *scope.Store, ros state.Roster, decl Declaration, obs Observation, changedAt time.Time) failsafe.Result {
	const watcher = "onchain"
	if res, ok := govern.Result(watcher, govern.Ready(cfg, sc, ros, scope.KindWallet, decl.Address)); !ok {
		return res
	}
	if obs.Error != "" {
		return failsafe.NeedsHuman(watcher, "read-only chain read failed", errors.New(obs.Error))
	}
	var findings []failsafe.Finding
	var blind []string
	code := strings.ToLower(strings.TrimSpace(obs.Code))
	if code == "" {
		return failsafe.NeedsHuman(watcher, "empty code reply; refusing to treat the wallet as unchanged", errors.New("empty code"))
	}
	deleg, hasDel := DelegationTarget(code)
	knownDel := strings.ToLower(strings.TrimSpace(decl.KnownDelegation))
	if hasDel && deleg != knownDel {
		f := tier0("delegation-change", "Declared wallet code shows a new or changed delegation", decl)
		f.Evidence = append(f.Evidence,
			failsafe.Evidence{Key: "delegation", Value: deleg},
			failsafe.Evidence{Key: "previous_delegation", Value: knownDel},
		)
		findings = append(findings, stamp(f, obs.At, changedAt))
	}
	knownCode := strings.ToLower(strings.TrimSpace(decl.KnownCode))
	if knownCode == "" {
		knownCode = "0x"
	}
	if !sameCode(code, knownCode) && !(hasDel && knownDel != "" && deleg == knownDel && code == delegationCode(knownDel)) {
		// A delegation-only change is already tier-0 above. A different code
		// body is its own tier-0, including the first time a designator appears
		// when known code was 0x.
		if !(hasDel && deleg != knownDel) {
			f := tier0("code-change", "Declared wallet code changed", decl)
			f.Evidence = append(f.Evidence, failsafe.Evidence{Key: "code", Value: trim(code)})
			findings = append(findings, stamp(f, obs.At, changedAt))
		}
	}
	if len(obs.Transfers) == 0 {
		blind = append(blind, "no outgoing-transfer observation; limit and new-destination checks are blind on this pass")
	}
	limit, limitOK := new(big.Int).SetString(strings.TrimSpace(decl.LimitWei), 10)
	if strings.TrimSpace(decl.LimitWei) == "" || !limitOK {
		blind = append(blind, "no decimal wei limit declared")
	}
	var sum big.Int
	for _, tr := range obs.Transfers {
		val, ok := new(big.Int).SetString(strings.TrimSpace(tr.ValueWei), 10)
		if !ok {
			return failsafe.NeedsHuman(watcher, "transfer value is not decimal wei", fmt.Errorf("bad value"))
		}
		sum.Add(&sum, val)
		dest := strings.ToLower(tr.To)
		if !knownDest(decl.KnownDestinations, dest) {
			f := tier0("new-destination", "Outgoing transfer to a destination that is not on the declared list", decl)
			f.Detection = "det-wallet-new-destination"
			f.Evidence = append(f.Evidence,
				failsafe.Evidence{Key: "to", Value: dest},
				failsafe.Evidence{Key: "tx_hash", Value: tr.TxHash},
				failsafe.Evidence{Key: "value_wei", Value: tr.ValueWei},
			)
			findings = append(findings, stamp(f, obs.At, changedAt))
		}
		if limitOK && val.Cmp(limit) > 0 {
			f := tier0("limit-breach", "A single outgoing value exceeds the declared limit", decl)
			f.Detection = "det-wallet-limit"
			f.Evidence = append(f.Evidence,
				failsafe.Evidence{Key: "value_wei", Value: tr.ValueWei},
				failsafe.Evidence{Key: "limit_wei", Value: decl.LimitWei},
				failsafe.Evidence{Key: "tx_hash", Value: tr.TxHash},
			)
			findings = append(findings, stamp(f, obs.At, changedAt))
		}
	}
	if limitOK && sum.Sign() > 0 && sum.Cmp(limit) > 0 {
		f := tier0("limit-breach-sum", "Sum of observed outgoing value exceeds the declared limit", decl)
		f.Detection = "det-wallet-limit"
		f.Evidence = append(f.Evidence, failsafe.Evidence{Key: "sum_wei", Value: sum.String()})
		findings = append(findings, stamp(f, obs.At, changedAt))
	}
	if len(findings) == 0 {
		return failsafe.JustOK(watcher, "declared wallet code matches and no listed transfer broke a rule").WithBlind(blind)
	}
	res := failsafe.FromFindings(watcher, "tier-0 wallet watch needs a human", findings, blind)
	res.Lesson = "L8 signing path is part of the key"
	return res
}

func stamp(f failsafe.Finding, observed, changed time.Time) failsafe.Finding {
	if !observed.IsZero() && !changed.IsZero() && !observed.Before(changed) {
		f.Evidence = append(f.Evidence, failsafe.Evidence{
			Key: "notice_seconds", Value: fmt.Sprintf("%d", int64(observed.Sub(changed).Seconds())),
		})
	}
	return f
}

func tier0(id, title string, decl Declaration) failsafe.Finding {
	return failsafe.Finding{
		ID: id, Watcher: "onchain", Title: title, Summary: title,
		CIA: "integrity", Attack: "T1078", Lesson: "L8 signing path is part of the key",
		Severity: "tier-0", Asset: decl.Address, Detection: "det-wallet-delegation",
		Envelope: "hot-wallet-drain",
		Evidence: []failsafe.Evidence{
			{Key: "chain", Value: decl.Chain},
			{Key: "tier", Value: decl.Tier},
			{Key: "address", Value: decl.Address},
		},
	}
}

func knownDest(list []string, dest string) bool {
	for _, d := range list {
		if strings.ToLower(strings.TrimSpace(d)) == dest {
			return true
		}
	}
	return false
}

func sameCode(a, b string) bool {
	return strings.TrimPrefix(strings.ToLower(a), "0x") == strings.TrimPrefix(strings.ToLower(b), "0x")
}

func trim(code string) string {
	if len(code) > 80 {
		return code[:80] + "…"
	}
	return code
}

// DelegationTarget returns the address encoded by an EIP-7702 delegation
// designator. Other code returns false. This does not construct an authorization.
func DelegationTarget(code string) (string, bool) {
	c := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(code)), "0x")
	if !strings.HasPrefix(c, "ef0100") || len(c) < 6+40 {
		return "", false
	}
	addr := "0x" + c[6:46]
	for _, r := range addr[2:] {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return "", false
		}
	}
	return addr, true
}

func delegationCode(addr string) string {
	a := strings.TrimPrefix(strings.ToLower(addr), "0x")
	return "0xef0100" + a
}

// Client is a read-only JSON-RPC caller. URL must be a declared rpc asset.
type Client struct {
	URL   string
	HTTP  *http.Client
	Scope *scope.Store
}

// Call encodes one allowed method. Forbidden methods are refused locally and
// produce no request.
func (c *Client) Call(ctx context.Context, method string, params []any) (json.RawMessage, error) {
	if !AllowedMethods[method] {
		return nil, fmt.Errorf("rpc method refused: %s", method)
	}
	if c.Scope == nil {
		return nil, errors.New("rpc client has no scope gate")
	}
	if err := egress.Require(c.Scope, "POST", c.URL, ""); err != nil {
		return nil, err
	}
	if err := c.Scope.RequireVerified(scope.KindRPC, c.URL); err != nil {
		return nil, err
	}
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	})
	if err != nil {
		return nil, err
	}
	httpc := c.HTTP
	if httpc == nil {
		httpc = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("rpc status %d", resp.StatusCode)
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	if envelope.Error != nil {
		return nil, errors.New(envelope.Error.Message)
	}
	return envelope.Result, nil
}

func (c *Client) GetCode(ctx context.Context, address string) (string, error) {
	raw, err := c.Call(ctx, "eth_getCode", []any{address, "latest"})
	if err != nil {
		return "", err
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", err
	}
	return s, nil
}

func (c *Client) GetBalance(ctx context.Context, address string) (string, error) {
	raw, err := c.Call(ctx, "eth_getBalance", []any{address, "latest"})
	if err != nil {
		return "", err
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", err
	}
	return s, nil
}

func (c *Client) GetTransactionCount(ctx context.Context, address string) (uint64, error) {
	raw, err := c.Call(ctx, "eth_getTransactionCount", []any{address, "latest"})
	if err != nil {
		return 0, err
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return 0, err
	}
	n := new(big.Int)
	if _, ok := n.SetString(strings.TrimPrefix(s, "0x"), 16); !ok {
		return 0, fmt.Errorf("bad nonce")
	}
	return n.Uint64(), nil
}

// Fake is an in-memory reader for drills. It has no key material.
type Fake struct {
	Code    map[string]string
	Balance map[string]string
	Nonce   map[string]uint64
	Err     error
}

func (f Fake) GetCode(_ context.Context, address string) (string, error) {
	if f.Err != nil {
		return "", f.Err
	}
	v, ok := f.Code[strings.ToLower(address)]
	if !ok {
		return "0x", nil
	}
	return v, nil
}

func (f Fake) GetBalance(_ context.Context, address string) (string, error) {
	if f.Err != nil {
		return "", f.Err
	}
	if f.Balance == nil {
		return "0x0", nil
	}
	v, ok := f.Balance[strings.ToLower(address)]
	if !ok {
		return "0x0", nil
	}
	return v, nil
}

func (f Fake) GetTransactionCount(_ context.Context, address string) (uint64, error) {
	if f.Err != nil {
		return 0, f.Err
	}
	return f.Nonce[strings.ToLower(address)], nil
}

// Observe reads code through a Reader and keeps transfers from the caller.
// Transfers are not fetched by this client.
func Observe(ctx context.Context, r Reader, address string, transfers []Transfer, at time.Time) Observation {
	code, err := r.GetCode(ctx, address)
	if err != nil {
		return Observation{Error: err.Error(), At: at, Transfers: transfers}
	}
	return Observation{Code: code, Transfers: transfers, At: at}
}
