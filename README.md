# Perimeter Sentinel

Perimeter Sentinel is an open-source operator console for a live site you run. The CLI is `perimeterctl`. It watches assets you declare, keeps a hash-chained evidence ledger, and drafts freeze checklists a human sends. Your CDN, WAF, and identity provider still enforce. Sentinel is out of band. If this process stops, the site keeps the last policy you applied yourself.

Version 0.1.0. License [Apache-2.0](LICENSE). Creator-revenue only: the code is free to run and to modify. There is no hosted service, no paid pack, and no support contract.

## What it is for

Four verbs:

1. **See** what you declared: DNS names, certificates, pages, scripts, wallets, and outstanding authority.
2. **Notice** drift and behavior: served JavaScript against a signed build, vendor-script hashes, brand-plus-alert posts you supply, and read-only chain observations.
3. **Propose** a change card. v0.1 renders the text. It does not open the pull request and it cannot approve the card.
4. **Freeze** with a rehearsed playbook, a stopwatch, and drafts. You execute. Sentinel times the clock.

The comparison points for v0.1 are the 29 October 2026 Polymarket and Binance failure modes, as drills on synthetic fixtures. Those clocks are provisional. Beating one is a comparison, not prevention. Details are in [PRODUCT.md](PRODUCT.md) §0 and [THREAT_MODEL.md](THREAT_MODEL.md).

## What it does not do

- It does not prevent incidents, replace a WAF, or sit inline on a request.
- It does not hold keys, sign, move funds, or construct transactions.
- It does not scan, probe, or contact systems you have not declared.
- It does not send email, file a report, or post in public. Drafts stay `sent: false`.
- It does not decide fraud, eligibility, or election content.
- It is not FedRAMP authorized. There is no hosted offering for an authorization to cover. A self-hosted copy sits inside the operator's own boundary.
- It does not claim to "secure the election." The civic profile is availability and integrity of pages the office operates.

Errors, missing files, and blind telemetry become `needs_human`. That status is not an all-clear. Exit codes: `0` ok, `1` usage, `2` finding, `3` needs-human.

## Five-minute demo

`perimeterctl demo script-drift --home ./demo-home` serves a local origin on `127.0.0.1` only. It flips a fixture script, records a `finding` for `demo-vendor`, and writes a freeze draft whose first line is `SENT: false`. Notice is not prevention. The draft is unsent. Nothing is applied at an edge, and the command does not claim the site is safe. `time-to-contain` stays open unless you pass `--mark-contain`.

## Quickstart

Requires Go 1.22 or newer.

```bash
go build -o bin/perimeterctl ./cmd/perimeterctl

./bin/perimeterctl --home ./.perimeter init \
  --owner "Example Operator" --profile enterprise \
  --timezone America/Chicago --appetite low

./bin/perimeterctl --home ./.perimeter scope affirm --statement "I operate these"
./bin/perimeterctl --home ./.perimeter roster set \
  --role incident-commander --name "Example Operator" --oob voice
./bin/perimeterctl --home ./.perimeter scope add --kind dns --name example.com
./bin/perimeterctl --home ./.perimeter scope list

./bin/perimeterctl --home ./.perimeter ledger append \
  --type note --actor operator --payload '{"text":"quickstart"}'
./bin/perimeterctl --home ./.perimeter ledger verify

./bin/perimeterctl --home ./.perimeter brief || true
./bin/perimeterctl --home ./.perimeter freeze list
./bin/perimeterctl --home ./.perimeter drill list
./bin/perimeterctl --home ./.perimeter drill run
```

`brief` exits 3 after a fresh init. Log sources start absent, and the signer pin is empty. The brief still prints. Read the blind spots. `drill run` uses a throwaway home and synthetic fixtures. It does not touch the network.

`PERIMETER_HOME` is the same switch as `--home`. The default home is `./.perimeter` (mode `0700`, files `0600`).

Declare a name, then publish the TXT record `perimeterctl scope list` prints at `_perimeter-sentinel.<host>` before `--live` verification will pass. Wallets are operator-attested. Attestation is not a signature, and the brief says so.

Page and chain watches read observation files unless you pass `--live`. Default commands in tests never dial a network.

```bash
./bin/perimeterctl --home ./.perimeter watch dns \
  --name example.com --desired desired.json --observation observed.json
```

A missing observation is `needs_human`.

## Oct 29 drills

`perimeterctl drill run` checks five synthetic drills from PRODUCT.md §0.3:

| Drill | Bar |
|---|---|
| `oct29-vendor-script` | Vendor script hash change, vendor named, notice ≤ 5 min, envelope `vendor-script-compromise` |
| `oct29-external-signal` | Brand plus "drained", notice ≤ 2 min |
| `oct29-delegation` | Testnet code delegation, tier-0 notice ≤ 60 s, issuer drafts prefilled and unsent |
| `oct29-ledger-stopwatch` | Alerts, a human approval receipt, freeze start and contain, chain verifies |
| `oct29-no-keys` | No key material, no send or sign RPC, no envelope execution |

Probe defaults are inside those bars: page probes `1m`, intake `1m`, on-chain `30s`. A looser interval is a blind spot in the brief.

## Layout

`cmd/perimeterctl` is the binary. `internal/scope` is deny-by-default. Every watcher calls it. `internal/ledger` is a hash-chained JSONL log. `internal/freeze` holds the two v0.1 playbooks. `watchers/` collectors are read-only. `drills/oct29` is the acceptance test. `detections/*.ads.yaml` is one record per detection id. `bot/skills` is the Grok Bot copy of the same rules. `freeze-desk/` is the roster schema and draft templates.

## Develop

```bash
make test
make ci
```

`make ci` runs `go test ./...`, `go vet`, the license gate, and a secret scan. The license gate refuses AGPL, GPL-3, FCL, FoxIO, Unleash, Flipt, and the other modules named in [NOTICE](NOTICE) if they show up as imports. Copyleft tools, when an operator wants them later, run as separate processes. They are not linked into this binary.

## Known gaps in v0.1

- No live Cloudflare, Fastly, or X API client. Interfaces and file fixtures only.
- Ledger export is Markdown. There is no PDF writer.
- Rekor is a config field. This version does not submit or query it.
- Cosign and SLSA are release policy, not a CI job that signs.
- Certificate Transparency reads JSON you supply. It does not shell out to certspotter.
- Multi-region probes are vantage labels on fixtures.
- No age key is published. Do not send a secret to the address in SECURITY.md until one is.
- `policy/*.rego` mirrors `internal/policy`. OPA is not executed.
- Kill switches record intent locally. `flags.Apply` does not call a vendor.
- Envelopes and change cards do not execute and do not approve.
- gitleaks runs when it is installed. Otherwise CI uses the pattern scan in `ci/secret-scan.sh`.

## Further reading

- [THREAT_MODEL.md](THREAT_MODEL.md) — assume this program is compromised.
- [SECURITY.md](SECURITY.md) — how to report a flaw in Sentinel itself.
- [CONTRIBUTING.md](CONTRIBUTING.md) — DCO, and the ban on offensive code.
- [GOVERNANCE.md](GOVERNANCE.md) — maintainers, Apache-2.0 stays.
- [TRADEMARKS.md](TRADEMARKS.md) — the name is not cleared.
- [docs/school/README.md](docs/school/README.md) — the ten lessons as product behavior.
