# Threat model

Perimeter Sentinel v0.1. This document assumes the Sentinel process, its host, and its ledger files are in the hands of someone who should not have them. Design choices below exist so that compromise of the console is not compromise of the site, the wallet, or the approval path.

The operator's CDN, WAF, bot manager, and identity provider enforce. Sentinel is an operator console across those vendors. It is not a bot detector and it is not in the request path.

## Assets

| Asset | What a compromise would mean |
|---|---|
| Scope file | The attacker learns which names you operate. They do not gain those names. |
| Ledger | The attacker can read history and, with filesystem access, can rewrite the file. A rewrite can recompute the hash chain. Rekor anchoring is not wired in v0.1. Treat the local chain as tamper-evident against accidents, not against a root user. |
| Freeze drafts | Unsent text. Sending still requires the human and a channel Sentinel does not hold. |
| Signer pin | A name of a repo, workflow, and ref. Not a signing key. |
| Pre-authorization book | Fingerprints and revocation paths. Secrets are rejected on write. |
| Bot memory | Must stay scrubbed: types, locations, fingerprints. Never seeds or keys. |

## Actors

- **Operator.** Declares scope, affirms `I operate these`, fills the roster, sends drafts, applies changes on their own systems.
- **Incident commander.** A human with an out-of-band channel. Sentinel cannot occupy this role. Names equal to "sentinel" or "perimeter sentinel" are refused.
- **Scribe.** The Sentinel process. It records. It does not command.
- **Compromised Sentinel.** Can forge local ledger lines, draft misleading text, and propose bad diffs. Cannot sign, cannot approve, cannot apply an edge rule, cannot move funds.
- **Compromised vendor script or signing path.** Out of Sentinel's enforcement power. The console's job is to notice sooner and to have the freeze desk already rehearsed.

## Trust boundaries

1. Observation files and `--live` fetches. Live fetch is GET or HEAD of a declared page, or of a script that page referenced, or POST to a declared RPC URL. Other methods and other hosts are denied. Redirects stay on the same host and are checked again.
2. External text (posts, pages, CSP reports) is data. It is not an instruction to the operator or to the bot.
3. RPC is read-only. Allowed methods are `eth_chainId`, `eth_getBalance`, `eth_getCode`, and `eth_getTransactionCount`. `eth_sendRawTransaction`, `personal_sign`, and `eth_sign` are refused before a request is built.
4. Approvals. Two distinct human fingerprints are required for the receipt shape. A fingerprint of `sentinel`, `perimeterctl`, or `perimeter-sentinel` is refused. v0.1 does not verify a signature, so a well-shaped receipt is still `needs_human` and is not authorization to apply.
5. Tripwire body. The marker is a fixed string. Caller input is ignored. The body does not tell a visiting agent to fetch or run code. A hit advises the quarantine lane. The edge would enforce that lane. v0.1 does not push the lane.

## STRIDE on the control plane

| Threat | What we do |
|---|---|
| Spoofing | Scope is deny-by-default. DNS TXT at `_perimeter-sentinel.<host>` binds a name to a token this home generated. Wallets are attested by a human statement, and briefs say that attestation is not cryptographic. Non-ASCII hosts are refused so a lookalike cannot sneak in as Unicode. |
| Tampering | Ledger lines are canonical JSON hashed with SHA-256 over `actor`, `payload`, `prev`, `seq`, `ts`, `type`. Genesis previous hash is 64 zero hex digits. Verify fails on a flipped byte or a deleted middle line. Append refuses to extend a broken chain. A full-file rewrite by someone who can write the file can still recompute links. Say that in the brief's gaps until Rekor is real. |
| Repudiation | Freeze start, contain, watcher results, and human approval receipts are ledger events. The stopwatch stores time-to-notice and time-to-contain. The KPI sentence says the comparison is not prevention. |
| Information disclosure | Home directory `0700`, files `0600`. The secrets filter rejects PEM private keys, blocked field names, and 12- or 24-word lowercase seed phrases. Fingerprints and transaction hashes are allowed. |
| Denial of service | Sentinel is out of band. Stopping it does not stop the site. Watchers fail closed under error rather than retrying into a third party. |
| Elevation | Event types `tx.signed`, `tx.broadcast`, `freeze.execute`, and `approval.granted` are refused for every actor. The scribe actor cannot append any `approval.*` type. `envelopes.Execute` returns an error. `cards.Approve` returns an error. `edgerules.Apply` returns an error. `flags.Apply` returns an error and does not call a vendor. |

## What "assume Sentinel is compromised" changes

- Human approval keys, if they exist later, live on the operator's device. This process never holds them.
- The default later apply path is a pull request the operator merges. v0.1 only renders the body (`adapters/gitops-pr`).
- A freeze without out-of-band confirmation does not start the stopwatch.
- Draft templates tell the reader that Sentinel does not send.
- Civic behavioral telemetry cannot be turned on. A verified-agent lane does not relax fraud checks. Identity is not intent.
- Traffic lanes (`human`, `verified-agent`, `declared-automation`, `unknown-automation`, `quarantine`) are names for a policy the edge already has. Assigning a lane in this process sets `Apply` to false.

## What the world sees

Served JavaScript is hashed and compared with the signed build manifest. A match with an empty signer pin is `needs_human`, because a signature from an unknown workflow is not a reason to call the page safe. Third-party scripts on a page that touches a session or a signing path are inventory, not a trusted dependency. PCI DSS v4.0.1 requirements 6.4.3 and 11.6.1 are the evidence shape a QSA may read. This project does not make the compliance determination.

## Oct 29 failure modes the drills cover

Facts below are provisional. They are clock comparisons for drills. They are not a finding about any vendor's root cause.

- **Vendor script on an authenticated page (Polymarket, 29 October 2026).** Public reconstructions put the first victim post near 35 minutes and cancel-only near 55 minutes. The v0.1 drill pages on a hash change within one probe interval, names the vendor, and opens the `vendor-script-compromise` envelope as a checklist. The operator's edge would deny the origin. Sentinel does not.
- **Hot-wallet signing path (Binance, 29 October 2026).** Root cause is undisclosed. An EIP-7702 delegation was reported on the execution path and is not established as the cause. Issuer freezes were reported near 24 minutes (USDC) and 37 minutes (USDT). The drill treats a delegation designator (`0xef0100` plus a 20-byte address) on a declared testnet wallet as tier-0, and it prefills issuer drafts with the address and the transaction hash the operator supplied. Sentinel does not build or send that transaction.

## Out of scope for the threat model

Visitor exploit development, third-party credential testing, and any action on a system the operator does not run. Those are banned in [CONTRIBUTING.md](CONTRIBUTING.md), not merely deferred.
