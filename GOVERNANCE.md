# Governance

## Maintainer

Phillip Holland is the maintainer of this repository. The maintainer decides what lands on the default branch and what the project is called.

## License pledge

The core stays Apache-2.0. That includes `cmd/`, `internal/`, `watchers/`, `adapters/`, `detections/`, `drills/`, `rules/`, `profiles/` (except a third-party checklist an operator imports themselves), `bot/`, and the docs that ship with the tool.

A contribution that requires a CLA, a proprietary rider, or a move of the core to a different license will not be merged. There is no contributor license agreement. The Developer Certificate of Origin in [CONTRIBUTING.md](CONTRIBUTING.md) is the sign-off.

SEAL Framework text, if you add it locally, stays under CC BY-SA 4.0. It is not pulled into the Apache-2.0 grant by being mentioned here. See `profiles/custody-ops/seal/README.md`.

## Money

Creator-revenue only. The only intended income is the platform share from a Grok Bot that uses `bot/`. There is no hosted Sentinel, no paid signal pack, no paid support, and no paid compliance pack. Everyone self-hosts. Do not add a billing client, a license server, or a feature flag that unlocks code for a fee.

## What the maintainer will not do

- Claim prevention, FedRAMP authorization, or that the project secures an election.
- Brand the project as an "AI control plane."
- Merge offensive tooling. The ban in CONTRIBUTING.md is a governance rule, not a preference.
- Hold user keys or operate a wallet on a user's behalf.

## Decisions

Small fixes land when tests pass. A change to the scope gate, the ledger hash, the fail-closed statuses, or the "never send / never sign" rule needs a note in [THREAT_MODEL.md](THREAT_MODEL.md) in the same change. Those are the load-bearing promises.
