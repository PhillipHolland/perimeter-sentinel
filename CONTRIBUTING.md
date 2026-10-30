# Contributing

Perimeter Sentinel is Apache-2.0. Contributions are welcome under that license. There is no contributor license agreement. A Developer Certificate of Origin sign-off is required.

## Developer Certificate of Origin

Add this line to each commit message:

```
Signed-off-by: Your Name <you@example.com>
```

By adding it you certify the [Developer Certificate of Origin](https://developercertificate.org/) version 1.1.

## Offensive code is banned

Do not open a pull request that adds any of the following. Maintainers will close it.

- Exploit proof-of-concept code, weaponized payloads, or reproduction steps for a vulnerability.
- Malware, command-and-control, implants, or droppers.
- Credential testing, password spraying, or scanning of systems the operator has not declared and does not operate.
- Hack-back, counter-flooding, or any "active defense" against a third party.
- Instructions that tell a visiting agent, browser, or reader to download or run code. Tripwires alert and name a lane. They do not equip an agent.
- Code that holds a private key, seed phrase, or withdrawal credential, or that signs, builds, or broadcasts a transaction.
- Code that sends a freeze-desk message, posts in public, or contacts an undeclared host.

Detections describe a behavior and a blind spot. They do not describe how to perform the behavior. Synthetic fixtures in tests use reserved names (`example.com`, documentation addresses, fake transaction hashes).

## Review

`rules/`, `adapters/`, `detections/`, and `internal/approve/` need a careful read. v0.1 has one maintainer, named in [GOVERNANCE.md](GOVERNANCE.md). Two-reviewer branch protection is the intended bar once the project has a second reviewer. Until then, changes in those paths still need an explicit note in the commit message saying what enforcement they do not gain.

## Tests

`make test` must pass. New watcher behavior needs a fail-closed test: an error or a missing input returns `needs_human`, not an empty success. A new detection id needs a `detections/<id>.ads.yaml` record. `go test ./internal/ads` fails when the record and the code disagree.

## License header

New Go files start with:

```
// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0
```

Do not copy AGPL, GPL-3, FCL, or FoxIO code into the tree. Do not relicense SEAL Framework text. A pointer and an attribution are enough. See [NOTICE](NOTICE).
