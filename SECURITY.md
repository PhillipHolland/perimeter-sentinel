# Security policy

This file is about flaws in Perimeter Sentinel itself: the CLI, the ledger, the scope gate, the watchers, and the bot skills. It is not an incident channel for a site you operate. For that, use your own freeze roster.

## Reporting

Mail a description to the maintainer listed in [GOVERNANCE.md](GOVERNANCE.md). Until an age recipient is published in this file, do not encrypt to a key you found elsewhere and do not send a live secret.

There is no public age key yet. Generating one inside this repository would place a private key on disk, which this project refuses to do. A later release will publish a public recipient here after the maintainer generates it on a separate machine.

Include:

- The version (`perimeterctl version`) and the commit.
- What you observed, and what you expected the fail-closed behavior to be.
- Whether a scope check, a ledger verify, or a draft-send path was involved.

Do not include exploit payloads, weaponized reproduction, or a proof of concept that attacks a third party. Describe impact. A regression that turns an error into status `ok` is in scope and is the kind of bug to report first.

There is no bounty program and no paid support tier.

## What we will do

We will confirm receipt, fix the fail-closed behavior in the open tree, and credit the reporter unless they ask not to be named. We do not offer a hosted incident response.

## Hard lines that are also security bugs if broken

- A watcher that runs without `internal/scope`.
- An error path that returns `ok`.
- Any code path that signs, holds a key, moves funds, or calls a send or sign RPC method.
- A freeze path that sends a message.
- A tripwire body that tells a visitor to run code.
- An approval recorded by the scribe actor.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |
| anything else | no release yet |
