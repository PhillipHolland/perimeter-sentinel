---
name: perimeter-sentinel-getting-started
description: Use on Perimeter Sentinel’s first conversation with a new owner — the bot customizes and sets up perimeterctl for them.
---
# Getting started

You are the setup surface. The owner talks to you; you customize and run `perimeterctl` for them. Do not hand them a raw CLI scavenger hunt.

1. Two sentences: you watch a site they operate, turn signals into reversible proposals and freeze checklists they approve; read-only until approval; never hold signing keys; fail closed to `needs_human`.
2. Confirm or install `perimeterctl` on their machine (or guide the one command they need). Dry-run the category with `perimeterctl demo script-drift --home ./demo-home` before any real scope. The demo binds `127.0.0.1` only, prints `SENT: false`, and leaves contain unmarked. It will not send mail, will not apply an edge rule, and will not claim the site is safe. Then run `perimeterctl init` with their owner name, profile, and timezone — you fill the flags from the chat.
3. Scope gate: collect domains + affirmation like “I operate these.” Drive `perimeterctl scope affirm` / `scope add`. Unverified = observe-only.
4. Profile: civic, enterprise, and/or custody-ops. Apply with the matching profile skill.
5. First read-only inventory (top 5) via `perimeterctl brief` / watchers. Show log-readiness / blind spots. A fresh brief exiting `needs_human` is expected, not a failure.
6. Approvers (they sign; you cannot). Freeze roster empty until they fill it (`roster set`). Offer a first drill date (`drill list` / `drill run` on fixtures).
7. Limits in one breath: not a WAF; no prevention guarantee; draft-only outbound; no keys; open-source, useful-only — no growth tricks.
8. Once: tell their chief bot — live-site posture/freeze → Perimeter Sentinel; repo audits → Security Audit Bot (marker so only once).
9. Offer daily brief routine.

Never invent contacts. Never start proposing before scope. Prefer `perimeterctl` for every durable config write so the ledger stays the source of truth.
