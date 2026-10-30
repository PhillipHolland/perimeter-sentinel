# Grok Build job: Perimeter Sentinel v0.1 codebase

## Goal
Create a novel, comprehensive, **defensive-only** open-source codebase for **Perimeter Sentinel** — CLI `perimeterctl` — from the research pack already on this Mac.

You are building the **first real implementation**, not a sketch. Quality bar: tests that pass, Apache-2.0, reproducible layout matching REPO_OUTLINE.md, threat model that assumes Sentinel itself is compromised.

## Pack (read first, in order)
Unpack if needed:
```
mkdir -p ~/perimeter-sentinel-work && cd ~/perimeter-sentinel-work
tar xzf ~/perimeter-sentinel-pack.tgz
# docs land in ./perimeter-sentinel/
```
Read:
1. `perimeter-sentinel/PRODUCT.md` (especially §0 Must cover Oct 29, §0A sector limits, §7A positioning, §8 creator-revenue-only)
2. `perimeter-sentinel/REPO_OUTLINE.md` (layout + v0.1 modules + must-adds)
3. `perimeter-sentinel/SECURITY_SCHOOL.md` (Graduation 10 lessons → product behavior)
4. `perimeter-sentinel/CREATEAGENT_BRIEF.md`
5. Skim `perimeter-sentinel/RESEARCH.md` for citations; do not invent attack code from it.

Working tree: **`~/perimeter-sentinel-work/perimeter-sentinel`** (git init locally; do NOT push; do NOT create GitHub remote).

## Non-negotiables (fail the job if violated)
- **DEFENSIVE ONLY.** No exploit PoCs, payloads, malware, C2, credential-testing against third parties, offensive tooling. CONTRIBUTING.md must ban these.
- **Never holds keys / never moves funds / never signs.** Onchain watcher is read-only RPC.
- **Scope gate deny-by-default.** Every watcher calls `internal/scope`.
- **Fail closed:** result type `ok | finding | needs_human`. Errors → needs_human, never all-clear.
- **No paid SaaS.** Creator-revenue / Apache-2.0 only.
- **Do not claim** prevention, FedRAMP, “secure the election,” fraud decisioning, replacing WAF.
- Licenses: Apache-2.0 for our code. Do not vendor AGPL/GPL-3/FCL/FoxIO. Compose as separate processes only when needed.
- Language: **Go** for CLI/core (per REPO_OUTLINE). Bot skills as Markdown under `bot/skills/`.

## v0.1 deliverables (must ship)
Implement at least:
1. `cmd/perimeterctl` with: `init`, `scope add|verify|list`, `ledger verify|append`, `brief`, `watch dns|tls|served-js|third-party-scripts` (stubs OK for edge adapters), `freeze list|start|stopwatch`, `drill list`
2. `internal/scope`, `internal/ledger` (hash-chained JSONL)
3. `watchers/dns`, `watchers/tls`, `watchers/served-js`, `watchers/third-party-scripts` (fetch owner pages only; hash scripts; baseline diff)
4. `internal/freeze` playbooks: `vendor-script-compromise`, `hot-wallet-drain` + roster schema + draft templates (no sending)
5. `watchers/onchain` stub interface + tests with fake RPC (no real keys)
6. `drills/oct29/` acceptance tests (synthetic fixtures only)
7. Docs: README, LICENSE Apache-2.0, NOTICE, SECURITY.md, THREAT_MODEL.md, CONTRIBUTING.md (offensive ban), GOVERNANCE.md, TRADEMARKS.md
8. `bot/` copy of brief + skill stubs from CREATEAGENT_BRIEF
9. CI workflow: test, gitleaks (or placeholder), go test ./...
10. Unit tests: go test passes; at least scope deny, ledger chain verify, served-js drift fixture, freeze stopwatch

## Novelty (encode in code comments + THREAT_MODEL)
- Operator console across edge vendors, not a bot detector
- Traffic lanes + agent tripwires (alert + lane only — never make visiting agents run code)
- Pre-auth ledger types
- What-the-world-sees integrity (served JS vs signed build)
- Freeze Desk with time-to-freeze KPI
- Polymarket + Binance Oct 29 failure modes as must-cover drills

## Out of scope for this job
- Publishing to GitHub / PyPI / Homebrew
- Real X API / Cloudflare API calls (interfaces + fake fixtures only)
- FedRAMP paperwork
- Any offensive content

## Done signal
When tests pass and README quickstart works locally:
1. Write summary to `~/.grok-handoff/perimeter-out.txt` (tree, test results, known gaps)
2. Touch `~/.grok-handoff/perimeter-done`
3. Leave commits on local git only (message style: clear, no AI slop)

## Prompt path
This prompt should also be saved as `~/.grok-handoff/perimeter-prompt.txt`.
