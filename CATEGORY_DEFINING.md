# Making Perimeter Sentinel category-defining

Date: 2026-10-29. Grounded in `PRODUCT.md`, `THREAT_MODEL.md`, `REPO_OUTLINE.md`, and the v0.1 audit (`PASS-WITH-GAPS`). v0.1 already does see + ledger + two freeze playbooks + five synthetic drills. It does not yet make a stranger feel the category in five minutes on a page they can point at.

This plan does not expand into a bot-detection SaaS, does not claim prevention, and does not propose paid security partnerships. Creator revenue stays the Grok Bot. Code stays Apache-2.0 and self-hosted. SpaceXSI-shaped paid security partnerships stay out.

## 1. Category name and pitch

**Category name:** Live-site operator console (see → notice → propose → freeze).

**One breath, technical:** Perimeter Sentinel is the out-of-band console that inventories what a site you operate actually serves, pages on script, DNS, TLS, or signing-path drift, drafts a reversible change and an unsent freeze, and writes time-to-notice and time-to-contain into a hash-chained ledger. Your CDN, WAF, and IdP still enforce. Sentinel never sits in the request path and never approves itself.

**One breath, non-technical:** When a page you run starts serving something you did not ship, Perimeter Sentinel shows you the change, starts a clock, and hands you a freeze checklist and the messages you would send. It does not block visitors and it does not promise the incident will not happen. It makes the team faster and leaves a record.

Working brand remains **Perimeter Sentinel**. The category phrase is the thing people should repeat. Do not brand it “AI control plane” (DataDome already uses that) or “bot detector.”

## 2. Why a category can exist

The niche is empty in the middle and crowded at both ends.

People already buy **edges that score and block** and **process tools that page humans**. Nobody owns the operator loop that starts from *bytes the public is being served right now*, names the drift, drafts the freeze without sending it, and scores the team on minutes. That loop is what the 29 October 2026 Polymarket script case and the Binance hot-wallet case both lacked: notice measured in a probe interval, and a desk that was already rehearsed. v0.1 drills that loop on fixtures. The category exists when the same loop is the default habit on a real origin.

Incumbents and the gap they leave:

| Incumbent | What they own | Gap Sentinel can own |
|---|---|---|
| Cloudflare Bot Management, HUMAN, DataDome, Akamai, Kasada | Request-path scores and challenges on **their** edge. Forrester’s “Bot and Agent Trust Management.” | One console across edges. They do not ship a vendor-neutral freeze desk, issuer drafts, or a public time-to-contain ledger. Sentinel reads verdicts later; it does not resell a score. |
| c/side, Feroot, Source Defense, Jscrambler, Cloudflare client-side security | Paid in-browser or edge **blocking** of payment-page scripts (PCI 6.4.3 / 11.6.1 as a product). | Open evidence of what was served, hashed from outside, with an unsent freeze. A QSA still decides. We do not inject a blocker. |
| PagerDuty, incident.io, FireHydrant | Incident command, timelines, on-call. | They start when a human already knows. They do not hash served JavaScript or prefill a vendor-script envelope. |
| Falco, Tetragon, Wazuh, a SIEM | Host and log detection inside the boundary. | Blind to a vendor CDN that changed a script the origin never deployed (the Polymarket shape). |
| Terraform / OpenTofu, dnscontrol, octorules | Desired state and plan/apply for infra and WAF YAML. | Desired state is not what the world was served at 12:41. No stopwatch, no freeze roster, no “assume the console is compromised” threat model. |

Me-too would be another bot score. The empty niche is **operator tempo**: see the served object, notice the delta, propose a card, freeze on a clock, keep the evidence. Terraform is how people change infrastructure. Tailscale is how people reach a machine. Perimeter Sentinel should be how people **run the first hour of a live-site integrity incident**.

## 3. The visceral demo (build next)

**Name:** `demo script-drift`. **Promise:** in under five minutes, on a site the operator owns or on a local demo origin, a script hash changes, the console notices, and an **unsent** freeze draft is on disk with a stopwatch. Nothing is posted. Nothing is applied at an edge.

### What the operator sees

```
$ perimeterctl demo script-drift --home ./demo-home
# minute 0: local origin http://127.0.0.1:8765/ serves app.js sha256:aaa…
# minute 1: demo flips app.js to sha256:bbb… (file on the demo origin only)
notice  script-drift  page=/  vendor=demo-origin  was=aaa… now=bbb…  status=finding
freeze  start vendor-script-compromise  (oob confirmed by this command's own flag)
draft   ./demo-home/freeze/vendor-script-compromise/draft.md   SENT=false
stopwatch  time-to-notice=4s  time-to-contain=not-yet (operator has not marked contain)
ledger verify  ok
```

Exit 0 only if all of the following are true. Otherwise exit 3 (`needs_human`) or 1 (broken chain).

### Build spec (engineer can implement without inventing product)

1. **Demo origin, loopback only.** Add `cmd/perimeterctl` subcommand `demo script-drift` that:
   - Binds `127.0.0.1` on an ephemeral port (or `--port`, default 8765). Refuses any other bind address.
   - Serves `/` HTML that references `/app.js` and a second path `/vendor.js` labeled in the inventory as `vendor=demo-vendor` with `session=true` (synthetic flag in the fixture HTML comment or a sidecar JSON the server reads). No third-party hosts.
   - Starts with fixed bytes for both scripts (checked into `drills/demo/script-drift/golden/`).
   - After the baseline watcher pass, swaps `/vendor.js` bytes to `drills/demo/script-drift/flipped/vendor.js`. The swap is a local file change. It is not an exploit and it does not touch a network beyond loopback.

2. **Scope.** The command creates a temp home (mode `0700`), `init` profile `enterprise`, `scope affirm`, `scope add --kind dns --name 127.0.0.1` **or** a dedicated kind `loopback` if DNS TXT cannot apply. Loopback names skip the public TXT challenge and record `attestation=loopback-demo` on the ledger. Any non-loopback name still requires the existing TXT gate. Fail closed if the host is not loopback.

3. **Watcher.** Reuse `watchers/served-js` and `watchers/third-party-scripts` against `http://127.0.0.1:<port>/`. First pass writes the baseline hashes. Second pass (after the flip) must return `finding` with vendor name `demo-vendor`, path `/vendor.js`, old hash, new hash. Empty signer pin stays `needs_human` on the **safety** line of the brief, and the **drift** line is still `finding`. Do not call the page safe.

4. **Freeze.** Call the existing `vendor-script-compromise` playbook. The demo passes `--oob-confirmed` only because the human typed the subcommand (the command is the out-of-band act for the demo). Write the draft from `freeze-desk/templates/` with hashes filled in. The file’s first line is `SENT: false`. The writer must refuse to open a socket except the loopback origin GET/HEAD already allowed by the threat model.

5. **Ledger.** Append `watcher.finding`, `freeze.start`, `freeze.draft`. Run `ledger verify`. Record `time-to-notice` from process start to finding. Do not mark contain unless the operator passes `--mark-contain` (default off, so the demo shows an honest open clock).

6. **Acceptance test.** `drills/demo/script-drift/script_drift_test.go` (or a shell script under `drills/demo/`) runs the command with `--home` in `t.TempDir()`, asserts the substrings `finding`, `demo-vendor`, `SENT: false`, `ledger verify`, and `time-to-notice`, and asserts no file under the home contains a URL scheme other than `http://127.0.0.1`. Timeout 60s. No live Cloudflare, no X, no RPC.

7. **README snippet (ten lines).** Document that this demo is a local origin, that notice is not prevention, and that the draft is unsent. Do not add it until the test is green. The category-defining moment is this command, not a diagram.

Out of scope for the demo: edge apply, CSP kill, email, X post, wallet RPC, multi-region probes. Those are later milestones. The demo’s job is to make the four verbs obvious.

## 4. Wedge (first 100 users)

**Who:** Operators of one public site that loads a third-party script on a page with a session or a signing button. Practically: small exchanges and on-chain apps, payment pages at companies that already worry about PCI 6.4.3 / 11.6.1, and one-person SaaS apps on Cloudflare who can read a zone but will not turn on a new bot vendor. Not election offices in the first 100 (too much downside if we overclaim). Not SOC teams who already have a SIEM and a retainer.

**Job to be done:** “Tell me this week if the JavaScript my users actually receive is still the JavaScript I approved, and if it is not, put the freeze checklist in my hand before I finish reading the alert.”

**Aha:** They run `demo script-drift`, then point the same watcher at **one** of their own pages with `--live` (GET/HEAD only, scope-affirmed). The inventory paints that page red because a vendor script sits on a session page. That red row, before any incident, is the screenshot they send a teammate. The second aha is the stopwatch on a drill they run on staging, with a number they can compare to the public 35-minute and 55-minute marks from 29 October 2026, labeled provisional and not a vendor finding.

**What we do not ask of user 1:** a bot-manager rip-and-replace, a write token, or a second approver. Read-only scope plus a draft is enough to be useful.

## 5. Moat that is not a trademark

Trademark filing is not the plan. The moat is the artifact other tools do not accumulate:

1. **Open evidence.** Hash-chained ledger anyone can `ledger verify`, with the honest gap that a host owner can rewrite the file until Rekor anchoring exists. Export Markdown first (PDF only as a local render). Maps later to CSF 2.0 labels without claiming an authorization.
2. **Drills as the product.** Every detection ships with a synthetic drill (ADS-style: goal, ATT&CK id, blind spots, false positives). CI fails the detection if the drill does not pass. The Oct 29 five drills are the seed. The category leader is whoever has the boring, green drill list.
3. **Freeze desk + stopwatch KPIs.** Rosters, unsent drafts, time-to-notice, time-to-contain. Published as numbers from **your** drills, never as “we would have saved Polymarket.” Comparison sentences stay in the ledger as measurements, not prevention.
4. **Bot-led setup.** The Grok Bot skill walks `init`, scope affirmation, roster, one watcher, one drill. The human still affirms scope and still sends every draft. Setup time under 15 minutes is the distribution moat: Tailscale’s feeling was “it just came up.”
5. **Fail-closed console.** Documented in `THREAT_MODEL.md`: compromise of Sentinel is not compromise of the site. `Apply` stays an error until a later, explicit, owner-token milestone. That property is the reason a careful operator picks this over a SaaS script blocker.

Network effects, if any, are shared **drill fixtures and playbooks**, not a surveillance graph of other people’s visitors.

## 6. Roadmap v0.2 → v1.0

Acceptance tests are executable. A milestone is not done when the doc says it is.

### v0.2 — Propose, still no vendor apply
- Change-card schema rendered to a GitOps PR **body** (v0.1 already renders; v0.2 opens a PR only with an owner-supplied git remote and a token kept outside the repo). Default remains “print the diff.”
- Two human fingerprints on the receipt shape, still `needs_human` until signatures are verified. `cards.Approve` stays an error.
- **Acceptance:** a unit test builds a card whose diff removes `demo-vendor` from a CSP allowlist fixture; the card file contains `Apply: false`; a test calls `Approve` and expects an error; ledger records `card.proposed`.

### v0.2.1 — Visceral demo
- Section 3, with the Go test green and the README snippet.
- **Acceptance:** `go test` covers `script-drift`; a clean machine finishes the command in under 60 seconds; draft contains `SENT: false`.

### v0.3 — Freeze desk on a clock, still unsent
- Scheduler runs the two playbooks against fixtures weekly in CI.
- Thaw checklist and envelope expiry recorded, not executed (`envelopes.Execute` still errors).
- **Acceptance:** drill emits notice and contain durations; a freeze without the oob flag does not start the stopwatch (already the threat-model rule; lock it in a test).

### v0.4 — One opt-in read-only live adapter
- Cloudflare **read** token, owner-supplied, never committed. Pull zone hostnames and, if the token allows, a script or configuration inventory the API already exposes. Compare to scope. Mismatch → `finding` or `needs_human`.
- **Apply stays refused.** A test proves the adapter has no code path that issues a write method (PUT/PATCH/DELETE/POST to Cloudflare). GET only. Missing token → `needs_human`, exit 3, zero network calls.
- **Acceptance:** httptest server, not the live API, feeds a fixture zone; a second test fails the build if a write verb appears in the adapter package.

### v0.5 — Swarm-shaped notice (advisory)
- Section 7. Score is a lane **recommendation** with `Apply: false`. No visitor blocking.
- **Acceptance:** synthetic log fixture of a coordinated pattern trips `finding`; a fixture of ordinary traffic does not; civic profile refuses behavioral telemetry (existing policy).

### v0.6 — Readiness in the daily brief
- Log-readiness line: which watchers ran, which are blind, signer pin empty or set.
- **Acceptance:** fresh home brief exits 3 with `needs_human` (already true). A home with signer pin set and one green watcher still lists remaining blinds and does not say “protected.”

### v0.9 — Release hardening
- cosign on release artifacts, public age recipient only (private key never in the repo), Rekor anchor for ledger checkpoints as an opt-in command. gitleaks in CI.
- **Acceptance:** `ledger verify` plus a checkpoint command; secret scan clean; `edgerules.Apply` and `flags.Apply` still return errors.

### v1.0 — The name sticks
- Stable ledger schema version. Multi-site: one home, N affirmed names, one brief.
- README quickstart is the demo, then “point it at a page you own.”
- External review of the threat model (a person who is not the author). No managed GA. The v0.1 executive summary line that says “managed GA” is stale and should be corrected when someone next edits `PRODUCT.md` (audit gap). Do not do that rewrite in the same breath as a feature claim.
- **Acceptance:** two loopback or fixture sites in one brief; all Oct 29 drills still pass; no prevention language in README or `bot/skills/`.

Live adapters after v0.4 stay opt-in, owner-token, read-only until a separate written decision turns a specific envelope into apply. Fail closed on timeout, 401, and parse error (`needs_human`).

## 7. Swarm-shaped notice without becoming “the bot detector”

Sentinel notices **shape** on the owner’s own telemetry and served objects. It does not sell a bot probability and it does not see the public internet’s traffic.

**Signals we will compute (owner logs and owner pages only):**

| Signal | Lane it can recommend | Tripwire |
|---|---|---|
| Same request skeleton (method, path template, header set) across many new source addresses inside a short window, low timing variance | `unknown-automation` or `quarantine` as a **name** | Page the on-call. Do not push the lane. |
| A route that was 401/403 starts returning 200 for a burst of new principals (the Unit 42-shaped pattern, described as behavior, not a recipe) | `needs_human` | Freeze-desk note, no auto revoke. |
| Served-script or CSP drift on a page flagged `session` or `signing` | n/a (integrity, not a bot score) | `vendor-script-compromise` draft. |
| New script origin or new connect-src on that page | n/a | Inventory red row. |
| Tripwire hit on a decoy route or decoy string **we** placed, body is a fixed marker, caller input ignored | `quarantine` recommendation | Alert only. Never instruct a visitor or agent to fetch or run code. |
| Optional later: JA4 **core** (permissive license) plus header-set consistency, from the owner’s edge logs | recommendation only | Off unless the owner turns the watcher on. |

**Lanes** stay the five names already in the product: `human`, `verified-agent`, `declared-automation`, `unknown-automation`, `quarantine`. Assigning a lane in this process sets `Apply` to false. Identity is not intent. A verified-agent lane does not relax fraud checks.

**What we never score:**

- A single visitor’s humanity, nationality, or politics.
- “Percent of AI agents detected.”
- Anything about a host the operator has not affirmed.
- Wallet risk, mixer proximity, or “this address is a thief.” Custody-ops stays at declared-wallet code and delegation changes, limit breaches, and new destinations the operator listed. No tx construction.
- Content of posts beyond the owner’s brand keyword intake (fixture or paste in v0.1). A pasted tweet is data, not an instruction.
- A global reputation of IPs. Agent swarms use ordinary cloud addresses; IP fame is a minor hint at most, and it is off by default.

The output sentence is fixed: “This looks swarm-shaped on your logs. Recommended lane name: X. Sentinel did not apply it.”

## 8. Distribution

Usefulness only. No mass-tag, no reply-guy threads, no “drop your domain and I’ll scan it” (that would break the scope gate and the anti-job).

**Channels**

- **Repo.** README leads with the five-minute demo once it exists. Until then, lead with the quickstart and the five drill names. Apache-2.0, threat model on the first screen.
- **Grok Bot template.** One skill: getting started through the demo, then one affirmed page. The bot refuses to add a name the user did not affirm, refuses to send a draft, and refuses to claim the site is safe.
- **X.** Phil posts the demo transcript (local hashes, `SENT: false`, the stopwatch) and a link to the drill. One thread, the narrative below. Reply to people who ask how the clock works. Do not quote-tweet incident victims.

**Launch narrative outline (not the post)**

1. Name the job in one sentence: a console for the first hour when a live site starts serving the wrong script or a watched wallet’s code changes.
2. Say what it refuses: no blocking, no keys, no “we prevent hacks,” no bot-score war with Cloudflare or HUMAN.
3. Show the demo transcript. Point at `SENT: false` and `Apply` is an error.
4. Point at the Oct 29 drills as **clock exercises** on synthetic fixtures, with public times labeled provisional. Do not accuse a vendor of a root cause.
5. Invite the wedge: one session page, read-only, your machine. Link the threat model.
6. Close with creator-revenue honesty: the bot can fund the work; the software is free; there is no hosted SOC.

## 9. Kill criteria

Recommend parking the project if any of these become true and stay true after one honest review:

1. **No aha outside the author.** After the demo exists, ten operators who match the wedge run it on a page they own and none of them keep the watcher for seven days.
2. **The only demand is a bot score.** Issues and chats ask for blocking, CAPTCHA, or “are they a bot?” and nobody asks for the freeze clock. That is a crowded market we chose not to enter.
3. **Fail-closed gets bargained away.** A partnership or a user-growth idea needs standing write tokens, Sentinel-held keys, or auto-send to issuers. Parking is better than becoming a SaaS that holds production credentials.
4. **Overclaim sticks.** A public post or README that says the tool secures an election, prevents theft, or is FedRAMP authorized, and the correction does not land in the same week.
5. **Maintenance without use.** Two consecutive quarters with no external drill run and no contributor, while creator revenue does not cover a security response. Leave the repo up, archived, with the threat model. Do not sell the name into a services shop.
6. **Dual-use pressure.** Contributors or a fork insist on exploit content, third-party scanning, or tripwires that tell an agent to run code. If that cannot be kept out of `main`, stop.

Parking means: tag the last good release, point the README at the audit and this file, and stop promising a roadmap.

## 10. Next 7 days

Ordered. Smallest category-shaping step first. Grok Build can do the code; Phil does the human decisions.

1. **Correct the stale promise in conversation, not in a drive-by rewrite.** Phil confirms the exec summary “managed GA” line is dead (§8). Next editor of `PRODUCT.md` deletes that phrase. No new product claims until then.
2. **Land `demo script-drift`** exactly as section 3, with the Go test, loopback only, `SENT: false`. This is the category-shaping step. Do it before any Cloudflare token.
3. **Ten-line README addition** only after that test is green. Include “does not prevent” and “draft is unsent.”
4. **Bot skill pass:** getting-started skill runs the demo in its dry instructions and states it will not send mail or apply an edge rule.
5. **Phil records one screen transcript** of the demo (local). That is the launch artifact. Do not post until step 3 is on `main`.
6. **Design the Cloudflare read-only adapter on paper in the PR** (routes, token env var name, httptest). Do not implement writes. Implement GET-against-httptest only if steps 2–4 are done.
7. **Do not file a trademark this week.** Do not add a paid tier. Do not take a security-partnership call that wants Sentinel in the request path.

## Honest risks

- **False safety.** A green brief can be misread as “we are fine.” v0.1 already exits 3 when the signer pin is empty. Keep a blind-spots section on every brief through v1.0. The category dies if marketing outruns that sentence.
- **Demo theater.** A loopback flip is not a vendor CDN compromise. Say so in the README. The wedge aha only counts when the same watcher reads a page the operator serves to users.
- **Ledger theater.** Without Rekor, the chain catches accidents, not a root attacker who rewrites the file (`THREAT_MODEL.md`). Do not call it tamper-proof.
- **Scope creep into detection SaaS.** Swarm score is the slippery feature. If the UI grows a 0–100 “bot number,” we have left the category and entered someone else’s, without their data.
- **Incident storytelling.** Citing 29 October 2026 times is fair as a clock benchmark and unfair as a root-cause claim. Keep the provisional label or cut the names.
- **Trademark and name collisions** (Microsoft Sentinel, HashiCorp Sentinel, SentinelOne, HUMAN/PerimeterX, Check Point Perimeter 81). Unregistered on purpose for now. Counsel before any commercial posture. The CLI stays `perimeterctl`.
- **Single-maintainer bus factor.** Creator revenue may not cover response. Kill criterion 5 is the relief valve. Open drills and an Apache-2.0 license are how the work survives a pause.
- **Audit gaps still open.** No live vendor client, no PDF, no Rekor, Rego not executed, gitleaks optional, several packages untested directly. None of those block the demo. All of them block a claim that v1.0 is done.
