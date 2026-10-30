# Perimeter Sentinel: Product Vision

> An open-source, bot-operated **control plane** for the security posture of a live site you operate. It watches, correlates, proposes, and keeps evidence. Humans approve. Your existing edge (CDN, WAF, IdP) enforces.

Status: concept v0.2 (Oct 29, 2026; updated with Oct 29 incident lessons and verified licenses). Author context: Phillip Holland (@Phil_Holland). Sibling: Security Audit Bot. Research basis: `RESEARCH.md`.

---

## 0. Must cover: Oct 29, 2026 incidents (v0.1 acceptance bar)

Phil's constraint: **v0.1 must at least defend against today's Polymarket and Binance failure modes.** "Defend" means *shorten time-to-notice and time-to-contain*. Sentinel can't make a compromised vendor or signer safe. Facts and their known/provisional status are in RESEARCH.md §0, with times in CT.

### 0.1 Polymarket: compromised third-party script on an authenticated trading page
Observed (provisional, per Defiprime): about **35 min** from first theft to the first public victim post, **49 min** to the code fix, and **55 min** to the halt (cancel-only plus relayer pause). The front-end fix didn't reach open tabs. The first signals came from users and security accounts on X.

| Verb | v0.1 capability | Would have shortened |
|---|---|---|
| **See** | **Third-party script inventory.** Per page, list every script origin, CSP-allowed domain and connect-src destination, each tagged with its vendor, owner and "page touches session/signing?" flag. Pages that mix vendor JS with money-moving sessions are flagged red on day 1. | Pre-incident. Makes the RUM-on-trading-page risk visible before an attacker uses it. |
| **Notice** | **What-the-world-sees probe**, every 1–5 min from outside, using several regions and clean browsers. It fetches each red page, hashes **every served script, including vendor-hosted ones**, and alerts on drift from the last approved hash, new outbound destinations, or new CSP violations (via a report-uri sink). | Content changed at the vendor CDN with no deploy on your side. This is the only place it shows up. Target: page within one probe interval of activation (minutes, not 35). |
| **Notice** | **External-signal intake.** Watch X for your brand plus words like "drained", "hacked" or "compromised", and watch named security accounts (PeckShield, Bubblemaps, SEAL 911, ZachXBT-style researchers). Optional **read-only** on-chain watch: bursts of outflows from many user accounts to a never-seen address. | Turns the first victim post (12:45 PM CT) into a page within about a minute. Turns an on-chain burst into a page before any public post. |
| **Propose** | Change cards (PRs) to remove or quarantine the vendor tag, add SRI or self-host pinned copies, tighten CSP, move vendor JS off session pages (separate origin or iframe sandbox), and add **step-up / velocity rules** for full-portfolio sell-and-sweep to new addresses. | Fix PR drafted at alert time, with the vendor tag already identified by the inventory. |
| **Freeze** | **Freeze Desk playbook "vendor script compromise"**: a pre-approved, auto-expiring envelope the operator triggers in one tap. It covers trading cancel-only, relayer/withdrawal pause, a forced session/token refresh so open tabs die, and a CSP kill of the vendor domain at the edge. It also includes vendor and law-enforcement contact drafts, a user-notice draft and a stopwatch. **Sentinel drafts and times. The operator's systems execute.** | Halt within minutes of the page instead of 55 min. The forced refresh closes the open-tab tail. |

### 0.2 Binance: hot-wallet signing path compromised, then a freeze race
Observed (provisional): root cause undisclosed. The execution path was EIP-7702 delegation of a hot wallet to a sweeper contract, possibly using pre-collected authorizations. Issuer freezes landed in about 24 min (USDC) and about 37 min (USDT). Assets without a freeze function were not recoverable. The first public flag came from a researcher on X.

| Verb | v0.1 capability | Would have shortened |
|---|---|---|
| **See** | **Pre-authorization ledger.** Operator-declared inventory of hot wallets, signers, signing services, policy engines and outstanding authorities (delegations, approvals, allowances, limits), plus the security vendors in the signing path. Read-only. Sentinel never holds keys. | Pre-incident. Makes "who can sign what, and where it's pending" auditable. |
| **Notice** | **Tier-0 watchers (read-only RPC or explorer).** Any code or delegation change on a declared hot wallet. Any outflow breaking a declared limit or going to a never-seen destination. Signing-UI integrity probe (served JS vs. signed build, the Bybit lesson). Security-vendor change watch (the Bitget lesson). External-signal intake as above. | A delegation change pages in seconds, ahead of the first public post (3:32 PM CT). |
| **Propose** | Rotation of signers and policies, limit reductions, revoking outstanding authorities, and moving remaining hot balances to cold storage. All of these are **change cards for the custody team**. Sentinel never constructs, signs or broadcasts transactions. | Containment steps listed at minute 0, not worked out mid-incident. |
| **Freeze** | **Freeze Desk playbook "hot-wallet drain"**: issuer freeze-request drafts with addresses, amounts and tx hashes filled in from the alert (Tether, Circle, Ripple, other issuers' published LE/compliance channels), a downstream counterparty notice (lending markets, bridges, other exchanges), a SEAL 911 contact, IC3, a stopwatch per issuer, and **time-to-freeze KPI** benchmarked against today's 24/37 min. | Requests leave within minutes of the page, so issuer clocks start sooner. Drills keep the roster current. |

### 0.3 Acceptance tests for v0.1 (drills, run against the owner's own staging)
1. A vendor-hosted test script changes on a staging trading page → page alert within **≤5 min**, with the vendor named. The freeze envelope is ready to approve.
2. A test X post with brand + "drained" is ingested → alert within **≤2 min**.
3. A delegation or code change on a declared **testnet** wallet → tier-0 page within **≤60 s**. Issuer-request drafts are prefilled.
4. Every alert, approval and freeze is written to the hash-chained ledger, and the stopwatch records time-to-notice and time-to-contain.
5. No step needs Sentinel to hold a key, move funds, or run code anywhere but the owner's systems.

---

## 0A. Can it protect federal / election / banking? (verdicts; sources in RESEARCH.md §8)

**Plain verdict:** **Yes with limits.** Against agentic swarms, Sentinel shortens time-to-notice and time-to-contain and produces audit-grade evidence. **The blocking happens in the owner's CDN, WAF, bot manager and IdP. Sentinel is not that layer.**

| Claim | Federal | Election | Banking |
|---|---|---|---|
| "Stops agentic swarms / DDoS" | **No.** That's the edge's job. | **No.** Use Athenian Project or Project Shield, which are free. | **No.** That's the bank's bot manager or CDN. |
| "Detects swarm shifts and trusted-path drift faster" | **Yes with limits.** Needs edge and IdP logs. | **Yes with limits.** Needs CDN logs. Best on election night. | **Yes with limits.** Covers web, login and API only; it can't see transactions. |
| "Shortens containment with drilled freezes" | **Yes.** Synchronized revoke and freeze playbooks. | **Yes.** Static fallback, lane tightening, comms drafts. | **Yes.** Includes the 36h regulator clock and vendor kill. |
| "Satisfies compliance" | **No.** It *produces evidence* for 800-53 / CSF / FedRAMP 20x KSIs. The AO or assessor decides. | **No.** Maps to the CISA plan's services and safeguards. | **No.** Strong evidence for **PCI 6.4.3 / 11.6.1**. The QSA decides. |
| "FedRAMP authorized" | **No.** There is no hosted offering (creator-revenue-only, §8). Self-hosted = covered by the agency's ATO. | n/a | n/a |
| "Secures the election" / truth or content decisions | n/a | **No, never.** Covers availability, integrity and presentation only. It never touches voting systems or eligibility. | n/a |
| "Prevents fraud / ATO" | n/a | n/a | **No.** It adds correlation and paging next to fraud platforms. No transaction decisions, no SARs. |

### Capability matrix: what actually reduces agentic-swarm risk
| Verb | Federal (.gov apps, portals) | Election (lookup, registration, results) | Banking (online banking, APIs, payment pages) |
|---|---|---|---|
| **See** | Asset/route/script inventory and the identity map. *Reduces risk:* yes, since unknown surfaces are where swarms land. | Public vs. system-of-record separation check (CISA VRDB safeguard). Script and vendor inventory. Change-freeze calendar. | **PCI 6.4.3 script inventory and justification.** API key and aggregator inventory. Third-party dependency map (NYDFS May 2026). |
| **Notice** | Swarm score across routes, IPs and accounts. 401→200 loops (Unit 42 pattern). KEV↔SBOM. CT and lookalikes. | Surge-vs-swarm split on `/results` and portals (Georgia 2024 shape). Defacement probe. Lookalike results sites. | **PCI 11.6.1 served-script and header tamper detection** (near-real-time instead of weekly). Agent-lane anomalies on login and open-banking APIs. External-signal intake. |
| **Propose** | Edge rule, lane and step-up PRs into agency change control (CM-3). | Turn on the challenge lane or static fallback. Tighten rate budgets. All pre-approved for election week. | Change cards into the bank's change management. Vendor-script removal. Step-up rules handed to the fraud and IdP teams. |
| **Freeze** | Synchronized containment (credentials, OAuth, CI/CD), plus CISA incident-reporting drafts. | Static-mirror switch, lane lockdown, public-notice draft, CISA regional advisor and fusion-center roster. | Vendor kill-switch envelope, session revoke, **36-hour regulator notice draft**, issuer and partner contacts, counterparty notices. |
| **Biggest reducer** | Notice + Freeze | **Freeze** (keeping availability on election night) + See (separation) | **Notice** (script integrity) + Freeze |

### Required integrations (minimum to be useful)
- **Federal:** agency CDN/WAF (often Akamai or Cloudflare via GSA/TIC), IdP (Login.gov / Okta / Entra / Keycloak), SIEM (Splunk/Elastic via Sigma/OCSF), ticketing (ServiceNow/Jira), SBOM source. Deployed **inside the agency boundary**, air-gap capable.
- **Election:** Athenian Project or Project Shield edge logs and controls, the state VRDB vendor's audit-log export (read-only), status-page and comms tooling, CISA services contacts. County IT teams are tiny, so a turnkey profile is required.
- **Banking:** CDN/bot manager, SIEM/SOAR, fraud platform (read-only alerts in, change cards out), IdP/CIAM, the API gateway for open-banking traffic, GRC tool for PCI and Part 500 evidence.

### Compliance blockers
- **Federal:** FedRAMP 20x certification for any hosted offering. Agency ATO and an SSP entry for self-hosted. Supply-chain attestation (SSDF / secure-software form), SBOM and signed releases (already planned). Section 508 for the UI. Any AI component falls under the CISA agentic-AI guide and agency AI policies.
- **Election:** state procurement and vendor certification rules vary. No connection to certified voting systems. Data residency (Hursti's Finland example). Political neutrality must be provable (open source helps).
- **Banking:** third-party risk due diligence (2023 interagency guidance). No hosted service (§8), so no SOC 2 or bank-service-provider duties from us. Banks diligence it as self-hosted OSS (SBOM, signatures, threat model, maintainer health). ~~Likely **bank service provider** notification duties~~ (≥4h disruption). Model-risk review if the swarm score influences any customer-facing decision (keep it advisory). PCI scope questions if it fetches payment pages. NYDFS Part 500 third-party policy.

### Liability posture
- Promise only **time-to-notice, time-to-contain and evidence**, never "protection". The Apache-2.0 license and README say decision support, operator-approved actions, and no warranty of prevention.
- Proposal-only plus human approval keeps the operator as the decision-maker, which matches the CISA agentic-AI guidance and limits Sentinel's liability.
- Election: refuse any role in content, eligibility or results certification. Publish the neutrality policy.
- Banking: no fraud decisions and no customer-facing blocks without the bank's own control in the loop.
- No managed deals (§8), so no E&O policy is needed for hosted service. Maintainer liability is limited by the license; counsel should review the README disclaimers.

### What must be true for these buyers
1. **Federal:** self-hosted inside the boundary first, with evidence exports in OSCAL/KSI format, signed and reproducible builds, and an SSDF attestation. There is no managed tier (§8), so FedRAMP doesn't apply to us.
2. **Election:** free, turnkey on top of Athenian or Project Shield, election-week envelopes pre-approved by the office, neutrality and no-voting-system rules in the code, and a CISA-services-first roster.
3. **Banking:** PCI 11.6.1 and 6.4.3 evidence that a QSA accepts, SIEM/SOAR integration, and a clean TPRM package for self-hosted OSS (SBOM, signatures, threat model, maintainer health), all positioned as an add-on to the SOC rather than a replacement.

---

## 1. One job

**Keep a live site you operate defensible against automated and agentic attacks, around the clock. Turn signals into approved, reversible changes and rehearsed freezes, with an evidence trail an auditor would accept.**

Every feature has to serve one of four verbs:
1. **See**: a continuous inventory and posture graph of what is actually exposed (DNS, certs, origins, routes, auth surfaces, AI endpoints, keys and tokens, third-party scripts).
2. **Notice**: correlated detection of swarm-shaped and novel behavior across layers. This is about how attacks are shaped, not one IP at a time.
3. **Propose**: a signed, minimal, reversible change card ("raise CRS paranoia on /login for 2h", "move unverified automation on /api/search to the PoW lane", "rotate the CI token found in the new npm advisory"). A human approves it. GitOps applies it.
4. **Freeze**: pre-built, drilled emergency playbooks with contact rosters and timers (revoke, lock, rate-shed, maintenance mode, registrar lock, upstream freeze requests), measured in minutes.

## 2. Anti-jobs (hard lines, written into code and policy)

- **Never attacks, scans, probes, or "tests" any system the owner does not operate and has not declared in scope.** No hack-back, no counter-DDoS, no "active defense" against third parties.
- **No offensive tooling.** No exploit generation, payload libraries, malware, C2, or credential-testing against live third-party services. Detections describe behavior, never how to reproduce it.
- **Never holds, uses, or asks for signing keys, seed phrases, or withdrawal authority.** For hot-wallet operators it watches and alerts. It cannot move funds or approve a transaction.
- **Never approves its own change.** Every write to enforcement config needs a human approval, recorded and signed. High-risk classes need two people.
- **Never auto-enforces outside a pre-approved envelope.** Pre-approved, time-boxed, auto-expiring envelopes such as "shed load on /results up to 50% for 15 min" are allowed only if a human pre-authorized that exact class.
- **No content moderation and no political judgments.** In the civic profile it protects availability and integrity of the owner's own pages. It does not judge speech, voters, or candidates.
- **No surveillance of individuals.** No building profiles of visitors beyond security telemetry the owner already lawfully collects. Minimize and expire data.
- **Never posts publicly or contacts third parties on its own.** Freeze-desk messages to issuers, registrars or CISA are drafts that the owner sends.
- **Not a WAF, CDN, DDoS scrubber, SIEM, or EDR replacement.** It orchestrates them.

## 3. Honest positioning: what a bot plus CLI can and cannot be

| Can | Cannot |
|---|---|
| Correlate signals across CDN, WAF, IdP, app logs, CT logs, KEV, and supply-chain advisories faster than an on-call human | Absorb a Tbps DDoS. That takes an anycast provider. |
| Keep WAF, bot and rate-limit policy as code with tests, diffs and rollback | Out-score a global ML bot network trained on trillions of requests |
| Run drills and time-to-freeze metrics, and keep contact rosters fresh | Guarantee prevention. It shortens time-to-notice and time-to-contain. |
| Produce auditor-grade evidence mapped to NIST CSF 2.0 / 800-53 / 800-61r3 | Replace an ATO / FedRAMP authorization (it supplies evidence for one) |
| Give small civic teams Google-style process without Google headcount | Be inline in the request path. By design it is out-of-band. |

## 4. Novel ideas (what is actually new here)

1. **Control plane, not a box.** Sentinel never sits inline. If it dies, the site keeps running on its last approved policy. If it is compromised, the attacker gets proposal rights only, because approvals are signed by human keys Sentinel never holds. This is the Bitget lesson built into the design.
2. **Traffic lanes instead of block/allow.** Requests are routed into lanes with separate budgets:
   - `human`: passkey or session-proven
   - `verified-agent`: RFC 9421 / Web Bot Auth signature verified against a pinned directory, with its own quotas, **never** with relaxed fraud checks
   - `declared-automation`: claims to be a bot but is unsigned. Treated as unverified, PoW lane.
   - `unknown-automation`: friction ladder (rate budget → PoW → step-up auth. Visual CAPTCHAs are a last resort only, because VLM solvers hit 60–100% in 2024–25 studies. See RESEARCH §10.1.)
   - `quarantine`: known-bad, shed first under load

   Sentinel's job is lane policy, budgets and drift detection. The edge (Anubis, Coraza, Envoy, Cloudflare and so on) enforces.
3. **Friction ladder, priced in attacker cost.** Escalation runs: observe → rate budget → PoW difficulty steps (Anubis) → step-up auth → maintenance page for non-human lanes. It is tied to a swarm score built from cross-route, cross-IP features (identical task graphs, timing entropy, coordinated new-account creation). Each step is a pre-approved, auto-expiring envelope.
4. **Agent tripwires on your own property.** These are defensive canaries for AI agents: decoy routes, decoy credentials (Canarytokens or self-hosted tokens), and machine-readable "instructions" placed where only automated agents read them (for example `llms.txt`-style files and hidden admin breadcrumbs). An agent that acts on them identifies itself as automation that ignored the site's stated rules. This draws on public work like Thinkst's Agent Provocateur but is an independent, original, open implementation. No visitor is harmed. A tripwire only raises a signal and moves the session to a lane. **Hard line:** unlike Thinkst's published demo, Sentinel tripwires **never instruct or persuade an agent to download or run code**. That would be intrusion into a system the owner doesn't operate. Any self-description an agent gives is untrusted (it may be hallucinated) and only adjusts a lane score.
5. **Freeze Desk.** These are emergency playbooks built from the Binance, Bybit and Bitget lessons. Each has a roster (issuers, registrars, CDN, IdP, CISA regional director, IC3, SEAL 911 for crypto), pre-drafted messages, a stopwatch, and a time-to-freeze KPI. Drills run quarterly, and results go to the evidence ledger. Sentinel drafts and times. Humans send and act.
6. **Pre-authorization ledger ("latent liability" inventory).** This tracks every long-lived authority: API keys, OAuth refresh tokens, CI tokens, signed but unused authorizations, delegated wallet permissions (for example EIP-7702 delegations), and admin sessions. Each one gets an owner, an expiry and a revocation path. That turns "pre-collected signatures" style failures into a weekly report.
7. **What-the-world-sees integrity.** External probes of the owner's own pages from several vantage points check DNS, TLS chain, served JS hashes against the signed build (SRI/CSP drift), and results-page content hash against the signed source. This catches Bybit-style front-end tampering and civic defacement even when host FIM is blind.
8. **Change freezes for known dates.** For elections, product launches and token events: a calendar-driven policy that tightens change control and pre-stages surge lanes. It runs a 48h pre-event checklist and a T-0 war-room mode.
9. **Evidence ledger.** Every observation, proposal, approval and action is appended to a hash-chained log, optionally anchored in Sigstore Rekor. Exports map to NIST CSF 2.0 functions and 800-61r3. This is what makes it credible at federal level.

## 5. Architecture layers

```
            ┌─────────────────────── Humans ───────────────────────┐
            │ Owner / on-call  ·  2nd approver  ·  Incident cmdr   │
            └──────▲──────────────────▲─────────────────────▲──────┘
                   │ approve (signed) │ freeze go/no-go     │ reports
┌──────────────────┴──────────────────┴─────────────────────┴──────────┐
│ L5  Grok Bot conversational control plane (skills, memory, routines)  │
│     triage · explain · draft change cards · run drills · daily brief  │
├───────────────────────────────────────────────────────────────────────┤
│ L4  Policy & approval core (`perimeterctl` CLI, Apache-2.0)           │
│     policy-as-code · change cards · envelopes · 2-person rule ·       │
│     evidence ledger (hash chain, optional Rekor) · profiles           │
├───────────────────────────────────────────────────────────────────────┤
│ L3  Correlation & detection                                            │
│     swarm score · lane drift · Sigma rules · KEV↔SBOM matcher ·       │
│     pre-authorization ledger · tripwire hits                           │
├───────────────────────────────────────────────────────────────────────┤
│ L2  Watchers (read-only collectors, each sandboxed)                   │
│     edge/WAF logs · IdP events · app logs · CT/certstream · DNS ·     │
│     dnstwist · KEV/OSV feeds · served-JS hashes · Falco/Tetragon ·    │
│     CrowdSec decisions · status of upstream providers · X/news intake │
├───────────────────────────────────────────────────────────────────────┤
│ L1  Enforcement adapters (write, only via approved change cards)      │
│     Coraza/CRS · Anubis · Envoy/Kong/APISIX · CrowdSec bouncers ·    │
│     Keycloak/authentik · Cloudflare/Fastly/Akamai APIs (vendor) ·     │
│     GitOps PR to infra repo (default)                                 │
├───────────────────────────────────────────────────────────────────────┤
│ L0  Owner's data plane (unchanged): CDN · WAF · origin · IdP · DNS    │
└───────────────────────────────────────────────────────────────────────┘
```

**Privilege model**
- Watchers hold read-only credentials scoped per source.
- Adapters hold no standing write credentials by default. The default write path is a pull request to the owner's infra repo, which branch protection and the owner merge. That is the Unit 42 lesson: branch protection held.
- The optional "direct apply" path is per-adapter, per-envelope, time-boxed, and still needs a signed approval token.
- The bot (L5) talks only to L4. It can read, explain and propose. It cannot sign approvals.

**Self-defense of the control plane** (assume Sentinel is the next Bitget target)
- Signed releases (cosign) and reproducible builds. SBOM and Scorecard on the Sentinel repo itself.
- Hash-pin MCP and tool definitions (OWASP MCP guidance). Ingested logs and web content are data and never instructions. Prompt-injection canaries go in its own inputs.
- No egress from correlation workers except to declared sinks (cuts Willison's exfiltration leg).
- Approval keys live on the humans' devices (passkeys or hardware keys), never on the box.

## 6. Profiles

### 6.1 Civic / election (`profile: civic`)
- Scope: results pages, voter lookup, polling-place finder, candidate filing portals, admin back-office.
- Defaults: change-freeze calendar (filing deadlines, early voting, election day, canvass). Surge lanes for `/results`. Static-fallback mirror check. CT and dnstwist lookalike watch for the jurisdiction's names. Passkey-only admin behind ZTNA. Defacement and integrity probes every minute on election night. Draft comms templates (status page, public notice).
- Freeze desk roster: CISA regional director (the 2026 plan names them Election Security Advisors), state fusion center, state election director, registrar, CDN, IdP vendor. EI-ISAC is **not mentioned** in CISA's 2026 plan, so it's included only if the jurisdiction confirms access.
- VRDB alignment (CISA 2026 plan): check for phishing-resistant MFA, network baseline, least privilege, ≥1-year logs with change reversal, and **separation of public lookup/registration from the system of record**. Point to CISA's free Canaries/Canary Tokens service before deploying Sentinel's own tripwires. Third-party vendor access is treated as insider risk (the Polymarket lesson applies: vendor JS on any authenticated election-admin page is red).
- Evidence: maps to the CISA election plan service areas, CIS election guidance and NIST CSF 2.0.
- Anti-job emphasis: no content or speech decisions, no voter data in the bot, no PII leaves the owner's tenancy.

### 6.2 Enterprise web (`profile: enterprise`)
- Scope: marketing and app sites, public APIs, login/ATO, checkout, AI chat endpoints.
- Defaults: lane policy with Web Bot Auth verification (IETF drafts on RFC 9421, still Internet-Drafts as of Oct 2026; a pinned, swappable adapter). ATO velocity detection across IdP and app. KEV↔SBOM matching with virtual-patch proposals. Third-party script integrity. AI endpoint guardrails following the OWASP Agentic Top 10 (tool allowlists, no-exfil egress, human confirmation for sensitive tools). Supply-chain advisory intake with rotation playbooks (Shai-Hulud class).
- Integrations: Cloudflare/Fastly/Akamai, Okta/Entra/Keycloak, Datadog/Splunk/Elastic via Sigma, PagerDuty/Slack.

### 6.3 Crypto hot-wallet ops hygiene (`profile: custody-ops`)
- Scope: exchange or treasury **operational** posture. **No keys, no signing, no fund movement.**
- Defaults: a pre-authorization ledger (delegations, approvals, allowances, hot-wallet limits as documented by the operator). Withdrawal-anomaly watch from read-only data. Signing-UI integrity probes (served JS hash vs. signed build; Bybit lesson). Security-vendor change watch (Bitget lesson: alert when any security product's config or version changes outside a ticket). Freeze-desk roster (stablecoin issuers' published law-enforcement or compliance contacts, SEAL 911, chain-analytics partners, IC3) with a time-to-freeze KPI.
- Not a crypto-only product: the same freeze desk and pre-authorization ledger apply to OAuth tokens and API keys in the enterprise profile.

## 7. How it differs from Security Audit Bot

| | Security Audit Bot | Perimeter Sentinel |
|---|---|---|
| Target | A repository (source) | A live site the owner operates |
| Cadence | One-shot or re-audit | Always-on, with routines and on-call |
| Inputs | Source tree, scanners, Cloudflare security-audit skill | Telemetry, configs, external probes of own assets, threat feeds |
| Output | Private findings report + smallest fix | Approved change cards, freeze drills, evidence ledger, daily brief |
| Writes | None (no pushes unless asked) | Proposals → PR or approved envelope, never self-approved |
| Touches live systems | Never | Read-only on owner's systems, writes only after approval, never on third parties |
| Handoff | Sentinel sends "this needs a code fix" to Security Audit Bot | Security Audit Bot sends "this needs runtime coverage" to Sentinel |

## 7A. Competitive positioning (sources: RESEARCH.md §10.3)

**The market as of Oct 2026:** Forrester has renamed the category **"Bot and Agent Trust Management"**. Cloudflare (Signed Agents, Aug 2025), HUMAN (AgenticTrust, Jul 2025), DataDome (Agent Trust, "AI Control Plane"), Akamai (Agentic Security Framework, Jun 2026), Kasada (AI Agent Trust, Jan 2026), F5/Shape (agentic protections, Sep 2026) and Imperva all ship verified-agent identity plus policy at their edge. Payment-page script integrity is a mature paid market too (Cloudflare Client-Side Security, Akamai, c/side, Jscrambler, Feroot, Source Defense, Reflectiz).

**Where Sentinel does *not* compete:** edge detection, CAPTCHA/challenge serving, bot-score models, DDoS absorption, payment-page script *blocking* in the browser. They have the network data and the edge. We don't.

**Where Sentinel wins (white space, based on public vendor material; to be verified per vendor):**
| Need | Bot/edge vendors | Perimeter Sentinel |
|---|---|---|
| One console across **multiple** CDNs and bot vendors | Each covers its own edge | **Adapters for Cloudflare, Akamai, DataDome, HUMAN, Kasada, Fastly, Coraza.** Reads verdicts and proposes rule changes as change cards. |
| Two-person, signed change control for security rules | Vendor RBAC and audit logs | **GitOps change cards, OPA guardrails, approval cards showing raw diffs** |
| **Freeze Desk** (issuer, registrar, regulator and vendor rosters, prefilled drafts, stopwatch, drills) | Not offered (public material) | **Core feature**, built from the Oct 29 incidents |
| Audit-grade evidence (CSF 2.0, 800-53, FedRAMP 20x KSIs, PCI 11.6.1, OSCAL) | Partial, per product | **Hash-chained ledger + OSCAL export** |
| Open source, self-hosted inside a federal or election boundary | SaaS | **Apache-2.0, air-gap capable** |
| Civic/election profile, free tier, neutrality rules | Athenian/Project Shield cover the edge only | **Turnkey ops on top of those** |

**Positioning line:** *"Your edge vendors detect. Perimeter Sentinel helps your team notice across all of them, approve the right change, freeze in minutes, and prove it."*

**Naming caution:** DataDome uses "AI Control Plane". Keep "control plane" as an architecture term and lead marketing with **"operator console + freeze desk + evidence ledger"**.

**Steal (ideas, not code):**
- Cloudflare's agent categories (Search / Agent / Training) as lane sub-classes.
- DataDome's 0–100 trust score that also covers **MCP servers**.
- HUMAN's per-action agent policy (browse vs. login vs. checkout).
- Akamai/Visa "Know Your Agent" and TAP as a pluggable identity input.
- F5's persistent device context.
- The academic multi-layer features: TLS/H2, header consistency, timing, behavior.

**Never claim:**
- "Detects X% of AI agents" (academic lab numbers, not ours).
- "Replaces your bot manager / WAF / CSP vendor".
- "The only PCI 11.6.1 solution".
- "Unhackable" / "prevents breaches".
- "AI control plane" as a brand.
- "Verified agents are safe" (identity is not intent).

---

## 8. Open source, creator-revenue only (v6 change, Oct 29, 2026)

**Owner decision (Phil, Oct 29):** **no paid product tiers.** No managed SaaS, no paid signal packs, no paid support SLAs, no paid compliance packs. The only revenue is **creator revenue from the Grok Bot** (Perimeter Sentinel as a published bot). Everything else is free and Apache-2.0.

| Free (everything) | Not offered |
|---|---|
| `perimeterctl` CLI, policy core, all watchers and adapters, profiles (civic, enterprise, custody-ops, federal), Sigma/ADS detections, drills, evidence ledger + OSCAL export, Grok Bot skills, Security School curriculum | Managed/hosted Sentinel · paid signal packs · paid SLAs · paid compliance packs · paid exercises |

**What this changes (and simplifies):**
- **No FedRAMP, SOC 2 or bank-service-provider burden from us.** Sentinel is software owners self-host. Their ATO, TPRM and PCI scope covers it like any OSS tool, so it still needs a clean SBOM, signed releases, an SSDF attestation and a threat model. §0A claims that referred to "Managed Sentinel" are now **moot**. Federal, election and bank buyers get self-hosted only.
- **Liability posture improves.** No SaaS, no custody of customer data, no SLA promises. The license disclaimer plus a clear "decision support, operator-approved" README.
- **Sustainability risk is real.** Creator revenue must fund maintenance, signal curation and security response. Mitigations: the CNCF/OpenSSF-style governance path, community maintainers, and grant programs (e.g. civic/open-source security funds; not researched yet).
- **The civic tier is simply the product.** It's free for everyone, so there's no "subsidy" story.
- **The trademark still matters** (TRADEMARKS.md) to stop look-alike paid forks from claiming to be the official Perimeter Sentinel.

Licensing hygiene (all verified Oct 29, 2026): never vendor AGPL (TruffleHog, Velociraptor, **Wazuh engine**) or GPL-3-with-clarifications (Canarytokens) code. Never vendor Tyk's commercial `ee/`. SEAL Frameworks content is CC BY-SA 4.0: keep imported checklists attributed and share-alike, in their own directory. Call them as separate processes or services. Don't redistribute Semgrep-maintained rules (use Opengrep or your own). Never redistribute CrowdSec blocklist data.

## 9. Federal and Google-scale story

- **Federal credibility:** an evidence ledger mapped to NIST CSF 2.0, SP 800-61r3 and 800-53. A zero-trust admin plane (800-207). Signed supply chain (SSDF 800-218, SLSA, Sigstore). Human-in-the-loop for every write. Data stays in the owner's tenancy. Air-gapped / GovCloud-deployable. Accessibility-safe friction (PoW and passkeys rather than image CAPTCHAs, with a no-JS fallback lane).
- **Google-scale ambition, honestly framed:** BeyondCorp-style access for ops, detection-as-code with tests and precision metrics, SRE incident command, multi-site fleets (one control plane, thousands of properties), and vendor-neutral adapters so a large org can run Sentinel over several CDNs at once. The global ML data network stays with vendors; Sentinel is the neutral brain that coordinates them.
- **Why now:** machine-tempo attacks (Anthropic, Unit 42), bots above 50% of traffic, thinner federal election support, and three exchange incidents in 20 months that were coordination failures at least as much as technical ones.

## 10. Roadmap

| Version | Theme | Ships |
|---|---|---|
| **v0.1** (4–6 wks) | See + evidence + **minimal Freeze Desk** (Oct 29 bar, §0) | `perimeterctl init/inventory/watch/brief/freeze`. Watchers: DNS, CT, TLS, **third-party script inventory + served-script hash drift (including vendor-hosted) + CSP report sink**, **external-signal intake (X)**, **read-only on-chain tier-0 watch** (declared wallets: delegation/code change, limit breach), KEV+OSV vs SBOM. Freeze Desk v0: two playbooks (vendor-script compromise, hot-wallet drain), rosters, prefilled drafts, stopwatch, time-to-freeze KPI. Hash-chained ledger. Civic, enterprise and custody-ops stubs. Grok Bot getting-started + daily brief. Still no write credentials: the operator executes every freeze. |
| **v0.2** | Propose | Change-card schema, GitOps PR adapter, Coraza/CRS and Anubis policy adapters, two-person approval, rollback. |
| **v0.3** | Freeze desk v1 | Full playbook library, drill scheduler, pre-approved envelope execution through owner adapters (edge CSP kill, session revoke), pre-authorization ledger v1. |
| **v0.4** | Lanes | Lane policy model, Web Bot Auth verifier adapter, friction ladder envelopes, CrowdSec and Envoy/Kong adapters. |
| **v0.5** | Notice | Swarm score v1, **multi-layer and behavior-first**: JA4 core and H2, header-consistency, request timing, and optional owner-deployed interaction telemetry (opt-in, aggregated, short retention, off by default in the civic profile). IP reputation is a minor feature only, because agent swarms use legitimate cloud IPs (GTIG Sep 2026). Edge-vendor verdict adapters (Cloudflare, DataDome, HUMAN, Akamai, Kasada). Sigma pack, Falco/Tetragon ingestion, agent tripwires v1 (alert-only, timing-confirmed). |
| **v0.6** | AI endpoints | OWASP Agentic Top 10 checks for the owner's own AI endpoints: tool-definition pinning, egress policy, confirmation gates. Integrations: promptfoo/garak on own models only. |
| **v0.8** | Custody-ops | Full custody-ops profile (SEAL SFC-IR checklist import), security-vendor change watch, richer withdrawal-anomaly models. The basic signing-UI probe and tier-0 wallet watch shipped in v0.1. |
| **v0.9** | Hardening | Self-audit by Security Audit Bot, external audit, reproducible builds, SLSA L3 target, threat model published. **Because attackers now mint valid SLSA L3 attestations with stolen CI OIDC tokens (GTIG, UNC6780):** pin signer identity (repo + workflow + ref), require two-person release approval outside CI, and monitor Rekor for unexpected signatures on Sentinel's identity. |
| **v1.0** | Production | Stable schemas, multi-site fleet, civic pilot with 2–3 jurisdictions, CSF 2.0/800-53 evidence export. |

## 11. Risk and liability notes

- **False sense of security (the biggest risk).** If an election or federal site is breached "while protected by Sentinel", the reputational and legal damage falls on the project. Mitigation: positioning language ("reduces time-to-notice and time-to-contain"), no prevention claims, a published threat model, and an explicit list of what isn't covered.
- **Control plane as target.** Mitigation: out-of-band, proposal-only, human-signed approvals, no standing write creds, signed releases. Put a bug bounty on Sentinel itself before v1.0.
- **Automated self-DoS.** A bad envelope could block real voters or customers. Mitigation: envelopes auto-expire, rate-shed caps, canary rollout per route, one-command rollback, and a "never lane" for accessibility and assistive tech.
- **Dual-use drift.** Contributors may push offensive features. Mitigation: CONTRIBUTING.md bans exploit, payload and C2 code; CODEOWNERS review on detection content; detections describe behavior only.
- **Legal:** CFAA/computer-misuse risk if anything ever touched third parties. Hence the hard anti-job. Data protection (GDPR/CCPA/state law) for logs: minimize and set retention. Liability caps and "no warranty" in Apache-2.0, plus commercial contracts with SLAs that stop short of guaranteeing outcomes.
- **Name/trademark:** "Sentinel" collides with Microsoft Sentinel, HashiCorp Sentinel and SentinelOne. Run a trademark search before launch. The CLI avoids the word (see REPO_OUTLINE.md).
- **Vendor ToS:** some CDN and bot vendors restrict automated config changes or redistribution of their signal. Adapters must respect them.
- **Civic neutrality:** keep the bot out of content and political decisions to stay trusted by both parties.

## EXECUTIVE SUMMARY (read first)
1. Perimeter Sentinel is an open-source (Apache-2.0), Grok Bot–operated **control plane** for a live site's security posture. It sees, notices, proposes, and runs freezes. Humans approve, and your existing edge enforces.
2. It is not a WAF or CDN. It orchestrates Coraza/CRS, Anubis, CrowdSec, Keycloak, Falco/Tetragon, Gitleaks, OSV/Trivy, CT/dnstwist and vendor edges.
3. What's new: traffic lanes (human / verified-agent / unknown) priced by a friction ladder, agent tripwires on your own property, a pre-authorization ledger, what-the-world-sees integrity probes, and a drilled Freeze Desk with a time-to-freeze KPI.
4. It is built to survive its own compromise: proposal-only, human-signed approvals, no standing write creds, signed releases. That is the Bitget lesson.
5. Three profiles: civic/election, enterprise web, custody-ops (no keys and no fund movement, ever).
6. Hard anti-jobs: never touches third parties, no offensive tooling, never self-approves, no content or political decisions.
7. Business model: **creator-revenue only** (the Grok Bot). All code, profiles and detections are free under Apache-2.0. There are no paid tiers, no SaaS and no SLAs (§8).
8. v0.1 (4–6 weeks) must pass the Oct 29 bar: catch a vendor-script swap or a hot-wallet delegation change within minutes, ingest X alarms, and run the freeze playbooks with a stopwatch. It still holds no write credentials. v1.0 adds fleet scale, managed GA and a civic pilot.
9. Naming: keep "Perimeter Sentinel" as the working name pending counsel (it collides with PerimeterX/HUMAN, Perimeter 81, and Microsoft/HashiCorp Sentinel). The CLI is `perimeterctl`.
10. Federal / election / banking: **yes with limits** (§0A). It is an evidence and freeze-speed layer, never the blocker. The best wedge is PCI 11.6.1/6.4.3 script integrity, FedRAMP 20x KSI evidence, and election-week freezes on top of free Athenian/Project Shield.
11. Competition (§7A): every bot vendor now ships verified-agent policy, and DataDome even says "AI Control Plane". Sentinel doesn't fight on detection. It's the cross-vendor operator console + freeze desk + evidence ledger that ingests their verdicts.
12. Biggest risk: overclaiming. A breach of a "protected" election site would hurt the brand. Sell time-to-notice and time-to-contain, not prevention.
