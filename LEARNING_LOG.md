# Learning log: Perimeter Sentinel

## 2026-10-29, v2 "Learn more" pass (around 7:45 PM CT)
Defensive-only research. No bot created, nothing posted. v1 backups are in /tmp/*.v1.md on the box.

### Verified
- **Licenses** (GitHub license API or LICENSE file):
  - Coraza, Falco (+rules), Tetragon, OSV-Scanner, Trivy, Grype, Syft, cyclonedx-cli, Keycloak, cosign/Rekor, Scorecard, CRS, ModSecurity, Pingora, Envoy/Envoy Gateway, Caddy, Kong, APISIX, Pomerium, OpenZiti, dnstwist, garak, GRR and NeMo Guardrails are Apache-2.0.
  - Anubis, CrowdSec engine, Gitleaks, BotD, promptfoo and LLM Guard are MIT. authentik core is MIT, with its own license on `enterprise/`.
  - OpenCanary is BSD-3-Clause, nginx BSD-2-Clause, and Zeek BSD-style.
  - Sigstore is Apache-2.0.
  - Copyleft: TruffleHog and Velociraptor AGPL-3.0. Semgrep, Opengrep and pySigma LGPL-2.1. osquery dual Apache-2.0/GPL-2.0. Suricata, fail2ban and AIDE GPL-2.0. Canarytokens GPL-3 with Thinkst clarifications. Tyk MPL-2.0 except commercial `ee/`. Sigma rules DRL 1.1. SEAL Frameworks CC BY-SA 4.0.
- **CISA 2026 Election Infrastructure Security Plan:** read the PDF itself. The "confirmed success in at least 20 states" voter-registration claim is CISA's own text, footnoted to a CISA 2026 report, but the underlying evidence isn't published. Also read the VRDB safeguards, the free Canaries service, regional directors as Election Security Advisors, and the fusion-center channel. EI-ISAC does not appear.
- **FBI/CISA PSA (Oct 16, 2026):** AI-enhanced phishing and deepfakes against election officials.
- **NIST:** CSF 2.0 (Feb 26, 2024). SP 800-53 Rel 5.2.0 (Aug 27, 2025; SA-15(13), SA-24, SI-02(07), SI-07(12)). The CSF→800-53 OLIR mapping exists. 800-61r3 (Apr 3, 2025).
- **Anthropic GTG-1002:** canonical URL plus the full-report PDF. Anthropic's own Nov 14 wording correction is noted.
- **Unit 42:** published Sep 2, 2026 and updated Sep 3. Its defender guidance ("synchronized containment") is captured.
- **Web Bot Auth:** the WG charter puts APIs, end-user auth, intent and reputation out of scope. Milestones slipped; the protocol is still `-01` I-D. RFC 9421 is Standards Track (Feb 2024).
- **Thinkst Agent Provocateur** (Sep 4, 2026). **SEAL** SFC-IR checklist and War Room roles.
- **Polymarket Oct 29:** checked the status page timeline (primary), CNBC, BleepingComputer and the Defiprime reconstruction. DebugBear's own X post.
- **Binance Oct 30 update:** Blockaid "key misuse / signing infra" (preliminary) vs. BIA "almost certainly key compromise". The root cause is still undisclosed.
- **Name availability:** checked on PyPI, npm, crates.io and Homebrew.

### Corrected
- Wazuh was listed as "GPLv2" in v1. It is actually mixed: the engine is AGPL-3.0-or-later, some shared modules are GPL-2.0 OR AGPL-3.0, and the rest is GPL-2.0.
- The "20 states" claim moves from *unverified (X/Nextgov)* to *verified as CISA's statement, evidence undisclosed*.
- Election plan details now cite the CISA PDF instead of Nextgov alone. The funding and staffing gap still rests on Nextgov/AP, and the plan is silent on it.
- X handles:
  - @Matt_Blaze → **@mattblaze**
  - @SEAL_Org → **@SEAL_911** / @_SEAL_Org
  - The Anubis author is **@theprincessxena**
  - @HudsonRockCyber, @TecharoHQ and @cside_dev did not resolve.
- Anthropic: the hubs.ly redirect is replaced by the canonical URL.
- CLI name: `perimeter`/`pmt` → **`perimeterctl`**, because `perimeter` is taken on PyPI and npm and `pmt` on three registries.
- Web Bot Auth is no longer implied to be near-standard.
- **Product:**
  - The Freeze Desk is pulled from v0.3 into v0.1 (minimal).
  - Added a third-party script inventory, vendor-hosted script hash drift, external X intake, and a read-only on-chain tier-0 watch to v0.1.
  - Added the tripwire hard line: never induce code execution.

### Lessons encoded
1. Trusted-path compromise (vendor JS or the signing path) beats perimeter controls. Watch what production actually serves and what's actually signed.
2. Outsiders on X noticed first in both Oct 29 incidents, so external intake is a v0.1 feature.
3. Containment was coarse kill switches (cancel-only, relayer pause, issuer freezes). Pre-wire, pre-approve and drill them, and time them.
4. Front-end fixes don't reach open sessions, so forced session refresh belongs in the vendor playbook.

### Still unknown
- Binance root cause and final loss.
- Polymarket: whether DebugBear's compromise hit other customers, DebugBear's own root cause, whether the June vendor was the same, final victim totals, and the meaning of the Oct 27 CDN timestamp.
- go-away and iocaine licenses.
- ASI06 naming is secondary-sourced.
- Underlying evidence for CISA's "20 states".
- EI-ISAC's current status.
- Trademark clearance (needs counsel).

## 2026-10-29, v3 "federal / election / banking?" pass (~7:50 PM CT)
Defensive only. Nothing posted, no bot created. v2 backups are in /tmp/*.v2.md.

### Verified (primary unless noted)
- CISA + NSA + partners, "Careful Adoption of Agentic AI Services" (CISA release May 1, 2026). Read the press release; the PDF was not opened.
- FedRAMP Consolidated Rules 2026 / 20x (Jun 24, 2026). KSIs with persistent automated validation; Class C needs ≥2 automated methods per KSI. RFC-0008 continuous reporting.
- PCI DSS v4.0.1 6.4.3 / 11.6.1, mandatory since Mar 31, 2025 (SSC blog plus a mirrored SSC guidance PDF).
- FFIEC authentication guidance (Aug 11, 2021). FFIEC CAT sunset (Aug 31, 2025). Interagency TPRM guidance (Jun 6, 2023). 36h incident-notification rule (86 FR 66424); service providers ≥4h.
- FinCEN FIN-2024-Alert004 (deepfakes). NYDFS AI letters (Oct 16, 2024; May 21, 2026 frontier-AI advisory).
- CFPB §1033: enjoined Oct 29, 2025. Reconsideration NPRM at OIRA since Aug 2026 (secondary).
- Election cases: Georgia absentee portal bot flood (Oct 14, 2024; about 420k requests; human-verification check fixed it in about 30 min; AP/CBS). Mississippi election-info DDoS (Nov 8, 2022; MS SOS). Cloudflare Athenian Project and Google Project Shield (CISA-listed) are free for election sites.

### Conclusions encoded
- **Verdict: yes with limits.** Sentinel is a detection, evidence and freeze-speed layer. Blocking stays with the CDN, WAF, bot manager and IdP.
- The strongest regulatory fit is **PCI 11.6.1/6.4.3**, which is almost exactly v0.1's served-script probe and inventory, plus FedRAMP 20x KSI evidence.
- Election "protect" = availability, integrity and presentation of the office's own information only. Never content, eligibility or voting systems.
- Banking: an add-on to the SOC, not a fraud platform. Managed Sentinel likely carries bank-service-provider duties.

### Unknowns
- The CISA/NSA agentic-AI PDF wasn't read in full.
- No primary 2026 agentic-swarm election incident was found.
- Bank service-provider status, FedRAMP class and VVSG boundaries need counsel or a deeper read.

## 2026-10-29, v4 GitHub scour (~8:00 PM CT)
Read-only GitHub API via the authenticated `gh` CLI: about 40 searches plus metadata and LICENSE reads for about 75 repos. No bot created, nothing posted. v3 backups are in /tmp/*.v3.md.

### Learned
- **Biggest gap = opportunity:** no credible OSS for PCI 6.4.3/11.6.1 payment-page script integrity (only ≤1★ toy or agent-built repos), and incident/freeze-as-code is thin (Dispatch archived Sep 2025, monzo/response stale, CISA LME archived May 2026).
- **A standards path for the Polymarket failure:** `draft-west-sri-signature-profile` (signature-based SRI over RFC 9421), active today.
- **The attacker side is out-starring defenders:** stealth agent browsers (CloakBrowser ~32.6k★, camofox ~12.1k★) vs BotD ~1.5k★. This confirms the behavioral + signed identity + PoW cost strategy.
- **Composable finds:** cloudflare/web-bot-auth, go-csp-collector, gatus, certspotter (MPL), dnscontrol/octoDNS, octorules (WAF-as-code), OPA/conftest, flagd (kill switches), SAP cloud-active-defense, thumper, OSCAL/compliance-trestle, ScubaGear, sigstore policy-controller, finch/fingerproxy (JA4).

### Corrected / new license facts
- Unleash LICENSE = AGPL-3.0. Flipt = FCL-1.0-MIT. OpenZeppelin Monitor = AGPL-3.0. JA4+ = FoxIO License 1.1 (JA4 core differs).
- certspotter = MPL-2.0. MetaMask eth-phishing-detect = DBAD 1.2. Skald = Elastic License 2.0. Forta node = Forta Network License (BSL-style).
- TecharoHQ/samesame (Anubis Web Bot Auth) = AGPL-3.0, even though Anubis is MIT.

### Still unknown
- go-away and iocaine remain off GitHub, so their licenses are unverified. conftest and libcoraza licenses read NOASSERTION in the API (the LICENSE files weren't opened).
- Star counts are point-in-time. Young repos (octorules, deckard, thumper, mr-yum) are unproven.

## 2026-10-29, v5 academic + vendor intel + competitors (~8:20 PM CT)
Defensive only. Nothing posted, no bot created. v4 backups are in /tmp/*.v4.md.

### Verified (sources in RESEARCH §10)
- **Academic:**
  - FP-Agent (arXiv 2605.01247): behavioral features caught 7/7 agents vs. Cloudflare 1/7.
  - Multi-layer attribution (2606.20910): 97%, with about 3 requests enough for early classification.
  - "Nobody Knows You're an LLM Bot" (2606.30119): some agents bypassed every tested anti-bot measure, but all were fingerprintable, and stealth tooling increased detectability.
  - UI-trace model ID (2605.14786): 96% F1.
  - CAPTCHA solvers: Halligan (USENIX Sec 2025) 60.7%; reCAPTCHAv2 100% (2024); Open CaptchaWorld 40% vs. 93% for humans.
  - Exploitation benchmarks: CVE-Bench 13% zero-day / 25% one-day; one-day agent 87% with the CVE description.
  - Palisade LLM Agent Honeypot: 8 possible / 2 confirmed agents in about 8M attempts.
  - CaMeL: 77% of AgentDojo tasks solved with provable security.
- **Vendor intel:**
  - CrowdStrike GTR 2026: breakout 29 min avg, 27 s fastest; AI-enabled adversary activity up 89%.
  - M-Trends 2026: dwell 14 days; exploits 32%; vishing 11%.
  - Unit 42 IR 2026: exfiltration in 72 min for the fastest quartile.
  - GTIG Sep 8, 2026 (read in full): an agent credential-harvesting campaign built and run in under 6 h from legitimate cloud IPs; UNC6780 minting valid SLSA L3 attestations with stolen OIDC tokens; prompt injection against LLM scanners and coding assistants; ShinyHunters using AI to write code to get past Cloudflare; no fully autonomous exploitation pipelines seen in the wild yet.
- **Competitors** (with dates):
  - Cloudflare Signed Agents (Aug 28, 2025), AI Crawl Control, Client-Side Security.
  - HUMAN AgenticTrust (Jul 30, 2025) and open-source Verified AI Agent (MIT).
  - DataDome Agent Trust, which calls itself an "AI Control Plane".
  - Akamai Agentic Security Framework (Jun 15, 2026).
  - Kasada AI Agent Trust (Jan 22, 2026).
  - F5 agentic protections (Sep 15, 2026).
  - Imperva ABP.
  - Forrester Wave "Bot and Agent Trust Management, Q2 2026" exists (not read).
  - PCI client-side vendors: c/side, Jscrambler, Feroot, Source Defense, Reflectiz, Akamai, Cloudflare.

### Corrected
- §9.3's "almost no OSS for PCI 11.6.1" still holds for OSS, but a **mature commercial market exists**. We must not claim to be the only solution.
- The swarm-score spec is now multi-layer and behavior-first, with IP reputation demoted. CAPTCHAs are a last resort. Self-defense adds signer-identity pinning and Rekor monitoring.

### Design changes
- PRODUCT §7A competitive positioning: the cross-vendor console + freeze desk + evidence ledger, with vendor verdict adapters, avoiding the "AI control plane" brand.
- Behavioral telemetry is opt-in, aggregated, short-retention, and off in the civic profile.
- Sentinel's own agent gets CaMeL-style control/data separation.
- LLM triage treats a refusal or skip as "needs human review".
- Freeze playbooks require out-of-band verification (vishing/deepfakes).

### Still open
- Forrester Wave contents unknown.
- Vendor pages for HUMAN, DataDome and Akamai blocked my fetcher, so their details come from search summaries.
- No head-to-head test of any vendor.
- CrowdStrike and M-Trends exact release dates not confirmed.
- Academic results are small-sample lab studies.
- No independent 2026 data on agent-swarm attacks against civic sites.

## 2026-10-29, v6 Security School (~8:30 PM CT)
No bot created, nothing posted. v5 backups are in /tmp/*.v5.md.

### Built
- **SECURITY_SCHOOL.md:** 13 modules (principles, CIA, CSF 2.0, zero trust, OWASP Top 10:2025 + Agentic, kill chain/ATT&CK/Pyramid of Pain, 800-61r3 IR, logging/detection engineering, key hygiene, DNS/TLS/CT, SLSA supply chain, bot vs. human, the bot's own ops hygiene), each mapped to see/notice/propose/freeze. Plus a library (textbooks, free courses, classic papers, standards shelf) and 10 graduation lessons.

### Verified this pass
- OWASP Top 10:2025 list (new A03 supply chain, A10 exceptional conditions).
- ATT&CK v20 current (Oct 13, 2026). v19's Defense Evasion → Stealth + Defense Impairment split. v19.2 added ShinyHunters, TeamPCP and Shai-Hulud.
- SLSA v1.2 Source track (Nov 24, 2025).
- About 30 curriculum URLs checked live (NIST, OMB, CISA, RFCs, courses, classic papers).

### Corrected
- The Google Cybersecurity Certificate is not free.
- CISA's "CISA Learning" URL from memory was wrong; I'm using the CISA training catalog instead.

### Owner decision recorded
- **Creator-revenue-only, no paid tiers.** PRODUCT §8 is rewritten, and §0A, the roadmap and the exec summary are updated. Managed-tier compliance burdens (FedRAMP, SOC 2, bank service provider) are dropped. New risk: sustainability of maintenance and security response on creator revenue alone.

### Product behavior changes
See SECURITY_SCHOOL "Graduation":
- fail-closed `needs_human`
- Govern-first gating
- behavior over indicators
- ADS records with drills
- no logs, no claim
- signer-identity pinning + Source L4
- served scripts treated as supply chain
- hot/warm/cold tiers and cryptoperiods
- freezes thaw, with out-of-band confirmation
- accessible and private friction, identity ≠ intent

### Still open
- Items marked [bk] in SECURITY_SCHOOL (Kerckhoffs, Shostack, Stoll, Anderson 1993, OAT IDs) were not re-opened.
- Grant or funding options for a creator-revenue-only OSS project weren't researched.
