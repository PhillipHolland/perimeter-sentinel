# Perimeter Sentinel: Security School

> The curriculum Perimeter Sentinel (the Grok Bot and its CLI `perimeterctl`) is taught from. Every lesson maps to the four verbs: **See** (inventory and baseline), **Notice** (detect drift and abuse), **Propose** (change cards for humans to approve), **Freeze** (pre-approved, drilled containment). Defensive only: concepts, controls and detection ideas, with no attack procedures.
>
> Built Oct 29, 2026 (~8:30 PM CT). Sources are primary where possible (NIST, CISA, OWASP, MITRE, IETF/RFC, SLSA, project docs), plus classic papers and free courses. Sources marked *[bk]* are cited from background knowledge and were not re-opened this session.

## How the bot uses this file
- Each module becomes a section of the bot's `perimeter-sentinel` skill (or a linked reference), so the bot explains *why* it raises each alert or change card in plain language a county clerk or bank SOC analyst can follow.
- Every change card and brief must cite **which lesson** it applies (e.g. `lesson: L4 zero-trust / least privilege`). That makes the reasoning auditable.
- "Quiz" lines are self-checks the bot runs in its getting-started flow and quarterly drills. They test the operator's setup, not the human.

---

## Module 0: Principles that outrank everything
**Learn:**
- Saltzer & Schroeder's design principles (1975): economy of mechanism, fail-safe defaults, complete mediation, open design, separation of privilege, least privilege, least common mechanism, psychological acceptability. https://web.mit.edu/Saltzer/www/publications/protection/
- Ken Thompson, "Reflections on Trusting Trust" (1984): you can't fully trust code you didn't build, and that includes the toolchain. https://www.cs.cmu.edu/~rdriley/487/papers/Thompson_1984_ReflectionsonTrustingTrust.pdf
- Kerckhoffs's principle: security must not depend on secrecy of the design *[bk]*.

**Sentinel behavior:**
- **Fail-safe defaults:** when a watcher can't decide (timeout, parse error, an LLM triage refusal), the result is "needs human", never "OK".
- **Separation of privilege:** two-person approval on every write, and no self-approval.
- **Open design:** the open-source rules and policies are the product. There is no security through obscurity.
- **Psychological acceptability:** approval cards must be one-screen, with raw diffs plus a plain-language summary.

## Module 1: CIA triad (+ authenticity, accountability)
**Learn:** confidentiality, integrity, availability. Anderson, *Security Engineering* 3rd ed., free chapters: https://www.cl.cam.ac.uk/archive/rja14/book.html . NIST glossary definitions *[bk]*.

| Property | See | Notice | Propose | Freeze |
|---|---|---|---|---|
| **Confidentiality** | Where secrets and PII live, and who can reach them | Secret exposure (Gitleaks), unexpected egress | Rotate, restrict scopes | Revoke tokens and sessions |
| **Integrity** | Signed build manifest, served-script hashes, DNS desired state | Drift: served JS ≠ build, DNS ≠ repo, new CT cert | Re-pin SRI, revert, tighten CSP | Kill the vendor script, static fallback |
| **Availability** | Capacity baselines, upstream dependencies | Surge-vs-swarm split, origin errors | Lane budgets, cache rules | Lane lockdown, "under attack" mode |

**Sentinel behavior:** every alert is tagged with the CIA property at risk. The **civic profile ranks integrity and availability first**: the office's information must be correct and reachable. **Custody-ops ranks integrity of the signing path first.**

## Module 2: NIST CSF 2.0 (Govern, Identify, Protect, Detect, Respond, Recover)
**Learn:** NIST CSWP 29 (Feb 26, 2024), 6 functions / 22 categories / 106 subcategories. https://csrc.nist.gov/pubs/cswp/29/the-nist-cybersecurity-framework-csf-20/final . CISA CPGs: https://www.cisa.gov/cross-sector-cybersecurity-performance-goals

| CSF function | Sentinel verb | Concretely |
|---|---|---|
| **Govern (GV)** | (all) | Scope gate, owner affirmation, roles and rosters, risk appetite in policy files, the ledger |
| **Identify (ID)** | **See** | Assets, routes, scripts, vendors, identities, pre-authorization ledger |
| **Protect (PR)** | **Propose** | Change cards for WAF/edge, IdP, CSP/SRI, lanes |
| **Detect (DE)** | **Notice** | Watchers, swarm score, tripwires, external intake |
| **Respond (RS)** | **Freeze** | Playbooks, envelopes, comms drafts, stopwatch |
| **Recover (RC)** | **Freeze → Propose** | Unfreeze checklist, root-cause card, post-incident review |

**Sentinel behavior:** the daily brief is organized by CSF function. Evidence exports carry CSF subcategory IDs. **Govern comes first:** Sentinel refuses to run watchers until scope, owner and roster exist.

## Module 3: Zero trust basics
**Learn:** NIST SP 800-207 (2020): never trust network location, authenticate and authorize every request, least privilege, continuous evaluation. https://csrc.nist.gov/pubs/sp/800/207/final . CISA Zero Trust Maturity Model v2.0 (identity, devices, networks, applications/workloads, data, plus visibility/analytics, automation/orchestration, governance): https://www.cisa.gov/zero-trust-maturity-model . Google BeyondCorp: https://ai.google/research/pubs/pub43231 . NIST SP 800-63-4 digital identity (final): https://csrc.nist.gov/pubs/sp/800/63/4/final

**Sentinel behavior:**
- **See:** an identity map of who/what can change the edge, DNS, IdP and signing.
- **Notice:** admin surfaces reachable from the internet, and non-phishing-resistant MFA on privileged roles.
- **Propose:** move admin behind ZTNA (Pomerium/OpenZiti), passkeys.
- **Freeze:** revoke sessions across the board ("synchronized containment").
- **Self-application:** Sentinel has **no standing write credentials**. Every write is a just-in-time, scoped, expiring grant. Its traffic lanes are zero trust for visitors: a verified signature buys identity, not trust.

## Module 4: OWASP Top 10:2025 + Agentic Top 10 (2026)
**Learn:** OWASP Top 10:2025 (8th edition): A01 Broken Access Control · A02 Security Misconfiguration · **A03 Software Supply Chain Failures (new)** · A04 Cryptographic Failures · A05 Injection · A06 Insecure Design · A07 Authentication Failures · A08 Software or Data Integrity Failures · **A09 Security Logging & Alerting Failures** · **A10 Mishandling of Exceptional Conditions (new)**. https://owasp.org/Top10/2025/ ; intro https://github.com/OWASP/Top10/blob/master/2025/docs/en/0x00_2025-Introduction.md . OWASP Agentic Top 10 2026 (ASI01–ASI10): https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ . OWASP Automated Threats (OAT) handbook: https://owasp.org/www-project-automated-threats-to-web-applications/

**Mapping (runtime posture only; code audit is the sibling Security Audit Bot's job):**
| Risk | What Sentinel does |
|---|---|
| A01/A07 | Notice ATO velocity and admin exposure. Propose step-up and passkeys. |
| A02 | Notice header/CSP/TLS/DNS misconfig drift. Propose fixes as PRs. |
| A03 / A08 | See vendor scripts and SBOM. Notice served-script drift, KEV hits, and new signers on dependencies (signed ≠ safe, RESEARCH §10.2). |
| A05 | Coraza/CRS virtual-patch proposals. Never auto-enabled. |
| A09 | **Sentinel is an A09 control:** it proves logs exist, alerts fire, and someone acknowledged them (ledger). |
| A10 | Sentinel's own watchers fail closed to "needs human" (Module 0). |
| ASI01/02/06/09 | Sentinel's own agent: CaMeL-style data/control separation, no memory writes from ingested content, raw diffs on approval cards |
| OAT-008 credential stuffing, OAT-011 scraping, OAT-021 denial of inventory, etc. *[bk: OAT numbering]* | Classify swarm alerts using OAT names so bot-defense vendors and SOCs share vocabulary |

## Module 5: Kill chain, ATT&CK, Pyramid of Pain (high level)
**Learn:**
- Lockheed Martin "Intelligence-Driven Computer Network Defense" (Hutchins, Cloppert, Amin, 2011): recon → weaponize → deliver → exploit → install → C2 → actions. The defender only needs to break one link. https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/documents/cyber/LM-White-Paper-Intel-Driven-Defense.pdf
- **MITRE ATT&CK v20** (current; released Oct 13, 2026). v19 (Apr 28, 2026) split "Defense Evasion" into **Stealth** and **Defense Impairment**. The v19.2 agile release (Aug 2026) added **ShinyHunters (G1057), TeamPCP (G1056), Shai-Hulud (S9008)**. https://attack.mitre.org/resources/updates/updates-october-2026/ ; https://attack.mitre.org/resources/updates/updates-april-2026/ ; https://attack.mitre.org/resources/updates/updates-august-2026/
- David Bianco's **Pyramid of Pain** (2013): hashes and IPs are trivial for attackers to change, while TTPs are painful. https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html

**Sentinel behavior:**
- Every detection is tagged with an ATT&CK technique ID (pinned to the ATT&CK version it was written against, re-mapped on upgrade).
- **Pyramid of Pain → design rule:** prefer detections on behavior and TTPs (swarm patterns, delegation changes, drift) over IP/hash blocklists. Matches GTIG's finding that swarms run from legitimate cloud IPs.
- **Kill-chain → freeze rule:** each playbook names the earliest link it breaks (e.g. vendor-script playbook breaks "actions on objectives" via cancel-only, and "C2/exfil" via a CSP kill of the vendor domain).

## Module 6: Incident response lifecycle (NIST SP 800-61r3)
**Learn:** 800-61r3 (Apr 3, 2025) recasts IR as a **CSF 2.0 Community Profile**: preparation lives in Govern/Identify/Protect, and incident work in Detect/Respond/Recover. It is continuous, not a one-shot cycle. https://csrc.nist.gov/pubs/sp/800/61/r3/final . Google SRE incident command: https://sre.google/books/ . PagerDuty IR docs (Apache-2.0): https://github.com/PagerDuty/incident-response-docs . SEAL 911 War Room roles (CC BY-SA): https://frameworks.securityalliance.org/incident-management/playbooks/seal-911-war-room-guidelines/

**Sentinel behavior:**
- **Freeze Desk roles:** incident commander, scribe, comms, ops/vendor liaison, and legal/regulatory. Sentinel fills the **scribe** role automatically through the ledger and stopwatch, and **never** the incident commander.
- **Severity ladder** with time-based escalation: if a page isn't acknowledged in N minutes, page the backup (SEAL SFC-IR requirement).
- **Unfreeze is a first-class step:** an expiry, a checklist and a root-cause change card. Freezes that never thaw become outages.
- **Blameless post-incident review** template is generated from the ledger.
- **Out-of-band verification** before acting on any freeze request (deepfake and vishing lesson).

## Module 7: Logging and detection engineering basics
**Learn:**
- OMB **M-21-31** (Aug 2021): federal logging maturity tiers EL0–EL3, retention, centralized access. https://www.whitehouse.gov/wp-content/uploads/2021/08/M-21-31-Improving-the-Federal-Governments-Investigative-and-Remediation-Capabilities-Related-to-Cybersecurity-Incidents.pdf
- NIST SP 800-92r1 (initial public draft, log management planning). https://csrc.nist.gov/pubs/sp/800/92/r1/ipd
- **Palantir Alerting & Detection Strategy (ADS) framework:** each detection documents goal, ATT&CK category, strategy, blind spots, false positives, validation and response. https://github.com/palantir/alerting-detection-strategy-framework
- Sigma detection-as-code (§2 of RESEARCH.md). CISA's 2026 election plan asks for ≥1-year log retention with the ability to reverse unauthorized changes.

**Sentinel behavior:**
- **Every Sentinel detection ships as an ADS-style record** (YAML) with goal, ATT&CK ID, data sources, **blind spots**, false-positive notes, a validation drill and the linked playbook. No detection merges without a test.
- **Detections have SLOs:** precision and recall measured against drills, with alert fatigue tracked. A noisy detection gets demoted automatically to "digest" (with a human notified), not silenced.
- **Log readiness check** at setup: Sentinel scores the owner against M-21-31-style tiers and the CISA ≥1-year retention guidance before claiming coverage.
- **"No logs, no claim":** if a data source is missing, the brief says that coverage is blind. Sentinel never implies protection it can't see.

## Module 8: Cryptographic key hygiene (hot / warm / cold)
**Learn:**
- NIST **SP 800-57 Part 1 Rev 5**, key management: key types, cryptoperiods, generation, distribution, rotation, compromise recovery. https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final
- **CryptoCurrency Security Standard (CCSS)**: key generation, storage, usage, compromise policy, audits for custody. https://cryptoconsortium.org/standards/CCSS
- SEAL Frameworks: wallet security, multisig, EIP-7702 page (CC BY-SA). https://frameworks.securityalliance.org/
- **Tiering:**
  - **Hot:** online, automated signing, small balances, strict limits.
  - **Warm:** online but policy-gated or multisig, human approval.
  - **Cold:** offline, air-gapped ceremonies.
  - The Bybit and Binance lessons: the *signing path* (UI, policy engine, signer service) is as critical as the key.

**Sentinel behavior (custody-ops; never holds keys):**
- **See:** a pre-authorization ledger with tier labels, limits and cryptoperiods for every key and authority (including OAuth refresh tokens and API keys in enterprise).
- **Notice:** hot-tier balance above the declared cap, any delegation or code change on a hot wallet (tier-0), keys past their cryptoperiod, signing-UI drift.
- **Propose:** sweep-to-cold *suggestions* for the custody team, rotation, limit cuts.
- **Freeze:** issuer and partner freeze drafts and a stopwatch.
- **Hard line:** Sentinel never constructs, signs or broadcasts transactions.

## Module 9: DNS, TLS and Certificate Transparency basics
**Learn:**
- DNS and DNSSEC (RFC 4033). https://www.rfc-editor.org/rfc/rfc4033
- TLS 1.3 (RFC 8446). https://www.rfc-editor.org/rfc/rfc8446
- Certificate Transparency v2 (RFC 9162). https://www.rfc-editor.org/rfc/rfc9162
- Registrar lock, CAA records, HSTS preload *[bk]*.
- DNS-as-code (dnscontrol, octoDNS; RESEARCH §9).

**Sentinel behavior:**
- **See:** desired DNS state (from repo), CAA, registrar-lock status, cert inventory.
- **Notice:**
  - DNS drift from the repo
  - a CT entry for your names from an unexpected CA (CAA mismatch)
  - a lost registrar lock or upcoming expiry
  - dangling CNAMEs (takeover risk)
  - lookalike domains (dnstwist)
- **Propose:** CAA records, registrar lock, DNSSEC where the owner's provider supports it.
- **Freeze:** registrar and CDN emergency contacts in the roster, and a "lock DNS changes" envelope during election week.
- **Civic default:** election-week DNS change freeze, plus monitoring of the jurisdiction's `.gov` names (CISA .gov program).

## Module 10: Software supply chain (SLSA v1.2, SSDF, SBOM, Sigstore)
**Learn:**
- **SLSA v1.2** (Nov 24, 2025): Build track L0–L3 (L1 provenance exists, L2 hosted and signed provenance, L3 hardened builds) and a **new Source track L1–L4** (L4 = required code review). https://slsa.dev/spec/v1.2/ ; https://slsa.dev/blog/2025/11/announce-slsa-v1.2
- NIST SSDF SP 800-218. https://csrc.nist.gov/pubs/sp/800/218/final
- Sigstore/Rekor and OpenSSF Scorecard (RESEARCH §2). Thompson (Module 0).
- GTIG Sep 2026: TeamPCP minted **valid SLSA L3 attestations with stolen CI OIDC tokens.**

**Sentinel behavior:**
- **Verify *who* signed, not just *that* it's signed:** pin the expected repo, workflow and ref for Sentinel's own releases and for owners' critical dependencies.
- Target **SLSA Source L4** (required review) for Sentinel's repo, plus Build L3.
- **Notice:** a new release of a critical dependency from an unexpected workflow or signer, or Rekor entries for Sentinel's identity that don't match a release.
- **Third-party browser scripts are supply chain too** (A03:2025). The served-script probe is Sentinel's supply-chain control for the web. Watch signature-based SRI (`draft-west-sri-signature-profile`).

## Module 11: Bot vs. human traffic
**Learn:**
- OWASP OAT handbook.
- RFC 9421 + IETF webbotauth (RESEARCH §6.1).
- Academic multi-layer fingerprinting: FP-Agent, 2606.20910, 2606.30119 (RESEARCH §10.1).
- CAPTCHA-solving studies (Halligan USENIX Sec 2025).
- Anubis PoW docs.
- Imperva/Thales bad-bot reports (RESEARCH §1.4).

**Core ideas:**
- Identity ≠ intent.
- Browser fingerprints are weak. Behavior plus network-layer consistency is strong.
- CAPTCHAs are failing.
- Cost (PoW) adds friction, not certainty.
- Swarms come from legitimate IPs.
- Accessibility: friction must have a non-JS, non-visual path.

**Sentinel behavior:**
- **Lanes** (human / verified-agent / declared-automation / unknown / quarantine) instead of block/allow.
- **Surge-vs-swarm split:** election-night surges are *legitimate humans*. Never auto-tighten `/results` without the pre-approved envelope.
- **Accessibility gate:** every friction rung needs an accessible fallback, or the change card is rejected by policy (Section 508 for federal).
- **Privacy gate:** behavioral telemetry is opt-in, aggregated and short-retention, and off by default in the civic profile.

## Module 12: Security operations hygiene for the bot itself
**Learn:**
- *Building Secure and Reliable Systems* (Google, free). https://google.github.io/building-secure-and-reliable-systems/raw/toc.html
- NCSC 10 Steps. https://www.ncsc.gov.uk/collection/10-steps
- CISA/NSA "Careful Adoption of Agentic AI Services" (May 2026; RESEARCH §8.1).

**Sentinel behavior:**
- Least-privilege tokens with expiry.
- Human approval for every write.
- Reversible actions only.
- Logs of its own reasoning inputs (not secrets).
- Quarterly self-audit by Security Audit Bot.
- The tool-definition (MCP) pin file is checked in CI.

---

## Library (cast-wide reading list)

**Textbooks (free or open where noted)**
- Ross Anderson, *Security Engineering*, 3rd ed. (Wiley 2020; chapters free online). https://www.cl.cam.ac.uk/archive/rja14/book.html
- Adkins et al., *Building Secure and Reliable Systems* (Google/O'Reilly 2020, free online). https://google.github.io/building-secure-and-reliable-systems/raw/toc.html
- Google SRE books, especially the *Site Reliability Engineering* chapters on incident management (free). https://sre.google/books/
- *[bk]* Shostack, *Threat Modeling: Designing for Security* (Wiley 2014).
- *[bk]* Stoll, *The Cuckoo's Egg* (1989), the classic on log-driven detection and persistence.

**Free courses**
- Stanford **CS253 Web Security** (lectures free). https://web.stanford.edu/class/cs253/
- Harvard **CS50's Introduction to Cybersecurity** (free). https://cs50.harvard.edu/cybersecurity/
- MIT **6.858 / 6.5660 Computer Systems Security** (OCW / course site). https://ocw.mit.edu/courses/6-858-computer-systems-security-fall-2014/ ; https://css.csail.mit.edu/6.858/2023/
- **OpenSecurityTraining2** (free, deep technical). https://p.ost2.fyi/
- **CISA training catalog** (free; includes election security training). https://www.cisa.gov/resources-tools/training ; https://www.cisa.gov/topics/election-security/election-security-training ; free services list https://www.cisa.gov/resources-tools/resources/free-cybersecurity-services-and-tools
- **Google Cybersecurity Certificate** (Coursera; **paid subscription, with financial aid available**, so not free). https://grow.google/certificates/cybersecurity/
- **SANS Cyber Aces** (free intro) https://www.sans.org/cyberaces/ ; SANS white papers https://www.sans.org/white-papers/ and posters (e.g., hunt and IR posters) https://www.sans.org/posters/

**Classic papers**
- Saltzer & Schroeder, "The Protection of Information in Computer Systems" (1975).
- Thompson, "Reflections on Trusting Trust" (1984).
- Hutchins, Cloppert, Amin, "Intelligence-Driven Computer Network Defense…" (2011).
- Bianco, "The Pyramid of Pain" (2013).
- Ward & Beyer, "BeyondCorp: A New Approach to Enterprise Security" (2014).
- *[bk]* Anderson, "Why Cryptosystems Fail" (1993), on operational failures beating crypto failures, which is the Bybit and Binance pattern.
- Debenedetti et al., "Defeating Prompt Injections by Design" (CaMeL, 2025). https://arxiv.org/abs/2503.18813

**Standards shelf:** NIST CSF 2.0 · SP 800-53r5 (5.2.0) · 800-61r3 · 800-207 · 800-63-4 · 800-57 Pt1 r5 · 800-218 · 800-92r1 (draft) · OMB M-21-31 · CISA CPGs and ZTMM v2 · OWASP Top 10:2025, ASVS, OAT, Agentic Top 10 · MITRE ATT&CK v20 · SLSA v1.2 · RFC 4033/8446/9162/9421 · PCI DSS v4.0.1 · CCSS · SEAL Frameworks.

---

## Graduation: 10 lessons that change product behavior
1. **Fail closed to "needs human"** (Saltzer/Schroeder fail-safe defaults; OWASP A10:2025). Watcher errors, timeouts and LLM refusals never count as "clean".
2. **Govern before Detect** (CSF 2.0). No watcher runs without scope, owner affirmation and a freeze roster. Every brief is organized by CSF function.
3. **Detect behaviors, not indicators** (Pyramid of Pain + ATT&CK). The swarm score and tripwires key on TTPs and drift. IP and hash blocklists are minor features only.
4. **Every detection is an ADS record with blind spots and a drill** (Palantir ADS, Sigma). Nothing merges without a test, and noisy detections get demoted to a digest, not silenced.
5. **"No logs, no claim"** (M-21-31, OWASP A09, CISA ≥1-year retention). Sentinel scores log readiness first and states blind spots in every brief.
6. **Signed ≠ safe: verify who signed** (Thompson, SLSA v1.2, TeamPCP). Pin signer identity (repo, workflow, ref), monitor Rekor, and target SLSA Source L4 + Build L3 for Sentinel itself.
7. **Third-party browser scripts are supply chain** (OWASP A03:2025, PCI 6.4.3/11.6.1). The served-script probe is a tier-1 control on any authenticated or money-moving page.
8. **The signing path is part of the key** (SP 800-57, CCSS, Bybit/Binance). Custody-ops tracks hot/warm/cold tiers, cryptoperiods and hot-cap breaches, and treats any delegation change as tier-0. Sentinel never signs.
9. **Freezes must thaw, and must be verified out of band** (800-61r3, SRE incident command, deepfake PSA). Every envelope has expiry, an unfreeze checklist, a root-cause card, and second-channel confirmation before action. Sentinel is scribe, never commander.
10. **Friction must be accessible and private; identity is not intent** (zero trust, 800-63-4, Section 508, the academic fingerprinting work). Lanes never relax fraud checks for verified agents, every friction rung has an accessible fallback, and behavioral telemetry is opt-in and off by default for civic sites.
