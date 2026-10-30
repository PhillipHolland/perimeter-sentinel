# Repo outline: Perimeter Sentinel

## Names
- **Repo:** `perimeter-sentinel` (GitHub org suggestion: `perimeter-sentinel` or under Phil's org)
- **CLI:** `perimeterctl` (v2 change). As of Oct 29, 2026 it is free on PyPI, npm, crates.io and Homebrew. `perimeter` is taken on PyPI (Django package) and npm (2016 package), and `pmt` is taken on PyPI, npm and crates.io, so both are dropped. Package and org name: `perimeter-sentinel`, which is free on all four registries and as a GitHub org, and `@perimeter-sentinel/cli` on npm. Claim them before announcing. Avoid `sentinel` alone (Microsoft Sentinel, HashiCorp Sentinel, SentinelOne). "Perimeter" also overlaps PerimeterX (now HUMAN Security, bot defense) and Perimeter 81 (Check Point), so get trademark clearance by counsel before commercial launch. See RESEARCH.md §7.
- **Language:** Go for the core and CLI. It builds a single static binary (air-gap friendly), is the same ecosystem as Coraza, Anubis, CrowdSec and Tetragon, and is easy to sign and reproduce. Grok Bot skills are Markdown plus small Python helpers where needed (matching Security Audit Bot).

## License recommendation
**Apache-2.0** for everything in the repo.
- It has an explicit patent grant, which federal and enterprise procurement and legal teams prefer. It matches CNCF and OWASP WAF projects (Coraza, CRS, Falco, Tetragon, Keycloak).
- MIT (the sibling's license) is fine but has no patent clause. Apache-2.0 is the better fit for a "sell at scale" product.
- Use DCO sign-off (no CLA) and add a `TRADEMARKS.md` that keeps the name and logo reserved. The trademark protects against look-alike paid forks. The project itself is creator-revenue-only, with no paid tiers (PRODUCT §8).
- `NOTICE` lists every external component, its license and how it is used. AGPL and modified-GPL tools are invoked as separate processes, never vendored.

## Layout

```
perimeter-sentinel/
├── README.md                 # what it is / is not, 5-min quickstart, threat model link
├── LICENSE                   # Apache-2.0
├── NOTICE                    # third-party components + how each is invoked
├── SECURITY.md               # vuln disclosure for Sentinel itself, PGP/age key, bounty
├── GOVERNANCE.md             # maintainers, "core stays Apache-2.0" pledge
├── CONTRIBUTING.md           # DCO; ban on exploit/payload/C2/offensive code
├── TRADEMARKS.md
├── THREAT_MODEL.md           # STRIDE on the control plane; "assume Sentinel compromised"
├── bot/                      # Grok Bot package
│   ├── bot-spec.md           # from CREATEAGENT_BRIEF.md
│   └── skills/
│       ├── perimeter-sentinel/SKILL.md
│       ├── perimeter-sentinel-getting-started/SKILL.md
│       ├── perimeter-freeze-desk/SKILL.md
│       ├── perimeter-daily-brief/SKILL.md
│       ├── perimeter-lanes/SKILL.md
│       ├── perimeter-tripwires/SKILL.md
│       └── perimeter-profile-{civic,enterprise,custody-ops}/SKILL.md
├── cmd/perimeterctl/         # CLI entrypoint
├── internal/
│   ├── scope/                # affirmation + DNS TXT ownership verify; deny-by-default targets
│   ├── ledger/               # hash-chained evidence log; optional Rekor anchoring
│   ├── cards/                # change-card schema, diff, expiry, rollback, signing verify
│   ├── approve/              # 2-person rule, WebAuthn/ssh-sig/age verification of approvals
│   ├── envelopes/            # pre-approved auto-expiring action classes
│   ├── inventory/            # posture graph (assets, routes, auth surfaces, AI endpoints, keys)
│   ├── correlate/            # swarm score, lane drift, KEV↔SBOM, preauth ledger
│   └── egress/               # allowlisted outbound sinks only
├── watchers/                 # read-only collectors, one dir each, sandboxed
│   ├── dns/  ct/  tls/  served-js/  kev/  osv/  dnstwist/
│   ├── edge-logs/ (cloudflare, fastly, nginx, envoy)  idp/ (keycloak, okta, entra)
│   ├── falco/  tetragon/  crowdsec/  advisories/ (npm, pypi, ghsa)  intake/ (news/X, read-only)
├── adapters/                 # write paths; all require an approved card
│   ├── gitops-pr/            # DEFAULT: open PR against owner's infra repo
│   ├── coraza-crs/  anubis/  envoy/  kong/  apisix/  crowdsec-bouncer/
│   ├── keycloak/  authentik/
│   └── vendor/ (cloudflare, fastly, akamai; some may live in a separate repo if SDK terms require)
├── profiles/
│   ├── civic/                # calendar, surge lanes, integrity probes, comms templates
│   ├── enterprise/
│   └── custody-ops/          # preauth ledger types, signing-UI integrity, vendor change watch
├── freeze-desk/
│   ├── playbooks/            # credential-leak, ddos-surge, defacement, supply-chain-advisory,
│   │                         # signing-ui-tamper, hot-wallet-anomaly (read-only), dns-hijack
│   ├── roster.schema.json
│   └── templates/            # draft messages: registrar, CDN, IdP, issuer, CISA region, IC3, status page
├── rules/
│   ├── sigma/                # detections (behavioral, no payloads)
│   ├── lanes/                # lane policy defaults
│   └── tests/                # fixtures are synthetic logs only
├── mappings/                 # NIST CSF 2.0, 800-53r5, 800-61r3, OWASP Agentic Top 10, CIS v8.1
├── deploy/                   # single-box systemd, docker compose, helm chart, air-gap bundle
├── docs/
└── .github/workflows/        # build, test, gitleaks, osv-scanner, scorecard, cosign sign, SLSA provenance
```

## First modules (v0.1: read-only "see + evidence" + minimal Freeze Desk; must pass the Oct 29 bar in PRODUCT.md §0)
1. `internal/scope`: deny-by-default target list, owner affirmation, DNS TXT verify. **Every** watcher calls it.
2. `internal/ledger`: append-only, hash-chained JSONL. `perimeterctl ledger verify`. Export to Markdown/PDF.
3. `watchers/dns`, `watchers/tls`, `watchers/ct`: baselines and diff alerts.
4. `watchers/served-js`: fetch the owner's own pages, hash script resources, compare to the signed build manifest, flag SRI/CSP drift.
5. `watchers/kev` + `watchers/osv`: match KEV and OSV against the owner's SBOM (CycloneDX/SPDX input, or Syft if the owner runs it).
6. `cmd/perimeterctl brief`: the daily brief generator the Grok Bot routine calls.
7. `bot/skills/perimeter-sentinel-getting-started` + `perimeter-sentinel` runbook.
8. `watchers/third-party-scripts`: per-page inventory of script origins, CSP and connect-src, with a "page has auth/signing session" flag. Hashes **vendor-hosted** scripts from external multi-region probes. Drift alerts on any change. Includes a CSP violation report sink.
9. `watchers/external-intake`: X keyword and named-account watch (brand + drained/hacked/compromised), deduped into alerts. Read-only.
10. `watchers/onchain` (custody-ops, read-only RPC/explorer): declared hot wallets. Alerts on code or delegation change (tier-0), limit breach, or a new destination. No keys and no tx construction, ever.
11. `internal/freeze`: playbooks `vendor-script-compromise` and `hot-wallet-drain`, roster schema, prefilled drafts, stopwatch, time-to-notice/contain KPI written to the ledger. The operator executes every action.
12. `drills/oct29/`: the five acceptance drills from PRODUCT.md §0.3, run against staging or testnet only.
13. `profiles/custody-ops/seal/`: imported SEAL checklists, kept **CC BY-SA 4.0** with attribution (not Apache).

## v0.2 modules
`internal/cards`, `internal/approve`, `adapters/gitops-pr`, `adapters/coraza-crs`, `adapters/anubis`.

## CI and self-protection
- Gitleaks, OSV-Scanner and OpenSSF Scorecard on every PR. Branch protection with two reviewers on `rules/`, `adapters/`, `internal/approve/`.
- Releases are signed with cosign (keyless OIDC), with SLSA provenance, reproducible builds and an SBOM attached.
- Pin hashes of any MCP/tool definitions the bot uses. CI fails on unreviewed changes.

## Must-adds from the GitHub scour (RESEARCH.md §9, Oct 29, 2026)
Compose these. Licenses were checked via the GitHub API or LICENSE files. Copyleft tools run as separate processes only.
- `watchers/csp-reports/`: embed or adapt **jacobbednarz/go-csp-collector** (MIT, Go) as the v0.1 CSP/Reporting-API sink.
- `watchers/probes/`: use **TwiN/gatus** (Apache-2.0, Go, YAML) or its config model for multi-region external probes. The script-hash and header-integrity logic stays custom, and it is the **PCI 6.4.3/11.6.1** evidence path. No credible OSS exists, so ship ours as a first-class `pci-script-integrity` module with QSA-friendly reports.
- `watchers/ct/`: run **SSLMate/certspotter** (MPL-2.0) as an external binary.
- `watchers/dns/`: read desired state from **dnscontrol** or **octoDNS** (MIT) repos when present, and diff it against live DNS.
- `adapters/edge-rules/`: adopt **octorules**'s plan/apply YAML model (Apache-2.0) for Cloudflare/AWS WAF/Cloud Armor/Azure change cards. Plan diff = approval card.
- `adapters/web-bot-auth/`: build on **cloudflare/web-bot-auth** test vectors and directory format (Apache-2.0). Use a reviewed Go RFC 9421 library. Do **not** vendor TecharoHQ/samesame (AGPL).
- `internal/policy/`: **OPA/Rego** (Apache-2.0) for change-card and envelope guardrails, with **conftest** in CI (check its license file first; the API shows NOASSERTION).
- `internal/freeze/flags/`: an **OpenFeature/flagd** (Apache-2.0) adapter so owners wire pre-approved kill switches (cancel-only, vendor-tag off, static fallback). Do **not** vendor Unleash (AGPL-3.0) or Flipt (FCL).
- `tripwires/`: integrate **SAP/cloud-active-defense** (Apache-2.0) decoys in alert-only mode, and **jestasecurity/thumper** (Apache-2.0) for CI/dev supply-chain tripwires.
- `watchers/onchain/` (custody-ops): call **OpenZeppelin Monitor** (AGPL-3.0) as a separate service via webhooks, or use the plain RPC watcher. Never link it in.
- `evidence/oscal/`: emit OSCAL assessment-results with **usnistgov/OSCAL** schemas, and offer **compliance-trestle** (Apache-2.0) integration for federal SSPs.
- `profiles/federal/`: optional **cisagov/ScubaGear** (CC0) run as an evidence source. Do **not** depend on cisagov/LME (archived May 2026).
- `ci/`: **falcosecurity/rules** pinned and tested in **falco-playground**. **sigstore/policy-controller** for "only signed Sentinel images run".
- `swarm/features/`: JA4 (core, permissive) via **finch** or **fingerproxy** (Apache-2.0). **Do not use JA4+ variants** (FoxIO License 1.1) without counsel.
- `docs/freeze-desk/roles.md`: adapt **PagerDuty/incident-response-docs** (Apache-2.0) with attribution.
- `THIRD_PARTY_LICENSES.md` + a CI license gate (e.g. a scanner that blocks AGPL, GPL-3, FCL, ELv2, DBAD and FoxIO in `go.mod`/`package.json`).

## Must-adds from Security School (SECURITY_SCHOOL.md, Oct 29, 2026)
- `detections/*.ads.yaml`: every detection is a Palantir-ADS-style record (goal, ATT&CK v20 ID, data sources, blind spots, false positives, validation drill, playbook link). CI rejects detections without a passing drill.
- `internal/readiness/`: log-readiness scoring (M-21-31-style tiers, ≥1-year retention check), shown in every brief as covered vs. blind.
- `internal/failsafe/`: a shared result type `ok | finding | needs_human`. Errors, timeouts and LLM refusals map to `needs_human`.
- `internal/freeze/thaw/`: envelope expiry, an unfreeze checklist, and a root-cause card generator. Out-of-band confirmation step before any freeze.
- `policy/accessibility.rego` + `policy/privacy.rego`: reject friction without an accessible fallback, and behavioral telemetry without opt-in (default off for civic).
- `docs/school/`: SECURITY_SCHOOL.md modules shipped as bot skill references. Change cards cite `lesson:` IDs.
- Release policy: SLSA Build L3 + **Source L4** (required review) for this repo, plus signer-identity pinning and Rekor monitoring.
