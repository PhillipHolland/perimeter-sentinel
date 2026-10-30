# Security school, as product behavior

The lessons live in [SECURITY_SCHOOL.md](../../SECURITY_SCHOOL.md). This page is the short form that the code is expected to follow. A change card or a detection record cites a lesson id.

1. Fail closed. Status is `ok`, `finding`, or `needs_human`. An error is `needs_human`.
2. Govern before detect. Owner, affirmation `I operate these`, risk appetite, and a human commander with an out-of-band channel come before a watcher runs.
3. Detect behavior. An IP list or a hash list alone is not a verdict. `internal/correlate` rejects IP-only input.
4. Every detection has an ADS record and a validation line. `internal/ads` fails CI when the record is missing.
5. No logs, no claim. Readiness starts at EL0. The brief prints blind spots. Short retention is not EL3.
6. Signed is not safe. Pin the repo, the workflow, and the ref. An empty pin downgrades a match.
7. Third-party browser scripts are supply chain. Inventory them. Hash them. PCI 6.4.3 and 11.6.1 are the evidence shape, not a determination.
8. The signing path is part of the key. Sentinel does not sign and does not hold keys.
9. Freezes expire. Out-of-band confirm before the stopwatch starts. Thaw is a checklist.
10. Friction needs an accessible fallback. Civic behavioral telemetry stays off. A verified agent is not trusted intent.

Bot skills under `bot/skills/` repeat these rules so a Grok Bot session does not drift from the CLI.
