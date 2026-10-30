# Freeze desk

Two playbooks ship in v0.1. The Go catalog in `internal/freeze` is the source of truth. The JSON files in `playbooks/` are the same documents for operators who do not want to read Go. `go test ./internal/freeze` fails if they drift.

| Playbook | Contacts required before the stopwatch starts | Expiry |
|---|---|---|
| `vendor-script-compromise` | `cdn`, `status-page` | 4h |
| `hot-wallet-drain` | `issuer-usdc`, `issuer-usdt`, `ic3` | 12h |

Both require an out-of-band confirmation. Sentinel does not place that call.

Drafts rendered at freeze start are unsent. The static templates in `templates/` are the same wording with no facts filled in. Do not add exploit detail to either copy.

The stopwatch compares time-to-notice and time-to-contain with provisional public clocks from 29 October 2026. The KPI text says the comparison is not prevention. Benchmarks: vendor-script notice 35 minutes and contain 55 minutes; hot-wallet notice 8 minutes and contain 24 minutes (USDC reported near 24 minutes, USDT near 37 minutes). Root cause of the hot-wallet event is undisclosed.
