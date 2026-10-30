# Third-party licenses

v0.1 does not vendor third-party Go modules. `go.mod` lists only this module.

| Component | How v0.1 uses it | License | Rule |
|---|---|---|---|
| Go standard library | CLI, hashes, TLS dial | Go authors' BSD-style license | Linked. |
| SEAL Frameworks | Not copied. Pointer only in `profiles/custody-ops/seal/`. | CC BY-SA 4.0 | Do not relicense. Operator imports checklists themselves. |
| PagerDuty incident-response docs | Attribution for the scribe/commander idea. Text in `docs/freeze-desk/roles.md` is original. | Apache-2.0 | Do not paste their docs in. |
| certspotter | Not run. `watchers/ct` reads JSON lines. | MPL-2.0 | Separate process only, if the operator adds it later. |
| go-csp-collector | Not run. `watchers/csp-reports` parses a report body. | MIT | Separate process only, if the operator adds it later. |
| gatus | Not run. Probe intervals are config fields. | Apache-2.0 | Separate process only, if the operator adds it later. |
| OpenZeppelin Monitor | Not run. `watchers/onchain` is a read-only RPC client with a fake in tests. | AGPL-3.0 | Never link. Webhooks in, files in, or not at all. |
| Unleash, Flipt | Not used. | AGPL-3.0, FCL | Blocked by `ci/license-gate.sh`. |
| OPA / conftest | Not executed. Rego files are the later mirror. | Apache-2.0 (confirm conftest's NOTICE before adding it) | Do not add until the license file is checked. |
| JA4+ / FoxIO | Not used. | FoxIO License 1.1 | Blocked. Permissive JA4 core is a later decision for counsel. |

`ci/license-gate.sh` fails the build if a blocked module path appears in `go.mod` or in a Go import.
