# NIST CSF 2.0 mapping (subset)

This is a map from CSF 2.0 functions to modules in this repository. It is not an assessment, not an authorization, and not a statement that a control is met. An assessor decides that.

| Function | Where it shows up in v0.1 | Limit |
|---|---|---|
| Govern (GV) | `internal/govern`, scope affirmation, roster, risk appetite, civic telemetry lock | No policy workflow product. A missing fact blocks watchers. |
| Identify (ID) | Scope inventory, third-party script list, pre-authorization book, readiness sources | No discovery scan of undeclared hosts. |
| Protect (PR) | Signer pin, SRI notes, lane names, tripwire marker that does not execute code | The edge enforces. Sentinel does not apply. |
| Detect (DE) | Watchers and `detections/*.ads.yaml` | Blind telemetry is `needs_human`, not a clean detect. |
| Respond (RS) | Freeze desk, stopwatch, unsent drafts | The operator sends and acts. |
| Recover (RC) | Thaw checklist on the playbook | v0.1 does not execute thaw. |

800-53, 800-61, and FedRAMP KSIs are not mapped as met. Evidence export in v0.1 is the ledger and the Markdown brief.
