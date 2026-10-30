# Adapters

Write paths live here. v0.1 does not perform the write.

- `gitops-pr` renders a pull-request body. It does not push and it does not call a forge.
- `edge-rules` renders a plan. `Apply` returns an error. The operator's change process is what touches Cloudflare, a cloud WAF, or any other vendor.

A later release may open a pull request after a human approval that this process still cannot grant itself.
