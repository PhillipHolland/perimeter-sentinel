# Cloudflare read-only adapter (design)

Status: design plus httptest fixtures. No live Cloudflare calls.

## Token

Owner-supplied environment variable: `PERIMETER_CLOUDFLARE_TOKEN`. Never commit it. Missing token returns `needs_human` and performs zero network calls.

## Routes (GET only)

- `GET /client/v4/zones?name={hostname}` — compare zone names to affirmed scope.
- `GET /client/v4/zones/{zone_id}/settings` — optional configuration inventory the API already exposes.

The adapter client accepts only `http.MethodGet`. PUT, PATCH, DELETE, and POST are refused in code and forbidden by a package test.

## Fail closed

| Condition | Result |
|---|---|
| Token unset | `needs_human`, no request |
| HTTP 401 | `needs_human` |
| Non-JSON or unexpected shape | `needs_human` |
| Zone name not in affirmed scope | `finding` |
| Timeout | `needs_human` |

Apply stays refused. This adapter does not change DNS, WAF, or page rules.
