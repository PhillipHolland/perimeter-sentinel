#!/bin/sh
# Pattern scan used when gitleaks is absent. Always fails on a private-key banner
# outside the rejection fixture in internal/secrets/secrets_test.go.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$root"

if command -v gitleaks >/dev/null 2>&1; then
  gitleaks detect --source . --config .gitleaks.toml --no-banner --redact || {
    echo "gitleaks reported a finding" >&2
    exit 1
  }
else
  echo "gitleaks not installed; pattern scan only"
fi

hits=$(grep -R -n -E 'BEGIN [A-Z0-9 ]*PRIVATE KEY' \
  --exclude-dir=.git --exclude-dir=bin --exclude-dir=dist \
  . | grep -v '^\./internal/secrets/secrets_test.go:' || true)
if [ -n "$hits" ]; then
  echo "private key banner found outside the rejection fixture:" >&2
  printf '%s\n' "$hits" >&2
  exit 1
fi
if ! grep -q 'func TestRejectPEM' internal/secrets/secrets_test.go; then
  echo "secrets rejection fixture missing" >&2
  exit 1
fi
echo "secret scan: no private key banner outside the rejection fixture"
