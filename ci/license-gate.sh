#!/bin/sh
# Fail when a blocked license family is imported into this module.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$root"

blocked='unleash|getunleash|flipt-io/flipt|trufflesecurity/trufflehog|wazuh/wazuh|foxio|ja4plus|open-policy-agent|velociraptor|certspotter|go-csp-collector|twin/gatus|OpenZeppelin/openzeppelin-monitor'
if [ -f go.mod ] && grep -E -i "$blocked" go.mod; then
  echo "license gate: blocked module in go.mod" >&2
  exit 1
fi
if [ -f go.sum ] && grep -E -i "$blocked" go.sum; then
  echo "license gate: blocked module in go.sum" >&2
  exit 1
fi
imports=$(grep -R -n -E '^[[:space:]]+"[^"]+"$' --include='*.go' . || true)
if printf '%s\n' "$imports" | grep -E -i "$blocked"; then
  echo "license gate: blocked import" >&2
  exit 1
fi
echo "license gate: no blocked modules"
