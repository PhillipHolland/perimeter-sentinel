package perimeter.privacy

# Mirror of internal/policy. Civic behavioral telemetry stays off.
# A verified agent does not relax fraud checks. Identity is not intent.

deny[msg] {
  input.profile == "civic"
  input.telemetry.enabled
  msg := "civic profile keeps behavioral telemetry off"
}

deny[msg] {
  input.telemetry.enabled
  not input.telemetry.opt_in
  msg := "behavioral telemetry requires opt-in"
}

deny[msg] {
  input.agent.verified_agent
  input.agent.relax_checks
  msg := "verified-agent identity does not relax fraud checks"
}
