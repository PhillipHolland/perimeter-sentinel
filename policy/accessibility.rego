package perimeter.accessibility

# Mirror of internal/policy. v0.1 does not execute OPA.
# A friction rung needs a fallback a person can use without a visual puzzle.

deny[msg] {
  input.friction.enabled
  not input.friction.accessible_fallback
  msg := "friction needs an accessible fallback"
}

deny[msg] {
  input.friction.enabled
  input.friction.fallback_description == ""
  msg := "friction fallback needs a description"
}
