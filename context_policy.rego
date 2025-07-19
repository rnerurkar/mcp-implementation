rego
package mcp.context

default allow = false

# Prevent malicious context patterns
allow {
    not contains_malicious_pattern(input.context)
    within_freshness_limits(input.timestamp)
    context_size_ok(input.context)
}

contains_malicious_pattern(ctx) {
    regex.match(`(?i)(system:|ignore previous|malicious-payload)`, ctx)
}