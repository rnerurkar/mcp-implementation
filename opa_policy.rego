package mcp

# Default deny
default allow = false

# Allow if all conditions pass
allow {
    input.context_type == "user_profile"
    not contains_pii(input.context)
    within_size_limit(5120)  # 5KB
}

allow {
    input.context_type == "order_history"
    input.metadata.query_depth <= 3
    within_size_limit(10240)  # 10KB
}

allow {
    input.context_type == "product_inventory"
    input.metadata.row_count <= 1000
    not contains_pii(input.context)
}

# Helper functions
contains_pii(ctx) {
    regex.match(`(?i)\b\d{3}-\d{2}-\d{4}\b`, ctx)  # SSN
}

within_size_limit(limit) {
    count(json.marshal(input.context)) <= limit
}