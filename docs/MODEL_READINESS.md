# Model inventory status (first readiness slice)

When Ollama policy is absent, the runtime reports `not_connected`. With policy
configured but no active instance, it reports `configured` without a probe. For
an active instance, a background worker queries the trusted configured host's
`/api/tags` with a five-second network deadline and a 1 MiB response limit.
Requests never wait for this query. The cache starts as `unavailable`, permits
only one query at a time and at most one start per five seconds, and expires
results after 15 seconds. A result for a different endpoint or model is never
reused; failed queries replace previous results with `unavailable`. Shutdown
does not wait for a pending query and discards any late result.
`model_present` means the exact configured model name appeared in a valid
inventory; `model_missing` means a valid inventory did not contain it.
Transport, HTTP, malformed or oversized responses report `unavailable` without
forwarding upstream diagnostics. The WebUI shows these statuses through the
existing runtime response. A probe originates on the supervisor host, not from
the agent network: it does not verify the agent's network route or policy.

Inventory is not inference or conversation evidence. Chat remains disabled;
no full-model inference is started by refresh. Production readiness requires a
separate verified end-to-end conversation/inference check, route and firewall
acceptance, and operational validation in the target environment. This slice
does not grant or change the direct-route receipt or firewall policy.
