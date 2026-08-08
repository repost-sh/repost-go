# Changelog

## 0.3.0

- Certified all 415 transport-contract cases through native Go tests: 329 runtime/custom-transport cases, 14 concurrency scenarios, 49 production HTTP cases, and 23 enterprise network cases.
- The raw HTTP/1.1 and HTTP/2 transport becomes the default, with explicit proxy, TLS, mTLS, DNS, and connection-pool options.
- Client configuration and environment fallbacks are snapshotted at construction.
- `Transport` performs one attempt; the runtime owns retries, deadlines, and classification.
- `Error` is the operation failure type.
- Generated clients own a runtime and must be closed.
- Stable error codes, categories, delivery states, diagnostics, observers, and OpenTelemetry bridges.
- Bounded concurrency and byte admission.
- Deterministic test controls in `reposttest`.
