# @opsimathically/nodenetscanner

This private workspace is reserved for the planned scanner package. It contains
no API or implementation yet and cannot be published.

The intended boundary is a scanner-specific Rust data plane and a focused
TypeScript control/results API. Low-level, policy-free raw networking remains in
`@opsimathically/nodenetraw`; reusable performance-sensitive Rust components may
be extracted into internal, non-published workspace crates after their contracts
are designed and benchmarked.
