# Contributing

Run the local gates before sending changes:

```powershell
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo doc --locked --no-deps
```

Receipts are part of the public contract. Add or rename fields deliberately, and cover behavior changes with CLI tests.

The REST endpoint catalog under `src/catalog.rs` is part of the public contract too. New catalog entries should include required permissions, classification (`exact`, `simulated`, or `unsupported`), and a one-line side-effect note. Off-catalog calls intentionally surface as `unsupported: rest.endpoint_not_in_catalog` so that ci-forge and other consumers can decide policy.
