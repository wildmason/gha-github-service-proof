# Security

Please report security issues privately to Wildmason before public disclosure.

`gha-github-service-proof` does not contact GitHub. It reads workflow files, captured API call bundles, and permission blocks, then emits receipts. The `oidc` command issues a deterministic local stub JWT signed with a documented constant local secret; this token is intentionally not trusted by cloud providers and must not be used as a real GitHub OIDC token.

The canonical `gh-log` JSON schema treats request and response bodies and the `authorization` header as redacted excerpts by contract. `gh-log` rejects captures whose `authorization` header is not `<redacted>` unless the caller passes `--unsafe-full-payloads`. Callers should still avoid passing real secrets when a placeholder is sufficient.
