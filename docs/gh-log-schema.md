# gh-log Canonical JSON Schema (v1)

`gh-log` ingests a stable, tool-agnostic canonical JSON bundle. The format is intentionally boring so adapters (gh CLI debug traces, HAR exports, ci-forge native emit) can target a single shape.

## Top level

```json
{
  "schema_version": 1,
  "tool": { "name": "ci-forge", "version": "0.1.0" },
  "captured_at": "2026-05-12T18:00:00Z",
  "calls": [ ... ]
}
```

- `schema_version` (integer, required) — must be `1` for v1.0. Bundles with other versions are rejected.
- `tool.name` (string, required) — the producer of the bundle (e.g. `ci-forge`, `gh-debug-adapter`, `mitmproxy-adapter`).
- `tool.version` (string, required) — version string for the producer.
- `captured_at` (RFC 3339 timestamp, optional) — when the bundle was captured.
- `calls` (array, required) — zero or more call objects.

## Call object

```json
{
  "id": "call-1",
  "timestamp": "2026-05-12T18:00:00Z",
  "source": "gh",
  "method": "POST",
  "url": "https://api.github.com/repos/wildmason/mortar/releases",
  "path": "/repos/wildmason/mortar/releases",
  "request_headers": {
    "accept": "application/vnd.github+json",
    "authorization": "<redacted>"
  },
  "request_body_excerpt": "{ \"tag_name\": \"v1.0.0\" }",
  "status": 201,
  "response_body_excerpt": "{ \"id\": 123 }",
  "exit_code": 0
}
```

- `id` (string, required) — stable identifier within the bundle.
- `source` (string, required) — origin of the call (`gh`, `curl`, `octokit`, `ci-forge-shim`, etc.).
- `method` (string, required) — uppercase HTTP method.
- `path` (string, required) — the request path used for catalog matching. Query strings are tolerated and stripped before matching.
- `url` (string, optional) — the full URL, retained for receipt provenance.
- `request_headers` (object, optional) — header name to value. Header names are matched case-insensitively.
- `request_body_excerpt` / `response_body_excerpt` (string, optional) — truncated bodies for context. **Never** raw payloads unless the operator has explicitly opted out of redaction.
- `status` (integer, optional) — HTTP status returned by the upstream/shim. Statuses ≥ 400 emit an advisory `gh_log.upstream_error` check.
- `exit_code` (integer, optional) — process exit code for tools like `gh`.

## Redaction by contract

The `authorization` request header must be the literal string `<redacted>`. Bundles that contain anything else (e.g. `Bearer ghp_xxx`) fail with `gh_log.authorization_not_redacted` unless the caller passes `--unsafe-full-payloads`, in which case the bundle is processed and a `gh_log.unsafe_full_payloads` warning is recorded on the receipt.

The same contract applies in spirit to the request and response body excerpts: producers should truncate and de-secret bodies before emit. v1.0 does not enforce a maximum excerpt size or perform content scanning; that is a future enhancement.

## Adapters (deferred to future releases)

v1.0 ships only the canonical JSON ingest. Future adapter flags will translate other capture formats into the canonical shape:

- `--gh-debug <trace.txt>` — parse `GH_DEBUG=api` traces.
- `--har <trace.har>` — parse HAR exports from mitmproxy / Charles / browser devtools.
- ci-forge's API shim is expected to emit the canonical format natively.

The schema is the boundary; adapters are convenience.
