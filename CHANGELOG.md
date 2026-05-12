# Changelog

## 1.0.0 - 2026-05-12

- Initial release.
- Added `check-workflow`, `permissions`, `call`, `oidc`, and `gh-log` commands.
- Added curated REST endpoint catalog for repos/contents, releases/assets, issues, pull requests, checks, statuses, actions metadata, deployments, packages, rate-limit, user, and app-installation probes.
- Added permission-key/level validation, sufficiency check against catalog entries, and parsing of workflow/job `permissions` blocks including `read-all` and `write-all` shortcuts.
- Added workflow scanner for `gh` CLI, `curl https://api.github.com`, `actions/github-script`, and `softprops/action-gh-release`-style steps.
- Added OIDC validator and deterministic stub JWT issuer with `signing_mode: stub-local` and explicit "not trusted by cloud providers" warning.
- Added canonical JSON v1 schema for `gh-log` capture replay, redaction-by-schema-contract enforcement, and `--unsafe-full-payloads` opt-out.
- Added composite GitHub Action wrapper.
