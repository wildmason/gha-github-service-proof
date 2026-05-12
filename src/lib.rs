//! GitHub Actions service/API compatibility checks for offline CI systems.
//!
//! `gha-github-service-proof` is the receipt-backed compatibility oracle for
//! the GitHub side-effect surface that ci-forge and other offline runners need
//! to model: REST endpoints, `GITHUB_TOKEN` permissions, `gh` CLI invocations,
//! `curl`-based API requests, well-known action releases such as
//! `softprops/action-gh-release`, OIDC token issuance, and the `/graphql`
//! boundary.
//!
//! The library does not call GitHub. It classifies every requested call as
//! `exact`, `simulated`, or `unsupported`, validates that the workflow's
//! resolved permissions cover each call, and emits text/JSON/Markdown receipts
//! that downstream runners can attach to job provenance.

pub mod call;
pub mod catalog;
pub mod engine;
pub mod gh_log;
pub mod model;
pub mod oidc;
pub mod permissions;
pub mod render;
pub mod workflow;

pub use engine::{
    CallOptions, CheckWorkflowOptions, GhLogOptions, OidcOptions, PermissionsOptions,
    check_workflows, classify_call, issue_oidc, permissions_command, replay_gh_log,
};
pub use model::{
    Check, CheckStatus, Compatibility, GithubServiceReceipt, OutputFormat, PermissionKey,
    PermissionLevel, PermissionScope, PermissionSet, RequiredPermission, ToolInfo,
};
pub use render::render_receipt;

pub const TOOL_NAME: &str = "gha-github-service-proof";
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
