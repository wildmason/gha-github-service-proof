use camino::Utf8PathBuf;
use chrono::{DateTime, Utc};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub type SchemaVersion = u32;
pub const SCHEMA_VERSION: SchemaVersion = 1;
pub const GH_LOG_SCHEMA_VERSION: SchemaVersion = 1;

#[derive(Clone, Copy, Debug, ValueEnum, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Text,
    Json,
    Markdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
    Skip,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Check {
    pub id: String,
    pub status: CheckStatus,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

impl Check {
    pub fn pass(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            status: CheckStatus::Pass,
            message: message.into(),
            location: None,
        }
    }

    pub fn warn(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            status: CheckStatus::Warn,
            message: message.into(),
            location: None,
        }
    }

    pub fn fail(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            status: CheckStatus::Fail,
            message: message.into(),
            location: None,
        }
    }

    pub fn skip(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            status: CheckStatus::Skip,
            message: message.into(),
            location: None,
        }
    }

    pub fn at(mut self, location: impl Into<String>) -> Self {
        self.location = Some(location.into());
        self
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReceiptSummary {
    pub passed: usize,
    pub warnings: usize,
    pub failed: usize,
    pub skipped: usize,
}

impl ReceiptSummary {
    pub fn from_checks(checks: &[Check]) -> Self {
        let mut summary = Self::default();
        for check in checks {
            match check.status {
                CheckStatus::Pass => summary.passed += 1,
                CheckStatus::Warn => summary.warnings += 1,
                CheckStatus::Fail => summary.failed += 1,
                CheckStatus::Skip => summary.skipped += 1,
            }
        }
        summary
    }

    pub fn add(&mut self, other: &Self) {
        self.passed += other.passed;
        self.warnings += other.warnings;
        self.failed += other.failed;
        self.skipped += other.skipped;
    }

    pub fn merge_checks(&mut self, checks: &[Check]) {
        let other = Self::from_checks(checks);
        self.add(&other);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum PermissionKey {
    Actions,
    Attestations,
    Checks,
    Contents,
    Deployments,
    Discussions,
    IdToken,
    Issues,
    Models,
    Packages,
    Pages,
    PullRequests,
    RepositoryProjects,
    SecurityEvents,
    Statuses,
}

impl PermissionKey {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Actions => "actions",
            Self::Attestations => "attestations",
            Self::Checks => "checks",
            Self::Contents => "contents",
            Self::Deployments => "deployments",
            Self::Discussions => "discussions",
            Self::IdToken => "id-token",
            Self::Issues => "issues",
            Self::Models => "models",
            Self::Packages => "packages",
            Self::Pages => "pages",
            Self::PullRequests => "pull-requests",
            Self::RepositoryProjects => "repository-projects",
            Self::SecurityEvents => "security-events",
            Self::Statuses => "statuses",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "actions" => Some(Self::Actions),
            "attestations" => Some(Self::Attestations),
            "checks" => Some(Self::Checks),
            "contents" => Some(Self::Contents),
            "deployments" => Some(Self::Deployments),
            "discussions" => Some(Self::Discussions),
            "id-token" => Some(Self::IdToken),
            "issues" => Some(Self::Issues),
            "models" => Some(Self::Models),
            "packages" => Some(Self::Packages),
            "pages" => Some(Self::Pages),
            "pull-requests" => Some(Self::PullRequests),
            "repository-projects" => Some(Self::RepositoryProjects),
            "security-events" => Some(Self::SecurityEvents),
            "statuses" => Some(Self::Statuses),
            _ => None,
        }
    }

    pub fn all() -> &'static [PermissionKey] {
        &[
            Self::Actions,
            Self::Attestations,
            Self::Checks,
            Self::Contents,
            Self::Deployments,
            Self::Discussions,
            Self::IdToken,
            Self::Issues,
            Self::Models,
            Self::Packages,
            Self::Pages,
            Self::PullRequests,
            Self::RepositoryProjects,
            Self::SecurityEvents,
            Self::Statuses,
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PermissionLevel {
    None,
    Read,
    Write,
}

impl PermissionLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Read => "read",
            Self::Write => "write",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "none" => Some(Self::None),
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            _ => None,
        }
    }

    pub fn satisfies(&self, required: PermissionLevel) -> bool {
        *self >= required
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PermissionSet {
    pub entries: BTreeMap<String, PermissionLevel>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unknown_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shorthand: Option<String>,
}

impl PermissionSet {
    pub fn level(&self, key: PermissionKey) -> PermissionLevel {
        self.entries
            .get(key.as_str())
            .copied()
            .unwrap_or(PermissionLevel::None)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionResolution {
    pub scope: PermissionScope,
    pub workflow_permissions: Option<PermissionSet>,
    pub job_permissions: Option<PermissionSet>,
    pub effective: PermissionSet,
    pub source: PermissionSource,
    pub checks: Vec<Check>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PermissionScope {
    Workflow,
    Job,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PermissionSource {
    JobBlock,
    WorkflowBlock,
    DefaultRestricted,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Compatibility {
    Exact,
    Simulated,
    Unsupported,
}

impl Compatibility {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Simulated => "simulated",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogMatch {
    pub endpoint_id: String,
    pub method: String,
    pub path_template: String,
    pub category: String,
    pub required_permissions: Vec<RequiredPermission>,
    pub classification: Compatibility,
    pub side_effect: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequiredPermission {
    pub key: PermissionKey,
    pub level: PermissionLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallReport {
    pub method: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub classification: Compatibility,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog_match: Option<CatalogMatch>,
    pub unsupported_reason: Option<String>,
    pub permissions: Option<PermissionSet>,
    pub satisfied: bool,
    pub missing_permissions: Vec<RequiredPermission>,
    pub checks: Vec<Check>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowReport {
    pub workflow: Utf8PathBuf,
    pub workflow_permissions: Option<PermissionSet>,
    pub jobs: Vec<JobApiReport>,
    pub summary: ReceiptSummary,
    pub checks: Vec<Check>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobApiReport {
    pub job_id: String,
    pub permissions: PermissionResolution,
    pub steps: Vec<StepApiReport>,
    pub summary: ReceiptSummary,
    pub checks: Vec<Check>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepApiReport {
    pub step_index: usize,
    pub step_name: Option<String>,
    pub uses: Option<String>,
    pub detections: Vec<ApiDetection>,
    pub checks: Vec<Check>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiDetection {
    pub origin: ApiDetectionOrigin,
    pub label: String,
    pub method: String,
    pub path: String,
    pub classification: Compatibility,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog_match: Option<CatalogMatch>,
    pub satisfied: bool,
    pub missing_permissions: Vec<RequiredPermission>,
    pub unsupported_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApiDetectionOrigin {
    GhCli,
    Curl,
    GithubScript,
    ReleaseAction,
    OidcAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcReport {
    pub audience: String,
    pub repository: String,
    pub git_ref: String,
    pub sha: String,
    pub workflow: String,
    pub job: String,
    pub job_workflow_ref: String,
    pub run_id: String,
    pub iat: i64,
    pub exp: i64,
    pub claims: BTreeMap<String, serde_json::Value>,
    pub token: String,
    pub signing_mode: String,
    pub compatibility: Compatibility,
    pub permissions: Option<PermissionSet>,
    pub checks: Vec<Check>,
    pub warning: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhLogReport {
    pub schema_version: SchemaVersion,
    pub tool: ToolInfo,
    pub captured_at: Option<DateTime<Utc>>,
    pub call_count: usize,
    pub redaction_enforced: bool,
    pub calls: Vec<CallReport>,
    pub summary: ReceiptSummary,
    pub checks: Vec<Check>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GithubServiceReceipt {
    pub schema_version: SchemaVersion,
    pub tool: ToolInfo,
    pub checked_at: DateTime<Utc>,
    pub mode: String,
    pub summary: ReceiptSummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<PermissionResolution>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workflows: Vec<WorkflowReport>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub calls: Vec<CallReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc: Option<OidcReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gh_log: Option<GhLogReport>,
    pub checks: Vec<Check>,
}
