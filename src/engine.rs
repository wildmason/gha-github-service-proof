use anyhow::{Context, Result, bail};
use camino::{Utf8Path, Utf8PathBuf};
use chrono::Utc;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;

use crate::call::{ClassifyOptions, classify};
use crate::gh_log;
use crate::model::{
    CallReport, Check, GithubServiceReceipt, OidcReport, PermissionScope, PermissionSet,
    ReceiptSummary, SCHEMA_VERSION, ToolInfo,
};
use crate::oidc::{self, IssueOptions};
use crate::permissions;
use crate::workflow;
use crate::{TOOL_NAME, TOOL_VERSION};

#[derive(Debug, Clone)]
pub struct CheckWorkflowOptions {
    pub repo_root: Utf8PathBuf,
    pub workflows: Vec<Utf8PathBuf>,
}

pub fn check_workflows(options: &CheckWorkflowOptions) -> Result<GithubServiceReceipt> {
    let workflows = workflow::scan_workflows(&options.repo_root, &options.workflows)?;
    let mut summary = ReceiptSummary::default();
    for workflow in &workflows {
        summary.add(&workflow.summary);
    }
    Ok(GithubServiceReceipt {
        schema_version: SCHEMA_VERSION,
        tool: tool_info(),
        checked_at: Utc::now(),
        mode: "check-workflow".to_owned(),
        summary,
        permissions: None,
        workflows,
        calls: Vec::new(),
        oidc: None,
        gh_log: None,
        checks: Vec::new(),
    })
}

#[derive(Debug, Clone)]
pub struct PermissionsOptions {
    pub workflow_path: Utf8PathBuf,
    pub job: Option<String>,
}

pub fn permissions_command(options: &PermissionsOptions) -> Result<GithubServiceReceipt> {
    let text = fs::read_to_string(&options.workflow_path)
        .with_context(|| format!("reading workflow {}", options.workflow_path))?;
    let stripped = text.strip_prefix('\u{feff}').unwrap_or(&text);
    let value: serde_yaml::Value = serde_yaml::from_str(stripped)
        .with_context(|| format!("parsing YAML {}", options.workflow_path))?;
    let serde_yaml::Value::Mapping(root) = value else {
        bail!("workflow root must be a YAML mapping");
    };

    let workflow_yaml = mapping_get(&root, "permissions");
    let (workflow_permissions, mut all_checks) = permissions::parse_yaml_block(workflow_yaml);

    let (job_permissions, scope) = if let Some(job_id) = &options.job {
        let jobs = mapping_get(&root, "jobs");
        let Some(serde_yaml::Value::Mapping(jobs_map)) = jobs else {
            bail!("workflow has no `jobs:` mapping");
        };
        let Some(serde_yaml::Value::Mapping(job_map)) = mapping_get(jobs_map, job_id) else {
            bail!("job '{job_id}' not found in workflow");
        };
        let job_yaml = mapping_get(job_map, "permissions");
        let (job_perms, job_checks) = permissions::parse_yaml_block(job_yaml);
        all_checks.extend(job_checks);
        (job_perms, PermissionScope::Job)
    } else {
        (None, PermissionScope::Workflow)
    };

    let resolution = permissions::resolve(workflow_permissions, job_permissions, scope);
    let mut summary = ReceiptSummary::from_checks(&all_checks);
    summary.merge_checks(&resolution.checks);

    Ok(GithubServiceReceipt {
        schema_version: SCHEMA_VERSION,
        tool: tool_info(),
        checked_at: Utc::now(),
        mode: "permissions".to_owned(),
        summary,
        permissions: Some(resolution),
        workflows: Vec::new(),
        calls: Vec::new(),
        oidc: None,
        gh_log: None,
        checks: all_checks,
    })
}

#[derive(Debug, Clone)]
pub struct CallOptions {
    pub method: String,
    pub path: String,
    pub url: Option<String>,
    pub permissions: Option<PermissionSet>,
    pub origin: Option<String>,
}

pub fn classify_call(options: &CallOptions) -> Result<GithubServiceReceipt> {
    let report = classify(ClassifyOptions {
        method: options.method.clone(),
        path: options.path.clone(),
        url: options.url.clone(),
        origin: options.origin.clone(),
        permissions: options.permissions.clone(),
    });
    let summary = ReceiptSummary::from_checks(&report.checks);
    Ok(GithubServiceReceipt {
        schema_version: SCHEMA_VERSION,
        tool: tool_info(),
        checked_at: Utc::now(),
        mode: "call".to_owned(),
        summary,
        permissions: None,
        workflows: Vec::new(),
        calls: vec![report],
        oidc: None,
        gh_log: None,
        checks: Vec::new(),
    })
}

#[derive(Debug, Clone)]
pub struct OidcOptions {
    pub audience: String,
    pub repository: String,
    pub git_ref: String,
    pub sha: String,
    pub workflow: String,
    pub job: String,
    pub run_id: String,
    pub job_workflow_ref: Option<String>,
    pub permissions: Option<PermissionSet>,
    pub ttl_seconds: Option<i64>,
    pub extra_claims: BTreeMap<String, Value>,
}

pub fn issue_oidc(options: &OidcOptions) -> Result<GithubServiceReceipt> {
    let report: OidcReport = oidc::issue(IssueOptions {
        audience: options.audience.clone(),
        repository: options.repository.clone(),
        git_ref: options.git_ref.clone(),
        sha: options.sha.clone(),
        workflow: options.workflow.clone(),
        job: options.job.clone(),
        run_id: options.run_id.clone(),
        job_workflow_ref: options.job_workflow_ref.clone(),
        permissions: options.permissions.clone(),
        now: None,
        ttl_seconds: options.ttl_seconds,
        extra_claims: options.extra_claims.clone(),
    });
    let mut summary = ReceiptSummary::from_checks(&report.checks);
    summary.merge_checks(&[]);
    Ok(GithubServiceReceipt {
        schema_version: SCHEMA_VERSION,
        tool: tool_info(),
        checked_at: Utc::now(),
        mode: "oidc".to_owned(),
        summary,
        permissions: None,
        workflows: Vec::new(),
        calls: Vec::new(),
        oidc: Some(report),
        gh_log: None,
        checks: Vec::new(),
    })
}

#[derive(Debug, Clone)]
pub struct GhLogOptions {
    pub log_path: Utf8PathBuf,
    pub permissions: Option<PermissionSet>,
    pub unsafe_full_payloads: bool,
}

pub fn replay_gh_log(options: &GhLogOptions) -> Result<GithubServiceReceipt> {
    let raw = fs::read_to_string(&options.log_path)
        .with_context(|| format!("reading gh-log bundle {}", options.log_path))?;
    let bundle = gh_log::parse_bundle(&raw)?;
    let report = gh_log::replay(gh_log::ReplayOptions {
        bundle,
        permissions: options.permissions.clone(),
        unsafe_full_payloads: options.unsafe_full_payloads,
    });
    let summary = report.summary.clone();
    Ok(GithubServiceReceipt {
        schema_version: SCHEMA_VERSION,
        tool: tool_info(),
        checked_at: Utc::now(),
        mode: "gh-log".to_owned(),
        summary,
        permissions: None,
        workflows: Vec::new(),
        calls: Vec::new(),
        oidc: None,
        gh_log: Some(report),
        checks: Vec::new(),
    })
}

fn mapping_get<'a>(map: &'a serde_yaml::Mapping, key: &str) -> Option<&'a serde_yaml::Value> {
    for (k, v) in map {
        if let serde_yaml::Value::String(s) = k {
            if s == key {
                return Some(v);
            }
        }
    }
    None
}

fn tool_info() -> ToolInfo {
    ToolInfo {
        name: TOOL_NAME.to_owned(),
        version: TOOL_VERSION.to_owned(),
    }
}

pub fn check_repo_root(path: &Utf8Path) -> Result<()> {
    if !path.is_dir() {
        bail!("--repo must be an existing directory: {path}");
    }
    Ok(())
}

#[allow(dead_code)]
pub fn enrich_call_with_location(call: &mut CallReport, location: String) {
    if call.origin.is_none() {
        call.origin = Some(location);
    }
}

#[allow(dead_code)]
fn ensure_call_has_check(_: &Check) {}
