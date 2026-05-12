use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use serde_yaml::Value as Yaml;
use std::fs;

use crate::call::{ClassifyOptions, classify};
use crate::model::{
    ApiDetection, ApiDetectionOrigin, Check, Compatibility, JobApiReport, PermissionResolution,
    PermissionScope, PermissionSet, ReceiptSummary, StepApiReport, WorkflowReport,
};
use crate::permissions;

const GITHUB_API_HOSTS: &[&str] = &["api.github.com", "uploads.github.com"];

pub fn scan_workflows(
    repo_root: &Utf8Path,
    workflows: &[Utf8PathBuf],
) -> Result<Vec<WorkflowReport>> {
    let (paths, join_with_repo) = if workflows.is_empty() {
        (discover_workflows(repo_root)?, true)
    } else {
        (workflows.to_vec(), false)
    };

    let mut reports = Vec::new();
    for workflow in paths {
        let absolute = if workflow.is_absolute() || !join_with_repo {
            workflow.clone()
        } else {
            repo_root.join(&workflow)
        };
        reports.push(scan_workflow_file(&workflow, &absolute)?);
    }
    Ok(reports)
}

fn discover_workflows(repo_root: &Utf8Path) -> Result<Vec<Utf8PathBuf>> {
    let dir = repo_root.join(".github").join("workflows");
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut found = Vec::new();
    for entry in fs::read_dir(&dir).with_context(|| format!("reading {dir}"))? {
        let entry = entry?;
        let path = entry.path();
        let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
            continue;
        };
        if !matches!(ext, "yml" | "yaml") {
            continue;
        }
        let Some(utf8) = Utf8PathBuf::from_path_buf(path).ok() else {
            continue;
        };
        let relative = utf8
            .strip_prefix(repo_root)
            .map(Utf8PathBuf::from)
            .unwrap_or_else(|_| utf8.clone());
        found.push(relative);
    }
    found.sort();
    Ok(found)
}

fn scan_workflow_file(workflow_path: &Utf8Path, absolute: &Utf8Path) -> Result<WorkflowReport> {
    let text = fs::read_to_string(absolute).with_context(|| format!("reading {absolute}"))?;
    let stripped = strip_utf8_bom(&text);
    let value: Yaml =
        serde_yaml::from_str(stripped).with_context(|| format!("parsing YAML {absolute}"))?;

    let mut checks = Vec::new();
    let Yaml::Mapping(root) = &value else {
        checks.push(Check::fail(
            "workflow.invalid_root",
            "workflow root must be a YAML mapping",
        ));
        return Ok(WorkflowReport {
            workflow: workflow_path.to_owned(),
            workflow_permissions: None,
            jobs: Vec::new(),
            summary: ReceiptSummary::from_checks(&checks),
            checks,
        });
    };

    let workflow_permissions_yaml = mapping_lookup(root, "permissions");
    let (workflow_permissions, workflow_checks) =
        permissions::parse_yaml_block(workflow_permissions_yaml);
    checks.extend(workflow_checks);

    let jobs_yaml = mapping_lookup(root, "jobs");
    let mut jobs = Vec::new();
    let mut summary = ReceiptSummary::from_checks(&checks);

    if let Some(Yaml::Mapping(jobs_map)) = jobs_yaml {
        for (key, value) in jobs_map {
            let Yaml::String(job_id) = key else {
                checks.push(Check::warn(
                    "workflow.non_string_job_id",
                    "skipping job with non-string id",
                ));
                continue;
            };
            let Yaml::Mapping(job_map) = value else {
                checks.push(Check::warn(
                    "workflow.job_not_mapping",
                    format!("job '{job_id}' is not a mapping"),
                ));
                continue;
            };
            let job_report = scan_job(job_id, job_map, workflow_permissions.as_ref());
            summary.add(&job_report.summary);
            jobs.push(job_report);
        }
    } else if jobs_yaml.is_none() {
        checks.push(Check::warn(
            "workflow.no_jobs",
            "workflow has no `jobs:` mapping",
        ));
    } else {
        checks.push(Check::fail(
            "workflow.jobs_not_mapping",
            "`jobs:` must be a mapping",
        ));
    }

    summary.add(&ReceiptSummary::from_checks(&checks));

    Ok(WorkflowReport {
        workflow: workflow_path.to_owned(),
        workflow_permissions,
        jobs,
        summary,
        checks,
    })
}

fn scan_job(
    job_id: &str,
    job_map: &serde_yaml::Mapping,
    workflow_permissions: Option<&PermissionSet>,
) -> JobApiReport {
    let mut checks = Vec::new();
    let job_permissions_yaml = mapping_lookup(job_map, "permissions");
    let (job_permissions, perm_checks) = permissions::parse_yaml_block(job_permissions_yaml);
    checks.extend(perm_checks);

    let resolution: PermissionResolution = permissions::resolve(
        workflow_permissions.cloned(),
        job_permissions,
        PermissionScope::Job,
    );

    let effective = resolution.effective.clone();
    let mut steps_reports = Vec::new();

    if let Some(Yaml::Sequence(steps)) = mapping_lookup(job_map, "steps") {
        for (index, step_value) in steps.iter().enumerate() {
            let Yaml::Mapping(step_map) = step_value else {
                checks.push(Check::warn(
                    "workflow.step_not_mapping",
                    format!("job '{job_id}' step {index} is not a mapping"),
                ));
                continue;
            };
            let step_report = scan_step(job_id, index, step_map, &effective);
            steps_reports.push(step_report);
        }
    }

    let mut summary = ReceiptSummary::from_checks(&checks);
    summary.merge_checks(&resolution.checks);
    for step in &steps_reports {
        summary.add(&step_summary(step));
    }

    JobApiReport {
        job_id: job_id.to_owned(),
        permissions: resolution,
        steps: steps_reports,
        summary,
        checks,
    }
}

fn step_summary(step: &StepApiReport) -> ReceiptSummary {
    ReceiptSummary::from_checks(&step.checks)
}

fn scan_step(
    job_id: &str,
    index: usize,
    step_map: &serde_yaml::Mapping,
    effective: &PermissionSet,
) -> StepApiReport {
    let step_name = mapping_lookup(step_map, "name").and_then(|v| match v {
        Yaml::String(text) => Some(text.clone()),
        _ => None,
    });
    let uses = mapping_lookup(step_map, "uses").and_then(|v| match v {
        Yaml::String(text) => Some(text.clone()),
        _ => None,
    });

    let mut detections = Vec::new();
    let mut checks = Vec::new();
    let location = format!("job '{job_id}' step {index}");

    if let Some(uses_ref) = uses.as_deref() {
        detections.extend(detect_from_action(uses_ref, &location));
    }

    if let Some(Yaml::String(run_text)) = mapping_lookup(step_map, "run") {
        detections.extend(detect_from_run(run_text, &location));
    }

    for detection in &mut detections {
        let report = classify(ClassifyOptions {
            method: detection.method.clone(),
            path: detection.path.clone(),
            url: None,
            origin: Some(location.clone()),
            permissions: Some(effective.clone()),
        });
        detection.classification = report.classification;
        detection.catalog_match = report.catalog_match.clone();
        detection.satisfied = report.satisfied;
        detection.missing_permissions = report.missing_permissions.clone();
        detection.unsupported_reason = report.unsupported_reason.clone();
        checks.extend(report.checks);
    }

    StepApiReport {
        step_index: index,
        step_name,
        uses,
        detections,
        checks,
    }
}

fn detect_from_action(uses: &str, location: &str) -> Vec<ApiDetection> {
    let (slug, _ref) = match uses.split_once('@') {
        Some((slug, r)) => (slug, Some(r)),
        None => (uses, None),
    };

    let mut detections = Vec::new();
    let owner_repo = match slug.rsplit_once('/') {
        Some((owner, _)) if !owner.is_empty() => slug.to_owned(),
        _ => slug.to_owned(),
    };

    let _ = owner_repo;
    let label_prefix = format!("uses {uses}");

    match slug {
        "softprops/action-gh-release" | "ncipollo/release-action" => {
            detections.push(ApiDetection {
                origin: ApiDetectionOrigin::ReleaseAction,
                label: format!("{label_prefix} (create release at {location})"),
                method: "POST".to_owned(),
                path: "/repos/{owner}/{repo}/releases".to_owned(),
                classification: Compatibility::Simulated,
                catalog_match: None,
                satisfied: false,
                missing_permissions: Vec::new(),
                unsupported_reason: None,
            });
            detections.push(ApiDetection {
                origin: ApiDetectionOrigin::ReleaseAction,
                label: format!("{label_prefix} (upload assets at {location})"),
                method: "POST".to_owned(),
                path: "/repos/{owner}/{repo}/releases/{id}/assets".to_owned(),
                classification: Compatibility::Simulated,
                catalog_match: None,
                satisfied: false,
                missing_permissions: Vec::new(),
                unsupported_reason: None,
            });
        }
        "actions/github-script" => {
            detections.push(ApiDetection {
                origin: ApiDetectionOrigin::GithubScript,
                label: format!("{label_prefix} (generic Octokit surface at {location})"),
                method: "GET".to_owned(),
                path: "/rate_limit".to_owned(),
                classification: Compatibility::Exact,
                catalog_match: None,
                satisfied: false,
                missing_permissions: Vec::new(),
                unsupported_reason: None,
            });
        }
        "aws-actions/configure-aws-credentials" | "google-github-actions/auth" | "azure/login" => {
            detections.push(ApiDetection {
                origin: ApiDetectionOrigin::OidcAction,
                label: format!("{label_prefix} (OIDC exchange at {location})"),
                method: "GET".to_owned(),
                path: "/rate_limit".to_owned(),
                classification: Compatibility::Simulated,
                catalog_match: None,
                satisfied: false,
                missing_permissions: Vec::new(),
                unsupported_reason: Some(
                    "oidc.cloud_exchange: federated OIDC exchange happens outside the ci-forge shim".to_owned(),
                ),
            });
        }
        _ => {}
    }

    detections
}

fn detect_from_run(run: &str, location: &str) -> Vec<ApiDetection> {
    let mut detections = Vec::new();
    for line in run.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let tokens = match shell_words::split(trimmed) {
            Ok(tokens) => tokens,
            Err(_) => continue,
        };
        if tokens.is_empty() {
            continue;
        }
        let cmd = tokens[0].as_str();
        match cmd {
            "gh" => detections.extend(detect_from_gh(&tokens, location)),
            "curl" => detections.extend(detect_from_curl(&tokens, location)),
            _ => {}
        }
    }
    detections
}

fn detect_from_gh(tokens: &[String], location: &str) -> Vec<ApiDetection> {
    let mut detections = Vec::new();
    let positional: Vec<&str> = tokens
        .iter()
        .skip(1)
        .filter(|t| !t.starts_with('-'))
        .map(String::as_str)
        .collect();
    if positional.is_empty() {
        return detections;
    }
    let label = format!("gh {} at {}", positional.join(" "), location);

    match positional[0] {
        "release" => detections.extend(detect_gh_release(&positional, location)),
        "issue" => detections.extend(detect_gh_issue(&positional, location)),
        "pr" => detections.extend(detect_gh_pr(&positional, location)),
        "run" => detections.extend(detect_gh_run(&positional, location)),
        "workflow" => detections.extend(detect_gh_workflow(&positional, location)),
        "api" => detections.extend(detect_gh_api(tokens, location)),
        _ => detections.push(ApiDetection {
            origin: ApiDetectionOrigin::GhCli,
            label,
            method: "GET".to_owned(),
            path: "gh-unmapped".to_owned(),
            classification: Compatibility::Unsupported,
            catalog_match: None,
            satisfied: false,
            missing_permissions: Vec::new(),
            unsupported_reason: Some(format!(
                "gh-cli.subcommand_not_in_v1: 'gh {}' is not mapped by v1.0",
                positional[0]
            )),
        }),
    }

    detections
}

fn detect_gh_release(positional: &[&str], location: &str) -> Vec<ApiDetection> {
    let sub = positional.get(1).copied().unwrap_or("");
    let label = |verb: &str| format!("gh release {verb} at {location}");
    match sub {
        "create" => vec![
            release_create(label("create")),
            release_assets_upload(label("create (asset upload)")),
        ],
        "upload" => vec![release_assets_upload(label("upload"))],
        "edit" => vec![ApiDetection {
            origin: ApiDetectionOrigin::GhCli,
            label: label("edit"),
            method: "PATCH".to_owned(),
            path: "/repos/{owner}/{repo}/releases/{id}".to_owned(),
            classification: Compatibility::Simulated,
            catalog_match: None,
            satisfied: false,
            missing_permissions: Vec::new(),
            unsupported_reason: None,
        }],
        "delete" => vec![ApiDetection {
            origin: ApiDetectionOrigin::GhCli,
            label: label("delete"),
            method: "DELETE".to_owned(),
            path: "/repos/{owner}/{repo}/releases/{id}".to_owned(),
            classification: Compatibility::Simulated,
            catalog_match: None,
            satisfied: false,
            missing_permissions: Vec::new(),
            unsupported_reason: None,
        }],
        "view" => vec![ApiDetection {
            origin: ApiDetectionOrigin::GhCli,
            label: label("view"),
            method: "GET".to_owned(),
            path: "/repos/{owner}/{repo}/releases/tags/{tag}".to_owned(),
            classification: Compatibility::Simulated,
            catalog_match: None,
            satisfied: false,
            missing_permissions: Vec::new(),
            unsupported_reason: None,
        }],
        "list" => vec![ApiDetection {
            origin: ApiDetectionOrigin::GhCli,
            label: label("list"),
            method: "GET".to_owned(),
            path: "/repos/{owner}/{repo}/releases".to_owned(),
            classification: Compatibility::Simulated,
            catalog_match: None,
            satisfied: false,
            missing_permissions: Vec::new(),
            unsupported_reason: None,
        }],
        "download" => vec![ApiDetection {
            origin: ApiDetectionOrigin::GhCli,
            label: label("download"),
            method: "GET".to_owned(),
            path: "/repos/{owner}/{repo}/releases/assets/{id}".to_owned(),
            classification: Compatibility::Simulated,
            catalog_match: None,
            satisfied: false,
            missing_permissions: Vec::new(),
            unsupported_reason: None,
        }],
        _ => Vec::new(),
    }
}

fn release_create(label: String) -> ApiDetection {
    ApiDetection {
        origin: ApiDetectionOrigin::GhCli,
        label,
        method: "POST".to_owned(),
        path: "/repos/{owner}/{repo}/releases".to_owned(),
        classification: Compatibility::Simulated,
        catalog_match: None,
        satisfied: false,
        missing_permissions: Vec::new(),
        unsupported_reason: None,
    }
}

fn release_assets_upload(label: String) -> ApiDetection {
    ApiDetection {
        origin: ApiDetectionOrigin::GhCli,
        label,
        method: "POST".to_owned(),
        path: "/repos/{owner}/{repo}/releases/{id}/assets".to_owned(),
        classification: Compatibility::Simulated,
        catalog_match: None,
        satisfied: false,
        missing_permissions: Vec::new(),
        unsupported_reason: None,
    }
}

fn detect_gh_issue(positional: &[&str], location: &str) -> Vec<ApiDetection> {
    let sub = positional.get(1).copied().unwrap_or("");
    let label = |verb: &str| format!("gh issue {verb} at {location}");
    match sub {
        "create" => vec![ApiDetection {
            origin: ApiDetectionOrigin::GhCli,
            label: label("create"),
            method: "POST".to_owned(),
            path: "/repos/{owner}/{repo}/issues".to_owned(),
            classification: Compatibility::Simulated,
            catalog_match: None,
            satisfied: false,
            missing_permissions: Vec::new(),
            unsupported_reason: None,
        }],
        "comment" => vec![ApiDetection {
            origin: ApiDetectionOrigin::GhCli,
            label: label("comment"),
            method: "POST".to_owned(),
            path: "/repos/{owner}/{repo}/issues/{number}/comments".to_owned(),
            classification: Compatibility::Simulated,
            catalog_match: None,
            satisfied: false,
            missing_permissions: Vec::new(),
            unsupported_reason: None,
        }],
        "close" | "reopen" | "edit" | "lock" | "unlock" => vec![ApiDetection {
            origin: ApiDetectionOrigin::GhCli,
            label: label(sub),
            method: "PATCH".to_owned(),
            path: "/repos/{owner}/{repo}/issues/{number}".to_owned(),
            classification: Compatibility::Simulated,
            catalog_match: None,
            satisfied: false,
            missing_permissions: Vec::new(),
            unsupported_reason: None,
        }],
        "view" => vec![ApiDetection {
            origin: ApiDetectionOrigin::GhCli,
            label: label("view"),
            method: "GET".to_owned(),
            path: "/repos/{owner}/{repo}/issues/{number}".to_owned(),
            classification: Compatibility::Simulated,
            catalog_match: None,
            satisfied: false,
            missing_permissions: Vec::new(),
            unsupported_reason: None,
        }],
        "list" => vec![ApiDetection {
            origin: ApiDetectionOrigin::GhCli,
            label: label("list"),
            method: "GET".to_owned(),
            path: "/repos/{owner}/{repo}/issues".to_owned(),
            classification: Compatibility::Simulated,
            catalog_match: None,
            satisfied: false,
            missing_permissions: Vec::new(),
            unsupported_reason: None,
        }],
        _ => Vec::new(),
    }
}

fn detect_gh_pr(positional: &[&str], location: &str) -> Vec<ApiDetection> {
    let sub = positional.get(1).copied().unwrap_or("");
    let label = |verb: &str| format!("gh pr {verb} at {location}");
    match sub {
        "create" => vec![ApiDetection {
            origin: ApiDetectionOrigin::GhCli,
            label: label("create"),
            method: "POST".to_owned(),
            path: "/repos/{owner}/{repo}/pulls".to_owned(),
            classification: Compatibility::Simulated,
            catalog_match: None,
            satisfied: false,
            missing_permissions: Vec::new(),
            unsupported_reason: None,
        }],
        "edit" | "close" | "reopen" => vec![ApiDetection {
            origin: ApiDetectionOrigin::GhCli,
            label: label(sub),
            method: "PATCH".to_owned(),
            path: "/repos/{owner}/{repo}/pulls/{number}".to_owned(),
            classification: Compatibility::Simulated,
            catalog_match: None,
            satisfied: false,
            missing_permissions: Vec::new(),
            unsupported_reason: None,
        }],
        "review" => vec![ApiDetection {
            origin: ApiDetectionOrigin::GhCli,
            label: label("review"),
            method: "POST".to_owned(),
            path: "/repos/{owner}/{repo}/pulls/{number}/reviews".to_owned(),
            classification: Compatibility::Simulated,
            catalog_match: None,
            satisfied: false,
            missing_permissions: Vec::new(),
            unsupported_reason: None,
        }],
        "comment" => vec![ApiDetection {
            origin: ApiDetectionOrigin::GhCli,
            label: label("comment"),
            method: "POST".to_owned(),
            path: "/repos/{owner}/{repo}/issues/{number}/comments".to_owned(),
            classification: Compatibility::Simulated,
            catalog_match: None,
            satisfied: false,
            missing_permissions: Vec::new(),
            unsupported_reason: None,
        }],
        "view" => vec![ApiDetection {
            origin: ApiDetectionOrigin::GhCli,
            label: label("view"),
            method: "GET".to_owned(),
            path: "/repos/{owner}/{repo}/pulls/{number}".to_owned(),
            classification: Compatibility::Simulated,
            catalog_match: None,
            satisfied: false,
            missing_permissions: Vec::new(),
            unsupported_reason: None,
        }],
        "list" => vec![ApiDetection {
            origin: ApiDetectionOrigin::GhCli,
            label: label("list"),
            method: "GET".to_owned(),
            path: "/repos/{owner}/{repo}/pulls".to_owned(),
            classification: Compatibility::Simulated,
            catalog_match: None,
            satisfied: false,
            missing_permissions: Vec::new(),
            unsupported_reason: None,
        }],
        _ => Vec::new(),
    }
}

fn detect_gh_run(positional: &[&str], location: &str) -> Vec<ApiDetection> {
    let sub = positional.get(1).copied().unwrap_or("");
    let label = |verb: &str| format!("gh run {verb} at {location}");
    match sub {
        "view" => vec![ApiDetection {
            origin: ApiDetectionOrigin::GhCli,
            label: label("view"),
            method: "GET".to_owned(),
            path: "/repos/{owner}/{repo}/actions/runs/{id}".to_owned(),
            classification: Compatibility::Simulated,
            catalog_match: None,
            satisfied: false,
            missing_permissions: Vec::new(),
            unsupported_reason: None,
        }],
        "list" => vec![ApiDetection {
            origin: ApiDetectionOrigin::GhCli,
            label: label("list"),
            method: "GET".to_owned(),
            path: "/repos/{owner}/{repo}/actions/runs".to_owned(),
            classification: Compatibility::Simulated,
            catalog_match: None,
            satisfied: false,
            missing_permissions: Vec::new(),
            unsupported_reason: None,
        }],
        "cancel" => vec![ApiDetection {
            origin: ApiDetectionOrigin::GhCli,
            label: label("cancel"),
            method: "POST".to_owned(),
            path: "/repos/{owner}/{repo}/actions/runs/{id}/cancel".to_owned(),
            classification: Compatibility::Simulated,
            catalog_match: None,
            satisfied: false,
            missing_permissions: Vec::new(),
            unsupported_reason: None,
        }],
        _ => Vec::new(),
    }
}

fn detect_gh_workflow(positional: &[&str], location: &str) -> Vec<ApiDetection> {
    let sub = positional.get(1).copied().unwrap_or("");
    let label = |verb: &str| format!("gh workflow {verb} at {location}");
    match sub {
        "run" => vec![ApiDetection {
            origin: ApiDetectionOrigin::GhCli,
            label: label("run"),
            method: "POST".to_owned(),
            path: "/repos/{owner}/{repo}/actions/workflows/{id}/dispatches".to_owned(),
            classification: Compatibility::Simulated,
            catalog_match: None,
            satisfied: false,
            missing_permissions: Vec::new(),
            unsupported_reason: None,
        }],
        "view" | "list" => vec![ApiDetection {
            origin: ApiDetectionOrigin::GhCli,
            label: label(sub),
            method: "GET".to_owned(),
            path: "/repos/{owner}/{repo}/actions/workflows".to_owned(),
            classification: Compatibility::Simulated,
            catalog_match: None,
            satisfied: false,
            missing_permissions: Vec::new(),
            unsupported_reason: None,
        }],
        _ => Vec::new(),
    }
}

fn detect_gh_api(tokens: &[String], location: &str) -> Vec<ApiDetection> {
    let mut method = "GET".to_owned();
    let mut path: Option<String> = None;
    let mut iter = tokens.iter().skip(2).peekable();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-X" | "--method" => {
                if let Some(next) = iter.next() {
                    method = next.to_uppercase();
                }
            }
            "-H" | "--header" | "-f" | "--field" | "-F" | "--raw-field" | "-q" | "--jq" | "-i"
            | "--include" | "--paginate" | "--silent" | "-s" => {
                if matches!(
                    arg.as_str(),
                    "-H" | "--header" | "-f" | "--field" | "-F" | "--raw-field" | "-q" | "--jq"
                ) {
                    let _ = iter.next();
                }
            }
            other if other.starts_with('-') => {
                let _ = iter.next();
            }
            other => {
                if path.is_none() {
                    path = Some(other.to_owned());
                }
            }
        }
    }

    let Some(raw_path) = path else {
        return Vec::new();
    };

    let normalized = normalize_api_path(&raw_path);
    vec![ApiDetection {
        origin: ApiDetectionOrigin::GhCli,
        label: format!("gh api {method} {normalized} at {location}"),
        method,
        path: normalized,
        classification: Compatibility::Simulated,
        catalog_match: None,
        satisfied: false,
        missing_permissions: Vec::new(),
        unsupported_reason: None,
    }]
}

fn normalize_api_path(raw: &str) -> String {
    let stripped = raw.trim();
    if stripped.starts_with('/') {
        stripped.to_owned()
    } else {
        format!("/{stripped}")
    }
}

fn detect_from_curl(tokens: &[String], location: &str) -> Vec<ApiDetection> {
    let mut method = "GET".to_owned();
    let mut url: Option<String> = None;
    let mut iter = tokens.iter().skip(1).peekable();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-X" | "--request" => {
                if let Some(next) = iter.next() {
                    method = next.to_uppercase();
                }
            }
            "-d" | "--data" | "--data-raw" | "--data-binary" | "-H" | "--header" | "-u"
            | "--user" | "-A" | "--user-agent" | "--cookie" | "-b" | "-o" | "--output" => {
                let _ = iter.next();
            }
            "-s" | "-sS" | "--silent" | "-L" | "--location" | "-f" | "--fail" | "-i" | "-I"
            | "--head" | "--retry" => {}
            other if other.starts_with("http://") || other.starts_with("https://") => {
                if url.is_none() {
                    url = Some(other.to_owned());
                }
            }
            other if other.starts_with('-') => {
                // unknown flag with potential value; consume conservatively
            }
            _ => {}
        }
    }

    let Some(url) = url else {
        return Vec::new();
    };

    let Some(path) = extract_github_path(&url) else {
        return Vec::new();
    };

    vec![ApiDetection {
        origin: ApiDetectionOrigin::Curl,
        label: format!("curl {method} {url} at {location}"),
        method,
        path,
        classification: Compatibility::Simulated,
        catalog_match: None,
        satisfied: false,
        missing_permissions: Vec::new(),
        unsupported_reason: None,
    }]
}

fn extract_github_path(url: &str) -> Option<String> {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let (host, rest) = without_scheme.split_once('/')?;
    if !GITHUB_API_HOSTS
        .iter()
        .any(|known| host.eq_ignore_ascii_case(known))
    {
        return None;
    }
    Some(format!("/{}", rest))
}

fn mapping_lookup<'a>(map: &'a serde_yaml::Mapping, key: &str) -> Option<&'a Yaml> {
    for (k, v) in map {
        if let Yaml::String(s) = k {
            if s == key {
                return Some(v);
            }
        }
    }
    None
}

fn strip_utf8_bom(text: &str) -> &str {
    text.strip_prefix('\u{feff}').unwrap_or(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_softprops_release_action_with_two_calls() {
        let detections = detect_from_action("softprops/action-gh-release@v2", "step 0");
        assert_eq!(detections.len(), 2);
        assert_eq!(detections[0].path, "/repos/{owner}/{repo}/releases");
        assert_eq!(
            detections[1].path,
            "/repos/{owner}/{repo}/releases/{id}/assets"
        );
    }

    #[test]
    fn detects_gh_release_create_run_block() {
        let detections = detect_from_run("gh release create v1.0 ./binary.zip\n", "step 1");
        assert_eq!(detections.len(), 2);
        assert_eq!(detections[0].method, "POST");
        assert_eq!(
            detections[1].path,
            "/repos/{owner}/{repo}/releases/{id}/assets"
        );
    }

    #[test]
    fn detects_gh_api_post_path_explicitly() {
        let detections = detect_from_run(
            "gh api repos/wildmason/mortar/releases --method POST\n",
            "step 2",
        );
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].method, "POST");
        assert_eq!(detections[0].path, "/repos/wildmason/mortar/releases");
    }

    #[test]
    fn detects_curl_github_api_url() {
        let detections = detect_from_run(
            "curl -X POST -H 'Authorization: Bearer $TOKEN' https://api.github.com/repos/o/r/issues -d '{}'",
            "step 3",
        );
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].method, "POST");
        assert_eq!(detections[0].path, "/repos/o/r/issues");
    }

    #[test]
    fn ignores_curl_to_non_github_host() {
        let detections = detect_from_run(
            "curl -X POST https://hooks.slack.com/services/x/y/z -d '{}'",
            "step 4",
        );
        assert!(detections.is_empty());
    }

    #[test]
    fn scan_workflow_detects_gh_release_with_resolved_permissions() {
        let temp = tempfile::tempdir().unwrap();
        let repo: Utf8PathBuf = temp.path().to_path_buf().try_into().unwrap();
        let workflows_dir = repo.join(".github/workflows");
        std::fs::create_dir_all(&workflows_dir).unwrap();
        let workflow = workflows_dir.join("release.yml");
        std::fs::write(
            &workflow,
            r#"
name: Release
on: push
permissions:
  contents: write
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - name: Create release
        run: gh release create v1.0 ./binary.zip
"#,
        )
        .unwrap();

        let reports = scan_workflows(&repo, &[]).unwrap();
        assert_eq!(reports.len(), 1);
        let report = &reports[0];
        assert_eq!(report.jobs.len(), 1);
        let job = &report.jobs[0];
        assert_eq!(job.steps.len(), 1);
        let step = &job.steps[0];
        assert_eq!(step.detections.len(), 2);
        // both detections should be satisfied by contents: write
        assert!(step.detections.iter().all(|d| d.satisfied));
    }

    #[test]
    fn scan_workflow_flags_missing_permissions_for_release() {
        let temp = tempfile::tempdir().unwrap();
        let repo: Utf8PathBuf = temp.path().to_path_buf().try_into().unwrap();
        let workflows_dir = repo.join(".github/workflows");
        std::fs::create_dir_all(&workflows_dir).unwrap();
        let workflow = workflows_dir.join("release.yml");
        std::fs::write(
            &workflow,
            r#"
name: Release
on: push
permissions:
  contents: read
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: gh release create v1.0
"#,
        )
        .unwrap();

        let reports = scan_workflows(&repo, &[]).unwrap();
        let step = &reports[0].jobs[0].steps[0];
        assert!(step.detections.iter().any(|d| !d.satisfied));
        assert!(
            step.checks
                .iter()
                .any(|c| c.id.contains("permissions_insufficient"))
        );
    }
}
