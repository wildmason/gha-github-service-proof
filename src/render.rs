use anyhow::Result;

use crate::model::{
    ApiDetection, CallReport, CheckStatus, GithubServiceReceipt, JobApiReport, OidcReport,
    OutputFormat, PermissionResolution, StepApiReport, WorkflowReport,
};

pub fn render_receipt(receipt: &GithubServiceReceipt, format: OutputFormat) -> Result<String> {
    match format {
        OutputFormat::Text => Ok(render_text(receipt)),
        OutputFormat::Json => Ok(format!("{}\n", serde_json::to_string_pretty(receipt)?)),
        OutputFormat::Markdown => Ok(render_markdown(receipt)),
    }
}

fn render_text(receipt: &GithubServiceReceipt) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{} {} ({})\n",
        receipt.tool.name, receipt.tool.version, receipt.mode
    ));
    out.push_str(&format!(
        "summary: {} passed, {} warned, {} failed, {} skipped\n",
        receipt.summary.passed,
        receipt.summary.warnings,
        receipt.summary.failed,
        receipt.summary.skipped
    ));

    if let Some(resolution) = &receipt.permissions {
        out.push_str(&format!(
            "\npermissions ({:?} from {:?}):\n",
            resolution.scope, resolution.source
        ));
        for (key, level) in &resolution.effective.entries {
            out.push_str(&format!("  {key}: {}\n", level.as_str()));
        }
        if let Some(shorthand) = &resolution.effective.shorthand {
            out.push_str(&format!("  shorthand: {shorthand}\n"));
        }
        for unknown in &resolution.effective.unknown_keys {
            out.push_str(&format!("  unknown: {unknown}\n"));
        }
        for check in &resolution.checks {
            out.push_str(&format!(
                "  {} {:<5} {}\n",
                status_symbol(check.status),
                status_word(check.status),
                check.message
            ));
        }
    }

    for workflow in &receipt.workflows {
        render_workflow_text(&mut out, workflow);
    }

    if !receipt.calls.is_empty() {
        out.push_str("\ncalls:\n");
        for call in &receipt.calls {
            render_call_text(&mut out, call, 2);
        }
    }

    if let Some(oidc) = &receipt.oidc {
        render_oidc_text(&mut out, oidc);
    }

    if let Some(gh_log) = &receipt.gh_log {
        out.push_str(&format!(
            "\ngh-log replay: tool={} v{} captured={} calls (redaction_enforced={})\n",
            gh_log.tool.name, gh_log.tool.version, gh_log.call_count, gh_log.redaction_enforced
        ));
        for call in &gh_log.calls {
            render_call_text(&mut out, call, 2);
        }
        for check in &gh_log.checks {
            out.push_str(&format!(
                "  {} {:<5} {}\n",
                status_symbol(check.status),
                status_word(check.status),
                check.message
            ));
        }
    }

    if !receipt.checks.is_empty() {
        out.push_str("\nchecks:\n");
        for check in &receipt.checks {
            out.push_str(&format!(
                "  {} {:<5} {}\n",
                status_symbol(check.status),
                status_word(check.status),
                check.message
            ));
        }
    }

    out
}

fn render_workflow_text(out: &mut String, workflow: &WorkflowReport) {
    out.push_str(&format!("\nworkflow {}:\n", workflow.workflow));
    out.push_str(&format!(
        "  summary: {} passed, {} warned, {} failed, {} skipped\n",
        workflow.summary.passed,
        workflow.summary.warnings,
        workflow.summary.failed,
        workflow.summary.skipped
    ));
    for job in &workflow.jobs {
        render_job_text(out, job);
    }
    for check in &workflow.checks {
        out.push_str(&format!(
            "  {} {:<5} {}\n",
            status_symbol(check.status),
            status_word(check.status),
            check.message
        ));
    }
}

fn render_job_text(out: &mut String, job: &JobApiReport) {
    out.push_str(&format!("  job {}:\n", job.job_id));
    render_permission_resolution_text(out, &job.permissions);
    for step in &job.steps {
        render_step_text(out, step);
    }
    for check in &job.checks {
        out.push_str(&format!(
            "    {} {:<5} {}\n",
            status_symbol(check.status),
            status_word(check.status),
            check.message
        ));
    }
}

fn render_permission_resolution_text(out: &mut String, resolution: &PermissionResolution) {
    out.push_str(&format!(
        "    permissions (source: {:?}):\n",
        resolution.source
    ));
    for (key, level) in &resolution.effective.entries {
        out.push_str(&format!("      {key}: {}\n", level.as_str()));
    }
    for check in &resolution.checks {
        out.push_str(&format!(
            "    {} {:<5} {}\n",
            status_symbol(check.status),
            status_word(check.status),
            check.message
        ));
    }
}

fn render_step_text(out: &mut String, step: &StepApiReport) {
    let label = step.step_name.clone().unwrap_or_else(|| {
        step.uses
            .clone()
            .unwrap_or_else(|| format!("step {}", step.step_index))
    });
    out.push_str(&format!("    step {}: {}\n", step.step_index, label));
    for detection in &step.detections {
        render_detection_text(out, detection);
    }
    for check in &step.checks {
        out.push_str(&format!(
            "      {} {:<5} {}\n",
            status_symbol(check.status),
            status_word(check.status),
            check.message
        ));
    }
}

fn render_detection_text(out: &mut String, detection: &ApiDetection) {
    out.push_str(&format!(
        "      detect: {} {} -> {} ({:?}) [{}]\n",
        detection.method,
        detection.path,
        detection.classification.as_str(),
        detection.origin,
        if detection.satisfied {
            "satisfied"
        } else {
            "missing"
        }
    ));
}

fn render_call_text(out: &mut String, call: &CallReport, indent: usize) {
    let pad = " ".repeat(indent);
    let classification = call.classification.as_str();
    out.push_str(&format!(
        "{pad}{} {} -> {}\n",
        call.method, call.path, classification
    ));
    if let Some(catalog) = &call.catalog_match {
        out.push_str(&format!(
            "{pad}  catalog: {} ({})\n",
            catalog.endpoint_id, catalog.category
        ));
    } else if let Some(reason) = &call.unsupported_reason {
        out.push_str(&format!("{pad}  reason: {reason}\n"));
    }
    for check in &call.checks {
        out.push_str(&format!(
            "{pad}  {} {:<5} {}\n",
            status_symbol(check.status),
            status_word(check.status),
            check.message
        ));
    }
}

fn render_oidc_text(out: &mut String, oidc: &OidcReport) {
    out.push_str(&format!(
        "\noidc: audience={} signing_mode={} compatibility={}\n",
        oidc.audience,
        oidc.signing_mode,
        oidc.compatibility.as_str()
    ));
    out.push_str(&format!(
        "  sub: {}\n",
        oidc.claims
            .get("sub")
            .map(value_to_string)
            .unwrap_or_default()
    ));
    out.push_str(&format!("  iat/exp: {}/{}\n", oidc.iat, oidc.exp));
    out.push_str(&format!(
        "  token: {}...\n",
        &oidc.token.chars().take(24).collect::<String>()
    ));
    out.push_str(&format!("  warning: {}\n", oidc.warning));
    for check in &oidc.checks {
        out.push_str(&format!(
            "  {} {:<5} {}\n",
            status_symbol(check.status),
            status_word(check.status),
            check.message
        ));
    }
}

fn render_markdown(receipt: &GithubServiceReceipt) -> String {
    let mut out = String::new();
    out.push_str("# gha-github-service-proof Receipt\n\n");
    out.push_str(&format!(
        "- Tool: `{}` `{}`\n",
        receipt.tool.name, receipt.tool.version
    ));
    out.push_str(&format!("- Mode: `{}`\n", markdown_escape(&receipt.mode)));
    out.push_str(&format!("- Checked at: `{}`\n", receipt.checked_at));
    out.push_str(&format!(
        "- Summary: **{} passed**, **{} warned**, **{} failed**, **{} skipped**\n\n",
        receipt.summary.passed,
        receipt.summary.warnings,
        receipt.summary.failed,
        receipt.summary.skipped
    ));

    if let Some(resolution) = &receipt.permissions {
        out.push_str("## Permissions\n\n");
        out.push_str(&format!("- Source: `{:?}`\n", resolution.source));
        out.push_str("- Effective scopes:\n");
        for (key, level) in &resolution.effective.entries {
            out.push_str(&format!("  - `{key}`: `{}`\n", level.as_str()));
        }
        if !resolution.effective.unknown_keys.is_empty() {
            out.push_str("- Unknown keys: ");
            out.push_str(
                &resolution
                    .effective
                    .unknown_keys
                    .iter()
                    .map(|k| format!("`{k}`"))
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            out.push('\n');
        }
        out.push('\n');
    }

    if !receipt.workflows.is_empty() {
        out.push_str("## Workflows\n\n");
        for workflow in &receipt.workflows {
            out.push_str(&format!(
                "### `{}`\n\n{} jobs scanned.\n\n",
                workflow.workflow,
                workflow.jobs.len()
            ));
            out.push_str("| Job | Step | Detection | Classification | Satisfied |\n");
            out.push_str("| --- | --- | --- | --- | --- |\n");
            for job in &workflow.jobs {
                for step in &job.steps {
                    for detection in &step.detections {
                        out.push_str(&format!(
                            "| `{}` | {} | `{} {}` | `{}` | `{}` |\n",
                            markdown_escape(&job.job_id),
                            step.step_index,
                            markdown_escape(&detection.method),
                            markdown_escape(&detection.path),
                            detection.classification.as_str(),
                            detection.satisfied,
                        ));
                    }
                }
            }
            out.push('\n');
        }
    }

    if !receipt.calls.is_empty() {
        out.push_str("## Calls\n\n");
        out.push_str("| Method | Path | Classification | Satisfied | Catalog |\n");
        out.push_str("| --- | --- | --- | --- | --- |\n");
        for call in &receipt.calls {
            let catalog = call
                .catalog_match
                .as_ref()
                .map(|m| format!("`{}`", m.endpoint_id))
                .unwrap_or_else(|| {
                    call.unsupported_reason
                        .clone()
                        .map(|r| format!("`{r}`"))
                        .unwrap_or_else(|| "—".to_owned())
                });
            out.push_str(&format!(
                "| `{}` | `{}` | `{}` | `{}` | {} |\n",
                markdown_escape(&call.method),
                markdown_escape(&call.path),
                call.classification.as_str(),
                call.satisfied,
                catalog,
            ));
        }
        out.push('\n');
    }

    if let Some(oidc) = &receipt.oidc {
        out.push_str("## OIDC\n\n");
        out.push_str(&format!(
            "- Audience: `{}`\n- Signing mode: `{}`\n- Compatibility: `{}`\n- iat / exp: `{}` / `{}`\n- Token (truncated): `{}…`\n\n",
            markdown_escape(&oidc.audience),
            markdown_escape(&oidc.signing_mode),
            oidc.compatibility.as_str(),
            oidc.iat,
            oidc.exp,
            markdown_escape(&oidc.token.chars().take(40).collect::<String>()),
        ));
        out.push_str(&format!("> ⚠️ {}\n\n", markdown_escape(&oidc.warning)));
    }

    if let Some(gh_log) = &receipt.gh_log {
        out.push_str("## gh-log Replay\n\n");
        out.push_str(&format!(
            "- Tool: `{}` `{}`\n- Calls: `{}`\n- Redaction enforced: `{}`\n\n",
            markdown_escape(&gh_log.tool.name),
            markdown_escape(&gh_log.tool.version),
            gh_log.call_count,
            gh_log.redaction_enforced,
        ));
    }

    if !receipt.checks.is_empty() {
        out.push_str("## Checks\n\n");
        for check in &receipt.checks {
            out.push_str(&format!(
                "- `{}` `{}` — {}\n",
                status_word(check.status),
                check.id,
                markdown_escape(&check.message),
            ));
        }
    }

    out
}

fn value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn status_symbol(status: CheckStatus) -> &'static str {
    match status {
        CheckStatus::Pass => "[PASS]",
        CheckStatus::Warn => "[WARN]",
        CheckStatus::Fail => "[FAIL]",
        CheckStatus::Skip => "[SKIP]",
    }
}

fn status_word(status: CheckStatus) -> &'static str {
    match status {
        CheckStatus::Pass => "pass",
        CheckStatus::Warn => "warn",
        CheckStatus::Fail => "fail",
        CheckStatus::Skip => "skip",
    }
}

fn markdown_escape(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', "<br>")
}
