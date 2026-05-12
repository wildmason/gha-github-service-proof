use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::call::{ClassifyOptions, classify};
use crate::model::{
    Check, GH_LOG_SCHEMA_VERSION, GhLogReport, PermissionSet, ReceiptSummary, ToolInfo,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhLogBundle {
    pub schema_version: u32,
    pub tool: BundleTool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub captured_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub calls: Vec<GhLogCall>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleTool {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhLogCall {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<DateTime<Utc>>,
    pub source: String,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub path: String,
    #[serde(default)]
    pub request_headers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body_excerpt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_body_excerpt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct ReplayOptions {
    pub bundle: GhLogBundle,
    pub permissions: Option<PermissionSet>,
    pub unsafe_full_payloads: bool,
}

pub fn parse_bundle(raw: &str) -> Result<GhLogBundle> {
    let bundle: GhLogBundle =
        serde_json::from_str(raw).with_context(|| "parsing gh-log JSON bundle")?;
    if bundle.schema_version != GH_LOG_SCHEMA_VERSION {
        bail!(
            "gh-log schema_version {} is not supported by gha-github-service-proof v1 (expected {})",
            bundle.schema_version,
            GH_LOG_SCHEMA_VERSION
        );
    }
    if bundle.tool.name.trim().is_empty() {
        bail!("gh-log tool.name must be non-empty");
    }
    if bundle.tool.version.trim().is_empty() {
        bail!("gh-log tool.version must be non-empty");
    }
    Ok(bundle)
}

pub fn replay(options: ReplayOptions) -> GhLogReport {
    let bundle = options.bundle;
    let permissions = options.permissions;
    let unsafe_full_payloads = options.unsafe_full_payloads;

    let mut checks = Vec::new();
    let mut summary = ReceiptSummary::default();
    let mut calls = Vec::new();
    let mut redaction_enforced = !unsafe_full_payloads;

    if unsafe_full_payloads {
        checks.push(Check::warn(
            "gh_log.unsafe_full_payloads",
            "redaction-by-schema-contract is disabled (--unsafe-full-payloads). Bodies and authorization headers will not be checked. Use only for local debugging.",
        ));
    }

    if bundle.calls.is_empty() {
        checks.push(Check::warn(
            "gh_log.no_calls",
            "gh-log bundle contains zero captured calls",
        ));
    }

    for call in &bundle.calls {
        let location = format!("call {} ({})", call.id, call.source);
        if !unsafe_full_payloads {
            match find_header(&call.request_headers, "authorization") {
                Some("<redacted>") => {}
                Some(value) => {
                    let message = format!(
                        "call {} authorization header is not '<redacted>'; gh-log schema contract requires redacted captures unless --unsafe-full-payloads is set (header bytes were {} chars)",
                        call.id,
                        value.len()
                    );
                    checks.push(
                        Check::fail("gh_log.authorization_not_redacted", message)
                            .at(location.clone()),
                    );
                    redaction_enforced = false;
                }
                None => {
                    checks.push(Check::warn(
                        "gh_log.authorization_absent",
                        format!(
                            "call {} has no authorization header; assume unauthenticated or redacted upstream",
                            call.id
                        ),
                    ).at(location.clone()));
                }
            }
        }

        let mut report = classify(ClassifyOptions {
            method: call.method.clone(),
            path: call.path.clone(),
            url: call.url.clone(),
            origin: Some(location.clone()),
            permissions: permissions.clone(),
        });

        if let Some(status) = call.status {
            if status >= 400 {
                report.checks.push(
                    Check::warn(
                        "gh_log.upstream_error",
                        format!(
                            "captured response status is {status}; ci-forge classification reflects request shape, not response failure",
                        ),
                    )
                    .at(location.clone()),
                );
            }
        }

        summary.merge_checks(&report.checks);
        calls.push(report);
    }

    summary.add(&ReceiptSummary::from_checks(&checks));

    GhLogReport {
        schema_version: bundle.schema_version,
        tool: ToolInfo {
            name: bundle.tool.name,
            version: bundle.tool.version,
        },
        captured_at: bundle.captured_at,
        call_count: calls.len(),
        redaction_enforced,
        calls,
        summary,
        checks,
    }
}

fn find_header<'a>(headers: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    for (key, value) in headers {
        if key.eq_ignore_ascii_case(name) {
            return Some(value.as_str());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CheckStatus, PermissionKey, PermissionLevel};

    fn perms_with(key: PermissionKey, level: PermissionLevel) -> PermissionSet {
        let mut set = PermissionSet::default();
        set.entries.insert(key.as_str().to_owned(), level);
        set
    }

    fn sample_bundle(authorization: &str) -> GhLogBundle {
        let mut headers = BTreeMap::new();
        headers.insert(
            "accept".to_owned(),
            "application/vnd.github+json".to_owned(),
        );
        headers.insert("authorization".to_owned(), authorization.to_owned());
        GhLogBundle {
            schema_version: 1,
            tool: BundleTool {
                name: "ci-forge".to_owned(),
                version: "0.1.0".to_owned(),
            },
            captured_at: None,
            calls: vec![GhLogCall {
                id: "call-1".to_owned(),
                timestamp: None,
                source: "gh".to_owned(),
                method: "POST".to_owned(),
                url: Some("https://api.github.com/repos/wildmason/mortar/releases".to_owned()),
                path: "/repos/wildmason/mortar/releases".to_owned(),
                request_headers: headers,
                request_body_excerpt: Some("{}".to_owned()),
                status: Some(201),
                response_body_excerpt: Some("{\"id\":123}".to_owned()),
                exit_code: Some(0),
            }],
        }
    }

    #[test]
    fn redacted_capture_classifies_call_and_keeps_redaction_enforced() {
        let bundle = sample_bundle("<redacted>");
        let report = replay(ReplayOptions {
            bundle,
            permissions: Some(perms_with(PermissionKey::Contents, PermissionLevel::Write)),
            unsafe_full_payloads: false,
        });
        assert_eq!(report.call_count, 1);
        assert!(report.redaction_enforced);
        let call = &report.calls[0];
        assert!(call.satisfied);
        assert!(call.catalog_match.is_some());
    }

    #[test]
    fn unredacted_authorization_fails_when_safe_mode() {
        let bundle = sample_bundle("Bearer ghp_real_secret_value");
        let report = replay(ReplayOptions {
            bundle,
            permissions: Some(perms_with(PermissionKey::Contents, PermissionLevel::Write)),
            unsafe_full_payloads: false,
        });
        assert!(!report.redaction_enforced);
        assert!(
            report
                .checks
                .iter()
                .any(|c| c.id == "gh_log.authorization_not_redacted"
                    && matches!(c.status, CheckStatus::Fail))
        );
    }

    #[test]
    fn unsafe_mode_permits_unredacted_authorization_but_warns() {
        let bundle = sample_bundle("Bearer ghp_real_secret_value");
        let report = replay(ReplayOptions {
            bundle,
            permissions: Some(perms_with(PermissionKey::Contents, PermissionLevel::Write)),
            unsafe_full_payloads: true,
        });
        // redaction_enforced reflects the flag, not header contents
        assert!(!report.redaction_enforced);
        assert!(report.checks.iter().any(
            |c| c.id == "gh_log.unsafe_full_payloads" && matches!(c.status, CheckStatus::Warn)
        ));
        assert!(
            !report
                .checks
                .iter()
                .any(|c| c.id == "gh_log.authorization_not_redacted")
        );
    }

    #[test]
    fn schema_version_mismatch_is_rejected() {
        let raw = r#"{"schema_version":99,"tool":{"name":"x","version":"y"},"calls":[]}"#;
        let err = parse_bundle(raw).unwrap_err();
        assert!(err.to_string().contains("schema_version"));
    }

    #[test]
    fn empty_call_list_warns() {
        let bundle = GhLogBundle {
            schema_version: 1,
            tool: BundleTool {
                name: "ci-forge".to_owned(),
                version: "0.1.0".to_owned(),
            },
            captured_at: None,
            calls: Vec::new(),
        };
        let report = replay(ReplayOptions {
            bundle,
            permissions: None,
            unsafe_full_payloads: false,
        });
        assert!(report.checks.iter().any(|c| c.id == "gh_log.no_calls"));
    }
}
