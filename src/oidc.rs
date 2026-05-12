use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::Sha256;
use std::collections::BTreeMap;

use crate::model::{
    Check, Compatibility, OidcReport, PermissionKey, PermissionLevel, PermissionSet,
};

/// Public constant: the HS256 secret used to sign all stub-local OIDC tokens.
/// This is intentionally documented so consumers (and reviewers) can see that
/// the resulting token is not authoritative.
pub const STUB_LOCAL_SECRET: &[u8] = b"gha-github-service-proof:stub-local:v1";

/// Public constant: the issuer claim that distinguishes a stub-local token
/// from a real GitHub-issued OIDC token.
pub const STUB_LOCAL_ISSUER: &str = "stub-local://gha-github-service-proof";

/// Public constant: the "this token is not trusted by cloud providers" warning
/// included verbatim in every OIDC receipt.
pub const STUB_LOCAL_WARNING: &str = "OIDC token is deterministic and signed by gha-github-service-proof with a documented local secret. It is not GitHub-issued and must not be trusted by AWS/GCP/Azure or any other cloud provider as a federated identity. Use for offline CI assertions only.";

pub const STUB_LOCAL_SIGNING_MODE: &str = "stub-local";

pub const DEFAULT_TTL_SECONDS: i64 = 300;

#[derive(Debug, Clone)]
pub struct IssueOptions {
    pub audience: String,
    pub repository: String,
    pub git_ref: String,
    pub sha: String,
    pub workflow: String,
    pub job: String,
    pub run_id: String,
    pub job_workflow_ref: Option<String>,
    pub permissions: Option<PermissionSet>,
    pub now: Option<DateTime<Utc>>,
    pub ttl_seconds: Option<i64>,
    pub extra_claims: BTreeMap<String, Value>,
}

pub fn issue(options: IssueOptions) -> OidcReport {
    let mut checks = Vec::new();

    if options.audience.trim().is_empty() {
        checks.push(Check::fail(
            "oidc.audience_missing",
            "audience must be a non-empty string",
        ));
    }
    if options.repository.trim().is_empty() {
        checks.push(Check::fail(
            "oidc.repository_missing",
            "repository must be in 'owner/repo' form",
        ));
    } else if !options.repository.contains('/') {
        checks.push(Check::warn(
            "oidc.repository_format",
            format!(
                "repository '{}' is not in 'owner/repo' form; ci-forge may treat the sub claim as malformed",
                options.repository
            ),
        ));
    }

    let id_token_level = options
        .permissions
        .as_ref()
        .map(|set| set.level(PermissionKey::IdToken))
        .unwrap_or(PermissionLevel::None);

    if !id_token_level.satisfies(PermissionLevel::Write) {
        match options.permissions.as_ref() {
            Some(_) => checks.push(Check::fail(
                "oidc.id_token_not_granted",
                "OIDC token requires `permissions: id-token: write`; current effective level is below `write`",
            )),
            None => checks.push(Check::warn(
                "oidc.id_token_unverified",
                "no permissions provided; cannot verify `id-token: write` is granted",
            )),
        }
    } else {
        checks.push(Check::pass(
            "oidc.id_token_granted",
            "`id-token: write` permission is granted",
        ));
    }

    let now = options.now.unwrap_or_else(Utc::now);
    let ttl = options.ttl_seconds.unwrap_or(DEFAULT_TTL_SECONDS).max(1);
    let iat = now.timestamp();
    let exp = iat + ttl;

    let job_workflow_ref = options.job_workflow_ref.clone().unwrap_or_else(|| {
        format!(
            "{}/.github/workflows/{}",
            options.repository, options.workflow
        )
    });

    let sub = format!("repo:{}:ref:{}", options.repository, options.git_ref);

    let mut claims = BTreeMap::new();
    claims.insert(
        "iss".to_owned(),
        Value::String(STUB_LOCAL_ISSUER.to_owned()),
    );
    claims.insert("sub".to_owned(), Value::String(sub.clone()));
    claims.insert("aud".to_owned(), Value::String(options.audience.clone()));
    claims.insert("iat".to_owned(), Value::from(iat));
    claims.insert("exp".to_owned(), Value::from(exp));
    claims.insert(
        "repository".to_owned(),
        Value::String(options.repository.clone()),
    );
    if let Some((owner, _)) = options.repository.split_once('/') {
        claims.insert(
            "repository_owner".to_owned(),
            Value::String(owner.to_owned()),
        );
    }
    claims.insert("ref".to_owned(), Value::String(options.git_ref.clone()));
    claims.insert("sha".to_owned(), Value::String(options.sha.clone()));
    claims.insert(
        "workflow".to_owned(),
        Value::String(options.workflow.clone()),
    );
    claims.insert("job".to_owned(), Value::String(options.job.clone()));
    claims.insert(
        "job_workflow_ref".to_owned(),
        Value::String(job_workflow_ref.clone()),
    );
    claims.insert("run_id".to_owned(), Value::String(options.run_id.clone()));
    claims.insert("stub_local".to_owned(), Value::Bool(true));
    for (key, value) in &options.extra_claims {
        claims.insert(key.clone(), value.clone());
    }

    let header = OidcHeader {
        alg: "HS256",
        typ: "JWT",
        kid: "stub-local",
    };
    let token = sign_hs256(&header, &claims);

    checks.push(Check::warn(
        "oidc.stub_local",
        "OIDC token is stub-local: signed with a documented constant secret and not trusted by GitHub or cloud providers.",
    ));

    OidcReport {
        audience: options.audience,
        repository: options.repository,
        git_ref: options.git_ref,
        sha: options.sha,
        workflow: options.workflow,
        job: options.job,
        job_workflow_ref,
        run_id: options.run_id,
        iat,
        exp,
        claims,
        token,
        signing_mode: STUB_LOCAL_SIGNING_MODE.to_owned(),
        compatibility: Compatibility::Simulated,
        permissions: options.permissions,
        checks,
        warning: STUB_LOCAL_WARNING.to_owned(),
    }
}

#[derive(Serialize)]
struct OidcHeader {
    alg: &'static str,
    typ: &'static str,
    kid: &'static str,
}

fn sign_hs256(header: &OidcHeader, claims: &BTreeMap<String, Value>) -> String {
    let header_bytes = serde_json::to_vec(header).expect("header is serializable");
    let claims_object: Map<String, Value> =
        claims.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    let claims_bytes =
        serde_json::to_vec(&Value::Object(claims_object)).expect("claims serialize to JSON object");

    let header_b64 = URL_SAFE_NO_PAD.encode(&header_bytes);
    let claims_b64 = URL_SAFE_NO_PAD.encode(&claims_bytes);
    let signing_input = format!("{header_b64}.{claims_b64}");

    let mut mac = Hmac::<Sha256>::new_from_slice(STUB_LOCAL_SECRET)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(signing_input.as_bytes());
    let signature = mac.finalize().into_bytes();
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature);

    format!("{signing_input}.{signature_b64}")
}

#[allow(dead_code)]
pub fn verify_stub_local(token: &str) -> bool {
    let mut parts = token.split('.');
    let (Some(header_b64), Some(payload_b64), Some(sig_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let signing_input = format!("{header_b64}.{payload_b64}");
    let Ok(expected) = URL_SAFE_NO_PAD.decode(sig_b64) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(STUB_LOCAL_SECRET) else {
        return false;
    };
    mac.update(signing_input.as_bytes());
    mac.verify_slice(&expected).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CheckStatus, PermissionKey, PermissionLevel};

    fn perms_with_id_token_write() -> PermissionSet {
        let mut set = PermissionSet::default();
        set.entries.insert(
            PermissionKey::IdToken.as_str().to_owned(),
            PermissionLevel::Write,
        );
        set
    }

    #[test]
    fn issue_with_id_token_write_passes() {
        let report = issue(IssueOptions {
            audience: "https://example.com".to_owned(),
            repository: "wildmason/mortar".to_owned(),
            git_ref: "refs/heads/main".to_owned(),
            sha: "deadbeef".to_owned(),
            workflow: "release.yml".to_owned(),
            job: "deploy".to_owned(),
            run_id: "1234567890".to_owned(),
            job_workflow_ref: None,
            permissions: Some(perms_with_id_token_write()),
            now: Some(DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap()),
            ttl_seconds: Some(300),
            extra_claims: BTreeMap::new(),
        });

        assert_eq!(report.audience, "https://example.com");
        assert_eq!(report.signing_mode, STUB_LOCAL_SIGNING_MODE);
        assert!(matches!(report.compatibility, Compatibility::Simulated));
        assert_eq!(report.iat, 1_700_000_000);
        assert_eq!(report.exp, 1_700_000_300);
        assert_eq!(
            report.claims.get("sub").and_then(|v| v.as_str()).unwrap(),
            "repo:wildmason/mortar:ref:refs/heads/main"
        );
        assert_eq!(
            report
                .claims
                .get("repository_owner")
                .and_then(|v| v.as_str())
                .unwrap(),
            "wildmason"
        );
        assert!(
            report
                .claims
                .get("stub_local")
                .and_then(|v| v.as_bool())
                .unwrap()
        );
        assert!(verify_stub_local(&report.token));
        assert!(
            report
                .checks
                .iter()
                .any(|c| matches!(c.status, CheckStatus::Pass) && c.id == "oidc.id_token_granted")
        );
        // the receipt always carries the stub-local advisory warning
        assert!(report.checks.iter().any(|c| c.id == "oidc.stub_local"));
    }

    #[test]
    fn issue_without_id_token_write_fails() {
        let mut set = PermissionSet::default();
        set.entries.insert(
            PermissionKey::Contents.as_str().to_owned(),
            PermissionLevel::Write,
        );

        let report = issue(IssueOptions {
            audience: "https://example.com".to_owned(),
            repository: "wildmason/mortar".to_owned(),
            git_ref: "refs/heads/main".to_owned(),
            sha: "deadbeef".to_owned(),
            workflow: "release.yml".to_owned(),
            job: "deploy".to_owned(),
            run_id: "1".to_owned(),
            job_workflow_ref: None,
            permissions: Some(set),
            now: None,
            ttl_seconds: None,
            extra_claims: BTreeMap::new(),
        });

        assert!(
            report
                .checks
                .iter()
                .any(|c| matches!(c.status, CheckStatus::Fail)
                    && c.id == "oidc.id_token_not_granted")
        );
    }

    #[test]
    fn issue_with_empty_audience_fails() {
        let report = issue(IssueOptions {
            audience: "".to_owned(),
            repository: "wildmason/mortar".to_owned(),
            git_ref: "refs/heads/main".to_owned(),
            sha: "deadbeef".to_owned(),
            workflow: "release.yml".to_owned(),
            job: "deploy".to_owned(),
            run_id: "1".to_owned(),
            job_workflow_ref: None,
            permissions: Some(perms_with_id_token_write()),
            now: None,
            ttl_seconds: None,
            extra_claims: BTreeMap::new(),
        });

        assert!(
            report
                .checks
                .iter()
                .any(|c| matches!(c.status, CheckStatus::Fail) && c.id == "oidc.audience_missing")
        );
    }

    #[test]
    fn token_round_trips_through_local_verifier() {
        let report = issue(IssueOptions {
            audience: "aud".to_owned(),
            repository: "wildmason/mortar".to_owned(),
            git_ref: "refs/heads/main".to_owned(),
            sha: "abc".to_owned(),
            workflow: "release.yml".to_owned(),
            job: "deploy".to_owned(),
            run_id: "1".to_owned(),
            job_workflow_ref: None,
            permissions: Some(perms_with_id_token_write()),
            now: None,
            ttl_seconds: None,
            extra_claims: BTreeMap::new(),
        });

        assert!(verify_stub_local(&report.token));
        let mutated = format!("{}x", report.token);
        assert!(!verify_stub_local(&mutated));
    }
}
