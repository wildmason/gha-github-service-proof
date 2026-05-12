use crate::catalog;
use crate::model::{
    CallReport, Check, Compatibility, PermissionSet, ReceiptSummary, RequiredPermission,
};
use crate::permissions;

#[derive(Debug, Clone)]
pub struct ClassifyOptions {
    pub method: String,
    pub path: String,
    pub url: Option<String>,
    pub origin: Option<String>,
    pub permissions: Option<PermissionSet>,
}

pub fn classify(options: ClassifyOptions) -> CallReport {
    let mut checks = Vec::new();
    let method = options.method.trim().to_uppercase();
    let path = options.path.clone();

    let location = options
        .origin
        .clone()
        .unwrap_or_else(|| format!("{method} {path}"));

    if catalog::is_graphql_path(&path) {
        checks.push(
            Check::fail(
                "call.graphql_classification_not_implemented",
                "graphql.classification_not_implemented: /graphql operations are not classified by v1.0; ci-forge should treat the call as unsupported until a future release adds operation parsing",
            )
            .at(location.clone()),
        );
        return CallReport {
            method,
            path,
            url: options.url,
            classification: Compatibility::Unsupported,
            catalog_match: None,
            unsupported_reason: Some("graphql.classification_not_implemented".to_owned()),
            permissions: options.permissions,
            satisfied: false,
            missing_permissions: Vec::new(),
            checks,
            origin: options.origin,
        };
    }

    let Some(catalog_match) = catalog::lookup(&method, &path) else {
        checks.push(
            Check::warn(
                "call.endpoint_not_in_catalog",
                format!(
                    "rest.endpoint_not_in_catalog: {method} {path} is not covered by the v1.0 CI-relevant catalog; ci-forge should classify as unsupported"
                ),
            )
            .at(location.clone()),
        );
        return CallReport {
            method,
            path,
            url: options.url,
            classification: Compatibility::Unsupported,
            catalog_match: None,
            unsupported_reason: Some("rest.endpoint_not_in_catalog".to_owned()),
            permissions: options.permissions,
            satisfied: false,
            missing_permissions: Vec::new(),
            checks,
            origin: options.origin,
        };
    };

    let permissions_set = options.permissions.clone();
    let (satisfied, missing) = evaluate_permissions(
        permissions_set.as_ref(),
        &catalog_match.required_permissions,
    );

    if catalog_match.required_permissions.is_empty() {
        checks.push(
            Check::pass(
                format!("call.{}", catalog_match.endpoint_id),
                format!(
                    "{method} {path} maps to {} ({}); no specific permission scopes are required",
                    catalog_match.endpoint_id,
                    catalog_match.classification.as_str()
                ),
            )
            .at(location.clone()),
        );
    } else if satisfied {
        checks.push(
            Check::pass(
                format!("call.{}", catalog_match.endpoint_id),
                format!(
                    "{method} {path} maps to {} ({}); granted permissions satisfy required scopes",
                    catalog_match.endpoint_id,
                    catalog_match.classification.as_str()
                ),
            )
            .at(location.clone()),
        );
    } else if permissions_set.is_none() {
        checks.push(
            Check::warn(
                format!("call.{}.permissions_unknown", catalog_match.endpoint_id),
                format!(
                    "{method} {path} maps to {} ({}); no permissions provided so requirement {} cannot be evaluated",
                    catalog_match.endpoint_id,
                    catalog_match.classification.as_str(),
                    format_required(&catalog_match.required_permissions),
                ),
            )
            .at(location.clone()),
        );
    } else {
        checks.push(
            Check::fail(
                format!(
                    "call.{}.permissions_insufficient",
                    catalog_match.endpoint_id
                ),
                format!(
                    "{method} {path} maps to {} ({}); missing {}",
                    catalog_match.endpoint_id,
                    catalog_match.classification.as_str(),
                    format_required(&missing),
                ),
            )
            .at(location.clone()),
        );
    }

    let classification = catalog_match.classification;

    CallReport {
        method,
        path,
        url: options.url,
        classification,
        catalog_match: Some(catalog_match),
        unsupported_reason: None,
        permissions: permissions_set,
        satisfied,
        missing_permissions: missing,
        checks,
        origin: options.origin,
    }
}

pub fn evaluate_permissions(
    set: Option<&PermissionSet>,
    required: &[RequiredPermission],
) -> (bool, Vec<RequiredPermission>) {
    let Some(set) = set else {
        if required.is_empty() {
            return (true, Vec::new());
        }
        return (false, required.to_vec());
    };
    let missing = permissions::missing(set, required);
    (missing.is_empty(), missing)
}

pub fn summary(report: &CallReport) -> ReceiptSummary {
    ReceiptSummary::from_checks(&report.checks)
}

pub fn format_required(required: &[RequiredPermission]) -> String {
    if required.is_empty() {
        return "(none)".to_owned();
    }
    required
        .iter()
        .map(|req| format!("{}:{}", req.key.as_str(), req.level.as_str()))
        .collect::<Vec<_>>()
        .join(", ")
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

    #[test]
    fn classify_in_catalog_with_sufficient_permissions() {
        let report = classify(ClassifyOptions {
            method: "POST".to_owned(),
            path: "/repos/wildmason/mortar/releases".to_owned(),
            url: None,
            origin: Some("workflow ci.yml job release step 0".to_owned()),
            permissions: Some(perms_with(PermissionKey::Contents, PermissionLevel::Write)),
        });
        assert!(matches!(report.classification, Compatibility::Simulated));
        assert!(report.satisfied);
        assert!(report.missing_permissions.is_empty());
        assert!(report.catalog_match.is_some());
        assert!(
            report
                .checks
                .iter()
                .any(|c| matches!(c.status, CheckStatus::Pass))
        );
    }

    #[test]
    fn classify_in_catalog_with_missing_permissions_fails() {
        let report = classify(ClassifyOptions {
            method: "POST".to_owned(),
            path: "/repos/wildmason/mortar/releases".to_owned(),
            url: None,
            origin: None,
            permissions: Some(perms_with(PermissionKey::Contents, PermissionLevel::Read)),
        });
        assert!(matches!(report.classification, Compatibility::Simulated));
        assert!(!report.satisfied);
        assert_eq!(report.missing_permissions.len(), 1);
        assert!(
            report
                .checks
                .iter()
                .any(|c| matches!(c.status, CheckStatus::Fail))
        );
    }

    #[test]
    fn classify_off_catalog_returns_unsupported() {
        let report = classify(ClassifyOptions {
            method: "POST".to_owned(),
            path: "/repos/wildmason/mortar/branches/main/protection".to_owned(),
            url: None,
            origin: None,
            permissions: Some(perms_with(PermissionKey::Contents, PermissionLevel::Write)),
        });
        assert!(matches!(report.classification, Compatibility::Unsupported));
        assert!(report.catalog_match.is_none());
        assert_eq!(
            report.unsupported_reason.as_deref(),
            Some("rest.endpoint_not_in_catalog"),
        );
    }

    #[test]
    fn classify_graphql_returns_unsupported_with_specific_reason() {
        let report = classify(ClassifyOptions {
            method: "POST".to_owned(),
            path: "/graphql".to_owned(),
            url: None,
            origin: None,
            permissions: None,
        });
        assert!(matches!(report.classification, Compatibility::Unsupported));
        assert!(report.catalog_match.is_none());
        assert_eq!(
            report.unsupported_reason.as_deref(),
            Some("graphql.classification_not_implemented"),
        );
    }

    #[test]
    fn classify_no_required_permissions_passes_without_permissions() {
        let report = classify(ClassifyOptions {
            method: "GET".to_owned(),
            path: "/rate_limit".to_owned(),
            url: None,
            origin: None,
            permissions: None,
        });
        assert!(matches!(report.classification, Compatibility::Exact));
        assert!(report.satisfied);
        assert!(
            report
                .checks
                .iter()
                .any(|c| matches!(c.status, CheckStatus::Pass))
        );
    }

    #[test]
    fn classify_in_catalog_without_permissions_warns() {
        let report = classify(ClassifyOptions {
            method: "POST".to_owned(),
            path: "/repos/wildmason/mortar/releases".to_owned(),
            url: None,
            origin: None,
            permissions: None,
        });
        assert!(matches!(report.classification, Compatibility::Simulated));
        assert!(!report.satisfied);
        assert!(
            report
                .checks
                .iter()
                .any(|c| matches!(c.status, CheckStatus::Warn))
        );
    }
}
