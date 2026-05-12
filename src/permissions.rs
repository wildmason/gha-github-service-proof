use anyhow::{Result, bail};
use serde_json::Value;
use serde_yaml::Value as Yaml;
use std::collections::BTreeMap;

use crate::model::{
    Check, PermissionKey, PermissionLevel, PermissionResolution, PermissionScope, PermissionSet,
    PermissionSource, RequiredPermission,
};

const ALL_LEVELS_READ: &str = "read-all";
const ALL_LEVELS_WRITE: &str = "write-all";

pub fn parse_yaml_block(value: Option<&Yaml>) -> (Option<PermissionSet>, Vec<Check>) {
    let Some(value) = value else {
        return (None, Vec::new());
    };

    let mut checks = Vec::new();
    let mut set = PermissionSet::default();

    match value {
        Yaml::String(text) => {
            let trimmed = text.trim();
            match trimmed {
                ALL_LEVELS_READ => {
                    set.shorthand = Some(ALL_LEVELS_READ.to_owned());
                    for key in PermissionKey::all() {
                        if matches!(key, PermissionKey::IdToken) {
                            // id-token follows GitHub: write must be explicit
                            continue;
                        }
                        set.entries
                            .insert(key.as_str().to_owned(), PermissionLevel::Read);
                    }
                }
                ALL_LEVELS_WRITE => {
                    set.shorthand = Some(ALL_LEVELS_WRITE.to_owned());
                    for key in PermissionKey::all() {
                        if matches!(key, PermissionKey::IdToken) {
                            continue;
                        }
                        set.entries
                            .insert(key.as_str().to_owned(), PermissionLevel::Write);
                    }
                }
                "" => {
                    checks.push(Check::fail(
                        "permissions.empty_scalar",
                        "permissions: cannot be an empty scalar",
                    ));
                }
                other => {
                    checks.push(Check::fail(
                        "permissions.unknown_scalar",
                        format!(
                            "permissions scalar must be 'read-all' or 'write-all', got '{other}'"
                        ),
                    ));
                }
            }
        }
        Yaml::Mapping(map) => {
            for (key_value, level_value) in map {
                let Yaml::String(key) = key_value else {
                    checks.push(Check::fail(
                        "permissions.non_string_key",
                        "permission keys must be strings",
                    ));
                    continue;
                };
                let Some(level_text) = scalar_text(level_value) else {
                    checks.push(Check::fail(
                        "permissions.non_string_level",
                        format!("permission '{key}' must map to a string level"),
                    ));
                    continue;
                };
                let Some(level) = PermissionLevel::parse(&level_text) else {
                    checks.push(Check::fail(
                        "permissions.unknown_level",
                        format!(
                            "permission '{key}': level '{level_text}' is not one of none|read|write"
                        ),
                    ));
                    continue;
                };
                if PermissionKey::parse(key).is_none() {
                    set.unknown_keys.push(key.clone());
                    checks.push(Check::warn(
                        "permissions.unknown_key",
                        format!("permission key '{key}' is not a recognized GitHub permission"),
                    ));
                }
                set.entries.insert(key.clone(), level);
            }
        }
        _ => {
            checks.push(Check::fail(
                "permissions.invalid_shape",
                "permissions must be a scalar (read-all|write-all) or a mapping",
            ));
        }
    }

    (Some(set), checks)
}

fn scalar_text(value: &Yaml) -> Option<String> {
    match value {
        Yaml::String(text) => Some(text.clone()),
        Yaml::Bool(b) => Some(b.to_string()),
        Yaml::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

pub fn parse_json_permissions(value: &Value) -> Result<PermissionSet> {
    let mut set = PermissionSet::default();
    match value {
        Value::Null => Ok(set),
        Value::String(text) => match text.as_str() {
            ALL_LEVELS_READ => {
                set.shorthand = Some(ALL_LEVELS_READ.to_owned());
                for key in PermissionKey::all() {
                    if matches!(key, PermissionKey::IdToken) {
                        continue;
                    }
                    set.entries
                        .insert(key.as_str().to_owned(), PermissionLevel::Read);
                }
                Ok(set)
            }
            ALL_LEVELS_WRITE => {
                set.shorthand = Some(ALL_LEVELS_WRITE.to_owned());
                for key in PermissionKey::all() {
                    if matches!(key, PermissionKey::IdToken) {
                        continue;
                    }
                    set.entries
                        .insert(key.as_str().to_owned(), PermissionLevel::Write);
                }
                Ok(set)
            }
            other => bail!("permissions scalar must be 'read-all' or 'write-all', got '{other}'"),
        },
        Value::Object(map) => {
            for (key, level) in map {
                let Value::String(level_text) = level else {
                    bail!("permission '{key}' must map to a string level");
                };
                let Some(parsed) = PermissionLevel::parse(level_text) else {
                    bail!("permission '{key}': level '{level_text}' is not one of none|read|write");
                };
                if PermissionKey::parse(key).is_none() {
                    set.unknown_keys.push(key.clone());
                }
                set.entries.insert(key.clone(), parsed);
            }
            Ok(set)
        }
        _ => bail!("permissions must be null, a string shorthand, or an object mapping"),
    }
}

pub fn resolve(
    workflow_permissions: Option<PermissionSet>,
    job_permissions: Option<PermissionSet>,
    scope: PermissionScope,
) -> PermissionResolution {
    let (effective, source) = match (&job_permissions, &workflow_permissions, scope) {
        (Some(job), _, PermissionScope::Job) => (job.clone(), PermissionSource::JobBlock),
        (None, Some(wf), PermissionScope::Job) => (wf.clone(), PermissionSource::WorkflowBlock),
        (_, Some(wf), PermissionScope::Workflow) => (wf.clone(), PermissionSource::WorkflowBlock),
        _ => (default_restricted(), PermissionSource::DefaultRestricted),
    };

    let mut checks = Vec::new();
    if matches!(source, PermissionSource::DefaultRestricted) {
        checks.push(Check::warn(
            "permissions.default_restricted",
            "no permissions block found at workflow or job level; assuming restricted defaults (contents: read). Set an explicit permissions block to pin behavior.",
        ));
    }

    PermissionResolution {
        scope,
        workflow_permissions,
        job_permissions,
        effective,
        source,
        checks,
    }
}

pub fn default_restricted() -> PermissionSet {
    let mut set = PermissionSet::default();
    set.entries.insert(
        PermissionKey::Contents.as_str().to_owned(),
        PermissionLevel::Read,
    );
    set
}

pub fn missing(set: &PermissionSet, required: &[RequiredPermission]) -> Vec<RequiredPermission> {
    required
        .iter()
        .filter(|req| !set.level(req.key).satisfies(req.level))
        .cloned()
        .collect()
}

pub fn satisfies(set: &PermissionSet, required: &[RequiredPermission]) -> bool {
    missing(set, required).is_empty()
}

pub fn effective_map(set: &PermissionSet) -> BTreeMap<String, PermissionLevel> {
    set.entries.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_yaml::from_str;

    #[test]
    fn parse_yaml_mapping_block() {
        let yaml: Yaml = from_str("contents: write\nissues: read\n").unwrap();
        let (set, checks) = parse_yaml_block(Some(&yaml));
        let set = set.unwrap();
        assert_eq!(set.level(PermissionKey::Contents), PermissionLevel::Write);
        assert_eq!(set.level(PermissionKey::Issues), PermissionLevel::Read);
        assert_eq!(
            set.level(PermissionKey::PullRequests),
            PermissionLevel::None
        );
        assert!(
            checks
                .iter()
                .all(|c| !matches!(c.status, crate::model::CheckStatus::Fail))
        );
    }

    #[test]
    fn parse_yaml_read_all_shortcut() {
        let yaml: Yaml = from_str("read-all").unwrap();
        let (set, _) = parse_yaml_block(Some(&yaml));
        let set = set.unwrap();
        assert_eq!(set.level(PermissionKey::Contents), PermissionLevel::Read);
        assert_eq!(set.level(PermissionKey::Issues), PermissionLevel::Read);
        // id-token must remain default-none even under read-all
        assert_eq!(set.level(PermissionKey::IdToken), PermissionLevel::None);
        assert_eq!(set.shorthand.as_deref(), Some("read-all"));
    }

    #[test]
    fn parse_yaml_unknown_key_warns_but_keeps_value() {
        let yaml: Yaml = from_str("bogus: write\n").unwrap();
        let (set, checks) = parse_yaml_block(Some(&yaml));
        let set = set.unwrap();
        assert!(set.unknown_keys.iter().any(|k| k == "bogus"));
        assert!(checks.iter().any(|c| c.id == "permissions.unknown_key"));
    }

    #[test]
    fn parse_yaml_invalid_level_fails() {
        let yaml: Yaml = from_str("contents: full\n").unwrap();
        let (_, checks) = parse_yaml_block(Some(&yaml));
        assert!(checks.iter().any(|c| c.id == "permissions.unknown_level"));
    }

    #[test]
    fn satisfies_when_level_matches() {
        let mut set = PermissionSet::default();
        set.entries
            .insert("contents".to_owned(), PermissionLevel::Write);
        let required = vec![RequiredPermission {
            key: PermissionKey::Contents,
            level: PermissionLevel::Write,
        }];
        assert!(satisfies(&set, &required));
        assert!(missing(&set, &required).is_empty());
    }

    #[test]
    fn missing_when_below_required_level() {
        let mut set = PermissionSet::default();
        set.entries
            .insert("contents".to_owned(), PermissionLevel::Read);
        let required = vec![RequiredPermission {
            key: PermissionKey::Contents,
            level: PermissionLevel::Write,
        }];
        assert_eq!(missing(&set, &required).len(), 1);
        assert!(!satisfies(&set, &required));
    }

    #[test]
    fn resolve_prefers_job_over_workflow() {
        let mut wf = PermissionSet::default();
        wf.entries
            .insert("contents".to_owned(), PermissionLevel::Write);
        let mut job = PermissionSet::default();
        job.entries
            .insert("contents".to_owned(), PermissionLevel::Read);
        let resolution = resolve(Some(wf), Some(job), PermissionScope::Job);
        assert!(matches!(resolution.source, PermissionSource::JobBlock));
        assert_eq!(
            resolution.effective.level(PermissionKey::Contents),
            PermissionLevel::Read
        );
    }

    #[test]
    fn resolve_default_restricted_emits_warning() {
        let resolution = resolve(None, None, PermissionScope::Job);
        assert!(matches!(
            resolution.source,
            PermissionSource::DefaultRestricted
        ));
        assert!(
            resolution
                .checks
                .iter()
                .any(|c| c.id == "permissions.default_restricted")
        );
    }

    #[test]
    fn parse_json_permissions_object() {
        let value: Value = serde_json::from_str(r#"{"contents":"write","issues":"read"}"#).unwrap();
        let set = parse_json_permissions(&value).unwrap();
        assert_eq!(set.level(PermissionKey::Contents), PermissionLevel::Write);
        assert_eq!(set.level(PermissionKey::Issues), PermissionLevel::Read);
    }

    #[test]
    fn parse_json_permissions_shorthand() {
        let value: Value = serde_json::from_str(r#""write-all""#).unwrap();
        let set = parse_json_permissions(&value).unwrap();
        assert_eq!(set.level(PermissionKey::Contents), PermissionLevel::Write);
        assert_eq!(set.level(PermissionKey::IdToken), PermissionLevel::None);
    }
}
