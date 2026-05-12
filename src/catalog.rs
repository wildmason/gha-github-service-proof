use crate::model::{
    CatalogMatch, Compatibility, PermissionKey, PermissionLevel, RequiredPermission,
};

use PermissionKey as PK;
use PermissionLevel as PL;

pub struct EndpointEntry {
    pub id: &'static str,
    pub method: &'static str,
    pub path_template: &'static str,
    pub category: &'static str,
    pub required: &'static [(PermissionKey, PermissionLevel)],
    pub classification: Compatibility,
    pub side_effect: &'static str,
}

impl EndpointEntry {
    pub fn to_match(&self) -> CatalogMatch {
        CatalogMatch {
            endpoint_id: self.id.to_owned(),
            method: self.method.to_owned(),
            path_template: self.path_template.to_owned(),
            category: self.category.to_owned(),
            required_permissions: self
                .required
                .iter()
                .map(|(key, level)| RequiredPermission {
                    key: *key,
                    level: *level,
                })
                .collect(),
            classification: self.classification,
            side_effect: self.side_effect.to_owned(),
        }
    }
}

pub const CATALOG: &[EndpointEntry] = &[
    // -- repos / contents --
    EndpointEntry {
        id: "repos.get",
        method: "GET",
        path_template: "/repos/{owner}/{repo}",
        category: "repos",
        required: &[(PK::Contents, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "Read repository metadata; ci-forge serves deterministic stub.",
    },
    EndpointEntry {
        id: "contents.get",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/contents/{path}",
        category: "contents",
        required: &[(PK::Contents, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "Read file contents; ci-forge serves from local workspace.",
    },
    EndpointEntry {
        id: "contents.put",
        method: "PUT",
        path_template: "/repos/{owner}/{repo}/contents/{path}",
        category: "contents",
        required: &[(PK::Contents, PL::Write)],
        classification: Compatibility::Simulated,
        side_effect: "Create or update file; ci-forge mutates local workspace.",
    },
    EndpointEntry {
        id: "contents.delete",
        method: "DELETE",
        path_template: "/repos/{owner}/{repo}/contents/{path}",
        category: "contents",
        required: &[(PK::Contents, PL::Write)],
        classification: Compatibility::Simulated,
        side_effect: "Delete file; ci-forge mutates local workspace.",
    },
    EndpointEntry {
        id: "git.refs.get",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/git/refs/{ref}",
        category: "git-refs",
        required: &[(PK::Contents, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "Read git ref; ci-forge serves from local repository.",
    },
    EndpointEntry {
        id: "git.refs.create",
        method: "POST",
        path_template: "/repos/{owner}/{repo}/git/refs",
        category: "git-refs",
        required: &[(PK::Contents, PL::Write)],
        classification: Compatibility::Simulated,
        side_effect: "Create git ref; ci-forge mutates local repository.",
    },
    EndpointEntry {
        id: "git.refs.update",
        method: "PATCH",
        path_template: "/repos/{owner}/{repo}/git/refs/{ref}",
        category: "git-refs",
        required: &[(PK::Contents, PL::Write)],
        classification: Compatibility::Simulated,
        side_effect: "Update git ref; ci-forge mutates local repository.",
    },
    EndpointEntry {
        id: "git.refs.delete",
        method: "DELETE",
        path_template: "/repos/{owner}/{repo}/git/refs/{ref}",
        category: "git-refs",
        required: &[(PK::Contents, PL::Write)],
        classification: Compatibility::Simulated,
        side_effect: "Delete git ref; ci-forge mutates local repository.",
    },
    EndpointEntry {
        id: "git.tags.get",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/git/tags/{sha}",
        category: "git-tags",
        required: &[(PK::Contents, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "Read git tag; ci-forge serves from local repository.",
    },
    EndpointEntry {
        id: "git.tags.create",
        method: "POST",
        path_template: "/repos/{owner}/{repo}/git/tags",
        category: "git-tags",
        required: &[(PK::Contents, PL::Write)],
        classification: Compatibility::Simulated,
        side_effect: "Create annotated tag; ci-forge mutates local repository.",
    },
    // -- releases / assets --
    EndpointEntry {
        id: "releases.list",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/releases",
        category: "releases",
        required: &[(PK::Contents, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "List releases; ci-forge serves from local release store.",
    },
    EndpointEntry {
        id: "releases.create",
        method: "POST",
        path_template: "/repos/{owner}/{repo}/releases",
        category: "releases",
        required: &[(PK::Contents, PL::Write)],
        classification: Compatibility::Simulated,
        side_effect: "Create release; ci-forge persists to local release store.",
    },
    EndpointEntry {
        id: "releases.get",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/releases/{id}",
        category: "releases",
        required: &[(PK::Contents, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "Get release by id; ci-forge serves from local release store.",
    },
    EndpointEntry {
        id: "releases.update",
        method: "PATCH",
        path_template: "/repos/{owner}/{repo}/releases/{id}",
        category: "releases",
        required: &[(PK::Contents, PL::Write)],
        classification: Compatibility::Simulated,
        side_effect: "Edit release metadata; ci-forge mutates local release store.",
    },
    EndpointEntry {
        id: "releases.delete",
        method: "DELETE",
        path_template: "/repos/{owner}/{repo}/releases/{id}",
        category: "releases",
        required: &[(PK::Contents, PL::Write)],
        classification: Compatibility::Simulated,
        side_effect: "Delete release; ci-forge mutates local release store.",
    },
    EndpointEntry {
        id: "releases.latest",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/releases/latest",
        category: "releases",
        required: &[(PK::Contents, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "Get latest release; ci-forge serves from local release store.",
    },
    EndpointEntry {
        id: "releases.by_tag",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/releases/tags/{tag}",
        category: "releases",
        required: &[(PK::Contents, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "Get release by tag; ci-forge serves from local release store.",
    },
    EndpointEntry {
        id: "releases.assets.list",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/releases/{id}/assets",
        category: "release-assets",
        required: &[(PK::Contents, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "List release assets; ci-forge serves from local release store.",
    },
    EndpointEntry {
        id: "releases.assets.upload",
        method: "POST",
        path_template: "/repos/{owner}/{repo}/releases/{id}/assets",
        category: "release-assets",
        required: &[(PK::Contents, PL::Write)],
        classification: Compatibility::Simulated,
        side_effect: "Upload release asset; ci-forge persists asset to local release store.",
    },
    EndpointEntry {
        id: "releases.assets.delete",
        method: "DELETE",
        path_template: "/repos/{owner}/{repo}/releases/assets/{id}",
        category: "release-assets",
        required: &[(PK::Contents, PL::Write)],
        classification: Compatibility::Simulated,
        side_effect: "Delete release asset; ci-forge mutates local release store.",
    },
    EndpointEntry {
        id: "releases.assets.get",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/releases/assets/{id}",
        category: "release-assets",
        required: &[(PK::Contents, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "Get release asset metadata; ci-forge serves from local release store.",
    },
    // -- issues / comments / labels --
    EndpointEntry {
        id: "issues.list",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/issues",
        category: "issues",
        required: &[(PK::Issues, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "List issues; ci-forge serves empty/stub list offline.",
    },
    EndpointEntry {
        id: "issues.create",
        method: "POST",
        path_template: "/repos/{owner}/{repo}/issues",
        category: "issues",
        required: &[(PK::Issues, PL::Write)],
        classification: Compatibility::Simulated,
        side_effect: "Create issue; ci-forge logs deterministic stub locally.",
    },
    EndpointEntry {
        id: "issues.get",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/issues/{number}",
        category: "issues",
        required: &[(PK::Issues, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "Get issue; ci-forge serves stub offline.",
    },
    EndpointEntry {
        id: "issues.update",
        method: "PATCH",
        path_template: "/repos/{owner}/{repo}/issues/{number}",
        category: "issues",
        required: &[(PK::Issues, PL::Write)],
        classification: Compatibility::Simulated,
        side_effect: "Update issue; ci-forge logs stub mutation locally.",
    },
    EndpointEntry {
        id: "issues.comments.list",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/issues/{number}/comments",
        category: "issue-comments",
        required: &[(PK::Issues, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "List issue comments; ci-forge serves stub locally.",
    },
    EndpointEntry {
        id: "issues.comments.create",
        method: "POST",
        path_template: "/repos/{owner}/{repo}/issues/{number}/comments",
        category: "issue-comments",
        required: &[(PK::Issues, PL::Write)],
        classification: Compatibility::Simulated,
        side_effect: "Create issue comment; ci-forge logs stub mutation locally.",
    },
    EndpointEntry {
        id: "issues.labels.list",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/issues/{number}/labels",
        category: "issue-labels",
        required: &[(PK::Issues, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "List labels on issue; ci-forge serves stub locally.",
    },
    EndpointEntry {
        id: "issues.labels.add",
        method: "POST",
        path_template: "/repos/{owner}/{repo}/issues/{number}/labels",
        category: "issue-labels",
        required: &[(PK::Issues, PL::Write)],
        classification: Compatibility::Simulated,
        side_effect: "Add labels to issue; ci-forge logs stub mutation locally.",
    },
    EndpointEntry {
        id: "issues.labels.remove",
        method: "DELETE",
        path_template: "/repos/{owner}/{repo}/issues/{number}/labels/{name}",
        category: "issue-labels",
        required: &[(PK::Issues, PL::Write)],
        classification: Compatibility::Simulated,
        side_effect: "Remove label from issue; ci-forge logs stub mutation locally.",
    },
    EndpointEntry {
        id: "repo.labels.list",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/labels",
        category: "labels",
        required: &[(PK::Issues, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "List repo labels; ci-forge serves stub locally.",
    },
    // -- pull requests --
    EndpointEntry {
        id: "pulls.list",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/pulls",
        category: "pulls",
        required: &[(PK::PullRequests, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "List pull requests; ci-forge serves stub locally.",
    },
    EndpointEntry {
        id: "pulls.create",
        method: "POST",
        path_template: "/repos/{owner}/{repo}/pulls",
        category: "pulls",
        required: &[(PK::PullRequests, PL::Write)],
        classification: Compatibility::Simulated,
        side_effect: "Create pull request; ci-forge logs stub mutation locally.",
    },
    EndpointEntry {
        id: "pulls.get",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/pulls/{number}",
        category: "pulls",
        required: &[(PK::PullRequests, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "Get pull request; ci-forge serves stub locally.",
    },
    EndpointEntry {
        id: "pulls.update",
        method: "PATCH",
        path_template: "/repos/{owner}/{repo}/pulls/{number}",
        category: "pulls",
        required: &[(PK::PullRequests, PL::Write)],
        classification: Compatibility::Simulated,
        side_effect: "Update pull request; ci-forge logs stub mutation locally.",
    },
    EndpointEntry {
        id: "pulls.reviews.list",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/pulls/{number}/reviews",
        category: "pull-reviews",
        required: &[(PK::PullRequests, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "List PR reviews; ci-forge serves stub locally.",
    },
    EndpointEntry {
        id: "pulls.reviews.create",
        method: "POST",
        path_template: "/repos/{owner}/{repo}/pulls/{number}/reviews",
        category: "pull-reviews",
        required: &[(PK::PullRequests, PL::Write)],
        classification: Compatibility::Simulated,
        side_effect: "Create PR review; ci-forge logs stub mutation locally.",
    },
    EndpointEntry {
        id: "pulls.comments.create",
        method: "POST",
        path_template: "/repos/{owner}/{repo}/pulls/{number}/comments",
        category: "pull-comments",
        required: &[(PK::PullRequests, PL::Write)],
        classification: Compatibility::Simulated,
        side_effect: "Create PR review comment; ci-forge logs stub mutation locally.",
    },
    // -- checks --
    EndpointEntry {
        id: "checks.runs.create",
        method: "POST",
        path_template: "/repos/{owner}/{repo}/check-runs",
        category: "checks",
        required: &[(PK::Checks, PL::Write)],
        classification: Compatibility::Simulated,
        side_effect: "Create check run; ci-forge persists stub check locally.",
    },
    EndpointEntry {
        id: "checks.runs.update",
        method: "PATCH",
        path_template: "/repos/{owner}/{repo}/check-runs/{id}",
        category: "checks",
        required: &[(PK::Checks, PL::Write)],
        classification: Compatibility::Simulated,
        side_effect: "Update check run; ci-forge mutates stub check locally.",
    },
    EndpointEntry {
        id: "checks.runs.get",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/check-runs/{id}",
        category: "checks",
        required: &[(PK::Checks, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "Get check run; ci-forge serves stub check locally.",
    },
    EndpointEntry {
        id: "checks.runs.list_for_commit",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/commits/{sha}/check-runs",
        category: "checks",
        required: &[(PK::Checks, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "List check runs for commit; ci-forge serves stub list locally.",
    },
    EndpointEntry {
        id: "checks.suites.list_for_commit",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/commits/{sha}/check-suites",
        category: "checks",
        required: &[(PK::Checks, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "List check suites for commit; ci-forge serves stub list locally.",
    },
    // -- statuses --
    EndpointEntry {
        id: "statuses.create",
        method: "POST",
        path_template: "/repos/{owner}/{repo}/statuses/{sha}",
        category: "statuses",
        required: &[(PK::Statuses, PL::Write)],
        classification: Compatibility::Simulated,
        side_effect: "Create commit status; ci-forge persists stub status locally.",
    },
    EndpointEntry {
        id: "statuses.list_for_ref",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/commits/{ref}/statuses",
        category: "statuses",
        required: &[(PK::Statuses, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "List statuses for ref; ci-forge serves stub list locally.",
    },
    EndpointEntry {
        id: "statuses.combined_for_ref",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/commits/{ref}/status",
        category: "statuses",
        required: &[(PK::Statuses, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "Get combined status for ref; ci-forge serves stub locally.",
    },
    // -- actions metadata --
    EndpointEntry {
        id: "actions.runs.list",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/actions/runs",
        category: "actions",
        required: &[(PK::Actions, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "List workflow runs; ci-forge serves from local run store.",
    },
    EndpointEntry {
        id: "actions.runs.get",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/actions/runs/{id}",
        category: "actions",
        required: &[(PK::Actions, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "Get workflow run; ci-forge serves from local run store.",
    },
    EndpointEntry {
        id: "actions.runs.jobs",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/actions/runs/{id}/jobs",
        category: "actions",
        required: &[(PK::Actions, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "List jobs for workflow run; ci-forge serves from local run store.",
    },
    EndpointEntry {
        id: "actions.runs.cancel",
        method: "POST",
        path_template: "/repos/{owner}/{repo}/actions/runs/{id}/cancel",
        category: "actions",
        required: &[(PK::Actions, PL::Write)],
        classification: Compatibility::Simulated,
        side_effect: "Cancel workflow run; ci-forge mutates local run store.",
    },
    EndpointEntry {
        id: "actions.artifacts.list",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/actions/artifacts",
        category: "actions",
        required: &[(PK::Actions, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "List artifacts; ci-forge serves from local artifact store.",
    },
    EndpointEntry {
        id: "actions.artifacts.get",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/actions/artifacts/{id}",
        category: "actions",
        required: &[(PK::Actions, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "Get artifact metadata; ci-forge serves from local artifact store.",
    },
    EndpointEntry {
        id: "actions.artifacts.list_for_run",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/actions/runs/{id}/artifacts",
        category: "actions",
        required: &[(PK::Actions, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "List run artifacts; ci-forge serves from local artifact store.",
    },
    EndpointEntry {
        id: "actions.caches.list",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/actions/caches",
        category: "actions",
        required: &[(PK::Actions, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "List caches; ci-forge serves from local cache store.",
    },
    EndpointEntry {
        id: "actions.workflows.list",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/actions/workflows",
        category: "actions",
        required: &[(PK::Actions, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "List workflows; ci-forge serves from local workflow store.",
    },
    EndpointEntry {
        id: "actions.workflows.dispatch",
        method: "POST",
        path_template: "/repos/{owner}/{repo}/actions/workflows/{id}/dispatches",
        category: "actions",
        required: &[(PK::Actions, PL::Write)],
        classification: Compatibility::Simulated,
        side_effect: "Trigger workflow dispatch; ci-forge enqueues stub run locally.",
    },
    // -- deployments --
    EndpointEntry {
        id: "deployments.list",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/deployments",
        category: "deployments",
        required: &[(PK::Deployments, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "List deployments; ci-forge serves stub list locally.",
    },
    EndpointEntry {
        id: "deployments.create",
        method: "POST",
        path_template: "/repos/{owner}/{repo}/deployments",
        category: "deployments",
        required: &[(PK::Deployments, PL::Write)],
        classification: Compatibility::Simulated,
        side_effect: "Create deployment; ci-forge persists stub deployment locally.",
    },
    EndpointEntry {
        id: "deployments.get",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/deployments/{id}",
        category: "deployments",
        required: &[(PK::Deployments, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "Get deployment; ci-forge serves stub deployment locally.",
    },
    EndpointEntry {
        id: "deployments.statuses.create",
        method: "POST",
        path_template: "/repos/{owner}/{repo}/deployments/{id}/statuses",
        category: "deployment-statuses",
        required: &[(PK::Deployments, PL::Write)],
        classification: Compatibility::Simulated,
        side_effect: "Create deployment status; ci-forge persists stub status locally.",
    },
    EndpointEntry {
        id: "deployments.statuses.list",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/deployments/{id}/statuses",
        category: "deployment-statuses",
        required: &[(PK::Deployments, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "List deployment statuses; ci-forge serves stub list locally.",
    },
    // -- packages --
    EndpointEntry {
        id: "packages.user.list",
        method: "GET",
        path_template: "/user/packages",
        category: "packages",
        required: &[(PK::Packages, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "List user packages; ci-forge serves stub list locally.",
    },
    EndpointEntry {
        id: "packages.org.list",
        method: "GET",
        path_template: "/orgs/{org}/packages",
        category: "packages",
        required: &[(PK::Packages, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "List org packages; ci-forge serves stub list locally.",
    },
    EndpointEntry {
        id: "packages.user.get",
        method: "GET",
        path_template: "/user/packages/{package_type}/{name}",
        category: "packages",
        required: &[(PK::Packages, PL::Read)],
        classification: Compatibility::Simulated,
        side_effect: "Get user package; ci-forge serves stub locally.",
    },
    EndpointEntry {
        id: "packages.user.delete",
        method: "DELETE",
        path_template: "/user/packages/{package_type}/{name}",
        category: "packages",
        required: &[(PK::Packages, PL::Write)],
        classification: Compatibility::Simulated,
        side_effect: "Delete user package; ci-forge mutates local package store.",
    },
    // -- metadata / probes --
    EndpointEntry {
        id: "meta.rate_limit",
        method: "GET",
        path_template: "/rate_limit",
        category: "meta",
        required: &[],
        classification: Compatibility::Exact,
        side_effect: "Read rate limit; deterministic stub matches GitHub response shape exactly.",
    },
    EndpointEntry {
        id: "meta.user",
        method: "GET",
        path_template: "/user",
        category: "meta",
        required: &[],
        classification: Compatibility::Exact,
        side_effect: "Authenticated user identity; deterministic stub.",
    },
    EndpointEntry {
        id: "meta.meta",
        method: "GET",
        path_template: "/meta",
        category: "meta",
        required: &[],
        classification: Compatibility::Exact,
        side_effect: "GitHub meta info; deterministic stub.",
    },
    EndpointEntry {
        id: "meta.installation",
        method: "GET",
        path_template: "/repos/{owner}/{repo}/installation",
        category: "meta",
        required: &[],
        classification: Compatibility::Exact,
        side_effect: "App installation metadata; deterministic stub.",
    },
];

pub fn lookup(method: &str, path: &str) -> Option<CatalogMatch> {
    let normalized_method = method.trim().to_uppercase();
    let stripped = strip_query(path);
    for entry in CATALOG {
        if entry.method.eq_ignore_ascii_case(&normalized_method)
            && path_matches(entry.path_template, stripped)
        {
            return Some(entry.to_match());
        }
    }
    None
}

pub fn strip_query(path: &str) -> &str {
    match path.find('?') {
        Some(index) => &path[..index],
        None => path,
    }
}

pub fn path_matches(template: &str, path: &str) -> bool {
    let template_segs: Vec<&str> = trim_slashes(template).split('/').collect();
    let path_segs: Vec<&str> = trim_slashes(path).split('/').collect();
    if template_segs.len() != path_segs.len() {
        return false;
    }
    for (t, p) in template_segs.iter().zip(path_segs.iter()) {
        if t.is_empty() && p.is_empty() {
            continue;
        }
        if is_placeholder(t) {
            if p.is_empty() {
                return false;
            }
            continue;
        }
        if !t.eq_ignore_ascii_case(p) {
            return false;
        }
    }
    true
}

fn trim_slashes(value: &str) -> &str {
    value.trim_start_matches('/').trim_end_matches('/')
}

fn is_placeholder(segment: &str) -> bool {
    segment.starts_with('{') && segment.ends_with('}') && segment.len() >= 2
}

pub fn is_graphql_path(path: &str) -> bool {
    let stripped = strip_query(path);
    let trimmed = trim_slashes(stripped);
    trimmed.eq_ignore_ascii_case("graphql")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_matches_template_with_placeholders() {
        assert!(path_matches(
            "/repos/{owner}/{repo}/releases/{id}",
            "/repos/wildmason/mortar/releases/123",
        ));
    }

    #[test]
    fn path_matches_rejects_mismatched_segment_count() {
        assert!(!path_matches(
            "/repos/{owner}/{repo}/releases",
            "/repos/wildmason/mortar/releases/123",
        ));
    }

    #[test]
    fn path_matches_rejects_mismatched_literal() {
        assert!(!path_matches(
            "/repos/{owner}/{repo}/issues",
            "/repos/wildmason/mortar/releases",
        ));
    }

    #[test]
    fn lookup_returns_catalog_match_for_release_create() {
        let result = lookup("POST", "/repos/wildmason/mortar/releases").unwrap();
        assert_eq!(result.endpoint_id, "releases.create");
        assert_eq!(result.category, "releases");
        assert_eq!(result.required_permissions.len(), 1);
        assert_eq!(result.required_permissions[0].key, PermissionKey::Contents);
        assert_eq!(result.required_permissions[0].level, PermissionLevel::Write);
    }

    #[test]
    fn lookup_returns_none_for_off_catalog() {
        assert!(lookup("POST", "/repos/wildmason/mortar/branches/main/protection").is_none());
    }

    #[test]
    fn lookup_ignores_query_string() {
        let result = lookup("GET", "/repos/wildmason/mortar/issues?state=open").unwrap();
        assert_eq!(result.endpoint_id, "issues.list");
    }

    #[test]
    fn graphql_path_detection() {
        assert!(is_graphql_path("/graphql"));
        assert!(is_graphql_path("/graphql?foo=bar"));
        assert!(!is_graphql_path("/repos/x/y"));
    }
}
