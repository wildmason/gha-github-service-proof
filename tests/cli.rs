use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use tempfile::tempdir;

fn bin() -> Command {
    Command::cargo_bin("gha-github-service-proof").unwrap()
}

fn write_workflow(repo: &std::path::Path, body: &str) {
    let dir = repo.join(".github/workflows");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("ci.yml"), body).unwrap();
}

#[test]
fn check_workflow_detects_gh_release_with_sufficient_permissions() {
    let temp = tempdir().unwrap();
    let repo = temp.path().join("repo");
    fs::create_dir_all(&repo).unwrap();
    write_workflow(
        &repo,
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
    );

    let output = bin()
        .args([
            "check-workflow",
            "--repo",
            repo.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let receipt: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(receipt["mode"], "check-workflow");
    assert_eq!(receipt["workflows"][0]["jobs"][0]["job_id"], "publish");
    let detections = &receipt["workflows"][0]["jobs"][0]["steps"][0]["detections"];
    assert_eq!(detections.as_array().unwrap().len(), 2);
    assert_eq!(detections[0]["classification"], "simulated");
    assert_eq!(detections[0]["satisfied"], true);
    assert_eq!(receipt["summary"]["failed"], 0);
}

#[test]
fn check_workflow_fails_when_release_needs_write_but_block_grants_read() {
    let temp = tempdir().unwrap();
    let repo = temp.path().join("repo");
    fs::create_dir_all(&repo).unwrap();
    write_workflow(
        &repo,
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
    );

    let assertion = bin()
        .args([
            "check-workflow",
            "--repo",
            repo.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .failure();

    let receipt: Value = serde_json::from_slice(&assertion.get_output().stdout).unwrap();
    assert!(
        receipt["summary"]["failed"].as_u64().unwrap() > 0,
        "expected failed > 0, got receipt {receipt}"
    );
}

#[test]
fn permissions_command_resolves_job_block_over_workflow() {
    let temp = tempdir().unwrap();
    let workflow = temp.path().join("ci.yml");
    fs::write(
        &workflow,
        r#"
name: ci
on: push
permissions:
  contents: write
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    steps:
      - run: echo hi
"#,
    )
    .unwrap();

    let output = bin()
        .args([
            "permissions",
            "--workflow",
            workflow.to_str().unwrap(),
            "--job",
            "build",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let receipt: Value = serde_json::from_slice(&output).unwrap();
    let effective = &receipt["permissions"]["effective"]["entries"];
    assert_eq!(effective["contents"], "read");
    assert_eq!(effective["id-token"], "write");
    assert_eq!(receipt["permissions"]["source"], "job-block");
}

#[test]
fn call_command_classifies_release_create_as_simulated_with_write() {
    let output = bin()
        .args([
            "call",
            "--method",
            "POST",
            "--path",
            "/repos/wildmason/mortar/releases",
            "--permissions",
            r#"{"contents":"write"}"#,
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let receipt: Value = serde_json::from_slice(&output).unwrap();
    let call = &receipt["calls"][0];
    assert_eq!(call["classification"], "simulated");
    assert_eq!(call["catalog_match"]["endpoint_id"], "releases.create");
    assert_eq!(call["satisfied"], true);
}

#[test]
fn call_command_flags_off_catalog_as_unsupported() {
    let assertion = bin()
        .args([
            "call",
            "--method",
            "POST",
            "--path",
            "/repos/wildmason/mortar/branches/main/protection",
            "--permissions",
            r#"{"contents":"write"}"#,
            "--format",
            "json",
        ])
        .assert();

    let receipt: Value = serde_json::from_slice(&assertion.get_output().stdout).unwrap();
    let call = &receipt["calls"][0];
    assert_eq!(call["classification"], "unsupported");
    assert_eq!(call["unsupported_reason"], "rest.endpoint_not_in_catalog");
}

#[test]
fn call_command_flags_graphql_as_unsupported() {
    let assertion = bin()
        .args([
            "call", "--method", "POST", "--path", "/graphql", "--format", "json",
        ])
        .assert()
        .failure();

    let receipt: Value = serde_json::from_slice(&assertion.get_output().stdout).unwrap();
    let call = &receipt["calls"][0];
    assert_eq!(call["classification"], "unsupported");
    assert_eq!(
        call["unsupported_reason"],
        "graphql.classification_not_implemented"
    );
}

#[test]
fn oidc_command_issues_stub_jwt_with_id_token_write() {
    let output = bin()
        .args([
            "oidc",
            "--audience",
            "sts.amazonaws.com",
            "--repository",
            "wildmason/mortar",
            "--ref",
            "refs/heads/main",
            "--sha",
            "deadbeef",
            "--workflow",
            "release.yml",
            "--job",
            "deploy",
            "--run-id",
            "1234567890",
            "--permissions",
            r#"{"id-token":"write"}"#,
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let receipt: Value = serde_json::from_slice(&output).unwrap();
    let oidc = &receipt["oidc"];
    assert_eq!(oidc["audience"], "sts.amazonaws.com");
    assert_eq!(oidc["signing_mode"], "stub-local");
    assert_eq!(oidc["compatibility"], "simulated");
    assert_eq!(oidc["claims"]["aud"], "sts.amazonaws.com");
    assert_eq!(
        oidc["claims"]["sub"],
        "repo:wildmason/mortar:ref:refs/heads/main"
    );
    assert_eq!(oidc["claims"]["stub_local"], true);
    assert!(oidc["token"].as_str().unwrap().contains('.'));
    let exp = oidc["exp"].as_i64().unwrap();
    let iat = oidc["iat"].as_i64().unwrap();
    assert_eq!(exp - iat, 300);
}

#[test]
fn oidc_command_fails_without_id_token_write_under_strict() {
    bin()
        .args([
            "oidc",
            "--audience",
            "sts.amazonaws.com",
            "--permissions",
            r#"{"contents":"write"}"#,
            "--format",
            "json",
        ])
        .assert()
        .failure();
}

#[test]
fn gh_log_command_replays_redacted_bundle() {
    let temp = tempdir().unwrap();
    let bundle_path = temp.path().join("bundle.json");
    fs::write(
        &bundle_path,
        r#"{
            "schema_version": 1,
            "tool": {"name": "ci-forge", "version": "0.1.0"},
            "captured_at": "2026-05-12T18:00:00Z",
            "calls": [
                {
                    "id": "call-1",
                    "source": "gh",
                    "method": "POST",
                    "url": "https://api.github.com/repos/wildmason/mortar/releases",
                    "path": "/repos/wildmason/mortar/releases",
                    "request_headers": {
                        "accept": "application/vnd.github+json",
                        "authorization": "<redacted>"
                    },
                    "request_body_excerpt": "{}",
                    "status": 201,
                    "exit_code": 0
                }
            ]
        }"#,
    )
    .unwrap();

    let output = bin()
        .args([
            "gh-log",
            "--log",
            bundle_path.to_str().unwrap(),
            "--permissions",
            r#"{"contents":"write"}"#,
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let receipt: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(receipt["gh_log"]["call_count"], 1);
    assert_eq!(receipt["gh_log"]["redaction_enforced"], true);
    assert_eq!(
        receipt["gh_log"]["calls"][0]["catalog_match"]["endpoint_id"],
        "releases.create"
    );
}

#[test]
fn gh_log_fails_on_unredacted_authorization() {
    let temp = tempdir().unwrap();
    let bundle_path = temp.path().join("bundle.json");
    fs::write(
        &bundle_path,
        r#"{
            "schema_version": 1,
            "tool": {"name": "ci-forge", "version": "0.1.0"},
            "calls": [
                {
                    "id": "call-1",
                    "source": "gh",
                    "method": "GET",
                    "path": "/repos/wildmason/mortar/releases",
                    "request_headers": {
                        "authorization": "Bearer ghp_real_secret"
                    }
                }
            ]
        }"#,
    )
    .unwrap();

    bin()
        .args([
            "gh-log",
            "--log",
            bundle_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .failure();
}

#[test]
fn output_path_writes_receipt_to_file_and_suppresses_stdout() {
    let temp = tempdir().unwrap();
    let out_path = temp.path().join("receipt.json");
    let output = bin()
        .args([
            "call",
            "--method",
            "GET",
            "--path",
            "/rate_limit",
            "--format",
            "json",
            "--output",
            out_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert!(
        output.is_empty(),
        "stdout should be empty when --output is set"
    );
    let written = fs::read_to_string(&out_path).unwrap();
    let receipt: Value = serde_json::from_str(&written).unwrap();
    assert_eq!(receipt["mode"], "call");
    assert_eq!(receipt["calls"][0]["classification"], "exact");
}

#[test]
fn call_accepts_metadata_read_in_permissions_silently() {
    let output = bin()
        .args([
            "call",
            "--method",
            "POST",
            "--path",
            "/repos/wildmason/mortar/releases",
            "--permissions",
            r#"{"contents":"write","metadata":"read"}"#,
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let receipt: Value = serde_json::from_slice(&output).unwrap();
    let call = &receipt["calls"][0];
    assert_eq!(call["classification"], "simulated");
    assert_eq!(call["satisfied"], true);
    let granted = &call["permissions"]["entries"];
    assert_eq!(granted["contents"], "write");
    assert_eq!(granted["metadata"], "read");
    let unknown = &call["permissions"]["unknown_keys"];
    if let Some(list) = unknown.as_array() {
        assert!(
            list.iter().all(|v| v.as_str() != Some("metadata")),
            "metadata: read must not be flagged as unknown when supplied via JSON permissions"
        );
    }
}

#[test]
fn call_rejects_metadata_write_in_permissions() {
    let assertion = bin()
        .args([
            "call",
            "--method",
            "GET",
            "--path",
            "/rate_limit",
            "--permissions",
            r#"{"metadata":"write"}"#,
            "--format",
            "json",
        ])
        .assert()
        .failure();

    let stderr = String::from_utf8_lossy(&assertion.get_output().stderr).into_owned();
    assert!(
        stderr.contains("metadata"),
        "expected metadata error on stderr, got: {stderr}"
    );
}

#[test]
fn gh_log_accepts_metadata_read_in_permissions() {
    let temp = tempdir().unwrap();
    let bundle_path = temp.path().join("bundle.json");
    fs::write(
        &bundle_path,
        r#"{
            "schema_version": 1,
            "tool": {"name": "ci-forge", "version": "0.1.0"},
            "calls": [
                {
                    "id": "call-1",
                    "source": "gh",
                    "method": "GET",
                    "path": "/repos/wildmason/mortar",
                    "request_headers": {"authorization": "<redacted>"}
                }
            ]
        }"#,
    )
    .unwrap();

    let output = bin()
        .args([
            "gh-log",
            "--log",
            bundle_path.to_str().unwrap(),
            "--permissions",
            r#"{"contents":"read","metadata":"read"}"#,
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let receipt: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(receipt["gh_log"]["call_count"], 1);
    let call = &receipt["gh_log"]["calls"][0];
    assert_eq!(call["catalog_match"]["endpoint_id"], "repos.get");
    assert_eq!(call["satisfied"], true);
}

#[test]
fn check_workflow_flags_metadata_key_as_not_configurable() {
    let temp = tempdir().unwrap();
    let repo = temp.path().join("repo");
    fs::create_dir_all(&repo).unwrap();
    write_workflow(
        &repo,
        r#"
name: ci
on: push
permissions:
  contents: read
  metadata: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"#,
    );

    let assertion = bin()
        .args([
            "check-workflow",
            "--repo",
            repo.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .failure();

    let receipt: Value = serde_json::from_slice(&assertion.get_output().stdout).unwrap();
    let checks = &receipt["workflows"][0]["checks"];
    let ids: Vec<&str> = checks
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["id"].as_str())
        .collect();
    assert!(
        ids.contains(&"permissions.metadata_not_configurable"),
        "expected permissions.metadata_not_configurable in workflow checks, got: {ids:?}"
    );
    assert!(
        !ids.contains(&"permissions.unknown_key"),
        "permissions.unknown_key must not fire for the workflow-syntax `metadata` key; got: {ids:?}"
    );
}
