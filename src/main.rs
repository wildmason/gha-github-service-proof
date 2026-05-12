use anyhow::{Context, Result, bail};
use camino::Utf8PathBuf;
use clap::{Args, Parser, Subcommand};
use gha_github_service_proof::{
    CallOptions, CheckWorkflowOptions, GhLogOptions, OidcOptions, OutputFormat, PermissionSet,
    PermissionsOptions, check_workflows, classify_call, issue_oidc, permissions,
    permissions_command, render_receipt, replay_gh_log,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::process::ExitCode;

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Check GitHub Actions service/API compatibility with offline receipts"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    #[arg(long, global = true, value_enum, default_value = "text")]
    format: OutputFormat,

    #[arg(long, global = true, value_name = "PATH")]
    output: Option<Utf8PathBuf>,

    #[arg(long, global = true)]
    strict: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    CheckWorkflow(CheckWorkflowArgs),
    Permissions(PermissionsArgs),
    Call(CallArgs),
    Oidc(OidcArgs),
    GhLog(GhLogArgs),
}

#[derive(Debug, Args)]
struct CheckWorkflowArgs {
    #[arg(long, value_name = "DIR", default_value = ".")]
    repo: Utf8PathBuf,

    #[arg(long, value_name = "PATH")]
    workflow: Vec<Utf8PathBuf>,
}

#[derive(Debug, Args)]
struct PermissionsArgs {
    #[arg(long, value_name = "PATH")]
    workflow: Utf8PathBuf,

    #[arg(long, value_name = "JOB")]
    job: Option<String>,
}

#[derive(Debug, Args)]
struct CallArgs {
    #[arg(long, value_name = "METHOD")]
    method: String,

    #[arg(long, value_name = "PATH")]
    path: String,

    #[arg(long, value_name = "URL")]
    url: Option<String>,

    #[arg(long, value_name = "JSON")]
    permissions: Option<String>,

    #[arg(long, value_name = "PATH")]
    permissions_file: Option<Utf8PathBuf>,

    #[arg(long, value_name = "ORIGIN")]
    origin: Option<String>,
}

#[derive(Debug, Args)]
struct OidcArgs {
    #[arg(long, value_name = "AUDIENCE")]
    audience: String,

    #[arg(long, value_name = "JSON")]
    permissions: Option<String>,

    #[arg(long, value_name = "PATH")]
    permissions_file: Option<Utf8PathBuf>,

    #[arg(long, value_name = "OWNER/REPO", default_value = "wildmason/oss")]
    repository: String,

    #[arg(long = "ref", value_name = "REF", default_value = "refs/heads/main")]
    git_ref: String,

    #[arg(
        long,
        value_name = "SHA",
        default_value = "0000000000000000000000000000000000000000"
    )]
    sha: String,

    #[arg(long, value_name = "WORKFLOW", default_value = "release.yml")]
    workflow: String,

    #[arg(long, value_name = "JOB", default_value = "deploy")]
    job: String,

    #[arg(long = "run-id", value_name = "RUN-ID", default_value = "1")]
    run_id: String,

    #[arg(long = "job-workflow-ref", value_name = "REF")]
    job_workflow_ref: Option<String>,

    #[arg(long = "ttl-seconds", value_name = "SECONDS")]
    ttl_seconds: Option<i64>,

    #[arg(long = "claim", value_name = "NAME=JSON")]
    extra_claims: Vec<String>,
}

#[derive(Debug, Args)]
struct GhLogArgs {
    #[arg(long, value_name = "PATH")]
    log: Utf8PathBuf,

    #[arg(long, value_name = "JSON")]
    permissions: Option<String>,

    #[arg(long, value_name = "PATH")]
    permissions_file: Option<Utf8PathBuf>,

    #[arg(long = "unsafe-full-payloads")]
    unsafe_full_payloads: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let receipt = match &cli.command {
        Command::CheckWorkflow(args) => {
            if !args.repo.is_dir() {
                bail!("--repo must be an existing directory: {}", args.repo);
            }
            check_workflows(&CheckWorkflowOptions {
                repo_root: args.repo.clone(),
                workflows: args.workflow.clone(),
            })?
        }
        Command::Permissions(args) => permissions_command(&PermissionsOptions {
            workflow_path: args.workflow.clone(),
            job: args.job.clone(),
        })?,
        Command::Call(args) => {
            let permissions = load_permissions(
                args.permissions.as_deref(),
                args.permissions_file.as_deref(),
            )?;
            classify_call(&CallOptions {
                method: args.method.clone(),
                path: args.path.clone(),
                url: args.url.clone(),
                permissions,
                origin: args.origin.clone(),
            })?
        }
        Command::Oidc(args) => {
            let permissions = load_permissions(
                args.permissions.as_deref(),
                args.permissions_file.as_deref(),
            )?;
            let extra_claims = parse_extra_claims(&args.extra_claims)?;
            issue_oidc(&OidcOptions {
                audience: args.audience.clone(),
                repository: args.repository.clone(),
                git_ref: args.git_ref.clone(),
                sha: args.sha.clone(),
                workflow: args.workflow.clone(),
                job: args.job.clone(),
                run_id: args.run_id.clone(),
                job_workflow_ref: args.job_workflow_ref.clone(),
                permissions,
                ttl_seconds: args.ttl_seconds,
                extra_claims,
            })?
        }
        Command::GhLog(args) => {
            let permissions = load_permissions(
                args.permissions.as_deref(),
                args.permissions_file.as_deref(),
            )?;
            replay_gh_log(&GhLogOptions {
                log_path: args.log.clone(),
                permissions,
                unsafe_full_payloads: args.unsafe_full_payloads,
            })?
        }
    };

    let rendered = render_receipt(&receipt, cli.format)?;
    if let Some(output) = cli.output {
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {parent}"))?;
        }
        fs::write(&output, rendered).with_context(|| format!("writing {output}"))?;
    } else {
        print!("{rendered}");
    }

    if receipt.summary.failed > 0 || (cli.strict && receipt.summary.warnings > 0) {
        bail!("github service proof failed");
    }

    Ok(())
}

fn load_permissions(
    inline: Option<&str>,
    file: Option<&camino::Utf8Path>,
) -> Result<Option<PermissionSet>> {
    if let Some(path) = file {
        let raw =
            fs::read_to_string(path).with_context(|| format!("reading permissions file {path}"))?;
        let value: Value = serde_json::from_str(&raw)
            .with_context(|| format!("parsing permissions file {path}"))?;
        return Ok(Some(permissions::parse_json_permissions(&value)?));
    }
    if let Some(text) = inline {
        let trimmed = text.trim();
        let value: Value = match serde_json::from_str(trimmed) {
            Ok(value) => value,
            Err(_) => Value::String(trimmed.to_owned()),
        };
        return Ok(Some(permissions::parse_json_permissions(&value)?));
    }
    Ok(None)
}

fn parse_extra_claims(entries: &[String]) -> Result<BTreeMap<String, Value>> {
    let mut claims = BTreeMap::new();
    for entry in entries {
        let Some((name, value_text)) = entry.split_once('=') else {
            bail!("--claim entries must be NAME=JSON, got '{entry}'");
        };
        let value: Value = serde_json::from_str(value_text.trim())
            .with_context(|| format!("parsing JSON for claim '{name}'"))?;
        claims.insert(name.trim().to_owned(), value);
    }
    Ok(claims)
}
