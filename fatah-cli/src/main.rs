//! `fatah` — async credential-auditing CLI.
//!
//! Subcommands:
//!   * `list-protocols`     — enumerate compiled-in modules.
//!   * `run`                 — execute an attack plan (flags or profile).
//!   * `findings`            — list saved findings from the sled db.
//!
//! A run can be assembled three ways:
//!   1. Pure CLI flags (`-t`, `-l`, `-P`, …) — quick ad-hoc auditing.
//!   2. `--profile <path>` (TOML/YAML/JSON via figment) — declarative,
//!      versionable, supports every source kind.
//!   3. `--resume <session-id>` — picks up where a previous run stopped;
//!      the session's tried count is used as a stream offset.

#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

mod profile;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use fatah_attack::Engine;
use fatah_core::{AttackPlan, Endpoint, RateLimit, StrategyKind, Target};
use fatah_database::{Repository, SledRepository, StoredFinding};
use fatah_proto::Registry;
use fatah_report::{ConsoleReporter, JsonlReporter, Reporter};
use fatah_telemetry::{init as init_telemetry, Format as TelemetryFormat, TelemetryConfig};
use fatah_wordlist::{ComboSource, CredentialSource, FileWordlist, StaticSource};
use futures::StreamExt;
use uuid::Uuid;

use crate::profile::Profile;

#[derive(Parser, Debug)]
#[command(name = "fatah", version, about = "async credential-auditing toolkit")]
struct Cli {
    /// Global log filter (e.g. `info`, `fatah_attack=debug`).
    #[arg(long, global = true)]
    log: Option<String>,

    /// Emit logs as JSON instead of pretty.
    #[arg(long, global = true)]
    log_json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// List every protocol compiled into this binary.
    ListProtocols,
    /// Execute an attack plan.
    Run(RunArgs),
    /// Dump every saved finding from the sled db.
    Findings(FindingsArgs),
}

#[derive(clap::Args, Debug)]
struct RunArgs {
    /// Load every parameter (target, strategy, source) from a profile
    /// file. Any other run-flag is ignored when this is set.
    #[arg(long)]
    profile: Option<PathBuf>,

    /// Target URL: `<proto>://<host>[:<port>]`.
    #[arg(short = 't', long, conflicts_with = "profile")]
    target: Option<String>,

    #[arg(short = 'l', long, conflicts_with = "profile")]
    login: Option<String>,

    #[arg(short = 'L', long, conflicts_with_all = ["login", "profile"])]
    logins: Option<PathBuf>,

    #[arg(short = 'p', long, conflicts_with = "profile")]
    password: Option<String>,

    #[arg(short = 'P', long, conflicts_with_all = ["password", "profile"])]
    passwords: Option<PathBuf>,

    /// Concurrent workers.
    #[arg(long, default_value_t = 16)]
    concurrency: usize,

    /// Global rate-limit (0 = unlimited).
    #[arg(long, default_value_t = 0)]
    rate: u32,

    /// Per-attempt timeout (e.g. `10s`, `500ms`).
    #[arg(long, default_value = "10s", value_parser = humantime::parse_duration)]
    timeout: Duration,

    /// TLS-wrap the connection (HTTPS, FTPS, …).
    #[arg(long)]
    tls: bool,

    /// Don't stop on the first successful hit.
    #[arg(long)]
    keep_going: bool,

    /// Sled directory for findings + session persistence.
    #[arg(long, default_value = "./fatah.db")]
    db: PathBuf,

    /// JSONL event log path.
    #[arg(long)]
    jsonl: Option<PathBuf>,

    /// Resume a previous session by id (taken from `--db`).
    #[arg(long)]
    resume: Option<Uuid>,

    /// Snapshot the session every N consumed pairs.
    #[arg(long, default_value_t = 50)]
    checkpoint_every: u64,
}

#[derive(clap::Args, Debug)]
struct FindingsArgs {
    #[arg(long, default_value = "./fatah.db")]
    db: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    init_telemetry(TelemetryConfig {
        filter: cli.log.clone(),
        format: if cli.log_json { TelemetryFormat::Json } else { TelemetryFormat::Pretty },
        log_file: None,
        with_ansi: !cli.log_json,
    })
    .context("init telemetry")?;

    match cli.command {
        Command::ListProtocols => list_protocols(),
        Command::Run(args) => run(args).await,
        Command::Findings(args) => list_findings(args).await,
    }
}

fn list_protocols() -> Result<()> {
    let mut descriptors = Registry::descriptors();
    descriptors.sort_by_key(|d| d.id);
    println!("Available protocols:");
    for d in descriptors {
        println!(
            "  {:<14} port={:<5} tls={:<5}  {}",
            d.id, d.default_port, d.supports_tls, d.summary
        );
    }
    Ok(())
}

async fn run(args: RunArgs) -> Result<()> {
    let (target, plan, source): (Target, AttackPlan, Box<dyn CredentialSource>) =
        if let Some(path) = &args.profile {
            let profile = Profile::load(path).with_context(|| format!("load {}", path.display()))?;
            let target = profile.target();
            let plan = profile.build_plan();
            let source = profile.build_source()?;
            (target, plan, source)
        } else {
            build_from_flags(&args)?
        };

    let repo: Arc<dyn Repository> = Arc::new(
        SledRepository::open(&args.db)
            .with_context(|| format!("opening sled db at {}", args.db.display()))?,
    );

    let resume_state = if let Some(id) = args.resume {
        let state = fatah_session::load(repo.as_ref(), id)
            .await
            .with_context(|| format!("loading session {id}"))?
            .ok_or_else(|| anyhow!("no such session: {id}"))?;
        println!("[*] resuming session {id} (tried {})", state.tried);
        Some(state)
    } else {
        None
    };

    let mut engine = Engine::new()
        .with_reporter(Arc::new(ConsoleReporter::default().verbose(true)))
        .with_repository(repo.clone())
        .checkpoint_every(args.checkpoint_every);
    if let Some(path) = args.jsonl.clone() {
        engine.add_reporter(Arc::new(JsonlReporter::new(path)) as Arc<dyn Reporter>);
    }

    let mut stream = source.build();
    if let Some(s) = &resume_state {
        let skip_n: usize = s.tried.try_into().unwrap_or(usize::MAX);
        stream = Box::pin(StreamExt::skip(stream, skip_n));
    }

    let summary = engine.run(plan, stream, resume_state).await?;

    for attempt in &summary.findings {
        let finding = StoredFinding::from_attempt(attempt);
        if let Err(e) = repo.save_finding(&finding).await {
            tracing::warn!(error=%e, "save finding");
        }
    }

    if summary.findings.is_empty() {
        println!("no credentials recovered after {} attempts", summary.tried);
    } else {
        println!("recovered {} credential(s) against {}:", summary.findings.len(), target.endpoint);
        for a in &summary.findings {
            println!(
                "  {}  {}:{}",
                a.target.protocol,
                a.credential.login_str().unwrap_or("-"),
                a.credential.secret.expose()
            );
        }
    }
    println!("[*] session id: {}", summary.session_id);
    Ok(())
}

async fn list_findings(args: FindingsArgs) -> Result<()> {
    let repo = SledRepository::open(&args.db)
        .with_context(|| format!("opening sled db at {}", args.db.display()))?;
    let findings = repo.list_findings().await?;
    if findings.is_empty() {
        println!("(no findings stored in {})", args.db.display());
        return Ok(());
    }
    for f in findings {
        println!(
            "{}  {}/{}  {}:{}  ({})",
            f.at.format("%Y-%m-%d %H:%M:%S"),
            f.target,
            f.protocol,
            f.login.as_deref().unwrap_or("-"),
            f.secret,
            f.id
        );
    }
    Ok(())
}

fn build_from_flags(
    args: &RunArgs,
) -> Result<(Target, AttackPlan, Box<dyn CredentialSource>)> {
    let raw = args.target.as_deref().ok_or_else(|| anyhow!("--target is required"))?;
    let mut target = parse_target(raw)?;
    target.tls = args.tls;

    let plan = AttackPlan::builder()
        .target(target.clone())
        .strategy(StrategyKind::BruteForce)
        .concurrency(args.concurrency)
        .timeout(args.timeout)
        .maybe_rate(RateLimit::per_second(args.rate))
        .stop_on_first(!args.keep_going)
        .build();

    let source = build_source_from_flags(args)?;
    Ok((target, plan, source))
}

fn parse_target(raw: &str) -> Result<Target> {
    let (scheme, rest) = raw
        .split_once("://")
        .ok_or_else(|| anyhow!("target must look like proto://host[:port]"))?;
    if scheme.is_empty() {
        bail!("target scheme is empty");
    }
    let descriptor = Registry::descriptors()
        .into_iter()
        .find(|d| d.id == scheme)
        .ok_or_else(|| anyhow!("unknown protocol `{scheme}`. Run `fatah list-protocols`."))?;

    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => (h.to_owned(), p.parse::<u16>().context("port")?),
        None => (rest.to_owned(), descriptor.default_port),
    };
    Ok(Target::new(Endpoint::new(host, port), scheme))
}

fn build_source_from_flags(args: &RunArgs) -> Result<Box<dyn CredentialSource>> {
    match (&args.login, &args.logins, &args.password, &args.passwords) {
        (Some(login), None, None, Some(p)) => {
            Ok(Box::new(FileWordlist::passwords_for(p, login.clone())))
        }
        (None, Some(logins), None, Some(passwords)) => {
            Ok(Box::new(ComboSource::new(logins.clone(), passwords.clone())))
        }
        (Some(login), None, Some(pass), None) => {
            use fatah_core::{Credential, CredentialPair, Secret};
            Ok(Box::new(StaticSource::new(vec![CredentialPair::with_login(
                Credential::from(login.clone()),
                Secret::new(pass.clone()),
            )])))
        }
        _ => bail!("provide either `-l + -P`, or `-L + -P`, or `-l + -p`"),
    }
}
