//! `grantcentral`: run flows headless (CI), serve the local web UI, and small
//! JOSE/discovery utilities.

mod web;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use grantcentral_core::engine::{ChromeOptions, Event};
use grantcentral_core::model::LoginMode;
use grantcentral_core::report::{Severity, StepStatus};
use grantcentral_core::{Project, RunOptions, RunReport, jose};
use serde_json::Value;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "grantcentral", version, about = "OAuth 2.0 and OpenID Connect flow testing")]
struct Cli {
    /// Project directory (default: search upwards from the current directory).
    #[arg(short = 'C', long, global = true, env = "GRANTCENTRAL_PROJECT")]
    project: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum Login {
    System,
    Chromium,
    Http,
    Manual,
}

#[derive(Subcommand)]
enum Command {
    /// Run flows. With no FLOWS, runs every flow in the project.
    Run {
        flows: Vec<PathBuf>,
        #[arg(short, long, env = "GRANTCENTRAL_ENV")]
        env: Option<String>,
        /// Set a variable: --var key=value (value parsed as JSON when possible).
        #[arg(long = "var", value_name = "KEY=VALUE")]
        vars: Vec<String>,
        /// Only run flows with this tag.
        #[arg(long)]
        tag: Vec<String>,
        /// Skip flows with this tag.
        #[arg(long)]
        skip_tag: Vec<String>,
        /// Override how every authorization step reaches the user agent.
        #[arg(long, value_enum)]
        login: Option<Login>,
        /// Chromium executable for --login chromium.
        #[arg(long, env = "CHROME")]
        chrome: Option<PathBuf>,
        /// Show the Chromium window.
        #[arg(long)]
        headful: bool,
        /// Run Chromium without its sandbox (containers).
        #[arg(long, env = "GRANTCENTRAL_NO_SANDBOX")]
        no_sandbox: bool,
        /// Write a JUnit XML report.
        #[arg(long)]
        junit: Option<PathBuf>,
        /// Write a JSON report.
        #[arg(long)]
        json: Option<PathBuf>,
        /// Print step logs and HTTP exchanges.
        #[arg(short, long)]
        verbose: bool,
    },
    /// Parse every project file and report errors.
    Validate,
    /// Create a project with example environments and flows.
    Init { dir: Option<PathBuf> },
    /// Print the JSON schemas for flow, environment and project files, or write them for editors.
    Schema {
        #[arg(long)]
        write: bool,
    },
    /// Fetch and audit an authorization server's metadata.
    Discover {
        issuer: String,
        /// Audit profile: confidential, browser (RFC 10017) or native (RFC 8252).
        #[arg(long, default_value = "confidential")]
        profile: String,
    },
    /// Decode a JWT (without verifying it).
    Decode { jwt: String },
    /// Generate and inspect keys (RFC 7517, thumbprints per RFC 7638 and RFC 9278).
    #[command(subcommand)]
    Jwk(JwkCommand),
    /// Manage secrets in the OS keychain.
    #[command(subcommand)]
    Secret(SecretCommand),
    /// Serve the web UI on localhost.
    Serve {
        #[arg(long, default_value_t = 0)]
        port: u16,
        /// Do not open a browser.
        #[arg(long)]
        no_open: bool,
    },
}

#[derive(Subcommand)]
enum JwkCommand {
    /// Generate a private key; prints the public JWK and its RFC 9278 thumbprint URI to stderr.
    Generate {
        #[arg(long, default_value = "ES256")]
        alg: String,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Show the public JWK and thumbprints of a key file (JWK or PEM).
    Inspect { file: PathBuf },
}

#[derive(Subcommand)]
enum SecretCommand {
    /// Store a secret in the OS keychain, for `{ keyring = "ACCOUNT" }` references.
    Set { account: String },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(cli).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn open_project(dir: &Option<PathBuf>) -> Result<Project> {
    Project::open(dir.clone().unwrap_or_else(|| PathBuf::from(".")))
}

async fn dispatch(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Command::Run { flows, env, vars, tag, skip_tag, login, chrome, headful, no_sandbox, junit, json, verbose } => {
            let project = open_project(&cli.project)?;
            let opts = RunOptions {
                environment: env,
                vars: parse_vars(&vars)?,
                login: login.map(|l| match l {
                    Login::System => LoginMode::System,
                    Login::Chromium => LoginMode::Chromium,
                    Login::Http => LoginMode::Http,
                    Login::Manual => LoginMode::Manual,
                }),
                chrome: ChromeOptions { path: chrome, headful, no_sandbox },
            };
            run(&project, &flows, (&tag, &skip_tag), &opts, junit, json, verbose).await
        }
        Command::Validate => {
            let project = open_project(&cli.project)?;
            let diags = project.validate();
            for d in &diags {
                eprintln!("{}\n", d.message);
            }
            let n = project.flows().len() + project.environments().len();
            if diags.is_empty() {
                println!("{n} files OK");
                Ok(ExitCode::SUCCESS)
            } else {
                eprintln!("{} of {n} files have errors", diags.len());
                Ok(ExitCode::from(1))
            }
        }
        Command::Init { dir } => {
            let dir = dir.unwrap_or_else(|| PathBuf::from("."));
            std::fs::create_dir_all(&dir)?;
            let written = grantcentral_core::project::init(&dir)?;
            for f in &written {
                println!("created {}", dir.join(f).display());
            }
            println!("JSON schemas in {}", dir.join(".grantcentral/schema").display());
            Ok(ExitCode::SUCCESS)
        }
        Command::Schema { write } => {
            if write {
                let project = open_project(&cli.project)?;
                grantcentral_core::project::write_schemas(&project.root)?;
                println!("wrote {}", project.root.join(".grantcentral/schema").display());
            } else {
                let all: serde_json::Map<String, Value> =
                    grantcentral_core::schemas().into_iter().map(|(k, v)| (k.to_string(), v)).collect();
                println!("{}", serde_json::to_string_pretty(&all)?);
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Discover { issuer, profile } => discover(&issuer, &profile).await,
        Command::Decode { jwt } => {
            let (h, p) = jose::decode(jwt.trim())?;
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({ "header": h, "payload": p }))?);
            Ok(ExitCode::SUCCESS)
        }
        Command::Jwk(JwkCommand::Generate { alg, out }) => {
            let key = jose::generate(&alg)?;
            let private = serde_json::to_string_pretty(&key)?;
            match &out {
                Some(p) => write_private(p, &private)?,
                None => println!("{private}"),
            }
            print_public(&key)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Jwk(JwkCommand::Inspect { file }) => {
            print_public(&jose::load_key(&file)?)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Secret(SecretCommand::Set { account }) => {
            let value = if std::io::stdin().is_terminal() {
                rpassword::prompt_password(format!("Secret for {account}: "))?
            } else {
                let mut s = String::new();
                std::io::stdin().read_line(&mut s)?;
                s.trim_end_matches(['\r', '\n']).to_string()
            };
            grantcentral_core::secrets::store_in_keyring(&account, &value)?;
            eprintln!("stored; reference it as {{ keyring = \"{account}\" }}");
            Ok(ExitCode::SUCCESS)
        }
        Command::Serve { port, no_open } => {
            let project = open_project(&cli.project)?;
            web::serve(project, port, !no_open).await?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn write_private(path: &Path, content: &str) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut f = opts.open(path).with_context(|| format!("creating {} (refusing to overwrite)", path.display()))?;
    f.write_all(content.as_bytes())?;
    eprintln!("private key written to {}", path.display());
    Ok(())
}

fn print_public(key: &jose::Jwk) -> Result<()> {
    let public = jose::public(key)?;
    eprintln!("public JWK:\n{}", serde_json::to_string_pretty(&public)?);
    eprintln!("thumbprint (RFC 7638): {}", jose::thumbprint(&public)?);
    eprintln!("thumbprint URI (RFC 9278): {}", jose::thumbprint_uri(&public)?);
    Ok(())
}

fn parse_vars(vars: &[String]) -> Result<std::collections::BTreeMap<String, Value>> {
    vars.iter()
        .map(|kv| {
            let (k, v) = kv.split_once('=').with_context(|| format!("--var {kv}: expected KEY=VALUE"))?;
            Ok((k.to_string(), serde_json::from_str(v).unwrap_or_else(|_| Value::String(v.to_string()))))
        })
        .collect()
}

/// Maps command-line flow paths (relative to the cwd or the project) to project-relative paths.
fn select_flows(project: &Project, args: &[PathBuf], (tags, skip): (&[String], &[String])) -> Result<Vec<String>> {
    let all = project.flows();
    let mut chosen = vec![];
    if args.is_empty() {
        chosen = all;
    } else {
        for a in args {
            let abs = std::fs::canonicalize(a).or_else(|_| std::fs::canonicalize(project.root.join(a)));
            let Ok(abs) = abs else { bail!("no such flow: {}", a.display()) };
            if abs.is_dir() {
                let prefix = abs.strip_prefix(&project.root).unwrap_or(&abs).to_string_lossy().replace('\\', "/");
                chosen.extend(all.iter().filter(|f| f.starts_with(&format!("{prefix}/")) || prefix.is_empty()).cloned());
            } else {
                let rel = abs.strip_prefix(&project.root).with_context(|| format!("{} is outside the project", a.display()))?;
                chosen.push(rel.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    if !tags.is_empty() || !skip.is_empty() {
        chosen.retain(|f| {
            // Unparseable flows stay in, so the run reports their errors.
            let Ok(fl) = project.load_flow(f) else { return true };
            (tags.is_empty() || fl.tags.iter().any(|t| tags.contains(t))) && !fl.tags.iter().any(|t| skip.contains(t))
        });
    }
    if chosen.is_empty() {
        bail!("no flows to run");
    }
    Ok(chosen)
}

async fn run(
    project: &Project,
    flows: &[PathBuf],
    tags: (&[String], &[String]),
    opts: &RunOptions,
    junit: Option<PathBuf>,
    json: Option<PathBuf>,
    verbose: bool,
) -> Result<ExitCode> {
    let flows = select_flows(project, flows, tags)?;
    let mut reports = vec![];
    for flow in flows {
        let mut h = grantcentral_core::start_run(project.clone(), flow, opts.clone());
        while let Some(ev) = h.events.recv().await {
            print_event(&ev, verbose, &h.input);
        }
        reports.push(h.task.await?);
    }
    let redacted: Vec<RunReport> = reports.iter().map(RunReport::redacted).collect();
    if let Some(p) = json {
        std::fs::write(&p, serde_json::to_string_pretty(&redacted)?).with_context(|| format!("writing {}", p.display()))?;
    }
    if let Some(p) = junit {
        std::fs::write(&p, junit_xml(&redacted)?).with_context(|| format!("writing {}", p.display()))?;
    }
    let failed = reports.iter().filter(|r| !r.passed).count();
    println!("\n{} flow(s): {} passed, {failed} failed", reports.len(), reports.len() - failed);
    Ok(if failed == 0 { ExitCode::SUCCESS } else { ExitCode::from(1) })
}

fn print_event(ev: &Event, verbose: bool, input: &tokio::sync::mpsc::UnboundedSender<String>) {
    match ev {
        Event::RunStarted { flow, file, .. } => println!("\n▶ {flow}  ({file})"),
        Event::StepStarted { .. } => {}
        Event::Log { message, .. } if verbose => println!("    · {message}"),
        Event::Log { .. } => {}
        Event::Notice { message, url, .. } => println!("    → {message} {}", url.as_deref().unwrap_or("")),
        Event::Prompt { message, url, .. } => {
            if let Some(u) = url {
                println!("    → {u}");
            }
            print!("    ? {message}: ");
            let _ = std::io::stdout().flush();
            let tx = input.clone();
            // Blocking stdin read off the async runtime; the engine waits on the channel.
            std::thread::spawn(move || {
                let mut line = String::new();
                if std::io::stdin().read_line(&mut line).is_ok() && !line.trim().is_empty() {
                    let _ = tx.send(line.trim().to_string());
                }
            });
        }
        Event::StepFinished { report: r } => {
            let mark = match r.status {
                StepStatus::Passed => "✓",
                StepStatus::Failed => "✗",
                StepStatus::Skipped => "-",
            };
            println!("  {mark} {} [{}] {}ms", r.name, r.kind, r.duration_ms);
            if let Some(f) = &r.failure {
                println!("      {f}");
            }
            for c in r.checks.iter().filter(|c| !c.passed && (verbose || c.severity != Severity::Info)) {
                let sev = match c.severity {
                    Severity::Error => "error",
                    Severity::Warning => "warn",
                    Severity::Info => "info",
                };
                let spec = c.spec.as_deref().map(|s| format!(" ({s})")).unwrap_or_default();
                let detail = if c.detail.is_empty() { String::new() } else { format!(": {}", c.detail) };
                println!("      {sev}: {}{detail}{spec}", c.name);
            }
            for a in r.assertions.iter().filter(|a| !a.passed) {
                println!("      assert {}{}", a.expr, a.message.as_deref().map(|m| format!(": {m}")).unwrap_or_default());
            }
            if r.status == StepStatus::Skipped && verbose {
                for l in &r.logs {
                    println!("      {l}");
                }
            }
            if verbose {
                for ex in &r.exchanges {
                    println!("      {} {} -> {} ({}ms)", ex.method, ex.url, ex.status, ex.duration_ms);
                }
            }
        }
        Event::RunFinished { report } => {
            if let Some(e) = &report.error {
                println!("  ✗ {e}");
            }
            let (p, f, s) = report.counts();
            println!("  {} — {p} passed, {f} failed, {s} skipped, {}ms", if report.passed { "PASS" } else { "FAIL" }, report.duration_ms);
        }
    }
}

fn junit_xml(reports: &[RunReport]) -> Result<String> {
    use quick_junit::{NonSuccessKind, Report, TestCase, TestCaseStatus, TestSuite};
    use std::time::Duration;
    let mut report = Report::new("grantcentral");
    for r in reports {
        let mut suite = TestSuite::new(r.flow.clone());
        suite.set_time(Duration::from_millis(r.duration_ms));
        if let Some(e) = &r.error {
            let mut status = TestCaseStatus::non_success(NonSuccessKind::Error);
            status.set_message(e.clone());
            suite.add_test_case(TestCase::new("load", status));
        }
        for s in &r.steps {
            let mut status = match s.status {
                StepStatus::Passed => TestCaseStatus::success(),
                StepStatus::Skipped => TestCaseStatus::skipped(),
                StepStatus::Failed => TestCaseStatus::non_success(NonSuccessKind::Failure),
            };
            if let Some(f) = &s.failure {
                status.set_message(f.clone());
                let mut detail = String::new();
                for c in s.checks.iter().filter(|c| !c.passed) {
                    detail.push_str(&format!("check {}: {} {}\n", c.name, c.detail, c.spec.as_deref().unwrap_or("")));
                }
                for a in s.assertions.iter().filter(|a| !a.passed) {
                    detail.push_str(&format!("assert {} {}\n", a.expr, a.message.as_deref().unwrap_or("")));
                }
                status.set_description(detail);
            }
            let mut case = TestCase::new(format!("{:02} {}", s.index + 1, s.name), status);
            case.set_classname(r.file.clone());
            case.set_time(Duration::from_millis(s.duration_ms));
            let out: Vec<String> =
                s.logs.iter().cloned().chain(s.exchanges.iter().map(|e| format!("{} {} -> {}", e.method, e.url, e.status))).collect();
            if !out.is_empty() {
                case.set_system_out(out.join("\n"));
            }
            suite.add_test_case(case);
        }
        report.add_test_suite(suite);
    }
    Ok(report.to_string()?)
}

async fn discover(issuer: &str, profile: &str) -> Result<ExitCode> {
    let url = grantcentral_core::oauth::well_known_url(issuer, "oauth-authorization-server")?;
    let oidc = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
    let client = grantcentral_core::http::plain_client()?;
    let mut meta = None;
    for u in [url, oidc] {
        if let Ok(r) = client.get(&u).send().await
            && r.status().is_success()
            && let Ok(v) = r.json::<Value>().await
        {
            eprintln!("metadata from {u}");
            meta = Some(v);
            break;
        }
    }
    let Some(meta) = meta else { bail!("no metadata found for {issuer}") };
    println!("{}", serde_json::to_string_pretty(&meta)?);
    if meta["issuer"].as_str() != Some(issuer) {
        eprintln!("error: issuer mismatch: metadata says {} (RFC 8414 §3.3)", meta["issuer"]);
    }
    let checks = grantcentral_core::oauth::audit_metadata(&meta, profile)?;
    eprintln!("\naudit ({profile}):");
    let mut errors = 0;
    for c in &checks {
        let mark = if c.passed {
            "✓"
        } else if c.severity == Severity::Error {
            "✗"
        } else {
            "!"
        };
        errors += (!c.passed && c.severity == Severity::Error) as usize;
        let detail = if c.detail.is_empty() || c.passed { String::new() } else { format!(": {}", c.detail) };
        eprintln!("  {mark} {}{detail}  ({})", c.name, c.spec.as_deref().unwrap_or(""));
    }
    Ok(if errors == 0 { ExitCode::SUCCESS } else { ExitCode::from(1) })
}
