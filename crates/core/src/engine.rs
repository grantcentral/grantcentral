//! Runs a flow: renders each step, executes it, evaluates checks, assertions
//! and captures, and streams events to whichever front end is attached.

use crate::http::Http;
use crate::model::{ClientConfig, Expect, LoginMode, Step, StepKind};
use crate::project::Project;
use crate::report::{AssertionResult, Check, RunReport, Severity, StepReport, StepStatus};
use crate::template::Templates;
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::Instant;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    RunStarted {
        flow: String,
        file: String,
        steps: Vec<String>,
    },
    StepStarted {
        index: usize,
        name: String,
    },
    Log {
        index: usize,
        message: String,
    },
    /// Something for the user to look at or open: an authorization URL, a device user code.
    Notice {
        index: usize,
        message: String,
        url: Option<String>,
    },
    /// The engine waits for one line of input, e.g. a pasted redirect URL.
    Prompt {
        index: usize,
        message: String,
        url: Option<String>,
    },
    StepFinished {
        report: StepReport,
    },
    RunFinished {
        report: RunReport,
    },
}

#[derive(Debug, Clone, Default)]
pub struct ChromeOptions {
    pub path: Option<PathBuf>,
    /// Show the browser window instead of running headless.
    pub headful: bool,
    /// Pass --no-sandbox (needed in most containers).
    pub no_sandbox: bool,
}

#[derive(Debug, Clone, Default)]
pub struct RunOptions {
    pub environment: Option<String>,
    /// Overrides every other variable source.
    pub vars: BTreeMap<String, Value>,
    /// Overrides the login mode of every step (e.g. `chromium` in CI).
    pub login: Option<LoginMode>,
    pub chrome: ChromeOptions,
}

pub struct Io {
    pub events: UnboundedSender<Event>,
    pub input: tokio::sync::Mutex<UnboundedReceiver<String>>,
}

/// A run in progress: events out, user input in.
pub struct RunHandle {
    pub events: UnboundedReceiver<Event>,
    pub input: UnboundedSender<String>,
    pub task: tokio::task::JoinHandle<RunReport>,
}

/// Starts a flow on the current tokio runtime.
pub fn start_run(project: Project, flow: String, opts: RunOptions) -> RunHandle {
    let (etx, erx) = unbounded_channel();
    let (itx, irx) = unbounded_channel();
    let task = tokio::spawn(async move {
        let io = Io { events: etx, input: tokio::sync::Mutex::new(irx) };
        run_flow(&project, &flow, &opts, &io).await
    });
    RunHandle { events: erx, input: itx, task }
}

/// Client-side protocol state carried between steps, exposed as `session.*`.
#[derive(Debug, Default, Serialize)]
pub struct Session {
    pub issuer: Option<String>,
    pub metadata: Option<Value>,
    pub jwks: Option<Value>,
    pub resource_metadata: Option<Value>,
    /// Set by dynamic registration; take precedence over `client.*`.
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub registration_access_token: Option<String>,
    pub registration_client_uri: Option<String>,
    pub redirect_uri: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_verifier: Option<String>,
    pub code: Option<String>,
    pub request_uri: Option<String>,
    pub max_age: Option<String>,
    pub access_token: Option<String>,
    pub token_type: Option<String>,
    pub refresh_token: Option<String>,
    pub previous_refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub id_token_claims: Option<Value>,
    pub scope: Option<String>,
    pub expires_in: Option<i64>,
    pub device_code: Option<String>,
    pub user_code: Option<String>,
    pub verification_uri: Option<String>,
    pub verification_uri_complete: Option<String>,
    /// JWK thumbprint of the DPoP key (RFC 7638).
    pub dpop_jkt: Option<String>,
    /// SHA-256 thumbprint of the mTLS client certificate (RFC 8705).
    pub cert_thumbprint: Option<String>,
    #[serde(skip)]
    pub dpop_key: Option<josekit::jwk::Jwk>,
    /// Latest DPoP nonce per origin.
    #[serde(skip)]
    pub dpop_nonces: HashMap<String, String>,
}

/// What a step produced: the result document and the protocol error, if any.
pub struct Output {
    pub doc: Value,
    pub error: Option<String>,
}

impl Output {
    pub fn ok(doc: Value) -> Self {
        Output { doc, error: None }
    }
}

/// Mutable state of one flow run, handed to every step.
pub struct Run<'a> {
    pub root: &'a Path,
    pub client: ClientConfig,
    pub http: Http,
    pub tpl: Templates,
    pub session: Session,
    pub vars: Map<String, Value>,
    pub secrets: BTreeMap<String, String>,
    pub steps: Map<String, Value>,
    pub opts: &'a RunOptions,
    pub io: &'a Io,
    pub index: usize,
    pub checks: Vec<Check>,
    pub logs: Vec<String>,
}

impl Run<'_> {
    /// The template context: variables at the top level plus `vars`, `secrets`, `session`, `steps` and `client`.
    pub fn ctx(&self) -> Value {
        let mut m = self.vars.clone();
        m.insert("vars".into(), Value::Object(self.vars.clone()));
        m.insert("secrets".into(), serde_json::to_value(&self.secrets).unwrap());
        m.insert("session".into(), serde_json::to_value(&self.session).unwrap());
        m.insert("steps".into(), Value::Object(self.steps.clone()));
        m.insert("client".into(), serde_json::to_value(&self.client).unwrap());
        Value::Object(m)
    }

    pub fn check(&mut self, name: impl Into<String>, passed: bool, severity: Severity, detail: impl Into<String>, spec: Option<&str>) {
        self.checks.push(Check { name: name.into(), passed, severity, detail: detail.into(), spec: spec.map(str::to_string) });
    }

    pub fn log(&mut self, message: impl Into<String>) {
        let message = message.into();
        let _ = self.io.events.send(Event::Log { index: self.index, message: message.clone() });
        self.logs.push(message);
    }

    pub fn notice(&mut self, message: impl Into<String>, url: Option<String>) {
        let message = message.into();
        self.logs.push(match &url {
            Some(u) => format!("{message} {u}"),
            None => message.clone(),
        });
        let _ = self.io.events.send(Event::Notice { index: self.index, message, url });
    }

    /// Asks the front end for one line of input.
    pub async fn prompt(&self, message: impl Into<String>, url: Option<String>) -> Result<String> {
        let mut input = self.io.input.lock().await;
        while input.try_recv().is_ok() {} // drop stale input
        let _ = self.io.events.send(Event::Prompt { index: self.index, message: message.into(), url });
        input.recv().await.ok_or_else(|| anyhow!("no input available (run is not interactive)"))
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    pub fn issuer(&self) -> Result<String> {
        self.session.issuer.clone().or_else(|| self.client.issuer.clone()).ok_or_else(|| anyhow!("no issuer: set client.issuer"))
    }

    pub fn client_id(&self) -> Result<String> {
        self.session.client_id.clone().or_else(|| self.client.client_id.clone()).ok_or_else(|| anyhow!("no client_id configured"))
    }

    pub fn client_secret(&self) -> Option<String> {
        self.session.client_secret.clone().or_else(|| self.client.client_secret.clone())
    }

    pub fn meta(&self, name: &str) -> Option<&Value> {
        self.session.metadata.as_ref().and_then(|m| m.get(name)).filter(|v| !v.is_null())
    }

    pub fn uses_mtls(&self) -> bool {
        self.client.tls_cert.is_some()
    }

    /// Endpoint URL: explicit override, then the mTLS alias (RFC 8705 §5) when
    /// a client certificate is configured, then discovered metadata.
    pub fn endpoint(&self, name: &str) -> Result<String> {
        if let Some(e) = self.client.endpoints.get(name) {
            return Ok(e.clone());
        }
        if self.uses_mtls()
            && let Some(e) = self.meta("mtls_endpoint_aliases").and_then(|a| a[name].as_str())
        {
            return Ok(e.to_string());
        }
        self.meta(name)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| anyhow!("no {name}: add a discover step or set client.endpoints.{name}"))
    }
}

/// Runs one flow file to completion.
pub async fn run_flow(project: &Project, flow_rel: &str, opts: &RunOptions, io: &Io) -> RunReport {
    let started = Instant::now();
    let environment = opts.environment.clone().or_else(|| project.default_environment());
    let mut report = RunReport {
        flow: flow_rel.to_string(),
        file: flow_rel.to_string(),
        environment: environment.clone(),
        started_at: crate::now(),
        duration_ms: 0,
        passed: false,
        error: None,
        steps: vec![],
        redactions: vec![],
    };
    if let Err(e) = run_inner(project, flow_rel, environment.as_deref(), opts, io, &mut report).await {
        report.error = Some(format!("{e:#}"));
        report.passed = false;
    }
    report.duration_ms = started.elapsed().as_millis() as u64;
    let _ = io.events.send(Event::RunFinished { report: report.clone() });
    report
}

async fn run_inner(
    project: &Project,
    flow_rel: &str,
    environment: Option<&str>,
    opts: &RunOptions,
    io: &Io,
    report: &mut RunReport,
) -> Result<()> {
    let flow = project.load_flow(flow_rel)?;
    let env = match environment {
        Some(name) => project.load_environment(name).with_context(|| format!("loading environment {name}"))?,
        None => Default::default(),
    };
    report.flow = flow.name.clone().unwrap_or_else(|| flow_rel.to_string());
    let _ = io.events.send(Event::RunStarted {
        flow: report.flow.clone(),
        file: flow_rel.to_string(),
        steps: flow.steps.iter().map(Step::label).collect(),
    });

    let (secrets, mut problems) = crate::secrets::resolve(&env.secrets, &project.root);
    report.redactions = secrets.values().cloned().collect();
    let mut vars: Map<String, Value> = flow.vars.clone().into_iter().collect();
    vars.extend(env.vars.clone());
    vars.extend(opts.vars.clone());

    // The client config is rendered once, with variables and secrets only.
    let tpl = Templates::default();
    let base_ctx = json!({ "vars": vars, "secrets": secrets });
    let mut ctx0 = vars.clone();
    ctx0.extend(base_ctx.as_object().unwrap().clone());
    // A field that fails to render (say, a secret this machine lacks) is left
    // unset, so flows that do not need it still run.
    let raw_client = serde_json::to_value(env.client.merged(&flow.client))?;
    let ctx0 = Value::Object(ctx0);
    let mut rendered = Map::new();
    for (k, v) in raw_client.as_object().unwrap() {
        match tpl.render_value(v, &ctx0, &[]) {
            Ok(r) => {
                rendered.insert(k.clone(), r);
            }
            Err(e) => problems.push(format!("client.{k} left unset: {e:#}")),
        }
    }
    let client: ClientConfig = serde_json::from_value(Value::Object(rendered)).context("client configuration after rendering")?;
    // Secret values used directly in the client config are redacted as well.
    report.redactions.extend(client.client_secret.clone());

    let http = Http::new(&client, &project.root)?;
    let mut run = Run {
        root: &project.root,
        client,
        http,
        tpl,
        session: Session::default(),
        vars,
        secrets,
        steps: Map::new(),
        opts,
        io,
        index: 0,
        checks: vec![],
        logs: problems,
    };
    if let Some(cert) = &run.client.tls_cert {
        run.session.cert_thumbprint = Some(crate::jose::cert_thumbprint(&std::fs::read(run.path(cert))?)?);
    }

    let mut failed = false;
    for (index, step) in flow.steps.iter().enumerate() {
        run.index = index;
        let _ = io.events.send(Event::StepStarted { index, name: step.label() });
        let r = if failed { skipped(index, step, "an earlier step failed") } else { run_step(&mut run, index, step).await };
        failed |= r.status == StepStatus::Failed;
        // Values a step captured from the server (tokens) are not secrets; masked secrets come from the environment.
        let _ = io.events.send(Event::StepFinished { report: r.clone() });
        report.steps.push(r);
    }
    report.passed = !failed;
    Ok(())
}

fn skipped(index: usize, step: &Step, why: &str) -> StepReport {
    StepReport {
        index,
        id: step.id.clone(),
        name: step.label(),
        kind: step.kind.type_name().into(),
        status: StepStatus::Skipped,
        duration_ms: 0,
        error: None,
        failure: None,
        checks: vec![],
        assertions: vec![],
        exchanges: vec![],
        logs: vec![why.to_string()],
        result: Value::Null,
    }
}

async fn run_step(run: &mut Run<'_>, index: usize, step: &Step) -> StepReport {
    let start = Instant::now();
    run.checks.clear();
    let mut logs = std::mem::take(&mut run.logs);
    run.logs.clear();
    let ctx = run.ctx();

    if let Some(cond) = &step.when {
        match run.tpl.truthy(cond, &ctx) {
            Ok(true) => {}
            Ok(false) => return skipped(index, step, &format!("`when = {cond}` is false")),
            Err(e) => {
                let mut r = skipped(index, step, "");
                r.status = StepStatus::Failed;
                r.failure = Some(format!("{e:#}"));
                return r;
            }
        }
    }

    let outcome = match render_step(run, &step.kind, &ctx) {
        Ok(kind) => crate::oauth::execute(run, &kind).await,
        Err(e) => Err(e),
    };
    let (mut doc, error) = match outcome {
        Ok(o) => (o.doc, o.error),
        Err(e) => (json!({}), Some(format!("{e:#}"))),
    };
    if !doc.is_object() {
        doc = json!({ "value": doc });
    }
    doc["error"] = error.clone().map(Value::String).unwrap_or(Value::Null);
    doc["checks"] = serde_json::to_value(&run.checks).unwrap();

    // Assertions see the result fields at the top level, over the usual context.
    let mut actx = run.ctx();
    if let (Some(a), Some(d)) = (actx.as_object_mut(), doc.as_object()) {
        a.extend(d.clone());
        a.insert("result".into(), doc.clone());
    }
    let assertions: Vec<AssertionResult> = step
        .assert
        .iter()
        .map(|expr| match run.tpl.truthy(expr, &actx) {
            Ok(passed) => AssertionResult { expr: expr.clone(), passed, message: None },
            Err(e) => AssertionResult { expr: expr.clone(), passed: false, message: Some(format!("{e:#}")) },
        })
        .collect();

    let mut failure = None;
    for (name, expr) in &step.capture {
        match run.tpl.eval(expr, &actx) {
            Ok(v) if !v.is_null() => {
                run.vars.insert(name.clone(), v);
            }
            Ok(_) => failure = Some(format!("capture `{name}`: `{expr}` is undefined")),
            Err(e) => failure = Some(format!("capture `{name}`: {e:#}")),
        }
    }

    let failed_checks: Vec<&Check> = run.checks.iter().filter(|c| !c.passed && c.severity == Severity::Error).collect();
    let failed_asserts: Vec<&AssertionResult> = assertions.iter().filter(|a| !a.passed).collect();
    if failure.is_none() {
        failure = match step.expect {
            Expect::Success if error.is_some() => error.clone(),
            Expect::Success if !failed_checks.is_empty() => {
                Some(format!("failed check: {}", failed_checks.iter().map(|c| c.name.as_str()).collect::<Vec<_>>().join("; ")))
            }
            Expect::Error if error.is_none() => Some("expected an error, but the step succeeded".into()),
            _ if !failed_asserts.is_empty() => {
                Some(format!("assertion failed: {}", failed_asserts.iter().map(|a| a.expr.as_str()).collect::<Vec<_>>().join("; ")))
            }
            _ => None,
        };
    }

    if let Some(id) = &step.id {
        run.steps.insert(id.clone(), doc.clone());
    }
    logs.append(&mut run.logs);
    StepReport {
        index,
        id: step.id.clone(),
        name: step.label(),
        kind: step.kind.type_name().into(),
        status: if failure.is_some() { StepStatus::Failed } else { StepStatus::Passed },
        duration_ms: start.elapsed().as_millis() as u64,
        error,
        failure,
        checks: std::mem::take(&mut run.checks),
        assertions,
        exchanges: run.http.drain(),
        logs,
        result: doc,
    }
}

/// Renders templates in a step. Browser scripts are rendered later, action by
/// action, because they may use values (a device user code) that only exist
/// once the step is underway.
fn render_step(run: &Run, kind: &StepKind, ctx: &Value) -> Result<StepKind> {
    let raw = serde_json::to_value(kind)?;
    let rendered = run.tpl.render_value(&raw, ctx, &["login_script"])?;
    serde_json::from_value(rendered).map_err(|e| anyhow!("step after rendering templates: {e}"))
}

/// Fails unless `cond`, as a hard (non-check) error.
pub fn ensure(cond: bool, msg: impl Into<String>) -> Result<()> {
    if !cond {
        bail!(msg.into());
    }
    Ok(())
}
