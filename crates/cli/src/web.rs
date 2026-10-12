//! `grantcentral serve`: the browser UI talks to this local process, which owns
//! the filesystem, git, the loopback redirect listener and the keychain.
//!
//! Security: binds 127.0.0.1 only, every API call needs the random token from
//! the URL printed at startup, and the Host header must name the loopback
//! address (DNS rebinding defense).

use anyhow::Result;
use axum::extract::{Path as UrlPath, Query, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use grantcentral_core::engine::{Event, RunOptions};
use grantcentral_core::{Project, git};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Notify, mpsc::UnboundedSender};

const INDEX: &str = include_str!("../web/index.html");
const CM_JS: &str = include_str!("../web/vendor/codemirror.js");
const CM_CSS: &str = include_str!("../web/vendor/codemirror.css");

struct RunState {
    events: Vec<Event>,
    input: UnboundedSender<String>,
    abort: tokio::task::AbortHandle,
    done: bool,
}

struct App {
    project: Project,
    token: String,
    port: u16,
    runs: Mutex<HashMap<String, RunState>>,
    /// Bumped whenever a project file is added, removed or modified on disk.
    files_version: AtomicUsize,
    changed: Notify,
}

type St = State<Arc<App>>;

struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError(StatusCode::BAD_REQUEST, format!("{e:#}"))
    }
}

type ApiResult<T> = Result<T, ApiError>;

pub async fn serve(project: Project, port: u16, open_browser: bool) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    let port = listener.local_addr()?.port();
    let token = random_token();
    let name = project.name();
    let app = Arc::new(App {
        project,
        token: token.clone(),
        port,
        runs: Mutex::new(HashMap::new()),
        files_version: AtomicUsize::new(1),
        changed: Notify::new(),
    });
    let watcher = app.clone();
    std::thread::spawn(move || watch_files(&watcher));
    let api = Router::new()
        .route("/project", get(project_info))
        .route("/file", get(read_file).put(write_file))
        .route("/validate", get(validate))
        .route("/changes", get(changes))
        .route("/runs", post(start_run))
        .route("/runs/{id}/events", get(run_events))
        .route("/runs/{id}/input", post(run_input))
        .route("/runs/{id}/cancel", post(run_cancel))
        .route("/git/status", get(git_status))
        .route("/git/diff", get(git_diff))
        .route("/git/commit", post(git_commit))
        .route("/git/pull", post(git_pull))
        .route("/git/push", post(git_push))
        .layer(middleware::from_fn_with_state(app.clone(), require_token));
    let router = Router::new()
        .route("/", get(|| async { Html(INDEX) }))
        // Static and public, so outside the token check (the page can't send headers for <script src>).
        .route("/vendor/codemirror.js", get(|| async { ([(header::CONTENT_TYPE, "text/javascript")], CM_JS) }))
        .route("/vendor/codemirror.css", get(|| async { ([(header::CONTENT_TYPE, "text/css")], CM_CSS) }))
        .nest("/api", api)
        .layer(middleware::from_fn_with_state(app.clone(), check_host))
        .with_state(app);
    let url = format!("http://127.0.0.1:{port}/#token={token}");
    println!("GrantCentral web UI for {}:\n  {url}\nPress Ctrl+C to stop.", name);
    if open_browser {
        let _ = open::that_detached(&url);
    }
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

fn random_token() -> String {
    grantcentral_core::random_b64(24)
}

async fn check_host(State(app): St, req: Request, next: Next) -> Response {
    let host = req.headers().get(header::HOST).and_then(|h| h.to_str().ok()).unwrap_or("");
    let allowed = [format!("127.0.0.1:{}", app.port), format!("localhost:{}", app.port)];
    if !allowed.iter().any(|a| a == host) {
        return (StatusCode::FORBIDDEN, "unexpected Host header").into_response();
    }
    next.run(req).await
}

async fn require_token(State(app): St, req: Request, next: Next) -> Response {
    let got = req.headers().get(header::AUTHORIZATION).and_then(|h| h.to_str().ok()).and_then(|h| h.strip_prefix("Bearer ")).unwrap_or("");
    if !constant_time_eq(got.as_bytes(), app.token.as_bytes()) {
        return ApiError(StatusCode::UNAUTHORIZED, "missing or wrong token; open the URL printed by `grantcentral serve`".into())
            .into_response();
    }
    next.run(req).await
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn project_info(State(app): St) -> Json<Value> {
    let p = &app.project;
    Json(json!({
        "name": p.name(),
        "root": p.root.display().to_string(),
        "environments": p.environments(),
        "default_environment": p.default_environment(),
        "flows": p.flows(),
        "files": p.files(),
        "git": git::is_repo(&p.root),
    }))
}

#[derive(Deserialize)]
struct PathQuery {
    path: String,
}

async fn read_file(State(app): St, Query(q): Query<PathQuery>) -> ApiResult<String> {
    Ok(app.project.read(&q.path)?)
}

async fn write_file(State(app): St, Query(q): Query<PathQuery>, body: String) -> ApiResult<Json<Value>> {
    app.project.write(&q.path, &body)?;
    let diags: Vec<_> = app.project.validate().into_iter().filter(|d| d.file == q.path || q.path.starts_with("environments/")).collect();
    Ok(Json(json!({ "diagnostics": diags })))
}

async fn validate(State(app): St) -> Json<Value> {
    Json(json!({ "diagnostics": app.project.validate() }))
}

// ponytail: polls instead of OS file events (no extra dependency, and inotify misses
// edits on WSL's /mnt drives); switch to the `notify` crate if projects get large.
fn watch_files(app: &App) {
    let mut last = fingerprint(&app.project);
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let now = fingerprint(&app.project);
        if now != last {
            last = now;
            app.files_version.fetch_add(1, Ordering::Relaxed);
            app.changed.notify_waiters();
        }
    }
}

fn fingerprint(p: &Project) -> u64 {
    let mut h = DefaultHasher::new();
    for f in p.files() {
        let meta = std::fs::metadata(p.root.join(&f)).ok();
        (f, meta.map(|m| (m.len(), m.modified().ok()))).hash(&mut h);
    }
    h.finish()
}

/// Long poll: returns the files version as soon as it differs from `after`, or after 25s.
async fn changes(State(app): St, Query(q): Query<After>) -> Json<Value> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
    loop {
        let notified = app.changed.notified();
        let version = app.files_version.load(Ordering::Relaxed);
        if version != q.after || tokio::time::timeout_at(deadline, notified).await.is_err() {
            return Json(json!({ "version": version }));
        }
    }
}

#[derive(Deserialize)]
struct StartRun {
    flow: String,
    environment: Option<String>,
    #[serde(default)]
    vars: std::collections::BTreeMap<String, Value>,
}

async fn start_run(State(app): St, Json(req): Json<StartRun>) -> ApiResult<Json<Value>> {
    if !app.project.flows().contains(&req.flow) {
        return Err(ApiError(StatusCode::NOT_FOUND, format!("no flow {}", req.flow)));
    }
    let opts = RunOptions { environment: req.environment, vars: req.vars, ..Default::default() };
    let mut h = grantcentral_core::start_run(app.project.clone(), req.flow, opts);
    let id = random_token()[..12].to_string();
    app.runs
        .lock()
        .unwrap()
        .insert(id.clone(), RunState { events: vec![], input: h.input.clone(), abort: h.task.abort_handle(), done: false });
    let app2 = app.clone();
    let rid = id.clone();
    tokio::spawn(async move {
        while let Some(ev) = h.events.recv().await {
            let finished = matches!(ev, Event::RunFinished { .. });
            if let Some(r) = app2.runs.lock().unwrap().get_mut(&rid) {
                r.events.push(ev);
                r.done |= finished;
            }
            app2.changed.notify_waiters();
        }
        if let Some(r) = app2.runs.lock().unwrap().get_mut(&rid) {
            r.done = true;
        }
        app2.changed.notify_waiters();
    });
    Ok(Json(json!({ "id": id })))
}

#[derive(Deserialize)]
struct After {
    #[serde(default)]
    after: usize,
}

/// Long poll: returns events after index `after`, waiting up to 25s for new ones.
async fn run_events(State(app): St, UrlPath(id): UrlPath<String>, Query(q): Query<After>) -> ApiResult<Json<Value>> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
    loop {
        let notified = app.changed.notified();
        {
            let runs = app.runs.lock().unwrap();
            let r = runs.get(&id).ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no such run".into()))?;
            if r.events.len() > q.after || r.done {
                let events = r.events.get(q.after..).unwrap_or_default();
                return Ok(Json(json!({ "events": events, "next": r.events.len(), "done": r.done })));
            }
        }
        if tokio::time::timeout_at(deadline, notified).await.is_err() {
            return Ok(Json(json!({ "events": [], "next": q.after, "done": false })));
        }
    }
}

#[derive(Deserialize)]
struct Input {
    value: String,
}

async fn run_input(State(app): St, UrlPath(id): UrlPath<String>, Json(i): Json<Input>) -> ApiResult<StatusCode> {
    let runs = app.runs.lock().unwrap();
    let r = runs.get(&id).ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no such run".into()))?;
    let _ = r.input.send(i.value);
    Ok(StatusCode::NO_CONTENT)
}

async fn run_cancel(State(app): St, UrlPath(id): UrlPath<String>) -> ApiResult<StatusCode> {
    let mut runs = app.runs.lock().unwrap();
    let r = runs.get_mut(&id).ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no such run".into()))?;
    r.abort.abort();
    r.done = true;
    drop(runs);
    app.changed.notify_waiters();
    Ok(StatusCode::NO_CONTENT)
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> ApiResult<T> {
    Ok(tokio::task::spawn_blocking(f).await.map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))??)
}

async fn git_status(State(app): St) -> ApiResult<Json<git::Status>> {
    let root = app.project.root.clone();
    Ok(Json(blocking(move || git::status(&root)).await?))
}

#[derive(Deserialize)]
struct DiffQuery {
    path: Option<String>,
}

async fn git_diff(State(app): St, Query(q): Query<DiffQuery>) -> ApiResult<String> {
    if let Some(p) = &q.path {
        app.project.resolve(p)?;
    }
    let root = app.project.root.clone();
    blocking(move || git::diff(&root, q.path.as_deref())).await
}

#[derive(Deserialize)]
struct Commit {
    message: String,
    #[serde(default)]
    paths: Vec<String>,
}

async fn git_commit(State(app): St, Json(c): Json<Commit>) -> ApiResult<Json<Value>> {
    for p in &c.paths {
        app.project.resolve(p)?;
    }
    let root = app.project.root.clone();
    let out = blocking(move || git::commit(&root, &c.message, &c.paths)).await?;
    Ok(Json(json!({ "output": out })))
}

async fn git_pull(State(app): St) -> ApiResult<Json<Value>> {
    let root = app.project.root.clone();
    Ok(Json(json!({ "output": blocking(move || git::pull(&root)).await? })))
}

async fn git_push(State(app): St) -> ApiResult<Json<Value>> {
    let root = app.project.root.clone();
    Ok(Json(json!({ "output": blocking(move || git::push(&root)).await? })))
}
