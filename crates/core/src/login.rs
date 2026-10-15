//! Getting the authorization response back from the user agent: a loopback
//! redirect listener (RFC 8252 §7.3), the system browser, plain HTTP redirect
//! following, a pasted URL, or headless Chromium for CI.

use crate::engine::Run;
use crate::model::{BrowserAction, LoginMode};
use anyhow::{Context, Result, anyhow, bail};
use axum::extract::State;
use axum::http::{Method, StatusCode, Uri};
use axum::response::Html;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

/// An authorization response as received at the redirect URI.
#[derive(Debug, Clone)]
pub struct Callback {
    pub url: String,
    pub params: BTreeMap<String, String>,
}

/// Parses a redirect URL; fragment parameters (implicit, hybrid) win over query parameters.
pub fn parse_callback(url: &str) -> Result<Callback> {
    let u = url::Url::parse(url.trim()).with_context(|| format!("not a URL: {url}"))?;
    let mut params: BTreeMap<String, String> = u.query_pairs().into_owned().collect();
    if let Some(f) = u.fragment() {
        params.extend(url::form_urlencoded::parse(f.as_bytes()).into_owned());
    }
    Ok(Callback { url: url.trim().to_string(), params })
}

/// Same scheme, host, port and path; the query is ignored.
pub fn matches_redirect(url: &str, redirect: &str) -> bool {
    match (url::Url::parse(url), url::Url::parse(redirect)) {
        (Ok(a), Ok(b)) => {
            a.scheme() == b.scheme()
                && a.host_str() == b.host_str()
                && a.port_or_known_default() == b.port_or_known_default()
                && a.path() == b.path()
        }
        _ => false,
    }
}

pub fn is_loopback(uri: &str) -> bool {
    url::Url::parse(uri).is_ok_and(|u| u.scheme() == "http" && matches!(u.host_str(), Some("127.0.0.1" | "[::1]" | "localhost")))
}

/// A local HTTP listener on the loopback redirect URI. When the URI has no
/// port, an ephemeral one is chosen (RFC 8252 §7.3) and `redirect_uri` holds it.
pub struct Loopback {
    pub redirect_uri: String,
    rx: mpsc::Receiver<Callback>,
    _stop: oneshot::Sender<()>,
}

struct ListenerState {
    tx: mpsc::Sender<Callback>,
    path: String,
    base: String,
}

impl Loopback {
    pub async fn bind(redirect: &str) -> Result<Self> {
        let mut u = url::Url::parse(redirect)?;
        let ip: std::net::IpAddr = match u.host_str() {
            Some("[::1]") => std::net::Ipv6Addr::LOCALHOST.into(),
            _ => std::net::Ipv4Addr::LOCALHOST.into(),
        };
        let port = u.port().unwrap_or(0);
        let listener =
            tokio::net::TcpListener::bind((ip, port)).await.with_context(|| format!("binding the redirect listener on {ip}:{port}"))?;
        if u.port().is_none() {
            u.set_port(Some(listener.local_addr()?.port())).ok();
        }
        let (tx, rx) = mpsc::channel(4);
        let mut base = u.clone();
        base.set_query(None);
        let state = Arc::new(ListenerState { tx, path: u.path().to_string(), base: base.to_string() });
        let app = axum::Router::new().fallback(handle).with_state(state);
        let (stop, stopped) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await;
        });
        Ok(Loopback { redirect_uri: u.to_string(), rx, _stop: stop })
    }

    pub async fn recv(&mut self) -> Option<Callback> {
        self.rx.recv().await
    }
}

const DONE_PAGE: &str = "<!doctype html><meta charset=utf-8><title>GrantCentral</title>\
<body style=\"font:16px system-ui;margin:3em\"><h1>Authorization response received</h1><p>You can close this tab and return to GrantCentral.</p>";

/// Fragments never reach the server, so this page posts `location.hash` back.
const FRAGMENT_PAGE: &str = "<!doctype html><meta charset=utf-8><title>GrantCentral</title>\
<body style=\"font:16px system-ui;margin:3em\"><p id=m>Forwarding the authorization response...</p><script>\
fetch(location.pathname + '?gc_fragment=1', {method: 'POST', headers: {'content-type': 'application/x-www-form-urlencoded'}, body: location.hash.slice(1)})\
.then(r => r.text()).then(t => { document.open(); document.write(t); document.close(); })\
.catch(e => { document.getElementById('m').textContent = 'Could not forward the response: ' + e; });</script>";

async fn handle(State(st): State<Arc<ListenerState>>, method: Method, uri: Uri, body: String) -> (StatusCode, Html<&'static str>) {
    if uri.path() != st.path {
        return (StatusCode::NOT_FOUND, Html("not found"));
    }
    let query = uri.query().unwrap_or("");
    let fragment_forward = query == "gc_fragment=1";
    let source = if method == Method::POST { body.as_str() } else { query };
    let params: BTreeMap<String, String> = url::form_urlencoded::parse(source.as_bytes()).into_owned().collect();
    if method == Method::GET && params.is_empty() {
        return (StatusCode::OK, Html(FRAGMENT_PAGE));
    }
    let url = match (method == Method::POST, fragment_forward) {
        (true, true) => format!("{}#{body}", st.base),
        (true, false) => st.base.clone(),
        _ => format!("{}?{query}", st.base),
    };
    let _ = st.tx.send(Callback { url, params }).await;
    (StatusCode::OK, Html(DONE_PAGE))
}

/// Sends the user agent to `url` and waits for the authorization response at `redirect`.
pub async fn authorization_response(
    run: &mut Run<'_>,
    mode: LoginMode,
    url: &str,
    redirect: &str,
    listener: Option<Loopback>,
    script: &[BrowserAction],
    timeout: Duration,
) -> Result<Callback> {
    let fut = async {
        match mode {
            LoginMode::System => {
                open_browser(run, url);
                match listener {
                    Some(mut l) => l.recv().await.ok_or_else(|| anyhow!("redirect listener stopped")),
                    None => pasted(run, "Paste the URL the browser was redirected to", url).await,
                }
            }
            LoginMode::Manual => match listener {
                Some(mut l) => tokio::select! {
                    cb = l.recv() => cb.ok_or_else(|| anyhow!("redirect listener stopped")),
                    cb = pasted(run, "Open the URL, then paste the URL you were redirected to (or let the loopback listener catch it)", url) => cb,
                },
                None => pasted(run, "Open the URL, then paste the URL you were redirected to", url).await,
            },
            LoginMode::Http => http_follow(run, url, redirect).await,
            LoginMode::Chromium => chromium::drive(run, url, Some(redirect), script, timeout)
                .await?
                .ok_or_else(|| anyhow!("Chromium finished without reaching the redirect URI")),
        }
    };
    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| anyhow!("timed out after {}s waiting for the authorization response", timeout.as_secs()))?
}

/// Sends the user to a page where nothing comes back (device verification).
pub async fn visit(run: &mut Run<'_>, mode: LoginMode, url: &str, script: &[BrowserAction], timeout: Duration) -> Result<()> {
    match mode {
        LoginMode::System => open_browser(run, url),
        LoginMode::Chromium => {
            chromium::drive(run, url, None, script, timeout).await?;
        }
        LoginMode::Manual | LoginMode::Http => {}
    }
    Ok(())
}

fn open_browser(run: &mut Run, url: &str) {
    match open::that_detached(url) {
        Ok(()) => run.log("Opened the system browser"),
        Err(e) => run.log(format!("Could not open a browser ({e}); open the URL yourself")),
    }
}

async fn pasted(run: &Run<'_>, message: &str, url: &str) -> Result<Callback> {
    let line = run.prompt(message, Some(url.to_string())).await?;
    parse_callback(&line)
}

/// Follows redirects with a cookie-keeping HTTP client until the redirect URI
/// is reached. Works when the server needs no login (SSO session, test IdPs).
async fn http_follow(run: &mut Run<'_>, start: &str, redirect: &str) -> Result<Callback> {
    let client = crate::http::client_builder(&run.client, run.root)?.cookie_store(true).build()?;
    let mut url = start.to_string();
    for _ in 0..30 {
        if matches_redirect(&url, redirect) {
            return parse_callback(&url);
        }
        let resp = client.get(&url).send().await.with_context(|| format!("GET {url}"))?;
        let status = resp.status().as_u16();
        run.log(format!("User agent: GET {} -> {status}", url.split('?').next().unwrap_or(&url)));
        if let Some(loc) = resp.headers().get("location").filter(|_| (300..400).contains(&status)) {
            url = url::Url::parse(&url)?.join(loc.to_str()?)?.to_string();
            continue;
        }
        let body = resp.text().await?;
        if let Some(cb) = form_post(&body, redirect) {
            return Ok(cb);
        }
        if status >= 400 {
            bail!("the authorization server answered HTTP {status} at {url}: {}", text_excerpt(&body));
        }
        bail!(
            "HTTP login stopped at {url} (HTTP {status}); the page needs user interaction. \
             Use login = \"chromium\" with a login_script, or \"system\""
        );
    }
    bail!("more than 30 redirects")
}

/// Extracts an auto-submitting `form_post` response (OAuth 2.0 Form Post Response Mode).
fn form_post(html: &str, redirect: &str) -> Option<Callback> {
    let lower = html.to_ascii_lowercase();
    let start = lower.find("<form")?;
    let end = start + lower[start..].find('>')?;
    let action = html_unescape(attr(&html[start..end], "action")?);
    if !matches_redirect(&action, redirect) {
        return None;
    }
    let mut params = BTreeMap::new();
    let mut rest = end;
    while let Some(i) = lower[rest..].find("<input") {
        let s = rest + i;
        let e = s + lower[s..].find('>')?;
        let tag = &html[s..e];
        if let Some(name) = attr(tag, "name") {
            params.insert(html_unescape(name), html_unescape(attr(tag, "value").unwrap_or("")));
        }
        rest = e;
    }
    Some(Callback { url: action, params })
}

/// Visible text of an HTML page, shortened, for error messages.
fn text_excerpt(html: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    let body = html.find("<body").map_or(html, |i| &html[i..]);
    for c in body.chars() {
        match c {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                out.push(' ');
            }
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    let text = html_unescape(&out.split_whitespace().collect::<Vec<_>>().join(" "));
    text.chars().take(300).collect()
}

fn attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let lower = tag.to_ascii_lowercase();
    let mut from = 0;
    while let Some(i) = lower[from..].find(name) {
        let at = from + i;
        from = at + name.len();
        let before_ok = at > 0 && lower.as_bytes()[at - 1].is_ascii_whitespace();
        let after = lower[from..].trim_start();
        if !before_ok || !after.starts_with('=') {
            continue;
        }
        let val_start = tag.len() - after.len() + 1;
        let v = tag[val_start..].trim_start();
        let offset = tag.len() - v.len();
        return match v.chars().next()? {
            q @ ('"' | '\'') => v[1..].find(q).map(|j| &tag[offset + 1..offset + 1 + j]),
            _ => Some(&tag[offset..offset + v.find(|c: char| c.is_whitespace() || c == '>').unwrap_or(v.len())]),
        };
    }
    None
}

fn html_unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let Some(end) = rest.find(';').filter(|&e| e <= 10) else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let ent = &rest[1..end];
        let ch = match ent {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            e if e.starts_with("#x") || e.starts_with("#X") => u32::from_str_radix(&e[2..], 16).ok().and_then(char::from_u32),
            e if e.starts_with('#') => e[1..].parse().ok().and_then(char::from_u32),
            _ => None,
        };
        match ch {
            Some(c) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(feature = "chromium")]
mod chromium {
    use super::{Callback, matches_redirect, parse_callback};
    use crate::engine::Run;
    use crate::model::BrowserAction;
    use anyhow::{Context, Result, anyhow, bail};
    use base64::Engine as _;
    use chromiumoxide::cdp::browser_protocol::fetch::{
        ContinueRequestParams, EnableParams, EventRequestPaused, FulfillRequestParams, HeaderEntry, RequestPattern, RequestStage,
    };
    use chromiumoxide::cdp::browser_protocol::page::CaptureScreenshotFormat;
    use chromiumoxide::page::ScreenshotParams;
    use chromiumoxide::{Browser, BrowserConfig, Element, Page};
    use futures::StreamExt;
    use std::time::{Duration, Instant};
    use tokio::sync::oneshot;

    /// Opens `url` in headless Chromium, runs the script and, when `redirect`
    /// is given, intercepts the navigation to it (works for non-loopback URIs too).
    pub async fn drive(
        run: &mut Run<'_>,
        url: &str,
        redirect: Option<&str>,
        script: &[BrowserAction],
        timeout: Duration,
    ) -> Result<Option<Callback>> {
        let profile = std::env::temp_dir().join(format!("grantcentral-chrome-{}", crate::random_b64(8)));
        let mut b = BrowserConfig::builder().user_data_dir(&profile).window_size(1280, 900);
        if run.opts.chrome.headful {
            b = b.with_head();
        }
        if let Some(p) = run.opts.chrome.path.clone().or_else(|| std::env::var_os("CHROME").filter(|v| !v.is_empty()).map(Into::into)) {
            b = b.chrome_executable(p);
        }
        if run.opts.chrome.no_sandbox {
            b = b.no_sandbox();
        }
        if run.client.insecure == Some(true) {
            b = b.arg("--ignore-certificate-errors");
        }
        let config = b.build().map_err(|e| anyhow!("Chromium: {e} (pass --chrome or set CHROME to the browser executable)"))?;
        let (mut browser, mut handler) = Browser::launch(config).await.context("launching Chromium")?;
        let pump = tokio::spawn(async move { while handler.next().await.is_some() {} });
        run.log("Launched headless Chromium");
        let result = drive_page(run, &browser, url, redirect, script, timeout).await;
        let _ = browser.close().await;
        let _ = browser.wait().await;
        pump.abort();
        let _ = std::fs::remove_dir_all(&profile);
        result
    }

    async fn drive_page(
        run: &mut Run<'_>,
        browser: &Browser,
        url: &str,
        redirect: Option<&str>,
        script: &[BrowserAction],
        timeout: Duration,
    ) -> Result<Option<Callback>> {
        let page = browser.new_page("about:blank").await?;
        let (tx, mut rx) = oneshot::channel::<Result<Callback>>();
        if let Some(redirect) = redirect {
            let base = redirect.split(['?', '#']).next().unwrap_or(redirect);
            let pattern = RequestPattern::builder().url_pattern(format!("{base}*")).request_stage(RequestStage::Request).build();
            page.execute(EnableParams::builder().pattern(pattern).build()).await?;
            let mut events = page.event_listener::<EventRequestPaused>().await?;
            let p = page.clone();
            let redirect = redirect.to_string();
            tokio::spawn(async move {
                while let Some(ev) = events.next().await {
                    let mut full = ev.request.url.clone();
                    if let Some(f) = &ev.request.url_fragment {
                        full.push_str(f);
                    }
                    if !matches_redirect(&full, &redirect) {
                        let _ = p.execute(ContinueRequestParams::new(ev.request_id.clone())).await;
                        continue;
                    }
                    let mut cb = parse_callback(&full);
                    if let (Ok(cb), Some(entries)) = (&mut cb, &ev.request.post_data_entries) {
                        let body: Vec<u8> = entries
                            .iter()
                            .filter_map(|e| e.bytes.as_ref())
                            .flat_map(|b| base64::engine::general_purpose::STANDARD.decode(AsRef::<str>::as_ref(b)).unwrap_or_default())
                            .collect();
                        cb.params.extend(url::form_urlencoded::parse(&body).into_owned());
                    }
                    let html = base64::engine::general_purpose::STANDARD.encode(super::DONE_PAGE);
                    let fulfill = FulfillRequestParams::builder()
                        .request_id(ev.request_id.clone())
                        .response_code(200)
                        .response_header(HeaderEntry::new("content-type", "text/html; charset=utf-8"))
                        .body(html)
                        .build();
                    if let Ok(f) = fulfill {
                        let _ = p.execute(f).await;
                    }
                    let _ = tx.send(cb);
                    break;
                }
            });
        }

        let deadline = Instant::now() + timeout;
        let script_result = tokio::select! {
            cb = &mut rx => return cb.map_err(|_| anyhow!("interceptor stopped"))?.map(Some),
            r = run_script(run, &page, url, script) => r,
        };
        if redirect.is_none() {
            // Give the last submission a moment to land.
            tokio::time::sleep(Duration::from_secs(2)).await;
            return script_result.map(|_| None);
        }
        let wait = if script_result.is_ok() { deadline.saturating_duration_since(Instant::now()) } else { Duration::from_secs(3) };
        match tokio::time::timeout(wait, rx).await {
            Ok(Ok(cb)) => cb.map(Some),
            _ => {
                let here = page.url().await.ok().flatten().unwrap_or_default();
                let title = page.get_title().await.ok().flatten().unwrap_or_default();
                let shot = screenshot(run, &page).await;
                let why = match script_result {
                    Err(e) => format!("{e:#}"),
                    Ok(()) => "the login script finished but the redirect URI was not reached".into(),
                };
                bail!("{why}; browser is at {here} ({title}){shot}")
            }
        }
    }

    async fn run_script(run: &mut Run<'_>, page: &Page, url: &str, script: &[BrowserAction]) -> Result<()> {
        page.goto(url).await.with_context(|| format!("navigating to {url}"))?;
        let mut last: Option<Element> = None;
        for (i, a) in script.iter().enumerate() {
            let ctx = run.ctx();
            let r = |s: &Option<String>| -> Result<Option<String>> { s.as_ref().map(|s| run.tpl.render(s, &ctx)).transpose() };
            let (fill, value, click, wait, press) = (r(&a.fill)?, r(&a.value)?, r(&a.click)?, r(&a.wait)?, r(&a.press)?);
            if let Some(ms) = a.sleep_ms {
                tokio::time::sleep(Duration::from_millis(ms)).await;
            }
            let wait_for = Duration::from_secs(a.timeout.unwrap_or(if a.optional { 3 } else { 10 }));
            if let Some(sel) = fill.as_ref().or(click.as_ref()).or(wait.as_ref()) {
                match find(page, sel, wait_for).await {
                    Some(el) => {
                        if fill.is_some() {
                            el.click().await?;
                            el.type_str(value.clone().unwrap_or_default()).await?;
                        } else if click.is_some() {
                            el.click().await?;
                        }
                        last = Some(el);
                    }
                    None if a.optional => {
                        run.log(format!("Login script step {}: {sel} not found, skipped (optional)", i + 1));
                        continue;
                    }
                    None => bail!("login script step {}: {sel} did not appear within {}s", i + 1, wait_for.as_secs()),
                }
            }
            if let Some(key) = &press {
                let el = match &last {
                    Some(e) => e,
                    None => bail!("login script step {}: press needs a preceding fill or click", i + 1),
                };
                el.press_key(key).await?;
            }
        }
        Ok(())
    }

    async fn find(page: &Page, sel: &str, timeout: Duration) -> Option<Element> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Ok(e) = page.find_element(sel).await {
                return Some(e);
            }
            if Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    async fn screenshot(run: &Run<'_>, page: &Page) -> String {
        let dir = run.root.join(".grantcentral/screenshots");
        let path = dir.join(format!("step{}-{}.png", run.index + 1, crate::now()));
        let params = ScreenshotParams::builder().format(CaptureScreenshotFormat::Png).build();
        match page.screenshot(params).await {
            Ok(png) if std::fs::create_dir_all(&dir).is_ok() && std::fs::write(&path, &png).is_ok() => {
                format!("; screenshot: {}", path.display())
            }
            _ => String::new(),
        }
    }
}

#[cfg(not(feature = "chromium"))]
mod chromium {
    use super::Callback;
    use crate::engine::Run;
    use crate::model::BrowserAction;
    use anyhow::{Result, bail};
    use std::time::Duration;

    pub async fn drive(_: &mut Run<'_>, _: &str, _: Option<&str>, _: &[BrowserAction], _: Duration) -> Result<Option<Callback>> {
        bail!("this build has no Chromium support (enable the `chromium` feature)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_callbacks() {
        let cb = parse_callback("http://127.0.0.1:8765/cb?code=abc&state=xyz").unwrap();
        assert_eq!(cb.params["code"], "abc");
        let cb = parse_callback("https://app/cb#access_token=t&token_type=Bearer&state=s").unwrap();
        assert_eq!(cb.params["access_token"], "t");
        assert!(matches_redirect("http://127.0.0.1:8765/cb?code=1", "http://127.0.0.1:8765/cb"));
        assert!(!matches_redirect("http://127.0.0.1:8765/cb2", "http://127.0.0.1:8765/cb"));
        assert!(is_loopback("http://localhost/cb") && is_loopback("http://[::1]:3/x") && !is_loopback("https://127.0.0.1/cb"));
    }

    #[test]
    fn extracts_form_post() {
        let html = r#"<html><body onload="document.forms[0].submit()"><form method="post" action="https://app.example/cb">
            <input type="hidden" name="code" value="a&amp;b"/><input type='hidden' name='state' value='s1'></form>"#;
        let cb = form_post(html, "https://app.example/cb").unwrap();
        assert_eq!(cb.params["code"], "a&b");
        assert_eq!(cb.params["state"], "s1");
        assert!(form_post(html, "https://other/cb").is_none());
    }

    #[tokio::test]
    async fn loopback_receives_query_and_fragment() {
        let mut l = Loopback::bind("http://127.0.0.1/callback").await.unwrap();
        assert!(l.redirect_uri.starts_with("http://127.0.0.1:"));
        let base = l.redirect_uri.clone();
        let c = reqwest::Client::new();
        let page = c.get(&base).send().await.unwrap().text().await.unwrap();
        assert!(page.contains("location.hash"), "empty GET serves the fragment page");
        c.get(format!("{base}?code=c1&state=s")).send().await.unwrap();
        assert_eq!(l.recv().await.unwrap().params["code"], "c1");
        c.post(format!("{base}?gc_fragment=1")).body("access_token=t1").send().await.unwrap();
        let cb = l.recv().await.unwrap();
        assert_eq!(cb.params["access_token"], "t1");
        assert!(cb.url.contains("#access_token=t1"));
    }
}
