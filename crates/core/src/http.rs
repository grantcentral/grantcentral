//! HTTP client that records every exchange for reports. Redirects are never
//! followed: OAuth endpoints should not redirect, and the raw response is the
//! point of a test tool.

use crate::model::ClientConfig;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Exchange {
    pub method: String,
    pub url: String,
    pub request_headers: Vec<(String, String)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body: Option<String>,
    pub status: u16,
    pub response_headers: Vec<(String, String)>,
    pub response_body: String,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub enum Body {
    None,
    Form(Vec<(String, String)>),
    Json(Value),
    Raw { content_type: Option<String>, data: String },
}

#[derive(Debug, Clone)]
pub struct Req {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Body,
}

impl Req {
    pub fn get(url: impl Into<String>) -> Self {
        Req { method: "GET".into(), url: url.into(), headers: vec![], body: Body::None }
    }
    pub fn form(url: impl Into<String>, form: Vec<(String, String)>) -> Self {
        Req { method: "POST".into(), url: url.into(), headers: vec![], body: Body::Form(form) }
    }
    pub fn header(mut self, k: &str, v: impl Into<String>) -> Self {
        self.set_header(k, v);
        self
    }
    pub fn set_header(&mut self, k: &str, v: impl Into<String>) {
        self.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(k));
        self.headers.push((k.to_string(), v.into()));
    }
}

#[derive(Debug, Clone)]
pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Resp {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
    pub fn json(&self) -> Option<Value> {
        serde_json::from_str(&self.body).ok()
    }
    /// The body as JSON, or as a string when it is not JSON.
    pub fn body_value(&self) -> Value {
        self.json().unwrap_or_else(|| Value::String(self.body.clone()))
    }
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
    /// The result document steps expose to assertions.
    pub fn doc(&self) -> Value {
        let headers: serde_json::Map<String, Value> =
            self.headers.iter().map(|(k, v)| (k.to_ascii_lowercase(), Value::String(v.clone()))).collect();
        serde_json::json!({ "status": self.status, "headers": headers, "body": self.body_value() })
    }
}

pub use reqwest::Client;

/// A client with default settings, for one-off requests outside a run.
pub fn plain_client() -> Result<Client> {
    Ok(client_builder(&ClientConfig::default(), Path::new("."))?.build()?)
}

pub struct Http {
    client: reqwest::Client,
    log: Mutex<Vec<Exchange>>,
}

/// A reqwest builder with the client's TLS settings (mTLS identity, extra CA, insecure).
pub fn client_builder(cfg: &ClientConfig, root: &Path) -> Result<reqwest::ClientBuilder> {
    let mut b = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(cfg.timeout.unwrap_or(30)))
        .user_agent(concat!("GrantCentral/", env!("CARGO_PKG_VERSION")));
    if let (Some(cert), Some(key)) = (&cfg.tls_cert, &cfg.tls_key) {
        let mut pem = std::fs::read(root.join(cert)).with_context(|| format!("reading {cert}"))?;
        pem.push(b'\n');
        pem.extend(std::fs::read(root.join(key)).with_context(|| format!("reading {key}"))?);
        b = b.identity(reqwest::Identity::from_pem(&pem).context("loading the mTLS client certificate")?);
    }
    if let Some(ca) = &cfg.ca_cert {
        let pem = std::fs::read(root.join(ca)).with_context(|| format!("reading {ca}"))?;
        for cert in reqwest::Certificate::from_pem_bundle(&pem).context("parsing ca_cert")? {
            b = b.add_root_certificate(cert);
        }
    }
    if cfg.insecure == Some(true) {
        b = b.danger_accept_invalid_certs(true);
    }
    Ok(b)
}

impl Http {
    pub fn new(cfg: &ClientConfig, root: &Path) -> Result<Self> {
        Ok(Http { client: client_builder(cfg, root)?.build()?, log: Mutex::new(vec![]) })
    }

    /// Forgets the most recent exchange (repetitive device-flow polls).
    pub fn forget_last(&self) {
        self.log.lock().unwrap().pop();
    }

    pub async fn send(&self, req: &Req) -> Result<Resp> {
        let method = reqwest::Method::from_bytes(req.method.as_bytes()).context("invalid HTTP method")?;
        let mut rb = self.client.request(method, &req.url);
        let mut headers = req.headers.clone();
        let body_text = match &req.body {
            Body::None => None,
            Body::Form(f) => {
                let s = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(f).finish();
                headers.push(("content-type".into(), "application/x-www-form-urlencoded".into()));
                Some(s)
            }
            Body::Json(v) => {
                headers.push(("content-type".into(), "application/json".into()));
                Some(serde_json::to_string(v)?)
            }
            Body::Raw { content_type, data } => {
                if let Some(ct) = content_type {
                    headers.push(("content-type".into(), ct.clone()));
                }
                Some(data.clone())
            }
        };
        for (k, v) in &headers {
            rb = rb.header(k, v);
        }
        if let Some(b) = &body_text {
            rb = rb.body(b.clone());
        }
        let start = Instant::now();
        let mut ex = Exchange {
            method: req.method.clone(),
            url: req.url.clone(),
            request_headers: headers,
            request_body: body_text,
            status: 0,
            response_headers: vec![],
            response_body: String::new(),
            duration_ms: 0,
            error: None,
        };
        let result = async {
            let r = rb.send().await?;
            let status = r.status().as_u16();
            let headers: Vec<(String, String)> =
                r.headers().iter().map(|(k, v)| (k.to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned())).collect();
            let body = r.text().await?;
            Ok::<_, reqwest::Error>(Resp { status, headers, body })
        }
        .await;
        ex.duration_ms = start.elapsed().as_millis() as u64;
        match result {
            Ok(resp) => {
                ex.status = resp.status;
                ex.response_headers = resp.headers.clone();
                ex.response_body = resp.body.clone();
                self.log.lock().unwrap().push(ex);
                Ok(resp)
            }
            Err(e) => {
                let msg = error_chain(&e);
                ex.error = Some(msg.clone());
                self.log.lock().unwrap().push(ex);
                Err(anyhow::anyhow!("{} {}: {msg}", req.method, req.url))
            }
        }
    }

    /// Takes the exchanges recorded since the last call.
    pub fn drain(&self) -> Vec<Exchange> {
        std::mem::take(&mut *self.log.lock().unwrap())
    }
}

fn error_chain(e: &dyn std::error::Error) -> String {
    let mut msg = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        msg.push_str(": ");
        msg.push_str(&s.to_string());
        src = s.source();
    }
    msg
}
