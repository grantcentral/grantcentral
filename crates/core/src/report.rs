//! Run results, shared by every front end and the JSON/JUnit reporters.

use crate::http::Exchange;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Fails the step (unless the step expects an error).
    Error,
    Warning,
    Info,
}

/// A built-in protocol check, e.g. "state matches" or "issuer matches (RFC 8414 §3.3)".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Check {
    pub name: String,
    pub passed: bool,
    pub severity: Severity,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionResult {
    pub expr: String,
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Passed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepReport {
    pub index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub name: String,
    pub kind: String,
    pub status: StepStatus,
    pub duration_ms: u64,
    /// The protocol or transport error the step ran into, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Why the step failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
    pub checks: Vec<Check>,
    pub assertions: Vec<AssertionResult>,
    pub exchanges: Vec<Exchange>,
    pub logs: Vec<String>,
    /// The document assertions ran against.
    pub result: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunReport {
    pub flow: String,
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    pub started_at: u64,
    pub duration_ms: u64,
    pub passed: bool,
    /// Set when the flow could not run at all (parse errors, missing files).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub steps: Vec<StepReport>,
    /// Secret values to mask when the report leaves the machine.
    #[serde(skip)]
    pub redactions: Vec<String>,
}

impl RunReport {
    /// A copy with secret values and Basic credentials masked, for CI logs and report files.
    pub fn redacted(&self) -> RunReport {
        let mut needles: Vec<String> = vec![];
        for s in self.redactions.iter().filter(|s| s.len() >= 4) {
            needles.push(s.clone());
            needles.push(url::form_urlencoded::byte_serialize(s.as_bytes()).collect());
            // As it appears inside a JSON response body.
            let esc = serde_json::to_string(s).unwrap();
            needles.push(esc[1..esc.len() - 1].to_string());
        }
        needles.sort_by_key(|s| std::cmp::Reverse(s.len()));
        needles.dedup();
        let mut v = serde_json::to_value(self).expect("report serializes");
        mask(&mut v, &needles);
        let mut out: RunReport = serde_json::from_value(v).expect("redacted report deserializes");
        for step in &mut out.steps {
            for ex in &mut step.exchanges {
                for (k, v) in &mut ex.request_headers {
                    if k.eq_ignore_ascii_case("authorization") && v.to_ascii_lowercase().starts_with("basic ") {
                        *v = "Basic ***".into();
                    }
                }
            }
        }
        out
    }

    pub fn counts(&self) -> (usize, usize, usize) {
        let c = |s| self.steps.iter().filter(|x| x.status == s).count();
        (c(StepStatus::Passed), c(StepStatus::Failed), c(StepStatus::Skipped))
    }
}

fn mask(v: &mut Value, needles: &[String]) {
    match v {
        Value::String(s) => {
            for n in needles {
                if s.contains(n.as_str()) {
                    *s = s.replace(n.as_str(), "***");
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|x| mask(x, needles)),
        // Enum and label fields stay intact so the report still parses and reads.
        Value::Object(o) => o
            .iter_mut()
            .filter(|(k, _)| !["status", "kind", "severity", "name", "flow", "file", "spec", "environment", "expr"].contains(&k.as_str()))
            .for_each(|(_, x)| mask(x, needles)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_secrets_and_basic_auth() {
        let r = RunReport {
            flow: "f".into(),
            file: "f.toml".into(),
            environment: None,
            started_at: 0,
            duration_ms: 0,
            passed: true,
            error: None,
            steps: vec![StepReport {
                index: 0,
                id: None,
                name: "s".into(),
                kind: "token".into(),
                status: StepStatus::Passed,
                duration_ms: 0,
                error: None,
                failure: None,
                checks: vec![],
                assertions: vec![],
                exchanges: vec![Exchange {
                    method: "POST".into(),
                    url: "https://as/token".into(),
                    request_headers: vec![("Authorization".into(), "Basic YTpi".into())],
                    request_body: Some("password=p%26ss%22word".into()),
                    status: 200,
                    response_headers: vec![],
                    response_body: "{\"x\":\"p&ss\\\"word\"}".into(),
                    duration_ms: 0,
                    error: None,
                }],
                logs: vec![],
                result: serde_json::json!({}),
            }],
            redactions: vec!["p&ss\"word".into()],
        };
        let out = serde_json::to_string(&r.redacted()).unwrap();
        assert!(!out.contains("p&ss") && !out.contains("p%26ss") && !out.contains("YTpi"), "{out}");
    }
}
