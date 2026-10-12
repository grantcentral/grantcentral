//! GrantCentral core: file model, flow engine and the OAuth 2.0 / OpenID
//! Connect client implementation shared by the CLI and the web UI.

pub mod engine;
pub mod git;
pub mod http;
pub mod jose;
pub mod login;
pub mod model;
pub mod oauth;
pub mod project;
pub mod report;
pub mod secrets;
pub mod template;

pub use engine::{Event, RunHandle, RunOptions, run_flow, start_run};
pub use project::Project;
pub use report::{RunReport, StepReport, StepStatus};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub(crate) fn b64(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub(crate) fn unb64(s: &str) -> anyhow::Result<Vec<u8>> {
    // Tolerate padding, which some servers emit.
    Ok(URL_SAFE_NO_PAD.decode(s.trim_end_matches('='))?)
}

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    openssl::sha::sha256(data)
}

/// URL-safe random string from `n` random bytes.
pub fn random_b64(n: usize) -> String {
    let mut buf = vec![0u8; n];
    openssl::rand::rand_bytes(&mut buf).expect("OS random number generator");
    b64(&buf)
}

pub(crate) fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// JSON schemas for the files users edit, for editor validation.
pub fn schemas() -> Vec<(&'static str, serde_json::Value)> {
    vec![
        ("flow", serde_json::to_value(schemars::schema_for!(model::Flow)).unwrap()),
        ("environment", serde_json::to_value(schemars::schema_for!(model::EnvironmentFile)).unwrap()),
        ("project", serde_json::to_value(schemars::schema_for!(model::ProjectFile)).unwrap()),
    ]
}
