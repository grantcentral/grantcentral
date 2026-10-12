//! Static checks of authorization server metadata against the security BCPs.
//! Behavior that metadata cannot show (code reuse, refresh rotation, exact
//! redirect matching) is tested by the negative-test flows in `examples/`.

use crate::engine::{Output, Run};
use crate::model::AuditStep;
use crate::report::Check;
use crate::report::Severity::{self, Error, Info, Warning};
use anyhow::{Result, bail};
use serde_json::{Value, json};

pub fn audit(run: &mut Run<'_>, s: &AuditStep) -> Result<Output> {
    let Some(meta) = run.session.metadata.clone() else { bail!("audit needs a discover step first") };
    let checks = audit_metadata(&meta, s.profile.as_deref().unwrap_or("confidential"))?;
    let failed: Vec<String> = checks.iter().filter(|c| !c.passed).map(|c| c.name.clone()).collect();
    run.checks.extend(checks);
    Ok(Output::ok(json!({ "metadata": meta, "findings": failed })))
}

/// Checks metadata for a client profile: "confidential", "browser" (RFC 10017) or "native" (RFC 8252).
pub fn audit_metadata(meta: &Value, profile: &str) -> Result<Vec<Check>> {
    if !["confidential", "browser", "native"].contains(&profile) {
        bail!("unknown audit profile {profile:?} (confidential, browser, native)");
    }
    let public = profile != "confidential";
    let mut out = vec![];
    let mut check = |name: &str, passed: bool, severity: Severity, detail: String, spec: &str| {
        out.push(Check { name: name.into(), passed, severity, detail, spec: Some(spec.into()) });
    };
    let strs = |k: &str| -> Vec<String> {
        meta[k].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default()
    };
    let has = |k: &str| !meta[k].is_null();

    let pkce = strs("code_challenge_methods_supported");
    check(
        "PKCE S256 supported",
        pkce.iter().any(|m| m == "S256"),
        if public { Error } else { Warning },
        if pkce.is_empty() { "code_challenge_methods_supported absent, so PKCE support is unknown".into() } else { pkce.join(", ") },
        if public { "RFC 10017, RFC 8252 §8.1, RFC 9700 §2.1.1" } else { "RFC 7636, RFC 9700 §2.1.1" },
    );
    if pkce.iter().any(|m| m == "plain") {
        check("PKCE plain not offered", false, Info, "plain gives no protection when the challenge leaks".into(), "RFC 9700 §2.1.1");
    }

    let implicit: Vec<String> = strs("response_types_supported").into_iter().filter(|t| t.split(' ').any(|p| p == "token")).collect();
    check("implicit grant not offered", implicit.is_empty(), Warning, implicit.join(", "), "RFC 9700 §2.1.2");

    let grants = strs("grant_types_supported");
    check("password grant not offered", !grants.iter().any(|g| g == "password"), Warning, String::new(), "RFC 9700 §2.4");

    check(
        "iss in authorization responses",
        meta["authorization_response_iss_parameter_supported"] == Value::Bool(true),
        Warning,
        "authorization_response_iss_parameter_supported is not true; mix-up defense depends on distinct redirect URIs".into(),
        "RFC 9207, RFC 9700 §4.4",
    );

    for (k, spec) in [
        ("token_endpoint_auth_signing_alg_values_supported", "RFC 8414 §2"),
        ("revocation_endpoint_auth_signing_alg_values_supported", "RFC 8414 §2"),
        ("introspection_endpoint_auth_signing_alg_values_supported", "RFC 8414 §2"),
    ] {
        if strs(k).iter().any(|a| a == "none") {
            check(&format!("{k} excludes none"), false, Error, "\"none\" MUST NOT be used".into(), spec);
        }
    }
    for k in ["request_object_signing_alg_values_supported", "id_token_signing_alg_values_supported"] {
        if strs(k).iter().any(|a| a == "none") {
            check(&format!("{k} excludes none"), false, Warning, "unsigned JWTs are accepted".into(), "RFC 8725 §3.1, RFC 9101 §10");
        }
    }

    let auth_methods = strs("token_endpoint_auth_methods_supported");
    let strong = auth_methods.iter().any(|m| ["private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth"].contains(&m.as_str()));
    check(
        "asymmetric client authentication offered",
        strong,
        Info,
        auth_methods.join(", "),
        "RFC 9700 §2.5 (private_key_jwt, RFC 8705 mTLS)",
    );

    let sender_constrained =
        has("dpop_signing_alg_values_supported") || meta["tls_client_certificate_bound_access_tokens"] == Value::Bool(true);
    check(
        "sender-constrained tokens offered",
        sender_constrained,
        if public { Warning } else { Info },
        "neither DPoP (dpop_signing_alg_values_supported) nor mTLS-bound tokens advertised".into(),
        if public { "RFC 9700 §2.2, RFC 10017, RFC 9449, RFC 8705" } else { "RFC 9700 §2.2, RFC 9449, RFC 8705" },
    );

    check("pushed authorization requests offered", has("pushed_authorization_request_endpoint"), Info, String::new(), "RFC 9126");
    check("revocation endpoint offered", has("revocation_endpoint"), Info, String::new(), "RFC 7009");
    check("introspection endpoint offered", has("introspection_endpoint"), Info, String::new(), "RFC 7662");
    if has("device_authorization_endpoint") {
        check(
            "cross-device flow present",
            true,
            Info,
            "the device grant needs a cross-device risk assessment; run the device negative-test flow for code lifetime and reuse".into(),
            "RFC 10027 §6, RFC 8628 §5",
        );
    }
    if public && profile == "browser" {
        check("refresh token rotation", true, Info, "not visible in metadata; the refresh-rotation flow tests it".into(), "RFC 10017");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_weak_metadata() {
        let meta = json!({
            "issuer": "https://as",
            "response_types_supported": ["code", "token"],
            "grant_types_supported": ["authorization_code", "password"],
            "token_endpoint_auth_signing_alg_values_supported": ["none", "RS256"],
        });
        let checks = audit_metadata(&meta, "browser").unwrap();
        let failed = |n: &str| checks.iter().any(|c| c.name.starts_with(n) && !c.passed);
        assert!(failed("PKCE S256"));
        assert!(failed("implicit"));
        assert!(failed("password"));
        assert!(failed("token_endpoint_auth_signing_alg_values_supported"));
        assert!(checks.iter().any(|c| c.name.starts_with("PKCE") && c.severity == Error));
    }
}
