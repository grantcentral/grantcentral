//! Token endpoint grants (RFC 6749 §4, RFC 8693, RFC 7522, RFC 7523) and the
//! device authorization grant (RFC 8628).

use super::{
    URN_ACCESS_TOKEN, URN_DEVICE_CODE, URN_JWT_BEARER, URN_SAML2_BEARER, URN_TOKEN_EXCHANGE, apply_overrides, authenticate,
    handle_token_response, json_param, oauth_error, push_all, send_dpop, set, set_opt, signing_key,
};
use crate::engine::{Output, Run};
use crate::http::Req;
use crate::jose;
use crate::login;
use crate::model::{DeviceStep, LoginMode, TokenStep};
use crate::report::Severity::{Error, Warning};
use anyhow::{Result, anyhow};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

fn grant_uri(alias: &str) -> &str {
    match alias {
        "token_exchange" => URN_TOKEN_EXCHANGE,
        "jwt_bearer" => URN_JWT_BEARER,
        "saml2_bearer" => URN_SAML2_BEARER,
        "device_code" => URN_DEVICE_CODE,
        other => other,
    }
}

fn required(v: Option<String>, what: &str) -> Result<String> {
    v.ok_or_else(|| anyhow!("{what} is required for this grant (none given and none in the session)"))
}

pub async fn token(run: &mut Run<'_>, s: &TokenStep) -> Result<Output> {
    let grant = match &s.grant_type {
        Some(g) => grant_uri(g).to_string(),
        None if run.session.code.is_some() => "authorization_code".into(),
        None => "client_credentials".into(),
    };
    let ep = run.endpoint("token_endpoint")?;
    let mut f = vec![("grant_type".to_string(), grant.clone())];
    match grant.as_str() {
        "authorization_code" => {
            set(&mut f, "code", required(s.code.clone().or_else(|| run.session.code.clone()), "code")?);
            let redirect = s.redirect_uri.clone().or_else(|| run.session.redirect_uri.clone()).or_else(|| run.client.redirect_uri.clone());
            set_opt(&mut f, "redirect_uri", redirect.as_ref());
            set_opt(&mut f, "code_verifier", s.code_verifier.as_ref().or(run.session.code_verifier.as_ref()));
        }
        "refresh_token" => {
            set(&mut f, "refresh_token", required(s.refresh_token.clone().or_else(|| run.session.refresh_token.clone()), "refresh_token")?);
        }
        "client_credentials" => set_opt(&mut f, "scope", s.scope.as_ref().or(run.client.scope.as_ref())),
        "password" => {
            set(&mut f, "username", required(s.username.clone(), "username")?);
            set(&mut f, "password", required(s.password.clone(), "password")?);
            run.check("password grant avoided", false, Warning, "", Some("RFC 9700 §2.4"));
        }
        URN_TOKEN_EXCHANGE => {
            set(&mut f, "subject_token", required(s.subject_token.clone().or_else(|| run.session.access_token.clone()), "subject_token")?);
            set(&mut f, "subject_token_type", s.subject_token_type.clone().unwrap_or_else(|| URN_ACCESS_TOKEN.into()));
            if let Some(a) = &s.actor_token {
                set(&mut f, "actor_token", a);
                set(&mut f, "actor_token_type", s.actor_token_type.clone().unwrap_or_else(|| URN_ACCESS_TOKEN.into()));
            }
            set_opt(&mut f, "requested_token_type", s.requested_token_type.as_ref());
            push_all(&mut f, "audience", &s.audience);
        }
        URN_JWT_BEARER => {
            let assertion = match &s.assertion {
                Some(a) => a.clone(),
                None => bearer_assertion(run, s)?,
            };
            set(&mut f, "assertion", assertion);
        }
        URN_SAML2_BEARER => {
            let a = required(s.assertion.clone(), "assertion")?;
            // RFC 7522 §2.1: the assertion is base64url-encoded.
            let a = if a.trim_start().starts_with('<') { crate::b64(a.as_bytes()) } else { a };
            set(&mut f, "assertion", a);
        }
        URN_DEVICE_CODE => {
            set(&mut f, "device_code", required(s.device_code.clone().or_else(|| run.session.device_code.clone()), "device_code")?)
        }
        _ => {}
    }
    if grant != "client_credentials" {
        set_opt(&mut f, "scope", s.scope.as_ref());
    }
    push_all(&mut f, "resource", &s.resource);
    if let Some(d) = &s.authorization_details {
        set(&mut f, "authorization_details", json_param(d));
    }
    apply_overrides(&mut f, &s.params, &s.remove);

    let mut req = Req::form(&ep, f);
    authenticate(run, &mut req, &ep)?;
    let resp = send_dpop(run, req, None).await?;
    handle_token_response(run, resp, &grant, s.validate_access_token).await
}

/// A JWT authorization grant assertion (RFC 7523 §3), signed with the client key.
fn bearer_assertion(run: &Run, s: &TokenStep) -> Result<String> {
    let id = run.client_id()?;
    let now = crate::now();
    let mut claims = json!({ "iss": id, "sub": id, "aud": run.issuer()?, "iat": now, "exp": now + 300, "jti": crate::random_b64(16) });
    if let Some(Value::Object(extra)) = &s.assertion_claims {
        claims.as_object_mut().unwrap().extend(extra.clone());
    }
    jose::sign(&claims, json!({ "typ": "JWT" }), &signing_key(run)?, run.client.signing_alg.as_deref())
}

pub async fn device(run: &mut Run<'_>, s: &DeviceStep) -> Result<Output> {
    let spec = Some("RFC 8628 §3.2");
    let ep = run.endpoint("device_authorization_endpoint")?;
    let mut f = vec![];
    set_opt(&mut f, "scope", s.scope.as_ref().or(run.client.scope.as_ref()));
    push_all(&mut f, "resource", &s.resource);
    if let Some(d) = &s.authorization_details {
        set(&mut f, "authorization_details", json_param(d));
    }
    apply_overrides(&mut f, &s.params, &[]);
    let mut req = Req::form(&ep, f);
    authenticate(run, &mut req, &ep)?;
    let resp = run.http.send(&req).await?;
    let mut doc = json!({ "device": resp.doc() });
    if !resp.ok() {
        return Ok(Output { doc, error: oauth_error(&resp) });
    }
    let b = resp.json().unwrap_or(Value::Null);
    for k in ["device_code", "user_code", "verification_uri", "expires_in"] {
        run.check(format!("{k} present"), !b[k].is_null(), Error, "", spec);
    }
    let expires_in = b["expires_in"].as_u64().unwrap_or(600);
    // RFC 10027 asks for short-lived codes; RFC 8628's example uses 30 minutes.
    run.check("user code is short-lived", expires_in <= 1800, Warning, format!("expires_in {expires_in}s"), Some("RFC 10027 §6.1"));
    let user_code = b["user_code"].as_str().unwrap_or("").to_string();
    let significant = user_code.chars().filter(|c| c.is_ascii_alphanumeric()).count();
    run.check(
        "user code has enough entropy",
        significant >= 8,
        Warning,
        format!("{significant} significant characters"),
        Some("RFC 8628 §6.1"),
    );

    run.session.device_code = b["device_code"].as_str().map(str::to_string);
    run.session.user_code = Some(user_code.clone());
    run.session.verification_uri = b["verification_uri"].as_str().map(str::to_string);
    run.session.verification_uri_complete = b["verification_uri_complete"].as_str().map(str::to_string);
    let target = run.session.verification_uri_complete.clone().or_else(|| run.session.verification_uri.clone()).unwrap_or_default();
    run.notice(format!("Enter code {user_code} at"), Some(target.clone()));

    let mode = run.opts.login.or(s.login).unwrap_or(LoginMode::System);
    let timeout = Duration::from_secs(s.timeout.unwrap_or(expires_in).min(expires_in));
    login::visit(run, mode, &target, &s.login_script, timeout).await?;
    if s.poll == Some(false) {
        return Ok(Output::ok(doc));
    }

    let token_ep = run.endpoint("token_endpoint")?;
    let mut interval = b["interval"].as_u64().unwrap_or(5);
    let deadline = Instant::now() + timeout;
    let mut polls = 0;
    loop {
        tokio::time::sleep(Duration::from_secs(interval)).await;
        polls += 1;
        let mut req = Req::form(&token_ep, vec![("grant_type".into(), URN_DEVICE_CODE.into())]);
        if let crate::http::Body::Form(f) = &mut req.body {
            set(f, "device_code", run.session.device_code.clone().unwrap_or_default());
        }
        authenticate(run, &mut req, &token_ep)?;
        let resp = send_dpop(run, req, None).await?;
        let err = resp.json().and_then(|j| j["error"].as_str().map(str::to_string));
        match err.as_deref() {
            Some("authorization_pending") | Some("slow_down") if Instant::now() < deadline => {
                if err.as_deref() == Some("slow_down") {
                    interval += 5; // RFC 8628 §3.5
                    run.log(format!("slow_down: polling every {interval}s"));
                }
                if polls > 1 {
                    run.http.forget_last();
                }
                continue;
            }
            _ => {
                run.log(format!("Polled the token endpoint {polls} time(s)"));
                let out = handle_token_response(run, resp, URN_DEVICE_CODE, None).await?;
                let mut token_doc = out.doc;
                token_doc["device"] = doc["device"].take();
                return Ok(Output { doc: token_doc, error: out.error });
            }
        }
    }
}
