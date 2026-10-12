//! Authorization requests (RFC 6749 §4.1, OpenID Connect Core §3) with PKCE
//! (RFC 7636), PAR (RFC 9126), JAR (RFC 9101), RAR (RFC 9396), resource
//! indicators (RFC 8707), DPoP code binding (RFC 9449 §10) and issuer
//! identification (RFC 9207).

use super::{
    apply_overrides, authenticate, dpop_enabled, dpop_jkt, json_param, oauth_error, push_all, send_dpop, set, set_opt, signing_key,
};
use crate::engine::{Output, Run};
use crate::http::Req;
use crate::jose;
use crate::login::{self, Loopback};
use crate::model::{AuthorizeStep, LoginMode, Pkce, RequestObject};
use crate::report::Severity::{Error, Info, Warning};
use anyhow::{Result, anyhow};
use serde_json::{Map, Value, json};
use std::time::Duration;

/// PKCE code challenge for a verifier (RFC 7636 §4.2).
pub fn code_challenge(method: Pkce, verifier: &str) -> String {
    match method {
        Pkce::S256 => crate::b64(&crate::sha256(verifier.as_bytes())),
        _ => verifier.to_string(),
    }
}

pub async fn authorize(run: &mut Run<'_>, s: &AuthorizeStep) -> Result<Output> {
    let mode = run.opts.login.or(s.login).unwrap_or(LoginMode::System);
    let auth_ep = run.endpoint("authorization_endpoint")?;
    let client_id = run.client_id()?;

    let mut redirect =
        s.redirect_uri.clone().or_else(|| run.client.redirect_uri.clone()).ok_or_else(|| anyhow!("no redirect_uri configured"))?;
    let listener = if login::is_loopback(&redirect) {
        let l = Loopback::bind(&redirect).await?;
        redirect = l.redirect_uri.clone();
        Some(l)
    } else {
        None
    };
    if url::Url::parse(&redirect).is_ok_and(|u| u.host_str() == Some("localhost")) {
        run.check("loopback redirect uses an IP literal", false, Info, "localhost is NOT RECOMMENDED", Some("RFC 8252 §8.3"));
    }

    let response_type = s.response_type.clone().unwrap_or_else(|| "code".into());
    let rt_parts: Vec<&str> = response_type.split(' ').collect();
    let scope = s.scope.clone().or_else(|| run.client.scope.clone());
    let openid = scope.as_deref().is_some_and(|sc| sc.split(' ').any(|x| x == "openid"));
    let state = s.state.clone().unwrap_or_else(|| crate::random_b64(16));
    let nonce = s.nonce.clone().or_else(|| (openid || rt_parts.contains(&"id_token")).then(|| crate::random_b64(16)));
    let pkce = if rt_parts.contains(&"code") { s.pkce.unwrap_or(Pkce::S256) } else { Pkce::None };
    let verifier = crate::random_b64(32);
    let par = s.par.unwrap_or_else(|| run.meta("require_pushed_authorization_requests") == Some(&Value::Bool(true)));

    let mut p: Vec<(String, String)> = vec![];
    set(&mut p, "response_type", &response_type);
    set(&mut p, "client_id", &client_id);
    set(&mut p, "redirect_uri", &redirect);
    set_opt(&mut p, "scope", scope.as_ref());
    set(&mut p, "state", &state);
    set_opt(&mut p, "nonce", nonce.as_ref());
    if pkce != Pkce::None {
        set(&mut p, "code_challenge", code_challenge(pkce, &verifier));
        set(&mut p, "code_challenge_method", if pkce == Pkce::S256 { "S256" } else { "plain" });
    }
    set_opt(&mut p, "response_mode", s.response_mode.as_ref());
    if let Some(d) = &s.authorization_details {
        set(&mut p, "authorization_details", json_param(d));
    }
    push_all(&mut p, "resource", &s.resource);
    for (k, v) in [
        ("acr_values", &s.acr_values),
        ("max_age", &s.max_age),
        ("prompt", &s.prompt),
        ("login_hint", &s.login_hint),
        ("id_token_hint", &s.id_token_hint),
        ("ui_locales", &s.ui_locales),
    ] {
        set_opt(&mut p, k, v.as_ref());
    }
    if let Some(c) = &s.claims {
        set(&mut p, "claims", json_param(c));
    }
    if dpop_enabled(run) && s.dpop_jkt.unwrap_or(!par) {
        let jkt = dpop_jkt(run)?;
        set(&mut p, "dpop_jkt", jkt);
    }
    apply_overrides(&mut p, &s.params, &s.remove);
    if rt_parts.contains(&"token") {
        run.check("implicit grant avoided", false, Warning, format!("response_type {response_type}"), Some("RFC 9700 §2.1.2"));
    }

    // What the session remembers for the callback and the token request.
    let sent = |k: &str| p.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    run.session.redirect_uri = sent("redirect_uri");
    run.session.state = sent("state");
    run.session.nonce = sent("nonce");
    run.session.code_verifier = sent("code_challenge").map(|_| verifier.clone());
    run.session.max_age = sent("max_age");
    run.session.code = None;

    let mut doc = json!({ "redirect_uri": redirect });

    // JAR: the parameters move into a request object.
    let ro = s.request_object.unwrap_or(RequestObject::None);
    let mut outer = if ro != RequestObject::None || s.request_uri.is_some() {
        let mut o = vec![("client_id".to_string(), client_id.clone())];
        for k in &s.duplicate_params {
            if let Some(v) = sent(k) {
                o.push((k.clone(), v));
            }
        }
        if let Some(uri) = &s.request_uri {
            o.push(("request_uri".into(), uri.clone()));
        } else {
            let jwt = request_object(run, ro, &p, s).await?;
            doc["request_object"] =
                jose::decode(&jwt).map(|(h, c)| json!({ "header": h, "claims": c })).unwrap_or(Value::String(jwt.clone()));
            o.push(("request".into(), jwt));
        }
        o
    } else {
        p.clone()
    };

    if par {
        let par_ep = run.endpoint("pushed_authorization_request_endpoint")?;
        let mut req = Req::form(&par_ep, outer.clone());
        authenticate(run, &mut req, &par_ep)?;
        let resp = send_dpop(run, req, None).await?;
        doc["par"] = resp.doc();
        if !resp.ok() {
            return Ok(Output { doc, error: oauth_error(&resp).map(|e| format!("pushed authorization request: {e}")) });
        }
        let body = resp.json().unwrap_or(Value::Null);
        run.check("PAR responds 201 Created", resp.status == 201, Warning, format!("HTTP {}", resp.status), Some("RFC 9126 §2.2"));
        let request_uri = body["request_uri"].as_str().map(str::to_string);
        run.check("PAR request_uri present", request_uri.is_some(), Error, "", Some("RFC 9126 §2.2"));
        run.check("PAR expires_in present", body["expires_in"].is_number(), Warning, "", Some("RFC 9126 §2.2"));
        let request_uri = request_uri.ok_or_else(|| anyhow!("PAR response has no request_uri"))?;
        run.session.request_uri = Some(request_uri.clone());
        outer = vec![("client_id".into(), client_id.clone()), ("request_uri".into(), request_uri)];
    }

    let mut url = url::Url::parse(&auth_ep)?;
    url.query_pairs_mut().extend_pairs(&outer);
    let url = url.to_string();
    doc["authorization_url"] = url.clone().into();
    run.notice("Authorization request:", Some(url.clone()));

    let timeout = Duration::from_secs(s.timeout.unwrap_or(300));
    let cb = login::authorization_response(run, mode, &url, &redirect, listener, &s.login_script, timeout).await?;
    doc["callback"] = serde_json::to_value(&cb.params)?;
    doc["callback_url"] = cb.url.clone().into();
    let q = |k: &str| cb.params.get(k).cloned();

    // Checks that apply to success and error responses alike.
    if let Some(sent_state) = &run.session.state.clone() {
        run.check("state matches", q("state").as_ref() == Some(sent_state), Error, "", Some("RFC 6749 §4.1.2, RFC 9700 §2.1"));
    }
    let issuer = run.issuer().ok();
    let advertised = run.meta("authorization_response_iss_parameter_supported") == Some(&Value::Bool(true));
    // RFC 9207 §4: with an ID token in the response its `iss` claim does the job, so the parameter may be omitted.
    let has_id_token = q("id_token").is_some();
    match (q("iss"), &issuer) {
        (Some(got), Some(iss)) => run.check("iss matches the issuer", &got == iss, Error, format!("got {got}"), Some("RFC 9207 §2.4")),
        (None, _) if has_id_token => {
            run.check("iss present", true, Info, "omitted; the ID token's iss claim identifies the issuer", Some("RFC 9207 §4"))
        }
        (None, _) if advertised => run.check("iss present", false, Error, "advertised but missing", Some("RFC 9207 §2.4")),
        (None, _) => run.check(
            "iss present",
            false,
            Info,
            "server does not identify itself; use distinct redirect URIs per server",
            Some("RFC 9207"),
        ),
        _ => {}
    }

    if let Some(err) = q("error") {
        let desc = q("error_description").map(|d| format!(": {d}")).unwrap_or_default();
        return Ok(Output { doc, error: Some(format!("authorization error: {err}{desc}")) });
    }

    if rt_parts.contains(&"code") {
        let code = q("code");
        run.check("code present", code.is_some(), Error, "", Some("RFC 6749 §4.1.2"));
        run.session.code = code;
    }
    // Front-channel tokens (implicit and hybrid flows).
    if let Some(at) = q("access_token") {
        run.session.access_token = Some(at);
        run.session.token_type = q("token_type");
    }
    if let Some(idt) = q("id_token") {
        let at = run.session.access_token.clone().filter(|_| q("access_token").is_some());
        let code = run.session.code.clone();
        let claims = super::validate_id_token(run, &idt, at.as_deref(), code.as_deref(), true).await?;
        if let Some(iss) = q("iss") {
            run.check("iss parameter matches the ID token iss", claims["iss"].as_str() == Some(&iss), Error, "", Some("RFC 9207 §2.4"));
        }
        doc["claims"] = json!({ "id_token": claims });
        run.session.id_token_claims = Some(claims);
        run.session.id_token = Some(idt);
    }
    Ok(Output::ok(doc))
}

/// Builds the request object (RFC 9101 §4): every authorization parameter as a
/// claim, plus iss/aud/iat/nbf/exp/jti.
async fn request_object(run: &mut Run<'_>, ro: RequestObject, params: &[(String, String)], s: &AuthorizeStep) -> Result<String> {
    let mut claims = Map::new();
    for (k, v) in params {
        let value = match k.as_str() {
            "claims" | "authorization_details" => serde_json::from_str(v).unwrap_or(Value::String(v.clone())),
            "max_age" => v.parse::<i64>().map(Value::from).unwrap_or(Value::String(v.clone())),
            _ => Value::String(v.clone()),
        };
        match claims.get_mut(k) {
            // Repeated parameters (resource) become arrays.
            Some(Value::Array(a)) => a.push(value),
            Some(prev) => *prev = Value::Array(vec![prev.clone(), value]),
            None => {
                claims.insert(k.clone(), value);
            }
        }
    }
    let now = crate::now();
    claims.insert("iss".into(), run.client_id()?.into());
    claims.insert("aud".into(), run.issuer()?.into());
    claims.insert("iat".into(), now.into());
    claims.insert("nbf".into(), now.into());
    claims.insert("exp".into(), (now + 300).into());
    claims.insert("jti".into(), crate::random_b64(16).into());
    let claims = Value::Object(claims);
    let header = json!({ "typ": "oauth-authz-req+jwt" });
    if ro == RequestObject::Unsigned {
        return jose::unsigned(&claims, header);
    }
    let signed = jose::sign(&claims, header, &signing_key(run)?, run.client.signing_alg.as_deref())?;
    if ro != RequestObject::Encrypted {
        return Ok(signed);
    }
    super::ensure_jwks(run).await?;
    let algs: Vec<String> = run
        .meta("request_object_encryption_alg_values_supported")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let alg = s
        .request_object_encryption_alg
        .clone()
        .or_else(|| jose::SUPPORTED_JWE_ALGS.iter().find(|a| algs.iter().any(|x| x == *a)).map(|a| a.to_string()))
        .unwrap_or_else(|| "RSA-OAEP-256".into());
    let enc = s.request_object_encryption_enc.clone().unwrap_or_else(|| {
        run.meta("request_object_encryption_enc_values_supported").and_then(|v| v[0].as_str()).unwrap_or("A256GCM").to_string()
    });
    let kty = if alg.starts_with("RSA") { "RSA" } else { "EC" };
    let key = run
        .session
        .jwks
        .as_ref()
        .and_then(|j| j["keys"].as_array())
        .and_then(|keys| {
            keys.iter()
                .find(|k| k["kty"] == kty && k["use"].as_str().is_none_or(|u| u == "enc") && k["alg"].as_str().is_none_or(|a| a == alg))
        })
        .cloned()
        .ok_or_else(|| anyhow!("the server's JWKS has no {kty} encryption key for {alg}"))?;
    jose::encrypt(signed.as_bytes(), &key, &alg, &enc, Some("JWT"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7636_appendix_b() {
        assert_eq!(
            code_challenge(Pkce::S256, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }
}
