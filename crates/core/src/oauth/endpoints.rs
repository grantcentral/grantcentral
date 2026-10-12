//! Registration (RFC 7591, RFC 7592), introspection (RFC 7662, RFC 9701),
//! revocation (RFC 7009), UserInfo, protected resource requests (RFC 6750,
//! RFC 9449, RFC 9470, RFC 9728) and standalone JWT validation.

use super::{
    apply_overrides, authenticate, dpop_enabled, ensure_jwks, oauth_error, set, set_opt, token_is_dpop, validate_access_token,
    validate_id_token, verify_server_jwt,
};
use crate::engine::{Output, Run};
use crate::http::{Body, Req};
use crate::model::{
    AuthMethod, IntrospectStep, JwtProfile, ManageAction, ManageClientStep, RegisterStep, RequestStep, ResourceAuth, RevokeStep,
    UserinfoStep, ValidateJwtStep,
};
use crate::report::Severity::{Error, Info, Warning};
use anyhow::{Result, anyhow, bail};
use serde_json::{Map, Value, json};

pub async fn register(run: &mut Run<'_>, s: &RegisterStep) -> Result<Output> {
    let spec = Some("RFC 7591 §3.2.1");
    let ep = run.endpoint("registration_endpoint")?;
    let mut meta = match &s.metadata {
        Value::Object(m) => m.clone(),
        Value::Null => Map::new(),
        _ => bail!("register.metadata must be a table"),
    };
    if !meta.contains_key("redirect_uris")
        && let Some(r) = &run.client.redirect_uri
    {
        meta.insert("redirect_uris".into(), json!([r]));
    }
    if let Some(ss) = &s.software_statement {
        meta.insert("software_statement".into(), ss.clone().into());
    }
    let mut req = Req { method: "POST".into(), url: ep, headers: vec![], body: Body::Json(Value::Object(meta)) };
    if let Some(iat) = &s.initial_access_token {
        req.set_header("Authorization", format!("Bearer {iat}"));
    }
    let resp = run.http.send(&req).await?;
    let doc = resp.doc();
    if !resp.ok() {
        return Ok(Output { doc, error: oauth_error(&resp) });
    }
    let b = resp.json().unwrap_or(Value::Null);
    run.check("responds 201 Created", resp.status == 201, Warning, format!("HTTP {}", resp.status), spec);
    run.check("client_id present", b["client_id"].is_string(), Error, "", spec);
    if b["client_secret"].is_string() {
        run.check(
            "client_secret_expires_at present",
            b["client_secret_expires_at"].is_number(),
            Error,
            "required with a client_secret",
            spec,
        );
    }
    let managed = b["registration_access_token"].is_string() && b["registration_client_uri"].is_string();
    run.check("client management supported", managed, Info, "registration_access_token and registration_client_uri", Some("RFC 7592 §3"));
    if s.use_client != Some(false) {
        run.session.client_id = b["client_id"].as_str().map(str::to_string);
        run.session.client_secret = b["client_secret"].as_str().map(str::to_string);
        if let Some(m) = b["token_endpoint_auth_method"].as_str().and_then(|m| serde_json::from_value::<AuthMethod>(json!(m)).ok()) {
            run.client.auth_method = Some(m);
        }
        run.session.registration_access_token = b["registration_access_token"].as_str().map(str::to_string);
        run.session.registration_client_uri = b["registration_client_uri"].as_str().map(str::to_string);
    }
    Ok(Output::ok(doc))
}

pub async fn manage_client(run: &mut Run<'_>, s: &ManageClientStep) -> Result<Output> {
    let uri = run.session.registration_client_uri.clone().ok_or_else(|| anyhow!("no registration_client_uri: register a client first"))?;
    let rat = run.session.registration_access_token.clone().ok_or_else(|| anyhow!("no registration_access_token"))?;
    let mut req = match s.action {
        ManageAction::Read => Req::get(&uri),
        ManageAction::Delete => Req { method: "DELETE".into(), url: uri.clone(), headers: vec![], body: Body::None },
        ManageAction::Update => {
            let mut meta = s.metadata.as_object().cloned().unwrap_or_default();
            // RFC 7592 §2.2: the request carries the client_id (and the secret, if any).
            meta.insert("client_id".into(), run.client_id()?.into());
            if let Some(sec) = run.session.client_secret.clone() {
                meta.entry("client_secret").or_insert(sec.into());
            }
            Req { method: "PUT".into(), url: uri.clone(), headers: vec![], body: Body::Json(Value::Object(meta)) }
        }
    };
    req.set_header("Authorization", format!("Bearer {rat}"));
    let resp = run.http.send(&req).await?;
    let doc = resp.doc();
    if !resp.ok() {
        return Ok(Output { doc, error: oauth_error(&resp) });
    }
    let b = resp.json().unwrap_or(Value::Null);
    match s.action {
        ManageAction::Read | ManageAction::Update => {
            run.check("client_id matches", b["client_id"].as_str() == run.client_id().ok().as_deref(), Error, "", Some("RFC 7592 §3"));
            if let Some(sec) = b["client_secret"].as_str() {
                run.session.client_secret = Some(sec.into());
            }
            if let Some(t) = b["registration_access_token"].as_str() {
                run.session.registration_access_token = Some(t.into());
            }
        }
        ManageAction::Delete => {
            run.check("responds 204 No Content", resp.status == 204, Warning, format!("HTTP {}", resp.status), Some("RFC 7592 §2.3"));
        }
    }
    Ok(Output::ok(doc))
}

pub async fn introspect(run: &mut Run<'_>, s: &IntrospectStep) -> Result<Output> {
    let ep = run.endpoint("introspection_endpoint")?;
    let token = s.token.clone().or_else(|| run.session.access_token.clone()).ok_or_else(|| anyhow!("no token to introspect"))?;
    let mut f = vec![];
    set(&mut f, "token", token);
    set_opt(&mut f, "token_type_hint", s.token_type_hint.as_ref());
    apply_overrides(&mut f, &s.params, &[]);
    let mut req = Req::form(&ep, f);
    if s.jwt_response {
        req.set_header("Accept", "application/token-introspection+jwt");
    }
    authenticate(run, &mut req, &ep)?;
    let resp = run.http.send(&req).await?;
    let mut doc = resp.doc();
    if !resp.ok() {
        return Ok(Output { doc, error: oauth_error(&resp) });
    }
    let body = if s.jwt_response {
        let spec = Some("RFC 9701 §5");
        let ct = resp.header("content-type").unwrap_or("");
        run.check(
            "content type is application/token-introspection+jwt",
            ct.starts_with("application/token-introspection+jwt"),
            Error,
            ct,
            spec,
        );
        let (h, c) = verify_server_jwt(run, resp.body.trim(), "introspection response").await?;
        run.check(
            "typ is token-introspection+jwt",
            h["typ"].as_str().is_some_and(|t| t.ends_with("token-introspection+jwt")),
            Error,
            "",
            spec,
        );
        run.check("iss matches the issuer", c["iss"].as_str() == run.issuer().ok().as_deref(), Error, "", spec);
        let id = run.client_id().unwrap_or_default();
        let aud_ok = c["aud"].as_str() == Some(&id) || c["aud"].as_array().is_some_and(|a| a.iter().any(|x| x.as_str() == Some(&id)));
        run.check("aud is the client_id", aud_ok, Error, "", spec);
        doc["jwt"] = json!({ "header": h, "claims": c.clone() });
        let inner = c["token_introspection"].clone();
        doc["body"] = inner.clone();
        inner
    } else {
        resp.json().unwrap_or(Value::Null)
    };
    run.check("active is a boolean", body["active"].is_boolean(), Error, "", Some("RFC 7662 §2.2"));
    if let (Some(tp), Some(x5t)) = (run.session.cert_thumbprint.clone(), body["cnf"]["x5t#S256"].as_str()) {
        run.check("cnf.x5t#S256 matches the client certificate", x5t == tp, Error, "", Some("RFC 8705 §3.2"));
    }
    if dpop_enabled(run)
        && body["active"] == Value::Bool(true)
        && let Some(jkt) = body["cnf"]["jkt"].as_str()
    {
        run.check("cnf.jkt matches the DPoP key", Some(jkt) == run.session.dpop_jkt.as_deref(), Error, "", Some("RFC 9449 §6.2"));
    }
    Ok(Output::ok(doc))
}

pub async fn revoke(run: &mut Run<'_>, s: &RevokeStep) -> Result<Output> {
    let ep = run.endpoint("revocation_endpoint")?;
    let token = s
        .token
        .clone()
        .or_else(|| run.session.refresh_token.clone())
        .or_else(|| run.session.access_token.clone())
        .ok_or_else(|| anyhow!("no token to revoke"))?;
    let hint = s.token_type_hint.clone().or_else(|| {
        if Some(&token) == run.session.refresh_token.as_ref() {
            Some("refresh_token".into())
        } else if Some(&token) == run.session.access_token.as_ref() {
            Some("access_token".into())
        } else {
            None
        }
    });
    let mut f = vec![];
    set(&mut f, "token", token);
    set_opt(&mut f, "token_type_hint", hint.as_ref());
    apply_overrides(&mut f, &s.params, &[]);
    let mut req = Req::form(&ep, f);
    authenticate(run, &mut req, &ep)?;
    let resp = run.http.send(&req).await?;
    if resp.ok() {
        run.check("responds 200 OK", resp.status == 200, Warning, format!("HTTP {}", resp.status), Some("RFC 7009 §2.2"));
    }
    Ok(Output { doc: resp.doc(), error: oauth_error(&resp) })
}

/// Builds the Authorization header (or body/query parameter) for a resource request.
async fn send_with_token(run: &mut Run<'_>, mut req: Req, auth: ResourceAuth, token: Option<String>) -> Result<crate::http::Resp> {
    let auth = match auth {
        ResourceAuth::Auto if token_is_dpop(run) => ResourceAuth::Dpop,
        ResourceAuth::Auto => ResourceAuth::Bearer,
        a => a,
    };
    if auth == ResourceAuth::None {
        return run.http.send(&req).await;
    }
    let token = token.ok_or_else(|| anyhow!("no access token: run a token step first"))?;
    match auth {
        ResourceAuth::Bearer => req.set_header("Authorization", format!("Bearer {token}")),
        ResourceAuth::BearerBody => match &mut req.body {
            Body::Form(f) => set(f, "access_token", &token),
            _ => {
                req.body = Body::Form(vec![("access_token".into(), token.clone())]);
                if req.method == "GET" {
                    req.method = "POST".into();
                }
            }
        },
        ResourceAuth::BearerQuery => {
            let mut u = url::Url::parse(&req.url)?;
            u.query_pairs_mut().append_pair("access_token", &token);
            req.url = u.to_string();
            run.check("bearer token in query avoided", false, Warning, "", Some("RFC 6750 §2.3, RFC 9700 §4.3.2"));
        }
        ResourceAuth::Dpop => {
            req.set_header("Authorization", format!("DPoP {token}"));
            let proof = super::dpop_proof(run, &req.method.clone(), &req.url.clone(), Some(&token))?;
            req.set_header("DPoP", proof);
            // Retry once if the resource server asks for a nonce.
            let resp = run.http.send(&req).await?;
            if resp.status == 401
                && resp.header("www-authenticate").is_some_and(|h| h.contains("use_dpop_nonce"))
                && let Some(n) = resp.header("dpop-nonce")
            {
                let origin = url::Url::parse(&req.url)?.origin().ascii_serialization();
                run.session.dpop_nonces.insert(origin, n.to_string());
                run.log("Resource server asked for a DPoP nonce; retrying (RFC 9449 §9)");
                let proof = super::dpop_proof(run, &req.method.clone(), &req.url.clone(), Some(&token))?;
                req.set_header("DPoP", proof);
                return run.http.send(&req).await;
            }
            return Ok(resp);
        }
        ResourceAuth::Auto | ResourceAuth::None => unreachable!(),
    }
    run.http.send(&req).await
}

pub async fn userinfo(run: &mut Run<'_>, s: &UserinfoStep) -> Result<Output> {
    let ep = run.endpoint("userinfo_endpoint")?;
    let method = s.method.clone().unwrap_or_else(|| "GET".into()).to_ascii_uppercase();
    let req = Req { method, url: ep, headers: vec![], body: Body::None };
    let token = s.access_token.clone().or_else(|| run.session.access_token.clone());
    let resp = send_with_token(run, req, ResourceAuth::Auto, token).await?;
    let mut doc = resp.doc();
    doc["challenges"] = parse_www_authenticate(resp.header("www-authenticate").unwrap_or("")).into();
    if !resp.ok() {
        return Ok(Output { doc, error: oauth_error(&resp) });
    }
    let claims = if resp.header("content-type").is_some_and(|c| c.starts_with("application/jwt")) {
        let (_, c) = verify_server_jwt(run, resp.body.trim(), "UserInfo response").await?;
        run.check("UserInfo iss matches", c["iss"].as_str() == run.issuer().ok().as_deref(), Error, "", Some("OpenID Connect Core §5.3.2"));
        doc["body"] = c.clone();
        c
    } else {
        resp.json().unwrap_or(Value::Null)
    };
    if let Some(sub) = run.session.id_token_claims.as_ref().and_then(|c| c["sub"].as_str()) {
        run.check("sub matches the ID token", claims["sub"].as_str() == Some(sub), Error, "", Some("OpenID Connect Core §5.3.2"));
    }
    Ok(Output::ok(doc))
}

pub async fn request(run: &mut Run<'_>, s: &RequestStep) -> Result<Output> {
    let body = match (&s.json, &s.form, &s.body) {
        (Some(j), _, _) => Body::Json(j.clone()),
        (_, Some(f), _) => Body::Form(f.iter().map(|(k, v)| (k.clone(), v.clone())).collect()),
        (_, _, Some(b)) => Body::Raw { content_type: None, data: b.clone() },
        _ => Body::None,
    };
    let default_method = if matches!(body, Body::None) { "GET" } else { "POST" };
    let mut req = Req {
        method: s.method.clone().unwrap_or_else(|| default_method.into()).to_ascii_uppercase(),
        url: s.url.clone(),
        headers: vec![],
        body,
    };
    for (k, v) in &s.headers {
        req.set_header(k, v.clone());
    }
    let token = s.access_token.clone().or_else(|| run.session.access_token.clone());
    let resp = send_with_token(run, req, s.auth.unwrap_or(ResourceAuth::Auto), token).await?;
    let mut doc = resp.doc();
    let challenges = parse_www_authenticate(resp.header("www-authenticate").unwrap_or(""));
    let first = challenges.first().cloned().unwrap_or(Value::Null);
    if first["params"]["error"] == "insufficient_user_authentication" {
        // RFC 9470 §3: the client should re-authorize with these values.
        let acr = first["params"]["acr_values"].clone();
        let max_age = first["params"]["max_age"].clone();
        doc["step_up"] = json!({ "acr_values": acr, "max_age": max_age });
        run.notice(format!("Step-up authentication required (RFC 9470): acr_values={acr} max_age={max_age}"), None);
    }
    if let Some(rm) = first["params"]["resource_metadata"].as_str() {
        doc["resource_metadata_url"] = rm.into();
    }
    doc["challenge"] = first;
    doc["challenges"] = challenges.into();
    let error = (!resp.ok()).then(|| {
        let c = &doc["challenge"]["params"];
        match c["error"].as_str() {
            Some(e) => {
                format!("HTTP {}: {e}{}", resp.status, c["error_description"].as_str().map(|d| format!(": {d}")).unwrap_or_default())
            }
            None => oauth_error(&resp).unwrap_or_default(),
        }
    });
    Ok(Output { doc, error })
}

pub async fn validate_jwt(run: &mut Run<'_>, s: &ValidateJwtStep) -> Result<Output> {
    ensure_jwks(run).await?;
    let claims = match s.profile.unwrap_or(JwtProfile::Generic) {
        JwtProfile::IdToken => validate_id_token(run, &s.token, None, None, false).await?,
        JwtProfile::AccessToken => validate_access_token(run, &s.token).await?,
        JwtProfile::Generic => {
            let (_, c) = verify_server_jwt(run, &s.token, "JWT").await?;
            let now = crate::now() as i64;
            if let Some(exp) = c["exp"].as_i64() {
                run.check("not expired", exp + 60 > now, Error, "", Some("RFC 7519 §4.1.4"));
            }
            if let Some(nbf) = c["nbf"].as_i64() {
                run.check("not before nbf", nbf - 60 <= now, Error, "", Some("RFC 7519 §4.1.5"));
            }
            c
        }
    };
    if let Some(aud) = &s.audience {
        let ok = claims["aud"].as_str() == Some(aud) || claims["aud"].as_array().is_some_and(|a| a.iter().any(|x| x.as_str() == Some(aud)));
        run.check("aud matches", ok, Error, format!("aud {}", claims["aud"]), Some("RFC 7519 §4.1.3"));
    }
    let header = crate::jose::decode(&super::decrypt_if_needed(run, &s.token)?).map(|(h, _)| h).unwrap_or(Value::Null);
    Ok(Output::ok(json!({ "header": header, "claims": claims })))
}

/// Parses a WWW-Authenticate header (RFC 9110 §11.6.1) into
/// `[{scheme, params}]`; several challenges may share one header.
pub fn parse_www_authenticate(h: &str) -> Vec<Value> {
    let mut out: Vec<Value> = vec![];
    let b = h.as_bytes();
    let mut i = 0;
    let token = |i: &mut usize| {
        let s = *i;
        while *i < b.len() && !matches!(b[*i], b' ' | b'\t' | b',' | b'=') {
            *i += 1;
        }
        h[s..*i].to_string()
    };
    let skip_ws = |i: &mut usize| {
        while *i < b.len() && matches!(b[*i], b' ' | b'\t') {
            *i += 1;
        }
    };
    while i < b.len() {
        while i < b.len() && matches!(b[i], b' ' | b'\t' | b',') {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        let t = token(&mut i);
        let mut j = i;
        skip_ws(&mut j);
        if j < b.len() && b[j] == b'=' && !out.is_empty() {
            i = j + 1;
            skip_ws(&mut i);
            let value = if i < b.len() && b[i] == b'"' {
                i += 1;
                let mut v = String::new();
                while i < b.len() && b[i] != b'"' {
                    if b[i] == b'\\' && i + 1 < b.len() {
                        i += 1;
                    }
                    let ch = h[i..].chars().next().unwrap();
                    v.push(ch);
                    i += ch.len_utf8();
                }
                i += 1;
                v
            } else {
                token(&mut i)
            };
            out.last_mut().unwrap()["params"][t.to_ascii_lowercase()] = value.into();
        } else if !t.is_empty() {
            out.push(json!({ "scheme": t, "params": {} }));
        } else {
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn www_authenticate() {
        let c = parse_www_authenticate(
            r#"Bearer realm="api", error="insufficient_user_authentication", error_description="A different \"auth\" level", acr_values="myACR", max_age=5, DPoP algs="ES256 PS256", error="use_dpop_nonce""#,
        );
        assert_eq!(c.len(), 2);
        assert_eq!(c[0]["scheme"], "Bearer");
        assert_eq!(c[0]["params"]["error"], "insufficient_user_authentication");
        assert_eq!(c[0]["params"]["error_description"], "A different \"auth\" level");
        assert_eq!(c[0]["params"]["max_age"], "5");
        assert_eq!(c[1]["scheme"], "DPoP");
        assert_eq!(c[1]["params"]["algs"], "ES256 PS256");
        assert_eq!(parse_www_authenticate("Bearer")[0]["scheme"], "Bearer");
        assert!(parse_www_authenticate("").is_empty());
    }
}
