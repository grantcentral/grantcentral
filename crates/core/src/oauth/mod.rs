//! OAuth 2.0 / OpenID Connect client protocol. Each step type lives in a
//! submodule; this file holds what they share: client authentication, DPoP,
//! token response handling and JWT validation.

mod audit;
mod authorize;
mod discovery;
mod endpoints;
mod token;

pub use audit::audit_metadata;
pub use discovery::well_known_url;
pub use endpoints::parse_www_authenticate;

use crate::engine::{Output, Run};
use crate::http::{Body, Req, Resp};
use crate::jose;
use crate::model::{AuthMethod, Params, StepKind};
use crate::report::Severity::{Error, Info, Warning};
use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};

pub const URN_JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
pub const URN_SAML2_BEARER: &str = "urn:ietf:params:oauth:grant-type:saml2-bearer";
pub const URN_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
pub const URN_DEVICE_CODE: &str = "urn:ietf:params:oauth:grant-type:device_code";
pub const URN_CLIENT_ASSERTION_JWT: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
pub const URN_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";

pub async fn execute(run: &mut Run<'_>, kind: &StepKind) -> Result<Output> {
    match kind {
        StepKind::Discover(s) => discovery::discover(run, s).await,
        StepKind::DiscoverResource(s) => discovery::discover_resource(run, s).await,
        StepKind::Audit(s) => audit::audit(run, s),
        StepKind::Register(s) => endpoints::register(run, s).await,
        StepKind::ManageClient(s) => endpoints::manage_client(run, s).await,
        StepKind::Authorize(s) => authorize::authorize(run, s).await,
        StepKind::Token(s) => token::token(run, s).await,
        StepKind::Device(s) => token::device(run, s).await,
        StepKind::Introspect(s) => endpoints::introspect(run, s).await,
        StepKind::Revoke(s) => endpoints::revoke(run, s).await,
        StepKind::Userinfo(s) => endpoints::userinfo(run, s).await,
        StepKind::Request(s) => endpoints::request(run, s).await,
        StepKind::ValidateJwt(s) => endpoints::validate_jwt(run, s).await,
        StepKind::Wait(s) => {
            tokio::time::sleep(std::time::Duration::from_secs_f64(s.seconds.max(0.0))).await;
            Ok(Output::ok(json!({})))
        }
    }
}

// ---------------------------------------------------------------- form helpers

pub(crate) fn set(form: &mut Vec<(String, String)>, k: &str, v: impl Into<String>) {
    form.retain(|(n, _)| n != k);
    form.push((k.to_string(), v.into()));
}

pub(crate) fn set_opt(form: &mut Vec<(String, String)>, k: &str, v: Option<&String>) {
    if let Some(v) = v {
        set(form, k, v.clone());
    }
}

pub(crate) fn push_all(form: &mut Vec<(String, String)>, k: &str, vs: &[String]) {
    form.extend(vs.iter().map(|v| (k.to_string(), v.clone())));
}

/// Applies `params` (add or replace) and `remove` from a step.
pub(crate) fn apply_overrides(form: &mut Vec<(String, String)>, params: &Params, remove: &[String]) {
    for (k, v) in params {
        set(form, k, v.clone());
    }
    form.retain(|(k, _)| !remove.contains(k));
}

/// JSON values (RAR details, claims) travel as JSON text; strings pass through verbatim.
pub(crate) fn json_param(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// "HTTP 400: invalid_grant: code expired" for an unsuccessful OAuth response.
pub fn oauth_error(resp: &Resp) -> Option<String> {
    if resp.ok() {
        return None;
    }
    let j = resp.json().unwrap_or(Value::Null);
    let mut msg = format!("HTTP {}", resp.status);
    if let Some(e) = j["error"].as_str() {
        msg.push_str(": ");
        msg.push_str(e);
    }
    if let Some(d) = j["error_description"].as_str() {
        msg.push_str(": ");
        msg.push_str(d);
    }
    if j["error"].is_null()
        && let Some(c) = resp.header("www-authenticate")
    {
        msg.push_str(&format!(" ({c})"));
    }
    Some(msg)
}

// ------------------------------------------------------- client authentication

pub(crate) fn auth_method(run: &Run) -> AuthMethod {
    if let Some(m) = run.client.auth_method {
        return m;
    }
    if run.client_secret().is_some() {
        AuthMethod::ClientSecretBasic
    } else if run.client.signing_key.is_some() {
        AuthMethod::PrivateKeyJwt
    } else if run.uses_mtls() {
        AuthMethod::TlsClientAuth
    } else {
        AuthMethod::None
    }
}

/// Adds client authentication to a form request (RFC 6749 §2.3, RFC 7523 §2.2, RFC 8705 §2).
pub(crate) fn authenticate(run: &mut Run, req: &mut Req, endpoint: &str) -> Result<()> {
    let id = run.client_id()?;
    let method = auth_method(run);
    let Body::Form(form) = &mut req.body else { bail!("client authentication needs a form body") };
    match method {
        AuthMethod::None | AuthMethod::TlsClientAuth | AuthMethod::SelfSignedTlsClientAuth => set(form, "client_id", id),
        AuthMethod::ClientSecretBasic => {
            let secret = run.client_secret().ok_or_else(|| anyhow!("client_secret_basic needs client_secret"))?;
            req.set_header("Authorization", basic_auth(&id, &secret));
        }
        AuthMethod::ClientSecretPost => {
            let secret = run.client_secret().ok_or_else(|| anyhow!("client_secret_post needs client_secret"))?;
            set(form, "client_id", id);
            set(form, "client_secret", secret);
        }
        AuthMethod::ClientSecretJwt | AuthMethod::PrivateKeyJwt => {
            let assertion = client_assertion(run, method, endpoint)?;
            set(form, "client_id", id);
            set(form, "client_assertion_type", URN_CLIENT_ASSERTION_JWT);
            set(form, "client_assertion", assertion);
        }
    }
    Ok(())
}

/// RFC 6749 §2.3.1: id and secret are form-urlencoded before base64, which many clients get wrong.
pub fn basic_auth(id: &str, secret: &str) -> String {
    use base64::Engine as _;
    let enc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
    format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", enc(id), enc(secret))))
}

fn client_assertion(run: &Run, method: AuthMethod, endpoint: &str) -> Result<String> {
    let id = run.client_id()?;
    let aud = match run.client.assertion_audience.as_deref() {
        None | Some("issuer") => run.issuer().unwrap_or_else(|_| endpoint.to_string()),
        Some("endpoint") => endpoint.to_string(),
        Some(other) => other.to_string(),
    };
    let now = crate::now();
    let claims = json!({ "iss": id, "sub": id, "aud": aud, "jti": crate::random_b64(16), "iat": now, "exp": now + 60 });
    if method == AuthMethod::ClientSecretJwt {
        let secret = run.client_secret().ok_or_else(|| anyhow!("client_secret_jwt needs client_secret"))?;
        let alg = run.client.signing_alg.as_deref().filter(|a| a.starts_with("HS")).unwrap_or("HS256");
        jose::sign(&claims, json!({}), &jose::oct_key(&secret), Some(alg))
    } else {
        let key = signing_key(run)?;
        jose::sign(&claims, json!({}), &key, run.client.signing_alg.as_deref())
    }
}

pub(crate) fn signing_key(run: &Run) -> Result<josekit::jwk::Jwk> {
    let path = run.client.signing_key.as_ref().ok_or_else(|| anyhow!("client.signing_key is not set"))?;
    jose::load_key(&run.path(path))
}

// ------------------------------------------------------------------- DPoP

pub(crate) fn dpop_enabled(run: &Run) -> bool {
    run.client.dpop == Some(true)
}

fn ensure_dpop_key(run: &mut Run) -> Result<()> {
    if run.session.dpop_key.is_some() {
        return Ok(());
    }
    let key = match &run.client.dpop_key {
        Some(p) => jose::load_key(&run.path(p))?,
        None => jose::generate(run.client.dpop_alg.as_deref().unwrap_or("ES256"))?,
    };
    run.session.dpop_jkt = Some(jose::thumbprint(&jose::public(&key)?)?);
    run.session.dpop_key = Some(key);
    Ok(())
}

pub(crate) fn dpop_jkt(run: &mut Run) -> Result<String> {
    ensure_dpop_key(run)?;
    Ok(run.session.dpop_jkt.clone().unwrap())
}

fn origin(u: &str) -> String {
    url::Url::parse(u).map(|u| u.origin().ascii_serialization()).unwrap_or_default()
}

/// A DPoP proof JWT (RFC 9449 §4.2).
pub(crate) fn dpop_proof(run: &mut Run, method: &str, url: &str, access_token: Option<&str>) -> Result<String> {
    ensure_dpop_key(run)?;
    let key = run.session.dpop_key.as_ref().unwrap();
    let mut htu = url::Url::parse(url).context("DPoP target URL")?;
    htu.set_query(None);
    htu.set_fragment(None);
    let mut claims = json!({ "jti": crate::random_b64(16), "htm": method, "htu": htu.as_str(), "iat": crate::now() });
    if let Some(at) = access_token {
        claims["ath"] = crate::b64(&crate::sha256(at.as_bytes())).into();
    }
    if let Some(n) = run.session.dpop_nonces.get(&origin(url)) {
        claims["nonce"] = n.clone().into();
    }
    let header = json!({ "typ": "dpop+jwt", "jwk": jose::public(key)? });
    // The key travels in the header, so no `kid`.
    let mut k = key.clone();
    k.set_parameter("kid", None)?;
    jose::sign(&claims, header, &k, run.client.dpop_alg.as_deref())
}

/// Sends a request, with a DPoP proof when DPoP is enabled, retrying once when
/// the server asks for a nonce (RFC 9449 §8, §9).
pub(crate) async fn send_dpop(run: &mut Run<'_>, mut req: Req, access_token: Option<&str>) -> Result<Resp> {
    if !dpop_enabled(run) {
        return run.http.send(&req).await;
    }
    for attempt in 0..2 {
        let proof = dpop_proof(run, &req.method.clone(), &req.url.clone(), access_token)?;
        req.set_header("DPoP", proof);
        let resp = run.http.send(&req).await?;
        let new_nonce = resp.header("dpop-nonce").map(str::to_string);
        if let Some(n) = &new_nonce {
            run.session.dpop_nonces.insert(origin(&req.url), n.clone());
        }
        let wants_nonce = (resp.status == 400 && resp.json().is_some_and(|j| j["error"] == "use_dpop_nonce"))
            || (resp.status == 401 && resp.header("www-authenticate").is_some_and(|h| h.contains("use_dpop_nonce")));
        if attempt == 0 && wants_nonce && new_nonce.is_some() {
            run.log("Server asked for a DPoP nonce; retrying with it (RFC 9449 §8)");
            // A client assertion is single-use (its jti), so the retry needs a fresh one.
            if matches!(&req.body, Body::Form(f) if f.iter().any(|(k, _)| k == "client_assertion")) {
                let url = req.url.clone();
                authenticate(run, &mut req, &url)?;
            }
            continue;
        }
        return Ok(resp);
    }
    unreachable!()
}

/// Authorization header for a protected resource request, honoring DPoP-bound tokens.
pub(crate) fn token_is_dpop(run: &Run) -> bool {
    run.session.token_type.as_deref().is_some_and(|t| t.eq_ignore_ascii_case("dpop"))
}

// ------------------------------------------------------------ token responses

/// Fetches the JWKS from metadata when no discover step did.
pub(crate) async fn ensure_jwks(run: &mut Run<'_>) -> Result<()> {
    if run.session.jwks.is_some() {
        return Ok(());
    }
    let Ok(uri) = run.endpoint("jwks_uri") else { return Ok(()) };
    let resp = run.http.send(&Req::get(uri)).await?;
    if resp.ok() {
        run.session.jwks = resp.json();
    }
    Ok(())
}

/// Validates a token endpoint response (RFC 6749 §5), stores the tokens and
/// returns the result document.
pub(crate) async fn handle_token_response(run: &mut Run<'_>, resp: Resp, grant: &str, validate_at: Option<bool>) -> Result<Output> {
    let mut doc = resp.doc();
    if !resp.ok() {
        return Ok(Output { doc, error: oauth_error(&resp) });
    }
    let Some(body) = resp.json() else {
        return Ok(Output { doc, error: Some("token response is not JSON (RFC 6749 §5.1)".into()) });
    };
    let at = body["access_token"].as_str().map(str::to_string);
    run.check("access_token present", at.is_some(), Error, "", Some("RFC 6749 §5.1"));
    let tt = body["token_type"].as_str().unwrap_or("");
    run.check("token_type present", !tt.is_empty(), Error, "", Some("RFC 6749 §5.1"));
    let no_store = resp.header("cache-control").is_some_and(|c| c.to_ascii_lowercase().contains("no-store"));
    run.check("Cache-Control: no-store", no_store, Warning, resp.header("cache-control").unwrap_or("absent"), Some("RFC 6749 §5.1"));
    if dpop_enabled(run) {
        run.check("token_type is DPoP", tt.eq_ignore_ascii_case("dpop"), Error, format!("got {tt:?}"), Some("RFC 9449 §5"));
    } else if !tt.is_empty() && grant != URN_TOKEN_EXCHANGE {
        run.check("token_type is Bearer", tt.eq_ignore_ascii_case("bearer"), Warning, format!("got {tt:?}"), Some("RFC 6750 §4"));
    }
    run.check("expires_in present", body["expires_in"].is_number(), Info, "", Some("RFC 6749 §5.1 (RECOMMENDED)"));
    if grant == URN_TOKEN_EXCHANGE {
        run.check("issued_token_type present", body["issued_token_type"].is_string(), Error, "", Some("RFC 8693 §2.2.1"));
    }

    let new_rt = body["refresh_token"].as_str().map(str::to_string);
    if grant == "refresh_token" {
        let old = run.session.refresh_token.clone();
        let rotated = new_rt.is_some() && new_rt != old;
        let public = auth_method(run) == AuthMethod::None;
        let constrained = dpop_enabled(run) || run.uses_mtls();
        let severity = if public && !constrained { Warning } else { Info };
        run.check(
            "refresh token rotated",
            rotated || (constrained && !public),
            severity,
            if rotated { "new refresh token issued" } else { "same or no refresh token returned" },
            Some("RFC 9700 §4.14, RFC 10017"),
        );
        if rotated {
            run.session.previous_refresh_token = old;
        }
    }

    let mut claims = json!({});
    if let Some(at) = &at {
        if let Ok((h, p)) = jose::decode(at) {
            claims["access_token"] = p.clone();
            claims["access_token_header"] = h;
            check_binding(run, &p);
            if validate_at == Some(true) {
                validate_access_token(run, at).await?;
            }
        } else if validate_at == Some(true) {
            run.check("access token is a JWT", false, Error, "opaque token", Some("RFC 9068 §2"));
        }
    }
    if let Some(idt) = body["id_token"].as_str() {
        let idc = validate_id_token(run, idt, at.as_deref(), None, false).await?;
        run.session.id_token_claims = Some(idc.clone());
        claims["id_token"] = idc;
        run.session.id_token = Some(idt.to_string());
    }
    doc["claims"] = claims;

    run.session.access_token = at;
    run.session.token_type = Some(tt.to_string());
    if new_rt.is_some() {
        run.session.refresh_token = new_rt;
    }
    if let Some(s) = body["scope"].as_str() {
        run.session.scope = Some(s.to_string());
    }
    run.session.expires_in = body["expires_in"].as_i64();
    Ok(Output::ok(doc))
}

/// Sender-constraint checks on JWT access token claims.
fn check_binding(run: &mut Run, claims: &Value) {
    let cnf = &claims["cnf"];
    if dpop_enabled(run) && !cnf.is_null() {
        let ok = cnf["jkt"].as_str() == run.session.dpop_jkt.as_deref();
        run.check("cnf.jkt matches the DPoP key", ok, Error, format!("cnf {cnf}"), Some("RFC 9449 §6.1"));
    }
    if let Some(tp) = run.session.cert_thumbprint.clone() {
        if let Some(x5t) = cnf["x5t#S256"].as_str() {
            run.check("cnf.x5t#S256 matches the client certificate", x5t == tp, Error, "", Some("RFC 8705 §3.1"));
        } else if run.meta("tls_client_certificate_bound_access_tokens") == Some(&Value::Bool(true)) {
            run.check("access token is certificate-bound", false, Warning, "no cnf.x5t#S256 claim", Some("RFC 8705 §3"));
        }
    }
}

/// Decrypts an encrypted JWT with the client's decryption key.
pub(crate) fn decrypt_if_needed(run: &Run, token: &str) -> Result<String> {
    if !jose::is_jwe(token) {
        return Ok(token.to_string());
    }
    let path = run.client.decryption_key.as_ref().ok_or_else(|| anyhow!("token is encrypted; set client.decryption_key"))?;
    let plain = jose::decrypt(token, &jose::load_key(&run.path(path))?)?;
    Ok(String::from_utf8(plain)?)
}

/// Verifies a JWT signed by the authorization server and records the signature check.
pub(crate) async fn verify_server_jwt(run: &mut Run<'_>, token: &str, what: &str) -> Result<(Value, Value)> {
    ensure_jwks(run).await?;
    let jws = decrypt_if_needed(run, token)?;
    let secret = run.client_secret();
    match jose::verify(&jws, run.session.jwks.as_ref(), secret.as_deref()) {
        Ok(hp) => {
            run.check(format!("{what} signature verifies"), true, Error, hp.0["alg"].as_str().unwrap_or(""), None);
            Ok(hp)
        }
        Err(e) => {
            run.check(format!("{what} signature verifies"), false, Error, format!("{e:#}"), None);
            jose::decode(&jws)
        }
    }
}

/// OpenID Connect Core §3.1.3.7 / §3.2.2.11 ID token validation. Returns the claims.
pub(crate) async fn validate_id_token(
    run: &mut Run<'_>,
    token: &str,
    access_token: Option<&str>,
    code: Option<&str>,
    front_channel: bool,
) -> Result<Value> {
    let spec = Some("OpenID Connect Core §3.1.3.7");
    let (header, c) = verify_server_jwt(run, token, "ID token").await?;
    let alg = header["alg"].as_str().unwrap_or("");
    let issuer = run.issuer().unwrap_or_default();
    run.check("ID token iss matches the issuer", c["iss"].as_str() == Some(&issuer), Error, format!("iss {}", c["iss"]), spec);
    let client_id = run.client_id().unwrap_or_default();
    let aud_ok = match &c["aud"] {
        Value::String(a) => *a == client_id,
        Value::Array(a) => a.iter().any(|x| x.as_str() == Some(&client_id)),
        _ => false,
    };
    run.check("ID token aud contains the client_id", aud_ok, Error, format!("aud {}", c["aud"]), spec);
    if c["aud"].as_array().is_some_and(|a| a.len() > 1) {
        run.check("ID token azp is the client_id", c["azp"].as_str() == Some(&client_id), Warning, "", spec);
    }
    let now = crate::now() as i64;
    run.check("ID token not expired", c["exp"].as_i64().is_some_and(|e| e + 60 > now), Error, format!("exp {}", c["exp"]), spec);
    run.check("ID token iat present", c["iat"].is_number(), Error, "", spec);
    run.check("ID token sub present", c["sub"].is_string(), Error, "", spec);
    if let Some(n) = run.session.nonce.clone()
        && (front_channel || !c["nonce"].is_null())
    {
        run.check("ID token nonce matches", c["nonce"].as_str() == Some(&n), Error, "", spec);
    }
    if let Some(at) = access_token {
        match c["at_hash"].as_str() {
            Some(h) => run.check("at_hash matches", jose::half_hash(alg, at).as_deref() == Some(h), Error, "", spec),
            None if front_channel => {
                run.check("at_hash present", false, Error, "required with an access token from the authorization endpoint", spec)
            }
            None => {}
        }
    }
    if let Some(code) = code
        && let Some(h) = c["c_hash"].as_str()
    {
        run.check("c_hash matches", jose::half_hash(alg, code).as_deref() == Some(h), Error, "", Some("OpenID Connect Core §3.3.2.11"));
    }
    if run.session.max_age.is_some() {
        run.check("auth_time present (max_age was requested)", c["auth_time"].is_number(), Error, "", Some("OpenID Connect Core §3.1.2.1"));
    }
    Ok(c)
}

/// JWT access token profile checks (RFC 9068 §4).
pub(crate) async fn validate_access_token(run: &mut Run<'_>, token: &str) -> Result<Value> {
    let spec = Some("RFC 9068 §2.2, §4");
    let (header, c) = verify_server_jwt(run, token, "access token").await?;
    let typ = header["typ"].as_str().unwrap_or("");
    run.check(
        "typ is at+jwt",
        typ.eq_ignore_ascii_case("at+jwt") || typ.eq_ignore_ascii_case("application/at+jwt"),
        Error,
        format!("typ {typ:?}"),
        spec,
    );
    let issuer = run.issuer().unwrap_or_default();
    run.check("iss matches the issuer", c["iss"].as_str() == Some(&issuer), Error, format!("iss {}", c["iss"]), spec);
    for claim in ["exp", "aud", "sub", "client_id", "iat", "jti"] {
        run.check(format!("{claim} present"), !c[claim].is_null(), Error, "", spec);
    }
    if let Ok(id) = run.client_id()
        && c["client_id"].is_string()
    {
        run.check("client_id matches", c["client_id"].as_str() == Some(&id), Error, "", spec);
    }
    run.check("not expired", c["exp"].as_i64().is_some_and(|e| e + 60 > crate::now() as i64), Error, "", spec);
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_auth_urlencodes_first() {
        // RFC 6749 §2.3.1: "a:b" must become "a%3Ab".
        assert_eq!(basic_auth("a:b", "p w"), format!("Basic {}", base64_std("a%3Ab:p+w")));
        assert_eq!(basic_auth("client", "secret"), "Basic Y2xpZW50OnNlY3JldA==");
    }

    fn base64_std(s: &str) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(s)
    }
}
