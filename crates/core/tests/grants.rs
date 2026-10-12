//! Request-shape tests against a mock server, for grants and token usages the
//! end-to-end provider (e2e/) does not offer: JWT and SAML bearer grants,
//! client_secret_jwt, password, RFC 6750 body/query tokens, and DPoP nonces at
//! a resource server.

use grantcentral_core::report::{RunReport, Severity, StepStatus};
use grantcentral_core::{Project, RunOptions, jose};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use wiremock::matchers::{header_exists, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const ISSUER: &str = "https://as.example";

fn token_response() -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("cache-control", "no-store")
        .set_body_json(json!({ "access_token": "at-1", "token_type": "Bearer", "expires_in": 60 }))
}

/// Writes a one-flow project into a temp dir and runs it.
async fn run(flow: &str, files: &[(&str, &str)]) -> (RunReport, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("gc-it-{}", grantcentral_core::random_b64(6)));
    std::fs::create_dir_all(dir.join("flows")).unwrap();
    std::fs::write(dir.join("flows/f.toml"), flow).unwrap();
    for (name, content) in files {
        std::fs::write(dir.join(name), content).unwrap();
    }
    let project = Project::open(&dir).unwrap();
    let mut h = grantcentral_core::start_run(project, "flows/f.toml".into(), RunOptions { vars: BTreeMap::new(), ..Default::default() });
    while h.events.recv().await.is_some() {}
    (h.task.await.unwrap(), dir)
}

fn form(req: &Request) -> BTreeMap<String, String> {
    url::form_urlencoded::parse(&req.body).into_owned().collect()
}

fn assert_passed(r: &RunReport) {
    assert!(r.passed, "{}", serde_json::to_string_pretty(r).unwrap());
}

#[tokio::test]
async fn jwt_bearer_grant_with_client_secret_jwt() {
    let server = MockServer::start().await;
    Mock::given(method("POST")).and(path("/token")).respond_with(token_response()).mount(&server).await;
    let key = jose::generate("ES256").unwrap();
    let flow = format!(
        r#"
[client]
issuer = "{ISSUER}"
client_id = "c1"
client_secret = "a-long-shared-secret-for-hs256-0123456789"
auth_method = "client_secret_jwt"
signing_key = "key.json"
endpoints = {{ token_endpoint = "{}/token" }}

[[steps]]
type = "token"
grant_type = "jwt_bearer"
assertion_claims = {{ sub = "user-1" }}
scope = "read"
"#,
        server.uri()
    );
    let (r, _) = run(&flow, &[("key.json", &serde_json::to_string(key.as_ref()).unwrap())]).await;
    assert_passed(&r);
    let reqs = server.received_requests().await.unwrap();
    let f = form(&reqs[0]);
    assert_eq!(f["grant_type"], "urn:ietf:params:oauth:grant-type:jwt-bearer");
    assert_eq!(f["scope"], "read");
    // RFC 7523 §3: the grant assertion is signed by the client key...
    let jwks = json!({ "keys": [jose::public(&key).unwrap()] });
    let (_, claims) = jose::verify(&f["assertion"], Some(&jwks), None).unwrap();
    assert_eq!((claims["iss"].as_str(), claims["sub"].as_str(), claims["aud"].as_str()), (Some("c1"), Some("user-1"), Some(ISSUER)));
    // ...and client authentication is an HS256 assertion with aud = issuer (RFC 7523bis).
    assert_eq!(f["client_assertion_type"], "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
    let (h, ca) = jose::verify(&f["client_assertion"], None, Some("a-long-shared-secret-for-hs256-0123456789")).unwrap();
    assert_eq!(h["alg"], "HS256");
    assert_eq!(ca["aud"], ISSUER);
    assert_eq!(ca["sub"], "c1");
}

#[tokio::test]
async fn saml2_bearer_assertion_is_base64url_encoded() {
    let server = MockServer::start().await;
    Mock::given(method("POST")).and(path("/token")).respond_with(token_response()).mount(&server).await;
    let flow = format!(
        r#"
[client]
issuer = "{ISSUER}"
client_id = "c1"
client_secret = "s3cret"
endpoints = {{ token_endpoint = "{}/token" }}

[[steps]]
type = "token"
grant_type = "saml2_bearer"
assertion = "<saml:Assertion ID='x'>…</saml:Assertion>"
"#,
        server.uri()
    );
    let (r, _) = run(&flow, &[]).await;
    assert_passed(&r);
    let reqs = server.received_requests().await.unwrap();
    let f = form(&reqs[0]);
    assert_eq!(f["grant_type"], "urn:ietf:params:oauth:grant-type:saml2-bearer");
    let decoded = base64_url_decode(&f["assertion"]);
    assert!(decoded.starts_with("<saml:Assertion"), "{decoded}");
    // client_secret_basic by default, credentials form-urlencoded first (RFC 6749 §2.3.1).
    let auth = reqs[0].headers.get("authorization").unwrap().to_str().unwrap();
    assert_eq!(auth, "Basic YzE6czNjcmV0");
}

fn base64_url_decode(s: &str) -> String {
    use base64::Engine as _;
    String::from_utf8(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).unwrap()).unwrap()
}

#[tokio::test]
async fn password_grant_and_token_response_checks() {
    let server = MockServer::start().await;
    // No Cache-Control: no-store, and a DPoP-less "Bearer" token while DPoP was requested.
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "access_token": "at", "token_type": "Bearer" })))
        .mount(&server)
        .await;
    let flow = format!(
        r#"
[client]
issuer = "{ISSUER}"
client_id = "c1"
dpop = true
endpoints = {{ token_endpoint = "{}/token" }}

[[steps]]
type = "token"
grant_type = "password"
username = "alice"
password = "pw"
"#,
        server.uri()
    );
    let (r, _) = run(&flow, &[]).await;
    let step = &r.steps[0];
    assert_eq!(step.status, StepStatus::Failed);
    let failed = |name: &str| step.checks.iter().find(|c| c.name == name && !c.passed).map(|c| c.severity);
    assert_eq!(failed("token_type is DPoP"), Some(Severity::Error));
    assert_eq!(failed("Cache-Control: no-store"), Some(Severity::Warning));
    assert_eq!(failed("password grant avoided"), Some(Severity::Warning));
    let reqs = server.received_requests().await.unwrap();
    assert!(reqs[0].headers.contains_key("dpop"), "token request carries a DPoP proof");
    assert_eq!(form(&reqs[0])["client_id"], "c1", "public client sends client_id");
}

#[tokio::test]
async fn bearer_token_in_body_and_query() {
    let server = MockServer::start().await;
    Mock::given(method("POST")).and(path("/token")).respond_with(token_response()).mount(&server).await;
    Mock::given(path("/res")).respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ok": true }))).mount(&server).await;
    let flow = format!(
        r#"
[client]
issuer = "{ISSUER}"
client_id = "c1"
client_secret = "s"
endpoints = {{ token_endpoint = "{0}/token" }}

[[steps]]
type = "token"
grant_type = "client_credentials"

[[steps]]
type = "request"
url = "{0}/res"
auth = "bearer_body"
assert = ["body.ok"]

[[steps]]
type = "request"
url = "{0}/res?x=1"
auth = "bearer_query"
"#,
        server.uri()
    );
    let (r, _) = run(&flow, &[]).await;
    assert_passed(&r);
    let reqs = server.received_requests().await.unwrap();
    assert_eq!(reqs[1].method.as_str(), "POST", "RFC 6750 §2.2 uses a form-encoded POST");
    assert_eq!(form(&reqs[1])["access_token"], "at-1");
    assert!(reqs[2].url.query().unwrap().contains("access_token=at-1"));
    assert!(r.steps[2].checks.iter().any(|c| c.name == "bearer token in query avoided" && !c.passed));
}

#[tokio::test]
async fn dpop_nonce_from_resource_server() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("cache-control", "no-store")
                .set_body_json(json!({ "access_token": "dpop-at", "token_type": "DPoP" })),
        )
        .mount(&server)
        .await;
    // First call: ask for a nonce (RFC 9449 §9). Second: succeed.
    Mock::given(path("/res"))
        .respond_with(
            ResponseTemplate::new(401)
                .insert_header("www-authenticate", "DPoP error=\"use_dpop_nonce\", error_description=\"nonce required\"")
                .insert_header("dpop-nonce", "n-123"),
        )
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(path("/res")).and(header_exists("dpop")).respond_with(ResponseTemplate::new(200)).with_priority(2).mount(&server).await;
    let flow = format!(
        r#"
[client]
issuer = "{ISSUER}"
client_id = "c1"
dpop = true
endpoints = {{ token_endpoint = "{0}/token" }}

[[steps]]
type = "token"
grant_type = "client_credentials"

[[steps]]
type = "request"
url = "{0}/res?q=1"
assert = ["status == 200"]
"#,
        server.uri()
    );
    let (r, _) = run(&flow, &[]).await;
    assert_passed(&r);
    let reqs = server.received_requests().await.unwrap();
    let retry = &reqs[2];
    assert_eq!(retry.headers.get("authorization").unwrap().to_str().unwrap(), "DPoP dpop-at");
    let proof = retry.headers.get("dpop").unwrap().to_str().unwrap();
    let (h, c) = jose::decode(proof).unwrap();
    assert_eq!(h["typ"], "dpop+jwt");
    assert!(h["jwk"]["kty"].is_string() && h["jwk"]["d"].is_null(), "public key only");
    assert_eq!(c["nonce"], "n-123");
    assert_eq!(c["htm"], "GET");
    assert_eq!(c["htu"], format!("{}/res", server.uri()), "htu has no query (RFC 9449 §4.2)");
    use base64::Engine as _;
    let ath = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(openssl::sha::sha256(b"dpop-at"));
    assert_eq!(c["ath"], Value::String(ath));
}
