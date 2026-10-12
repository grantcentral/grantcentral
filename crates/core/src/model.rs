//! On-disk file model. Everything here is (de)serialized from TOML files that
//! users edit by hand and keep in git, so unknown keys are rejected.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// `grantcentral.toml` at the project root.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectFile {
    pub name: Option<String>,
    /// Environment used when none is selected.
    pub default_environment: Option<String>,
}

/// `environments/<name>.toml`, merged with an optional git-ignored `environments/<name>.local.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentFile {
    /// Template variables, available as `{{ name }}`.
    #[serde(default)]
    pub vars: BTreeMap<String, Value>,
    /// Secrets, available as `{{ secrets.name }}` and redacted from reports.
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretRef>,
    /// Client defaults shared by every flow run in this environment.
    #[serde(default)]
    pub client: ClientConfig,
}

/// Where a secret value comes from.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum SecretRef {
    /// Literal value. Only put these in `*.local.toml` files.
    Literal(String),
    /// Read from an environment variable (CI).
    Env { env: String },
    /// Read from the OS keychain (service "grantcentral", this account name).
    Keyring { keyring: String },
    /// Read from a file, relative to the project root (mounted CI secrets).
    File { file: String },
}

/// A flow file: `flows/**/*.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Flow {
    pub name: Option<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Default variables; environment and command-line variables override them.
    #[serde(default)]
    pub vars: BTreeMap<String, Value>,
    /// Overrides for the environment's `[client]`.
    #[serde(default)]
    pub client: ClientConfig,
    #[serde(default)]
    pub steps: Vec<Step>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    None,
    ClientSecretBasic,
    ClientSecretPost,
    ClientSecretJwt,
    PrivateKeyJwt,
    TlsClientAuth,
    SelfSignedTlsClientAuth,
}

/// The OAuth client under test. All fields are optional so environments and
/// flows can each set part of it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// Authorization server issuer identifier (RFC 8414).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// Token endpoint authentication method. Inferred from the credentials when unset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<AuthMethod>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Private JWK (JSON) or PEM key file for private_key_jwt, JAR and JWT bearer assertions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_alg: Option<String>,
    /// Private key for decrypting encrypted ID tokens, userinfo and introspection responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decryption_key: Option<String>,
    /// `aud` of client assertions: "issuer" (default, per RFC 7523bis), "endpoint", or a literal URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assertion_audience: Option<String>,
    /// Sender-constrain tokens with DPoP (RFC 9449).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop: Option<bool>,
    /// DPoP key file. A fresh key is generated per run when unset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_alg: Option<String>,
    /// Client certificate (PEM) for mutual TLS (RFC 8705).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_cert: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_key: Option<String>,
    /// Extra trusted CA certificate (PEM).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_cert: Option<String>,
    /// Accept invalid TLS certificates. Never use against production.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub insecure: Option<bool>,
    /// HTTP timeout in seconds (default 30).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    /// Endpoint overrides keyed by metadata name, e.g. `token_endpoint`. Takes precedence over discovery.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub endpoints: BTreeMap<String, String>,
}

impl ClientConfig {
    /// `over` wins field by field.
    pub fn merged(&self, over: &ClientConfig) -> ClientConfig {
        let mut base = serde_json::to_value(self).expect("client config serializes");
        let over = serde_json::to_value(over).expect("client config serializes");
        if let (Some(b), Value::Object(o)) = (base.as_object_mut(), over) {
            for (k, v) in o {
                if k == "endpoints" {
                    let e = b.entry(k).or_insert_with(|| Value::Object(Default::default()));
                    if let (Some(e), Value::Object(v)) = (e.as_object_mut(), v) {
                        e.extend(v);
                    }
                } else {
                    b.insert(k, v);
                }
            }
        }
        serde_json::from_value(base).expect("merged client config deserializes")
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Expect {
    /// The step must succeed, and failed error-level checks fail it.
    #[default]
    Success,
    /// The step must fail (negative test), e.g. the server rejects a bad request.
    Error,
    /// Only the assertions decide.
    Any,
}

/// One step of a flow.
///
/// Deserialized by hand (see below) because serde's `flatten` would silently
/// accept typos.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Step {
    /// Name used to reference the result as `steps.<id>`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Only run the step when this expression is true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub when: Option<String>,
    #[serde(default, skip_serializing_if = "is_default")]
    pub expect: Expect,
    /// Expressions that must be true, e.g. `status == 200` or `'openid' in body.scope`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assert: Vec<String>,
    /// Variables to set from expressions over the result, e.g. `token = "body.access_token"`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub capture: BTreeMap<String, String>,
    #[serde(flatten)]
    pub kind: StepKind,
}

fn is_default<T: Default + PartialEq>(v: &T) -> bool {
    *v == T::default()
}

const STEP_COMMON: [&str; 6] = ["id", "name", "when", "expect", "assert", "capture"];

impl<'de> Deserialize<'de> for Step {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let mut table = serde_json::Map::<String, Value>::deserialize(d)?;
        let mut common = serde_json::Map::new();
        for k in STEP_COMMON {
            if let Some(v) = table.remove(k) {
                common.insert(k.into(), v);
            }
        }
        #[derive(Deserialize)]
        struct Common {
            id: Option<String>,
            name: Option<String>,
            when: Option<String>,
            #[serde(default)]
            expect: Expect,
            #[serde(default)]
            assert: Vec<String>,
            #[serde(default)]
            capture: BTreeMap<String, String>,
        }
        let c: Common = serde_json::from_value(Value::Object(common)).map_err(D::Error::custom)?;
        let kind: StepKind = serde_json::from_value(Value::Object(table)).map_err(D::Error::custom)?;
        Ok(Step { id: c.id, name: c.name, when: c.when, expect: c.expect, assert: c.assert, capture: c.capture, kind })
    }
}

impl Step {
    pub fn label(&self) -> String {
        self.name.clone().or_else(|| self.id.clone()).unwrap_or_else(|| self.kind.type_name().to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StepKind {
    /// Fetch authorization server metadata (RFC 8414 / OpenID Connect Discovery) and its JWKS.
    Discover(DiscoverStep),
    /// Fetch protected resource metadata (RFC 9728).
    DiscoverResource(DiscoverResourceStep),
    /// Check the discovered metadata against the security BCPs (RFC 9700, 10017, 10027, ...).
    Audit(AuditStep),
    /// Dynamic client registration (RFC 7591).
    Register(RegisterStep),
    /// Dynamic client management (RFC 7592).
    ManageClient(ManageClientStep),
    /// Authorization request through the user agent, with PKCE, PAR, JAR, RAR and DPoP.
    Authorize(AuthorizeStep),
    /// Token endpoint request for any grant type.
    Token(TokenStep),
    /// Device authorization grant (RFC 8628).
    Device(DeviceStep),
    /// Token introspection (RFC 7662, JWT responses per RFC 9701).
    Introspect(IntrospectStep),
    /// Token revocation (RFC 7009).
    Revoke(RevokeStep),
    /// OpenID Connect UserInfo request.
    Userinfo(UserinfoStep),
    /// Request to a protected resource (RFC 6750 / RFC 9449), parsing step-up challenges (RFC 9470).
    Request(RequestStep),
    /// Validate a JWT: ID token, JWT access token (RFC 9068) or generic.
    ValidateJwt(ValidateJwtStep),
    /// Sleep, e.g. to let a token expire.
    Wait(WaitStep),
}

impl StepKind {
    pub fn type_name(&self) -> &'static str {
        match self {
            StepKind::Discover(_) => "discover",
            StepKind::DiscoverResource(_) => "discover_resource",
            StepKind::Audit(_) => "audit",
            StepKind::Register(_) => "register",
            StepKind::ManageClient(_) => "manage_client",
            StepKind::Authorize(_) => "authorize",
            StepKind::Token(_) => "token",
            StepKind::Device(_) => "device",
            StepKind::Introspect(_) => "introspect",
            StepKind::Revoke(_) => "revoke",
            StepKind::Userinfo(_) => "userinfo",
            StepKind::Request(_) => "request",
            StepKind::ValidateJwt(_) => "validate_jwt",
            StepKind::Wait(_) => "wait",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WellKnown {
    /// `oauth-authorization-server` first, then `openid-configuration`.
    Auto,
    Oauth,
    Openid,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoverStep {
    /// Defaults to `client.issuer`.
    pub issuer: Option<String>,
    /// Explicit metadata URL instead of the well-known location.
    pub url: Option<String>,
    pub well_known: Option<WellKnown>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoverResourceStep {
    /// Resource identifier, e.g. `https://api.example.com`.
    pub resource: String,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuditStep {
    /// Client profile to audit for: "confidential" (default), "browser" (RFC 10017) or "native" (RFC 8252).
    pub profile: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegisterStep {
    /// Client metadata (RFC 7591 §2) sent as JSON.
    #[serde(default)]
    pub metadata: Value,
    pub initial_access_token: Option<String>,
    pub software_statement: Option<String>,
    /// Use the registered client for the rest of the flow (default true).
    pub use_client: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ManageAction {
    Read,
    Update,
    Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ManageClientStep {
    pub action: ManageAction,
    /// Full client metadata for `update`.
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum Pkce {
    #[serde(rename = "S256")]
    S256,
    #[serde(rename = "plain")]
    Plain,
    #[serde(rename = "none")]
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RequestObject {
    None,
    /// Signed request object (RFC 9101).
    Signed,
    /// Signed, then encrypted to the authorization server.
    Encrypted,
    /// `alg: none`, for negative tests.
    Unsigned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LoginMode {
    /// Open the system browser and catch the redirect on a loopback listener (RFC 8252).
    System,
    /// Headless Chromium driven by `login_script` (CI).
    Chromium,
    /// Follow redirects with an HTTP client; for servers that do not ask for a login.
    Http,
    /// Print the URL and wait for the redirect URL to be pasted back.
    Manual,
}

/// One action of a Chromium login script. Exactly one of `fill`, `click`, `wait`, `press` or `sleep_ms`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BrowserAction {
    /// CSS selector of an input to type `value` into.
    pub fill: Option<String>,
    pub value: Option<String>,
    /// CSS selector to click.
    pub click: Option<String>,
    /// CSS selector to wait for.
    pub wait: Option<String>,
    /// Key to press in the focused element, e.g. "Enter".
    pub press: Option<String>,
    pub sleep_ms: Option<u64>,
    /// Skip the action if the selector does not appear (e.g. a consent screen shown only once).
    #[serde(default)]
    pub optional: bool,
    /// Seconds to wait for the selector (default 10, 3 when optional).
    pub timeout: Option<u64>,
}

/// Request parameters: extra values are added, existing ones replaced.
pub type Params = BTreeMap<String, String>;

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthorizeStep {
    pub response_type: Option<String>,
    /// query, fragment, form_post, ...
    pub response_mode: Option<String>,
    pub scope: Option<String>,
    pub redirect_uri: Option<String>,
    /// PKCE method (RFC 7636), default S256.
    pub pkce: Option<Pkce>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    /// Pushed authorization request (RFC 9126). Defaults to the server's `require_pushed_authorization_requests`.
    pub par: Option<bool>,
    /// JWT-secured authorization request (RFC 9101).
    pub request_object: Option<RequestObject>,
    /// Parameters to repeat outside the request object, e.g. ["response_type", "scope"] for OpenID Connect servers.
    #[serde(default)]
    pub duplicate_params: Vec<String>,
    /// Request object by reference: a URL you host (RFC 9101 §5.2).
    pub request_uri: Option<String>,
    pub request_object_encryption_alg: Option<String>,
    pub request_object_encryption_enc: Option<String>,
    /// Rich authorization request details (RFC 9396).
    pub authorization_details: Option<Value>,
    /// Resource indicators (RFC 8707).
    #[serde(default)]
    pub resource: Vec<String>,
    pub acr_values: Option<String>,
    pub max_age: Option<String>,
    pub prompt: Option<String>,
    pub login_hint: Option<String>,
    pub id_token_hint: Option<String>,
    pub ui_locales: Option<String>,
    /// OpenID Connect `claims` request parameter.
    pub claims: Option<Value>,
    /// Send `dpop_jkt` (RFC 9449 §10). Defaults to true with DPoP and without PAR.
    pub dpop_jkt: Option<bool>,
    #[serde(default)]
    pub params: Params,
    /// Default parameters to leave out, e.g. ["state"].
    #[serde(default)]
    pub remove: Vec<String>,
    pub login: Option<LoginMode>,
    #[serde(default)]
    pub login_script: Vec<BrowserAction>,
    /// Seconds to wait for the redirect (default 300).
    pub timeout: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TokenStep {
    /// Full grant type URI or alias: authorization_code, refresh_token, client_credentials,
    /// password, token_exchange, jwt_bearer, saml2_bearer, device_code.
    /// Defaults to authorization_code after an authorize step, else client_credentials.
    pub grant_type: Option<String>,
    pub code: Option<String>,
    pub code_verifier: Option<String>,
    pub redirect_uri: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    /// Token exchange (RFC 8693).
    pub subject_token: Option<String>,
    pub subject_token_type: Option<String>,
    pub actor_token: Option<String>,
    pub actor_token_type: Option<String>,
    pub requested_token_type: Option<String>,
    #[serde(default)]
    pub audience: Vec<String>,
    #[serde(default)]
    pub resource: Vec<String>,
    /// Assertion for jwt_bearer (RFC 7523) or saml2_bearer (RFC 7522, base64url-encoded if not already).
    pub assertion: Option<String>,
    /// Claims of a generated JWT bearer assertion, signed with `client.signing_key`.
    pub assertion_claims: Option<Value>,
    pub authorization_details: Option<Value>,
    pub device_code: Option<String>,
    #[serde(default)]
    pub params: Params,
    #[serde(default)]
    pub remove: Vec<String>,
    /// Apply the RFC 9068 checks to a JWT access token.
    pub validate_access_token: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceStep {
    pub scope: Option<String>,
    #[serde(default)]
    pub resource: Vec<String>,
    pub authorization_details: Option<Value>,
    #[serde(default)]
    pub params: Params,
    /// Poll the token endpoint until the user approves (default true).
    pub poll: Option<bool>,
    pub login: Option<LoginMode>,
    /// Run on `verification_uri_complete`; `{{ session.user_code }}` is available.
    #[serde(default)]
    pub login_script: Vec<BrowserAction>,
    pub timeout: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IntrospectStep {
    /// Defaults to the session access token.
    pub token: Option<String>,
    pub token_type_hint: Option<String>,
    /// Ask for a signed JWT response (RFC 9701).
    #[serde(default)]
    pub jwt_response: bool,
    #[serde(default)]
    pub params: Params,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevokeStep {
    /// Defaults to the session refresh token, else the access token.
    pub token: Option<String>,
    pub token_type_hint: Option<String>,
    #[serde(default)]
    pub params: Params,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UserinfoStep {
    /// GET (default) or POST.
    pub method: Option<String>,
    pub access_token: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResourceAuth {
    /// DPoP when the token is DPoP-bound, else a bearer header.
    Auto,
    /// `Authorization: Bearer` (RFC 6750 §2.1).
    Bearer,
    /// Form body `access_token` (RFC 6750 §2.2).
    BearerBody,
    /// Query `access_token` (RFC 6750 §2.3).
    BearerQuery,
    Dpop,
    None,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestStep {
    pub url: String,
    pub method: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Raw body.
    pub body: Option<String>,
    pub json: Option<Value>,
    pub form: Option<BTreeMap<String, String>>,
    pub auth: Option<ResourceAuth>,
    pub access_token: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum JwtProfile {
    IdToken,
    /// RFC 9068.
    AccessToken,
    /// Signature, `exp` and `nbf` only.
    Generic,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ValidateJwtStep {
    pub token: String,
    pub profile: Option<JwtProfile>,
    /// Expected `aud`. Defaults to the client ID for ID tokens.
    pub audience: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WaitStep {
    pub seconds: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step_rejects_unknown_fields() {
        let ok: Flow =
            toml::from_str("[[steps]]\ntype = \"token\"\ngrant_type = \"client_credentials\"\nassert = [\"status == 200\"]").unwrap();
        assert_eq!(ok.steps[0].assert.len(), 1);
        assert!(matches!(ok.steps[0].kind, StepKind::Token(_)));
        let err = toml::from_str::<Flow>("[[steps]]\ntype = \"token\"\ngrant_typo = \"x\"").unwrap_err();
        assert!(err.to_string().contains("grant_typo"), "{err}");
    }

    #[test]
    fn client_merge_prefers_override() {
        let base = ClientConfig { client_id: Some("a".into()), scope: Some("s".into()), ..Default::default() };
        let over = ClientConfig { client_id: Some("b".into()), ..Default::default() };
        let m = base.merged(&over);
        assert_eq!(m.client_id.as_deref(), Some("b"));
        assert_eq!(m.scope.as_deref(), Some("s"));
    }
}
