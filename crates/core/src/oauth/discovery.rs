//! Authorization server metadata (RFC 8414, OpenID Connect Discovery 1.0) and
//! protected resource metadata (RFC 9728).

use crate::engine::{Output, Run};
use crate::http::Req;
use crate::model::{DiscoverResourceStep, DiscoverStep, WellKnown};
use crate::report::Severity::{Error, Info, Warning};
use anyhow::{Context, Result};
use serde_json::{Value, json};

/// RFC 8414 §3.1 / RFC 9728 §3.1: the well-known segment goes between the host and the path.
pub fn well_known_url(identifier: &str, suffix: &str) -> Result<String> {
    let mut u = url::Url::parse(identifier).with_context(|| format!("invalid identifier {identifier}"))?;
    let path = u.path().trim_end_matches('/').to_string();
    u.set_path(&format!("/.well-known/{suffix}{path}"));
    u.set_query(None);
    u.set_fragment(None);
    Ok(u.to_string())
}

/// OpenID Connect Discovery §4: appended to the issuer.
fn openid_url(issuer: &str) -> String {
    format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'))
}

fn is_local(u: &url::Url) -> bool {
    matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
}

pub async fn discover(run: &mut Run<'_>, s: &DiscoverStep) -> Result<Output> {
    let issuer = match &s.issuer {
        Some(i) => i.clone(),
        None => run.issuer()?,
    };
    let urls = match (&s.url, s.well_known.unwrap_or(WellKnown::Auto)) {
        (Some(u), _) => vec![u.clone()],
        (None, WellKnown::Auto) => vec![well_known_url(&issuer, "oauth-authorization-server")?, openid_url(&issuer)],
        (None, WellKnown::Oauth) => vec![well_known_url(&issuer, "oauth-authorization-server")?],
        (None, WellKnown::Openid) => vec![openid_url(&issuer)],
    };
    let mut last = None;
    let mut found = None;
    for u in &urls {
        let resp = run.http.send(&Req::get(u)).await?;
        if resp.ok() && resp.json().is_some_and(|j| j.is_object()) {
            found = Some((u.clone(), resp));
            break;
        }
        run.log(format!("No metadata at {u} (HTTP {})", resp.status));
        last = Some(resp);
    }
    let Some((url, resp)) = found else {
        let doc = last.map(|r| r.doc()).unwrap_or(json!({}));
        return Ok(Output { doc, error: Some(format!("no authorization server metadata found at {}", urls.join(" or "))) });
    };
    let meta = resp.json().unwrap();

    let got = meta["issuer"].as_str().unwrap_or("");
    run.check("issuer matches", got == issuer, Error, format!("expected {issuer}, got {got:?}"), Some("RFC 8414 §3.3"));
    if let Ok(u) = url::Url::parse(got) {
        run.check("issuer has no query or fragment", u.query().is_none() && u.fragment().is_none(), Error, "", Some("RFC 8414 §2"));
    }
    run.check("response_types_supported present", meta["response_types_supported"].is_array(), Warning, "", Some("RFC 8414 §2"));
    for ep in ["authorization_endpoint", "token_endpoint"] {
        run.check(format!("{ep} present"), meta[ep].is_string(), Warning, "", Some("RFC 8414 §2"));
    }
    let mut insecure = vec![];
    for (k, v) in meta.as_object().unwrap() {
        if (k.ends_with("_endpoint") || k == "jwks_uri" || k == "issuer")
            && v.is_string()
            && let Ok(u) = url::Url::parse(v.as_str().unwrap())
            && u.scheme() != "https"
            && !is_local(&u)
        {
            insecure.push(k.clone());
        }
    }
    run.check("endpoints use TLS", insecure.is_empty(), Error, insecure.join(", "), Some("RFC 6749 §3.1, §3.2; RFC 8414 §2"));
    if let Some(sm) = meta["signed_metadata"].as_str() {
        let iss_ok = crate::jose::decode(sm).map(|(_, c)| c["iss"].as_str() == Some(&issuer)).unwrap_or(false);
        run.check("signed_metadata iss matches (signature not verified)", iss_ok, Warning, "", Some("RFC 8414 §2.1"));
    }

    run.session.issuer = Some(issuer);
    run.session.metadata = Some(meta.clone());
    let mut doc = resp.doc();
    doc["url"] = url.into();
    if let Some(jwks_uri) = meta["jwks_uri"].as_str() {
        let jr = run.http.send(&Req::get(jwks_uri)).await?;
        let jwks = jr.json().filter(|j| j["keys"].is_array());
        run.check("JWKS has a keys array", jwks.is_some(), Error, format!("HTTP {}", jr.status), Some("RFC 7517 §5"));
        doc["jwks"] = jwks.clone().unwrap_or(Value::Null);
        run.session.jwks = jwks;
    } else {
        run.check("jwks_uri present", false, Info, "signatures cannot be verified", Some("RFC 8414 §2"));
    }
    Ok(Output::ok(doc))
}

pub async fn discover_resource(run: &mut Run<'_>, s: &DiscoverResourceStep) -> Result<Output> {
    let url = match &s.url {
        Some(u) => u.clone(),
        None => well_known_url(&s.resource, "oauth-protected-resource")?,
    };
    let resp = run.http.send(&Req::get(&url)).await?;
    let mut doc = resp.doc();
    doc["url"] = url.clone().into();
    let Some(meta) = resp.json().filter(|j| resp.ok() && j.is_object()) else {
        return Ok(Output { doc, error: Some(format!("no protected resource metadata at {url} (HTTP {})", resp.status)) });
    };
    let got = meta["resource"].as_str().unwrap_or("");
    run.check("resource matches", got == s.resource, Error, format!("expected {}, got {got:?}", s.resource), Some("RFC 9728 §3.3"));
    if let Ok(iss) = run.issuer() {
        let listed = meta["authorization_servers"].as_array().is_some_and(|a| a.iter().any(|x| x.as_str() == Some(&iss)));
        run.check("authorization_servers lists the issuer", listed, Info, "", Some("RFC 9728 §2"));
    }
    run.session.resource_metadata = Some(meta);
    Ok(Output::ok(doc))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8414_path_insertion() {
        assert_eq!(
            well_known_url("https://example.com", "oauth-authorization-server").unwrap(),
            "https://example.com/.well-known/oauth-authorization-server"
        );
        assert_eq!(
            well_known_url("https://example.com/issuer1", "oauth-authorization-server").unwrap(),
            "https://example.com/.well-known/oauth-authorization-server/issuer1"
        );
        assert_eq!(openid_url("https://example.com/issuer1/"), "https://example.com/issuer1/.well-known/openid-configuration");
        assert_eq!(
            well_known_url("https://api.example.com/v1/", "oauth-protected-resource").unwrap(),
            "https://api.example.com/.well-known/oauth-protected-resource/v1"
        );
    }
}
