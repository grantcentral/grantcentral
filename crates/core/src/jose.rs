//! JWS, JWE and JWK helpers on top of josekit. JWS compact serialization is
//! assembled by hand so callers fully control the header (a test tool needs
//! to send odd `typ` values and the like).

use anyhow::{Context, Result, anyhow, bail};
use josekit::jwe::{self, JweDecrypter, JweEncrypter, JweHeader};
pub use josekit::jwk::Jwk;
use josekit::jwk::KeyPair;
use josekit::jwk::alg::{ec::EcCurve, ed::EdCurve};
use josekit::jws::{self, JwsSigner, JwsVerifier};
use serde_json::{Map, Value, json};

/// Loads a private key from a JWK (JSON) or PEM file.
pub fn load_key(path: &std::path::Path) -> Result<Jwk> {
    let bytes = std::fs::read(path).with_context(|| format!("reading key {}", path.display()))?;
    parse_key(&bytes).with_context(|| format!("parsing key {}", path.display()))
}

pub fn parse_key(bytes: &[u8]) -> Result<Jwk> {
    let text = String::from_utf8_lossy(bytes);
    if text.trim_start().starts_with('{') {
        let v: Value = serde_json::from_slice(bytes)?;
        // Accept a JWKS with a single key, too.
        let v = match v.get("keys").and_then(Value::as_array) {
            Some(keys) => keys.first().cloned().ok_or_else(|| anyhow!("empty JWKS"))?,
            None => v,
        };
        return Ok(Jwk::from_map(v.as_object().cloned().unwrap_or_default())?);
    }
    use josekit::jwk::alg::{ec::EcKeyPair, ed::EdKeyPair, rsa::RsaKeyPair};
    if let Ok(k) = RsaKeyPair::from_pem(bytes) {
        return Ok(k.to_jwk_key_pair());
    }
    if let Ok(k) = EcKeyPair::from_pem(bytes, None) {
        return Ok(k.to_jwk_key_pair());
    }
    if let Ok(k) = EdKeyPair::from_pem(bytes) {
        return Ok(k.to_jwk_key_pair());
    }
    bail!("not a JWK or a PEM private key (RSA, EC or Ed25519)")
}

/// Generates a key for a JWS algorithm.
pub fn generate(alg: &str) -> Result<Jwk> {
    let mut jwk = match alg {
        "ES256" => Jwk::generate_ec_key(EcCurve::P256)?,
        "ES384" => Jwk::generate_ec_key(EcCurve::P384)?,
        "ES512" => Jwk::generate_ec_key(EcCurve::P521)?,
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" => Jwk::generate_rsa_key(2048)?,
        "EdDSA" | "Ed25519" => Jwk::generate_ed_key(EdCurve::Ed25519)?,
        other => bail!("cannot generate a key for {other}"),
    };
    jwk.set_algorithm(if alg == "Ed25519" { "EdDSA" } else { alg });
    let tp = thumbprint(&public(&jwk)?)?;
    jwk.set_key_id(tp);
    Ok(jwk)
}

/// The public part of a key as JSON.
pub fn public(jwk: &Jwk) -> Result<Value> {
    if jwk.key_type() == "oct" {
        bail!("symmetric keys have no public part");
    }
    let mut m = jwk.to_public_key()?.as_ref().clone();
    // josekit keeps only `use` and the key material.
    for k in ["kid", "alg", "key_ops", "x5c", "x5t#S256"] {
        if let Some(v) = jwk.parameter(k) {
            m.insert(k.into(), v.clone());
        }
    }
    Ok(Value::Object(m))
}

/// The JWS algorithm to use with a key when none is configured.
pub fn default_alg(jwk: &Jwk) -> &'static str {
    if let Some(a) = jwk.algorithm() {
        for known in ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA", "HS256", "HS384", "HS512"] {
            if a == known {
                return known;
            }
        }
    }
    match (jwk.key_type(), jwk.curve()) {
        ("EC", Some("P-384")) => "ES384",
        ("EC", Some("P-521")) => "ES512",
        ("EC", _) => "ES256",
        ("OKP", _) => "EdDSA",
        ("oct", _) => "HS256",
        _ => "RS256",
    }
}

fn signer(alg: &str, jwk: &Jwk) -> Result<Box<dyn JwsSigner>> {
    Ok(match alg {
        "RS256" => Box::new(jws::RS256.signer_from_jwk(jwk)?),
        "RS384" => Box::new(jws::RS384.signer_from_jwk(jwk)?),
        "RS512" => Box::new(jws::RS512.signer_from_jwk(jwk)?),
        "PS256" => Box::new(jws::PS256.signer_from_jwk(jwk)?),
        "PS384" => Box::new(jws::PS384.signer_from_jwk(jwk)?),
        "PS512" => Box::new(jws::PS512.signer_from_jwk(jwk)?),
        "ES256" => Box::new(jws::ES256.signer_from_jwk(jwk)?),
        "ES384" => Box::new(jws::ES384.signer_from_jwk(jwk)?),
        "ES512" => Box::new(jws::ES512.signer_from_jwk(jwk)?),
        "EdDSA" => Box::new(jws::EdDSA.signer_from_jwk(jwk)?),
        "HS256" => Box::new(jws::HS256.signer_from_jwk(jwk)?),
        "HS384" => Box::new(jws::HS384.signer_from_jwk(jwk)?),
        "HS512" => Box::new(jws::HS512.signer_from_jwk(jwk)?),
        other => bail!("unsupported JWS algorithm {other}"),
    })
}

fn verifier(alg: &str, jwk: &Jwk) -> Result<Box<dyn JwsVerifier>> {
    Ok(match alg {
        "RS256" => Box::new(jws::RS256.verifier_from_jwk(jwk)?),
        "RS384" => Box::new(jws::RS384.verifier_from_jwk(jwk)?),
        "RS512" => Box::new(jws::RS512.verifier_from_jwk(jwk)?),
        "PS256" => Box::new(jws::PS256.verifier_from_jwk(jwk)?),
        "PS384" => Box::new(jws::PS384.verifier_from_jwk(jwk)?),
        "PS512" => Box::new(jws::PS512.verifier_from_jwk(jwk)?),
        "ES256" => Box::new(jws::ES256.verifier_from_jwk(jwk)?),
        "ES384" => Box::new(jws::ES384.verifier_from_jwk(jwk)?),
        "ES512" => Box::new(jws::ES512.verifier_from_jwk(jwk)?),
        "EdDSA" => Box::new(jws::EdDSA.verifier_from_jwk(jwk)?),
        "HS256" => Box::new(jws::HS256.verifier_from_jwk(jwk)?),
        "HS384" => Box::new(jws::HS384.verifier_from_jwk(jwk)?),
        "HS512" => Box::new(jws::HS512.verifier_from_jwk(jwk)?),
        other => bail!("unsupported JWS algorithm {other}"),
    })
}

/// An HMAC key from a shared secret (client_secret_jwt, HS* ID tokens).
pub fn oct_key(secret: &str) -> Jwk {
    let mut jwk = Jwk::new("oct");
    jwk.set_key_value(secret.as_bytes());
    jwk
}

/// Signs `claims`. `header` may add or override members; `alg` and `kid` are filled in.
pub fn sign(claims: &Value, header: Value, jwk: &Jwk, alg: Option<&str>) -> Result<String> {
    let alg = alg.unwrap_or_else(|| default_alg(jwk));
    let mut h = Map::new();
    h.insert("alg".into(), alg.into());
    if let Some(kid) = jwk.key_id() {
        h.insert("kid".into(), kid.into());
    }
    if let Value::Object(extra) = header {
        h.extend(extra);
    }
    let input = format!("{}.{}", crate::b64(&serde_json::to_vec(&h)?), crate::b64(&serde_json::to_vec(claims)?));
    let sig = signer(alg, jwk)?.sign(input.as_bytes())?;
    Ok(format!("{input}.{}", crate::b64(&sig)))
}

/// An unsecured JWT (`alg: none`), for negative tests.
pub fn unsigned(claims: &Value, header: Value) -> Result<String> {
    let mut h = json!({ "alg": "none" });
    if let (Some(h), Value::Object(extra)) = (h.as_object_mut(), header) {
        h.extend(extra);
    }
    Ok(format!("{}.{}.", crate::b64(&serde_json::to_vec(&h)?), crate::b64(&serde_json::to_vec(claims)?)))
}

/// Decodes a JWS without verifying it.
pub fn decode(jwt: &str) -> Result<(Value, Value)> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        bail!("not a JWS compact serialization ({} parts)", parts.len());
    }
    let header = serde_json::from_slice(&crate::unb64(parts[0])?).context("JWT header is not JSON")?;
    let payload = serde_json::from_slice(&crate::unb64(parts[1])?).context("JWT payload is not JSON")?;
    Ok((header, payload))
}

pub fn is_jwe(token: &str) -> bool {
    token.split('.').count() == 5
}

/// Verifies a JWS against a JWKS (or an HMAC secret for HS* algorithms).
/// Returns (header, payload).
pub fn verify(jwt: &str, jwks: Option<&Value>, hmac_secret: Option<&str>) -> Result<(Value, Value)> {
    let (header, payload) = decode(jwt)?;
    let alg = header["alg"].as_str().ok_or_else(|| anyhow!("JWT header has no alg"))?;
    if alg == "none" {
        bail!("JWT is unsigned (alg none)");
    }
    let (input, sig) = jwt.rsplit_once('.').unwrap();
    let sig = crate::unb64(sig)?;
    if alg.starts_with("HS") {
        let secret = hmac_secret.ok_or_else(|| anyhow!("{alg} JWT needs the client secret to verify"))?;
        verifier(alg, &oct_key(secret))?.verify(input.as_bytes(), &sig).map_err(|_| anyhow!("signature does not verify"))?;
        return Ok((header, payload));
    }
    let keys = jwks.and_then(|j| j["keys"].as_array()).ok_or_else(|| anyhow!("no JWKS available to verify the signature"))?;
    let kid = header["kid"].as_str();
    let candidates: Vec<&Value> = keys
        .iter()
        .filter(|k| kid.is_none_or(|kid| k["kid"].as_str() == Some(kid)))
        .filter(|k| k["use"].as_str().is_none_or(|u| u == "sig"))
        .filter(|k| k["alg"].as_str().is_none_or(|a| a == alg))
        .filter(|k| kty_for(alg) == k["kty"].as_str().unwrap_or(""))
        .collect();
    if candidates.is_empty() {
        bail!("no key in the JWKS matches kid {:?} and alg {alg}", kid.unwrap_or("-"));
    }
    for k in candidates {
        let Ok(jwk) = Jwk::from_map(k.as_object().cloned().unwrap_or_default()) else { continue };
        let Ok(v) = verifier(alg, &jwk) else { continue };
        if v.verify(input.as_bytes(), &sig).is_ok() {
            return Ok((header, payload));
        }
    }
    bail!("signature does not verify with any matching key")
}

fn kty_for(alg: &str) -> &'static str {
    match &alg[..2] {
        "RS" | "PS" => "RSA",
        "ES" => "EC",
        "Ed" => "OKP",
        _ => "",
    }
}

/// Encrypts `payload` to a public key (nested JWT when `cty` is "JWT").
pub fn encrypt(payload: &[u8], key: &Value, alg: &str, enc: &str, cty: Option<&str>) -> Result<String> {
    let jwk = Jwk::from_map(key.as_object().cloned().unwrap_or_default())?;
    let mut header = JweHeader::new();
    header.set_algorithm(alg);
    header.set_content_encryption(enc);
    if let Some(kid) = jwk.key_id() {
        header.set_key_id(kid);
    }
    if let Some(cty) = cty {
        header.set_content_type(cty);
    }
    let encrypter: Box<dyn JweEncrypter> = match alg {
        "RSA-OAEP" => Box::new(jwe::RSA_OAEP.encrypter_from_jwk(&jwk)?),
        "RSA-OAEP-256" => Box::new(jwe::RSA_OAEP_256.encrypter_from_jwk(&jwk)?),
        "RSA-OAEP-384" => Box::new(jwe::RSA_OAEP_384.encrypter_from_jwk(&jwk)?),
        "RSA-OAEP-512" => Box::new(jwe::RSA_OAEP_512.encrypter_from_jwk(&jwk)?),
        "ECDH-ES" => Box::new(jwe::ECDH_ES.encrypter_from_jwk(&jwk)?),
        "ECDH-ES+A128KW" => Box::new(jwe::ECDH_ES_A128KW.encrypter_from_jwk(&jwk)?),
        "ECDH-ES+A192KW" => Box::new(jwe::ECDH_ES_A192KW.encrypter_from_jwk(&jwk)?),
        "ECDH-ES+A256KW" => Box::new(jwe::ECDH_ES_A256KW.encrypter_from_jwk(&jwk)?),
        other => bail!("unsupported JWE algorithm {other}"),
    };
    Ok(jwe::serialize_compact(payload, &header, &*encrypter)?)
}

pub const SUPPORTED_JWE_ALGS: &[&str] =
    &["RSA-OAEP-256", "ECDH-ES+A256KW", "ECDH-ES+A128KW", "ECDH-ES", "RSA-OAEP-384", "RSA-OAEP-512", "RSA-OAEP"];

/// Decrypts a JWE with a private key. Returns the plaintext.
pub fn decrypt(token: &str, jwk: &Jwk) -> Result<Vec<u8>> {
    let header: Value = serde_json::from_slice(&crate::unb64(token.split('.').next().unwrap_or(""))?)?;
    let alg = header["alg"].as_str().unwrap_or("");
    let decrypter: Box<dyn JweDecrypter> = match alg {
        "RSA-OAEP" => Box::new(jwe::RSA_OAEP.decrypter_from_jwk(jwk)?),
        "RSA-OAEP-256" => Box::new(jwe::RSA_OAEP_256.decrypter_from_jwk(jwk)?),
        "RSA-OAEP-384" => Box::new(jwe::RSA_OAEP_384.decrypter_from_jwk(jwk)?),
        "RSA-OAEP-512" => Box::new(jwe::RSA_OAEP_512.decrypter_from_jwk(jwk)?),
        "ECDH-ES" => Box::new(jwe::ECDH_ES.decrypter_from_jwk(jwk)?),
        "ECDH-ES+A128KW" => Box::new(jwe::ECDH_ES_A128KW.decrypter_from_jwk(jwk)?),
        "ECDH-ES+A192KW" => Box::new(jwe::ECDH_ES_A192KW.decrypter_from_jwk(jwk)?),
        "ECDH-ES+A256KW" => Box::new(jwe::ECDH_ES_A256KW.decrypter_from_jwk(jwk)?),
        other => bail!("unsupported JWE algorithm {other}"),
    };
    Ok(jwe::deserialize_compact(token, &*decrypter)?.0)
}

/// JWK thumbprint (RFC 7638), base64url SHA-256 over the required members.
pub fn thumbprint(public_jwk: &Value) -> Result<String> {
    let members: &[&str] = match public_jwk["kty"].as_str() {
        Some("EC") => &["crv", "kty", "x", "y"],
        Some("RSA") => &["e", "kty", "n"],
        Some("OKP") => &["crv", "kty", "x"],
        Some("oct") => &["k", "kty"],
        other => bail!("unknown kty {other:?}"),
    };
    // serde_json maps are sorted, and the members are plain strings, so this is the canonical form.
    let mut m = Map::new();
    for k in members {
        let v = public_jwk.get(*k).ok_or_else(|| anyhow!("JWK lacks {k}"))?;
        m.insert(k.to_string(), v.clone());
    }
    Ok(crate::b64(&crate::sha256(serde_json::to_string(&m)?.as_bytes())))
}

/// JWK thumbprint URI (RFC 9278).
pub fn thumbprint_uri(public_jwk: &Value) -> Result<String> {
    Ok(format!("urn:ietf:params:oauth:jwk-thumbprint:sha-256:{}", thumbprint(public_jwk)?))
}

/// `x5t#S256` of a PEM certificate (RFC 8705 §3.1).
pub fn cert_thumbprint(pem: &[u8]) -> Result<String> {
    let cert = openssl::x509::X509::from_pem(pem).context("parsing client certificate")?;
    Ok(crate::b64(&crate::sha256(&cert.to_der()?)))
}

/// Left-half hash for `at_hash` / `c_hash` (OpenID Connect Core §3.1.3.6).
pub fn half_hash(alg: &str, value: &str) -> Option<String> {
    use openssl::hash::{MessageDigest, hash};
    let md = match alg {
        a if a.ends_with("256") => MessageDigest::sha256(),
        a if a.ends_with("384") => MessageDigest::sha384(),
        a if a.ends_with("512") || a == "EdDSA" => MessageDigest::sha512(),
        _ => return None,
    };
    let h = hash(md, value.as_bytes()).ok()?;
    Some(crate::b64(&h[..h.len() / 2]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7638_example_thumbprint() {
        // RFC 7638 §3.1
        let jwk = json!({
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29"
        });
        assert_eq!(thumbprint(&jwk).unwrap(), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
        assert_eq!(
            thumbprint_uri(&jwk).unwrap(),
            "urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    #[test]
    fn sign_verify_roundtrip() {
        for alg in ["ES256", "PS256", "EdDSA"] {
            let key = generate(alg).unwrap();
            let jwks = json!({ "keys": [public(&key).unwrap()] });
            let jwt = sign(&json!({"sub": "x"}), json!({"typ": "JWT"}), &key, None).unwrap();
            let (h, p) = verify(&jwt, Some(&jwks), None).unwrap();
            assert_eq!(h["alg"], alg);
            assert_eq!(p["sub"], "x");
            let other = generate(alg).unwrap();
            let tampered = sign(&json!({"sub": "x"}), json!({"kid": key.key_id().unwrap()}), &other, None).unwrap();
            assert!(verify(&tampered, Some(&jwks), None).is_err());
        }
        let hs = sign(&json!({"a": 1}), json!({}), &oct_key("secretsecretsecretsecretsecret!!"), Some("HS256")).unwrap();
        assert!(verify(&hs, None, Some("secretsecretsecretsecretsecret!!")).is_ok());
        assert!(verify(&unsigned(&json!({}), json!({})).unwrap(), None, None).is_err());
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = Jwk::generate_rsa_key(2048).unwrap();
        let jwe = encrypt(b"hello", &public(&key).unwrap(), "RSA-OAEP-256", "A256GCM", None).unwrap();
        assert!(is_jwe(&jwe));
        assert_eq!(decrypt(&jwe, &key).unwrap(), b"hello");
    }

    #[test]
    fn at_hash_example() {
        // OpenID Connect Core A.3/A.4 example: access token "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y"
        assert_eq!(half_hash("RS256", "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y").unwrap(), "77QmUPtjPfzWtF2AnpK9RQ");
    }
}
