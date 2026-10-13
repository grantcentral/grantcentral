//! JWS, JWE and JWK helpers on top of aws-lc-rs, the library rustls already
//! links. Serializations are assembled by hand so callers fully control the
//! header (a test tool needs to send odd `typ` values and the like), and JWKs
//! stay plain JSON objects so unknown members survive.

use anyhow::{Context, Result, anyhow, bail, ensure};
use aws_lc_rs::encoding::{AsBigEndian, AsDer};
use aws_lc_rs::key_wrap::{KeyEncryptionKey, KeyWrap};
use aws_lc_rs::signature::{self, EcdsaKeyPair, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use aws_lc_rs::{aead, agreement, cipher, digest, hmac, key_wrap, rand, rsa};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{Map, Value, json};

/// A JWK, as its JSON object.
pub type Jwk = Map<String, Value>;

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
        let Value::Object(jwk) = v else { bail!("a JWK must be a JSON object") };
        ensure!(jwk.get("kty").is_some_and(Value::is_string), "JWK lacks kty");
        return Ok(jwk);
    }
    let not_a_key = || anyhow!("not a JWK or a PEM private key (RSA, EC or Ed25519)");
    match PrivateKeyDer::from_pem_slice(bytes).map_err(|_| not_a_key())? {
        PrivateKeyDer::Pkcs1(k) => rsa_jwk(k.secret_pkcs1_der()),
        PrivateKeyDer::Sec1(k) => ec_jwk_from(|alg| EcdsaKeyPair::from_private_key_der(alg, k.secret_sec1_der())),
        PrivateKeyDer::Pkcs8(k) => {
            let der = k.secret_pkcs8_der();
            if rsa::KeyPair::from_pkcs8(der).is_ok() {
                rsa_jwk(pkcs8_inner(der)?)
            } else if let Ok(k) = Ed25519KeyPair::from_pkcs8_maybe_unchecked(der) {
                ed_jwk(&k)
            } else {
                ec_jwk_from(|alg| EcdsaKeyPair::from_pkcs8(alg, der))
            }
        }
        _ => Err(not_a_key()),
    }
}

/// Generates a key for a JWS algorithm.
pub fn generate(alg: &str) -> Result<Jwk> {
    let mut jwk = match alg {
        "ES256" | "ES384" | "ES512" => {
            let crv = ec_curve(alg);
            ec_jwk(crv, &EcdsaKeyPair::generate(ec_signing(crv)?)?)?
        }
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" => {
            rsa_jwk(pkcs8_inner(rsa::KeyPair::generate(rsa::KeySize::Rsa2048)?.as_der()?.as_ref())?)?
        }
        "EdDSA" | "Ed25519" => ed_jwk(&Ed25519KeyPair::generate()?)?,
        other => bail!("cannot generate a key for {other}"),
    };
    jwk.insert("alg".into(), (if alg == "Ed25519" { "EdDSA" } else { alg }).into());
    let tp = thumbprint(&public(&jwk)?)?;
    jwk.insert("kid".into(), tp.into());
    Ok(jwk)
}

/// The public part of a key as JSON.
pub fn public(jwk: &Jwk) -> Result<Value> {
    let material: &[&str] = match member(jwk, "kty") {
        Some("RSA") => &["n", "e"],
        Some("EC") => &["crv", "x", "y"],
        Some("OKP") => &["crv", "x"],
        Some("oct") => bail!("symmetric keys have no public part"),
        other => bail!("unknown kty {other:?}"),
    };
    let mut m = Map::new();
    for k in ["kty", "use", "kid", "alg", "key_ops", "x5c", "x5t#S256"].iter().chain(material) {
        if let Some(v) = jwk.get(*k) {
            m.insert(k.to_string(), v.clone());
        }
    }
    Ok(Value::Object(m))
}

/// The JWS algorithm to use with a key when none is configured.
pub fn default_alg(jwk: &Jwk) -> &'static str {
    if let Some(a) = member(jwk, "alg") {
        for known in ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA", "HS256", "HS384", "HS512"] {
            if a == known {
                return known;
            }
        }
    }
    match (member(jwk, "kty"), member(jwk, "crv")) {
        (Some("EC"), Some("P-384")) => "ES384",
        (Some("EC"), Some("P-521")) => "ES512",
        (Some("EC"), _) => "ES256",
        (Some("OKP"), _) => "EdDSA",
        (Some("oct"), _) => "HS256",
        _ => "RS256",
    }
}

/// An HMAC key from a shared secret (client_secret_jwt, HS* ID tokens).
pub fn oct_key(secret: &str) -> Jwk {
    let mut jwk = Map::new();
    jwk.insert("kty".into(), "oct".into());
    jwk.insert("k".into(), crate::b64(secret.as_bytes()).into());
    jwk
}

/// Signs `claims`. `header` may add or override members; `alg` and `kid` are filled in.
pub fn sign(claims: &Value, header: Value, jwk: &Jwk, alg: Option<&str>) -> Result<String> {
    let alg = alg.unwrap_or_else(|| default_alg(jwk));
    let mut h = Map::new();
    h.insert("alg".into(), alg.into());
    if let Some(kid) = member(jwk, "kid") {
        h.insert("kid".into(), kid.into());
    }
    if let Value::Object(extra) = header {
        h.extend(extra);
    }
    let input = format!("{}.{}", crate::b64(&serde_json::to_vec(&h)?), crate::b64(&serde_json::to_vec(claims)?));
    let sig = sign_bytes(alg, jwk, input.as_bytes())?;
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
        verify_bytes(alg, &oct_key(secret), input.as_bytes(), &sig).map_err(|_| anyhow!("signature does not verify"))?;
        return Ok((header, payload));
    }
    let keys = jwks.and_then(|j| j["keys"].as_array()).ok_or_else(|| anyhow!("no JWKS available to verify the signature"))?;
    let kid = header["kid"].as_str();
    let candidates: Vec<&Jwk> = keys
        .iter()
        .filter_map(Value::as_object)
        .filter(|k| kid.is_none_or(|kid| member(k, "kid") == Some(kid)))
        .filter(|k| member(k, "use").is_none_or(|u| u == "sig"))
        .filter(|k| member(k, "alg").is_none_or(|a| a == alg))
        .filter(|k| member(k, "kty") == Some(kty_for(alg)))
        .collect();
    if candidates.is_empty() {
        bail!("no key in the JWKS matches kid {:?} and alg {alg}", kid.unwrap_or("-"));
    }
    if candidates.iter().any(|k| verify_bytes(alg, k, input.as_bytes(), &sig).is_ok()) {
        return Ok((header, payload));
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

fn sign_bytes(alg: &str, jwk: &Jwk, input: &[u8]) -> Result<Vec<u8>> {
    Ok(match alg {
        "HS256" | "HS384" | "HS512" => hmac::sign(&hmac::Key::new(hmac_alg(alg), &bytes(jwk, "k")?), input).as_ref().to_vec(),
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" => {
            let key = rsa_key_pair(jwk)?;
            let mut sig = vec![0; key.public_modulus_len()];
            key.sign(rsa_encoding(alg), &rand::SystemRandom::new(), input, &mut sig)?;
            sig
        }
        "ES256" | "ES384" | "ES512" => ec_key_pair(jwk, ec_curve(alg))?.sign(&rand::SystemRandom::new(), input)?.as_ref().to_vec(),
        "EdDSA" => {
            ensure!(member(jwk, "crv") == Some("Ed25519"), "EdDSA needs an Ed25519 key");
            Ed25519KeyPair::from_seed_and_public_key(&bytes(jwk, "d")?, &bytes(jwk, "x")?)?.sign(input).as_ref().to_vec()
        }
        other => bail!("unsupported JWS algorithm {other}"),
    })
}

fn verify_bytes(alg: &str, jwk: &Jwk, input: &[u8], sig: &[u8]) -> Result<()> {
    match alg {
        "HS256" | "HS384" | "HS512" => hmac::verify(&hmac::Key::new(hmac_alg(alg), &bytes(jwk, "k")?), input, sig)?,
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" => rsa_public(jwk)?.verify(rsa_params(alg), input, sig)?,
        "ES256" | "ES384" | "ES512" => {
            let crv = ec_curve(alg);
            ensure!(member(jwk, "crv") == Some(crv), "{alg} needs a {crv} key");
            let verifying = match alg {
                "ES256" => &signature::ECDSA_P256_SHA256_FIXED,
                "ES384" => &signature::ECDSA_P384_SHA384_FIXED,
                _ => &signature::ECDSA_P521_SHA512_FIXED,
            };
            UnparsedPublicKey::new(verifying, ec_point(jwk)?).verify(input, sig)?
        }
        "EdDSA" => {
            ensure!(member(jwk, "crv") == Some("Ed25519"), "EdDSA needs an Ed25519 key");
            UnparsedPublicKey::new(&signature::ED25519, bytes(jwk, "x")?).verify(input, sig)?
        }
        other => bail!("unsupported JWS algorithm {other}"),
    }
    Ok(())
}

fn hmac_alg(alg: &str) -> hmac::Algorithm {
    match &alg[2..] {
        "256" => hmac::HMAC_SHA256,
        "384" => hmac::HMAC_SHA384,
        _ => hmac::HMAC_SHA512,
    }
}

fn rsa_encoding(alg: &str) -> &'static dyn signature::RsaEncoding {
    match alg {
        "RS256" => &signature::RSA_PKCS1_SHA256,
        "RS384" => &signature::RSA_PKCS1_SHA384,
        "RS512" => &signature::RSA_PKCS1_SHA512,
        "PS256" => &signature::RSA_PSS_SHA256,
        "PS384" => &signature::RSA_PSS_SHA384,
        _ => &signature::RSA_PSS_SHA512,
    }
}

fn rsa_params(alg: &str) -> &'static signature::RsaParameters {
    match alg {
        "RS256" => &signature::RSA_PKCS1_2048_8192_SHA256,
        "RS384" => &signature::RSA_PKCS1_2048_8192_SHA384,
        "RS512" => &signature::RSA_PKCS1_2048_8192_SHA512,
        "PS256" => &signature::RSA_PSS_2048_8192_SHA256,
        "PS384" => &signature::RSA_PSS_2048_8192_SHA384,
        _ => &signature::RSA_PSS_2048_8192_SHA512,
    }
}

// ------------------------------------------------------------------- keys

fn member<'a>(jwk: &'a Jwk, name: &str) -> Option<&'a str> {
    jwk.get(name).and_then(Value::as_str)
}

/// A base64url-encoded JWK member.
fn bytes(jwk: &Jwk, name: &str) -> Result<Vec<u8>> {
    let v = member(jwk, name).ok_or_else(|| anyhow!("JWK lacks {name}"))?;
    crate::unb64(v).with_context(|| format!("JWK member {name}"))
}

const RSA_MEMBERS: [&str; 8] = ["n", "e", "d", "p", "q", "dp", "dq", "qi"];

fn rsa_key_pair(jwk: &Jwk) -> Result<rsa::KeyPair> {
    let m = RSA_MEMBERS.iter().map(|m| bytes(jwk, m)).collect::<Result<Vec<_>>>()?;
    let [n, e, d, p, q, dp, dq, qi]: [Vec<u8>; 8] = m.try_into().unwrap();
    let components = rsa::KeyPairComponents { public_key: rsa::PublicKeyComponents { n, e }, d, p, q, dP: dp, dQ: dq, qInv: qi };
    rsa::KeyPair::from_components(&components).context("invalid RSA private key")
}

fn rsa_public(jwk: &Jwk) -> Result<rsa::PublicKeyComponents<Vec<u8>>> {
    Ok(rsa::PublicKeyComponents { n: bytes(jwk, "n")?, e: bytes(jwk, "e")? })
}

/// An RSA JWK from a PKCS#1 RSAPrivateKey (RFC 8017 A.1.2).
fn rsa_jwk(pkcs1: &[u8]) -> Result<Jwk> {
    let (mut body, _) = der(0x30, pkcs1)?;
    (_, body) = der(0x02, body)?; // version
    let mut jwk = Map::new();
    jwk.insert("kty".into(), "RSA".into());
    for name in RSA_MEMBERS {
        let (int, rest) = der(0x02, body)?;
        // JWK integers are unsigned and minimal; DER may add a sign byte.
        let start = int.iter().position(|b| *b != 0).unwrap_or(int.len().saturating_sub(1));
        jwk.insert(name.into(), crate::b64(&int[start..]).into());
        body = rest;
    }
    Ok(jwk)
}

/// The algorithm-specific key inside a PKCS#8 PrivateKeyInfo (RFC 5208 §5).
fn pkcs8_inner(pkcs8: &[u8]) -> Result<&[u8]> {
    let (body, _) = der(0x30, pkcs8)?;
    let (_, body) = der(0x02, body)?; // version
    let (_, body) = der(0x30, body)?; // algorithm
    Ok(der(0x04, body)?.0)
}

/// Splits one DER element with the given tag off `input`: (contents, rest).
fn der(tag: u8, input: &[u8]) -> Result<(&[u8], &[u8])> {
    let [t, len, rest @ ..] = input else { bail!("truncated DER") };
    ensure!(*t == tag, "unexpected DER tag {t:#04x}, expected {tag:#04x}");
    let (len, rest) = if *len < 0x80 {
        (*len as usize, rest)
    } else {
        let n = (len & 0x7f) as usize;
        ensure!((1..=4).contains(&n) && rest.len() >= n, "bad DER length");
        let (len, rest) = rest.split_at(n);
        (len.iter().fold(0, |acc, b| acc << 8 | *b as usize), rest)
    };
    ensure!(rest.len() >= len, "truncated DER");
    Ok(rest.split_at(len))
}

fn ec_curve(alg: &str) -> &'static str {
    match alg {
        "ES256" => "P-256",
        "ES384" => "P-384",
        _ => "P-521",
    }
}

fn ec_signing(crv: &str) -> Result<&'static signature::EcdsaSigningAlgorithm> {
    Ok(match crv {
        "P-256" => &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        "P-384" => &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
        "P-521" => &signature::ECDSA_P521_SHA512_FIXED_SIGNING,
        other => bail!("unsupported EC curve {other}"),
    })
}

fn ec_key_pair(jwk: &Jwk, crv: &str) -> Result<EcdsaKeyPair> {
    ensure!(member(jwk, "crv") == Some(crv), "this algorithm needs a {crv} key");
    EcdsaKeyPair::from_private_key_and_public_key(ec_signing(crv)?, &bytes(jwk, "d")?, &ec_point(jwk)?).context("invalid EC private key")
}

/// The uncompressed SEC1 point of an EC JWK.
fn ec_point(jwk: &Jwk) -> Result<Vec<u8>> {
    Ok([vec![4], bytes(jwk, "x")?, bytes(jwk, "y")?].concat())
}

fn ec_public_jwk(crv: &str, point: &[u8]) -> Jwk {
    let (x, y) = point[1..].split_at((point.len() - 1) / 2);
    let v = json!({ "kty": "EC", "crv": crv, "x": crate::b64(x), "y": crate::b64(y) });
    v.as_object().unwrap().clone()
}

fn ec_jwk(crv: &str, key: &EcdsaKeyPair) -> Result<Jwk> {
    let mut jwk = ec_public_jwk(crv, key.public_key().as_ref());
    jwk.insert("d".into(), crate::b64(key.private_key().as_be_bytes()?.as_ref()).into());
    Ok(jwk)
}

/// An EC JWK from a DER key of unknown curve.
fn ec_jwk_from<E>(parse: impl Fn(&'static signature::EcdsaSigningAlgorithm) -> Result<EcdsaKeyPair, E>) -> Result<Jwk> {
    for crv in ["P-256", "P-384", "P-521"] {
        if let Ok(key) = parse(ec_signing(crv)?) {
            return ec_jwk(crv, &key);
        }
    }
    bail!("not an RSA, EC (P-256, P-384, P-521) or Ed25519 private key")
}

fn ed_jwk(key: &Ed25519KeyPair) -> Result<Jwk> {
    let v = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": crate::b64(key.public_key().as_ref()),
        "d": crate::b64(key.seed()?.as_be_bytes()?.as_ref()),
    });
    Ok(v.as_object().unwrap().clone())
}

// -------------------------------------------------------------------- JWE

pub const SUPPORTED_JWE_ALGS: &[&str] =
    &["RSA-OAEP-256", "ECDH-ES+A256KW", "ECDH-ES+A128KW", "ECDH-ES", "RSA-OAEP-384", "RSA-OAEP-512", "RSA-OAEP"];

/// Encrypts `payload` to a public key (nested JWT when `cty` is "JWT").
pub fn encrypt(payload: &[u8], key: &Value, alg: &str, enc: &str, cty: Option<&str>) -> Result<String> {
    let jwk = key.as_object().ok_or_else(|| anyhow!("the encryption key is not a JSON object"))?;
    let mut header = json!({ "alg": alg, "enc": enc });
    if let Some(kid) = jwk.get("kid") {
        header["kid"] = kid.clone();
    }
    if let Some(cty) = cty {
        header["cty"] = cty.into();
    }
    let len = cek_len(enc)?;
    let (cek, encrypted_key) = if let Some(oaep) = oaep(alg) {
        let cek = random(len)?;
        let key = rsa::OaepPublicEncryptingKey::new(rsa_public(jwk)?.try_into()?)?;
        let mut out = vec![0; key.ciphertext_size()];
        let encrypted_key = key.encrypt(oaep, &cek, &mut out, None)?.to_vec();
        (cek, encrypted_key)
    } else if alg == "ECDH-ES" || kw_len(alg).is_some() {
        let curve = ecdh_alg(jwk)?;
        let ephemeral = agreement::PrivateKey::generate(curve)?;
        let epk = ephemeral.compute_public_key()?;
        header["epk"] = match member(jwk, "crv") {
            Some("X25519") => json!({ "kty": "OKP", "crv": "X25519", "x": crate::b64(epk.as_ref()) }),
            crv => Value::Object(ec_public_jwk(crv.unwrap_or_default(), epk.as_ref())),
        };
        match kw_len(alg) {
            None => (agree(&ephemeral, jwk, enc, b"", b"", len)?, vec![]),
            Some(kw) => {
                let cek = random(len)?;
                let wrapped = wrap(&agree(&ephemeral, jwk, alg, b"", b"", kw)?, &cek)?;
                (cek, wrapped)
            }
        }
    } else {
        bail!("unsupported JWE algorithm {alg}");
    };
    let protected = crate::b64(&serde_json::to_vec(&header)?);
    let iv = random(if enc.ends_with("GCM") { 12 } else { 16 })?;
    let (ciphertext, tag) = seal(enc, &cek, protected.as_bytes(), &iv, payload)?;
    Ok([protected, crate::b64(&encrypted_key), crate::b64(&iv), crate::b64(&ciphertext), crate::b64(&tag)].join("."))
}

/// Decrypts a JWE with a private key. Returns the plaintext.
pub fn decrypt(token: &str, jwk: &Jwk) -> Result<Vec<u8>> {
    let [protected, encrypted_key, iv, ciphertext, tag] = token.split('.').collect::<Vec<_>>()[..] else {
        bail!("not a JWE compact serialization");
    };
    let header: Value = serde_json::from_slice(&crate::unb64(protected)?).context("JWE header is not JSON")?;
    let alg = header["alg"].as_str().unwrap_or("");
    let enc = header["enc"].as_str().unwrap_or("");
    ensure!(header.get("zip").is_none(), "compressed JWEs (zip) are not supported");
    let len = cek_len(enc)?;
    let encrypted_key = crate::unb64(encrypted_key)?;
    let cek = if let Some(oaep) = oaep(alg) {
        let key = rsa::OaepPrivateDecryptingKey::new(rsa::PrivateDecryptingKey::from_pkcs8(rsa_key_pair(jwk)?.as_der()?.as_ref())?)?;
        let mut out = vec![0; key.min_output_size()];
        key.decrypt(oaep, &encrypted_key, &mut out, None).map_err(|_| anyhow!("the JWE encrypted key does not decrypt"))?.to_vec()
    } else if alg == "ECDH-ES" || kw_len(alg).is_some() {
        let epk = header["epk"].as_object().ok_or_else(|| anyhow!("ECDH-ES JWE has no epk"))?;
        let private = agreement::PrivateKey::from_private_key(ecdh_alg(jwk)?, &bytes(jwk, "d")?).context("invalid ECDH private key")?;
        let party = |name: &str| header[name].as_str().map(crate::unb64).transpose().map(Option::unwrap_or_default);
        let (apu, apv) = (party("apu")?, party("apv")?);
        match kw_len(alg) {
            None => {
                ensure!(encrypted_key.is_empty(), "ECDH-ES JWE must have an empty encrypted key");
                agree(&private, epk, enc, &apu, &apv, len)?
            }
            Some(kw) => unwrap(&agree(&private, epk, alg, &apu, &apv, kw)?, &encrypted_key)?,
        }
    } else {
        bail!("unsupported JWE algorithm {alg}");
    };
    ensure!(cek.len() == len, "the content encryption key has the wrong length for {enc}");
    open(enc, &cek, protected.as_bytes(), &crate::unb64(iv)?, &crate::unb64(ciphertext)?, &crate::unb64(tag)?)
}

fn oaep(alg: &str) -> Option<&'static rsa::OaepAlgorithm> {
    Some(match alg {
        "RSA-OAEP" => &rsa::OAEP_SHA1_MGF1SHA1,
        "RSA-OAEP-256" => &rsa::OAEP_SHA256_MGF1SHA256,
        "RSA-OAEP-384" => &rsa::OAEP_SHA384_MGF1SHA384,
        "RSA-OAEP-512" => &rsa::OAEP_SHA512_MGF1SHA512,
        _ => return None,
    })
}

/// Key-wrapping key length of an ECDH-ES+AxxxKW algorithm. aws-lc-rs has no
/// AES-192 key wrap, so A192KW is unsupported.
fn kw_len(alg: &str) -> Option<usize> {
    match alg {
        "ECDH-ES+A128KW" => Some(16),
        "ECDH-ES+A256KW" => Some(32),
        _ => None,
    }
}

/// Content encryption key length of an `enc` algorithm (RFC 7518 §5.1).
fn cek_len(enc: &str) -> Result<usize> {
    Ok(match enc {
        "A128GCM" => 16,
        "A192GCM" => 24,
        "A256GCM" | "A128CBC-HS256" => 32,
        "A192CBC-HS384" => 48,
        "A256CBC-HS512" => 64,
        other => bail!("unsupported JWE content encryption {other}"),
    })
}

fn random(n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0; n];
    rand::fill(&mut buf)?;
    Ok(buf)
}

fn ecdh_alg(jwk: &Jwk) -> Result<&'static agreement::Algorithm> {
    Ok(match member(jwk, "crv") {
        Some("P-256") => &agreement::ECDH_P256,
        Some("P-384") => &agreement::ECDH_P384,
        Some("P-521") => &agreement::ECDH_P521,
        Some("X25519") => &agreement::X25519,
        other => bail!("ECDH-ES needs a P-256, P-384, P-521 or X25519 key, not {other:?}"),
    })
}

/// ECDH followed by the Concat KDF with SHA-256 (RFC 7518 §4.6.2).
fn agree(private: &agreement::PrivateKey, peer: &Jwk, alg_id: &str, apu: &[u8], apv: &[u8], len: usize) -> Result<Vec<u8>> {
    let point = if member(peer, "crv") == Some("X25519") { bytes(peer, "x")? } else { ec_point(peer)? };
    let peer = agreement::UnparsedPublicKey::new(ecdh_alg(peer)?, point);
    let z = agreement::agree(private, peer, anyhow!("ECDH key agreement failed (curve mismatch or invalid point)"), |z| Ok(z.to_vec()))?;
    let mut out = Vec::new();
    for counter in 1u32.. {
        if out.len() >= len {
            break;
        }
        let mut ctx = digest::Context::new(&digest::SHA256);
        ctx.update(&counter.to_be_bytes());
        ctx.update(&z);
        for field in [alg_id.as_bytes(), apu, apv] {
            ctx.update(&(field.len() as u32).to_be_bytes());
            ctx.update(field);
        }
        ctx.update(&(len as u32 * 8).to_be_bytes());
        out.extend_from_slice(ctx.finish().as_ref());
    }
    out.truncate(len);
    Ok(out)
}

fn kek(key: &[u8]) -> Result<KeyEncryptionKey<key_wrap::AesBlockCipher>> {
    let cipher = if key.len() == 16 { &key_wrap::AES_128 } else { &key_wrap::AES_256 };
    Ok(KeyEncryptionKey::new(cipher, key)?)
}

fn wrap(key: &[u8], cek: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![0; cek.len() + 8];
    let n = kek(key)?.wrap(cek, &mut out)?.len();
    out.truncate(n);
    Ok(out)
}

fn unwrap(key: &[u8], wrapped: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![0; wrapped.len()];
    let n = kek(key)?.unwrap(wrapped, &mut out).map_err(|_| anyhow!("the JWE encrypted key does not unwrap"))?.len();
    out.truncate(n);
    Ok(out)
}

fn gcm(enc: &str) -> Option<&'static aead::Algorithm> {
    Some(match enc {
        "A128GCM" => &aead::AES_128_GCM,
        "A192GCM" => &aead::AES_192_GCM,
        "A256GCM" => &aead::AES_256_GCM,
        _ => return None,
    })
}

/// AES-CBC keyed with the second half of an AES_CBC_HMAC_SHA2 key (RFC 7518 §5.2.2.1).
fn cbc_key(cek: &[u8]) -> Result<cipher::UnboundCipherKey> {
    let key = &cek[cek.len() / 2..];
    let alg = match key.len() {
        16 => &cipher::AES_128,
        24 => &cipher::AES_192,
        _ => &cipher::AES_256,
    };
    Ok(cipher::UnboundCipherKey::new(alg, key)?)
}

/// The AES_CBC_HMAC_SHA2 tag: the HMAC, keyed with the first half of the key, truncated to its length.
fn cbc_tag(cek: &[u8], aad: &[u8], iv: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mac_key = &cek[..cek.len() / 2];
    let alg = match mac_key.len() {
        16 => hmac::HMAC_SHA256,
        24 => hmac::HMAC_SHA384,
        _ => hmac::HMAC_SHA512,
    };
    let mut ctx = hmac::Context::with_key(&hmac::Key::new(alg, mac_key));
    for part in [aad, iv, ciphertext, &(aad.len() as u64 * 8).to_be_bytes()] {
        ctx.update(part);
    }
    ctx.sign().as_ref()[..mac_key.len()].to_vec()
}

/// Content encryption: (ciphertext, tag).
fn seal(enc: &str, cek: &[u8], aad: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = plaintext.to_vec();
    if let Some(alg) = gcm(enc) {
        let key = aead::LessSafeKey::new(aead::UnboundKey::new(alg, cek)?);
        let tag = key.seal_in_place_separate_tag(aead::Nonce::try_assume_unique_for_key(iv)?, aead::Aad::from(aad), &mut buf)?;
        return Ok((buf, tag.as_ref().to_vec()));
    }
    let iv16 = <[u8; 16]>::try_from(iv).context("AES-CBC needs a 16-byte IV")?;
    cipher::PaddedBlockEncryptingKey::cbc_pkcs7(cbc_key(cek)?)?
        .less_safe_encrypt(&mut buf, cipher::EncryptionContext::Iv128(iv16.into()))?;
    let tag = cbc_tag(cek, aad, iv, &buf);
    Ok((buf, tag))
}

fn open(enc: &str, cek: &[u8], aad: &[u8], iv: &[u8], ciphertext: &[u8], tag: &[u8]) -> Result<Vec<u8>> {
    let mut buf = ciphertext.to_vec();
    let bad_tag = || anyhow!("the JWE authentication tag does not match");
    let n = if let Some(alg) = gcm(enc) {
        buf.extend_from_slice(tag);
        let key = aead::LessSafeKey::new(aead::UnboundKey::new(alg, cek)?);
        key.open_in_place(aead::Nonce::try_assume_unique_for_key(iv)?, aead::Aad::from(aad), &mut buf).map_err(|_| bad_tag())?.len()
    } else {
        aws_lc_rs::constant_time::verify_slices_are_equal(&cbc_tag(cek, aad, iv, ciphertext), tag).map_err(|_| bad_tag())?;
        let iv16 = <[u8; 16]>::try_from(iv).context("AES-CBC needs a 16-byte IV")?;
        cipher::PaddedBlockDecryptingKey::cbc_pkcs7(cbc_key(cek)?)?.decrypt(&mut buf, cipher::DecryptionContext::Iv128(iv16.into()))?.len()
    };
    buf.truncate(n);
    Ok(buf)
}

// ------------------------------------------------------------ thumbprints

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
    let cert = CertificateDer::from_pem_slice(pem).map_err(|e| anyhow!("parsing client certificate: {e}"))?;
    Ok(crate::b64(&crate::sha256(&cert)))
}

/// Left-half hash for `at_hash` / `c_hash` (OpenID Connect Core §3.1.3.6).
pub fn half_hash(alg: &str, value: &str) -> Option<String> {
    let md = match alg {
        a if a.ends_with("256") => &digest::SHA256,
        a if a.ends_with("384") => &digest::SHA384,
        a if a.ends_with("512") || a == "EdDSA" => &digest::SHA512,
        _ => return None,
    };
    let h = digest::digest(md, value.as_bytes());
    Some(crate::b64(&h.as_ref()[..h.as_ref().len() / 2]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(v: Value) -> Jwk {
        v.as_object().unwrap().clone()
    }

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

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
        for alg in ["ES256", "ES384", "ES512", "RS256", "PS384", "EdDSA"] {
            let key = generate(alg).unwrap();
            let jwks = json!({ "keys": [public(&key).unwrap()] });
            let jwt = sign(&json!({"sub": "x"}), json!({"typ": "JWT"}), &key, None).unwrap();
            let (h, p) = verify(&jwt, Some(&jwks), None).unwrap();
            assert_eq!(h["alg"], alg);
            assert_eq!(p["sub"], "x");
            let other = generate(alg).unwrap();
            let tampered = sign(&json!({"sub": "x"}), json!({"kid": key["kid"]}), &other, None).unwrap();
            assert!(verify(&tampered, Some(&jwks), None).is_err());
        }
        let hs = sign(&json!({"a": 1}), json!({}), &oct_key("secretsecretsecretsecretsecret!!"), Some("HS256")).unwrap();
        assert!(verify(&hs, None, Some("secretsecretsecretsecretsecret!!")).is_ok());
        assert!(verify(&hs, None, Some("wrong")).is_err());
        assert!(verify(&unsigned(&json!({}), json!({})).unwrap(), None, None).is_err());
        // An ES384 signature from a P-256 key must not be produced.
        assert!(sign(&json!({}), json!({}), &generate("ES256").unwrap(), Some("ES384")).is_err());
    }

    #[test]
    fn pem_keys() {
        use base64::Engine as _;
        let pem = |label: &str, der: &[u8]| {
            format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", base64::engine::general_purpose::STANDARD.encode(der))
        };
        let rsa = rsa::KeyPair::generate(rsa::KeySize::Rsa2048).unwrap().as_der().unwrap();
        let ec = EcdsaKeyPair::generate(&signature::ECDSA_P384_SHA384_FIXED_SIGNING).unwrap().to_pkcs8v1().unwrap();
        let ed = Ed25519KeyPair::generate().unwrap().to_pkcs8().unwrap();
        let ec1 = EcdsaKeyPair::generate(&signature::ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
        let sec1 = ec1.private_key().as_der().unwrap();
        for (file, alg) in [
            (pem("PRIVATE KEY", rsa.as_ref()), "PS256"),
            (pem("RSA PRIVATE KEY", pkcs8_inner(rsa.as_ref()).unwrap()), "RS256"),
            (pem("PRIVATE KEY", ec.as_ref()), "ES384"),
            (pem("EC PRIVATE KEY", sec1.as_ref()), "ES256"),
            (pem("PRIVATE KEY", ed.as_ref()), "EdDSA"),
        ] {
            let key = parse_key(file.as_bytes()).unwrap();
            assert_eq!(default_alg(&key), if alg == "PS256" { "RS256" } else { alg });
            let jwt = sign(&json!({}), json!({}), &key, Some(alg)).unwrap();
            assert!(verify(&jwt, Some(&json!({ "keys": [public(&key).unwrap()] })), None).is_ok(), "{alg}");
        }
        assert!(parse_key(b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n").is_err());
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let rsa = generate("RS256").unwrap();
        let ec = generate("ES256").unwrap();
        for alg in SUPPORTED_JWE_ALGS {
            let key = if alg.starts_with("RSA") { &rsa } else { &ec };
            for enc in ["A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"] {
                let jwe = encrypt(b"hello", &public(key).unwrap(), alg, enc, None).unwrap();
                assert!(is_jwe(&jwe));
                assert_eq!(decrypt(&jwe, key).unwrap(), b"hello", "{alg} {enc}");
                // Flip a ciphertext bit.
                let mut parts: Vec<String> = jwe.split('.').map(str::to_string).collect();
                let mut ct = crate::unb64(&parts[3]).unwrap();
                ct[0] ^= 1;
                parts[3] = crate::b64(&ct);
                assert!(decrypt(&parts.join("."), key).is_err(), "{alg} {enc}");
            }
        }
    }

    #[test]
    fn rfc7516_a1_rsa_oaep_a256gcm() {
        let key = obj(
            json!({"kty":"RSA","n":"oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2djYgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw","e":"AQAB","d":"kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5NWV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD93Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghkqDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vlt3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSndVTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ","p":"1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lffNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0","q":"wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBmUDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aXIWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc","dp":"ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KLhMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE","dq":"Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCjywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDBUfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis","qi":"VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY"}),
        );
        let jwe = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ";
        assert_eq!(decrypt(jwe, &key).unwrap(), b"The true sign of intelligence is not knowledge but imagination.");
    }

    #[test]
    fn rfc7518_b1_aes_128_cbc_hmac_sha_256() {
        let k = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let p = hex(
            "41206369706865722073797374656d206d757374206e6f7420626520726571756972656420746f206265207365637265742c20616e64206974206d7573742062652061626c6520746f2066616c6c20696e746f207468652068616e6473206f662074686520656e656d7920776974686f757420696e636f6e76656e69656e6365",
        );
        let iv = hex("1af38c2dc2b96ffdd86694092341bc04");
        let a = hex("546865207365636f6e64207072696e6369706c65206f662041756775737465204b6572636b686f666673");
        let e = hex(
            "c80edfa32ddf39d5ef00c0b468834279a2e46a1b8049f792f76bfe54b903a9c9a94ac9b47ad2655c5f10f9aef71427e2fc6f9b3f399a221489f16362c703233609d45ac69864e3321cf82935ac4096c86e133314c54019e8ca7980dfa4b9cf1b384c486f3a54c51078158ee5d79de59fbd34d848b3d69550a67646344427ade54b8851ffb598f7f80074b9473c82e2db",
        );
        let t = hex("652c3fa36b0a7c5b3219fab3a30bc1c4");
        assert_eq!(seal("A128CBC-HS256", &k, &a, &iv, &p).unwrap(), (e.clone(), t.clone()));
        assert_eq!(open("A128CBC-HS256", &k, &a, &iv, &e, &t).unwrap(), p);
    }

    #[test]
    fn rfc7518_c_ecdh_es() {
        let bob = obj(json!({"kty":"EC","crv":"P-256",
            "x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ","y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            "d":"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"}));
        let epk = obj(json!({"kty":"EC","crv":"P-256",
            "x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0","y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"}));
        let private = agreement::PrivateKey::from_private_key(&agreement::ECDH_P256, &bytes(&bob, "d").unwrap()).unwrap();
        let key = agree(&private, &epk, "A128GCM", b"Alice", b"Bob", 16).unwrap();
        assert_eq!(crate::b64(&key), "VqqN6vgjbSBcIijNcacQGg");
    }

    #[test]
    fn at_hash_example() {
        // OpenID Connect Core A.3/A.4 example: access token "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y"
        assert_eq!(half_hash("RS256", "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y").unwrap(), "77QmUPtjPfzWtF2AnpK9RQ");
    }
}
