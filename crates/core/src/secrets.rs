//! Secret resolution: OS keychain on desktops, environment variables or files in CI.

use crate::model::SecretRef;
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::Path;

pub const KEYRING_SERVICE: &str = "grantcentral";

/// Resolves every secret. Secrets that cannot be resolved are left out and
/// reported in the second value; using one in a template then fails.
pub fn resolve(refs: &BTreeMap<String, SecretRef>, root: &Path) -> (BTreeMap<String, String>, Vec<String>) {
    let mut values = BTreeMap::new();
    let mut problems = vec![];
    for (name, r) in refs {
        match resolve_one(r, root) {
            Ok(v) => {
                values.insert(name.clone(), v);
            }
            Err(e) => problems.push(format!("secret `{name}`: {e:#}")),
        }
    }
    (values, problems)
}

fn resolve_one(r: &SecretRef, root: &Path) -> Result<String> {
    match r {
        SecretRef::Literal(v) => Ok(v.clone()),
        SecretRef::Env { env } => std::env::var(env).with_context(|| format!("environment variable {env} is not set")),
        SecretRef::File { file } => Ok(std::fs::read_to_string(root.join(file))
            .with_context(|| format!("reading {file}"))?
            .trim_end_matches(['\r', '\n'])
            .to_string()),
        SecretRef::Keyring { keyring } => keyring::Entry::new(KEYRING_SERVICE, keyring)
            .and_then(|e| e.get_password())
            .with_context(|| format!("keychain entry {KEYRING_SERVICE}/{keyring}")),
    }
}

pub fn store_in_keyring(account: &str, value: &str) -> Result<()> {
    keyring::Entry::new(KEYRING_SERVICE, account)?.set_password(value)?;
    Ok(())
}
