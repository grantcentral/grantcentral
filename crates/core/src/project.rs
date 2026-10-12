//! A project is a directory (usually a git repository) of TOML files:
//!
//! ```text
//! grantcentral.toml
//! environments/<name>.toml        committed
//! environments/<name>.local.toml  git-ignored overrides, e.g. literal secrets
//! flows/**/*.toml
//! ```

use crate::model::{EnvironmentFile, Flow, ProjectFile};
use anyhow::{Context, Result, bail};
use std::path::{Component, Path, PathBuf};

pub const PROJECT_FILE: &str = "grantcentral.toml";

#[derive(Debug, Clone)]
pub struct Project {
    pub root: PathBuf,
    pub config: ProjectFile,
}

/// A file that failed to load.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Diagnostic {
    pub file: String,
    pub message: String,
}

impl Project {
    /// Opens the project containing `dir`, searching parent directories for
    /// `grantcentral.toml`. Falls back to `dir` itself.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = std::fs::canonicalize(dir.as_ref()).with_context(|| format!("opening {}", dir.as_ref().display()))?;
        let root = dir.ancestors().find(|d| d.join(PROJECT_FILE).is_file()).unwrap_or(&dir).to_path_buf();
        let config = match std::fs::read_to_string(root.join(PROJECT_FILE)) {
            Ok(s) => toml::from_str(&s).with_context(|| format!("in {PROJECT_FILE}"))?,
            Err(_) => ProjectFile::default(),
        };
        Ok(Project { root, config })
    }

    pub fn name(&self) -> String {
        self.config.name.clone().unwrap_or_else(|| self.root.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default())
    }

    /// Resolves a project-relative path, refusing anything that escapes the root.
    pub fn resolve(&self, rel: &str) -> Result<PathBuf> {
        let p = Path::new(rel);
        if p.components().any(|c| !matches!(c, Component::Normal(_) | Component::CurDir)) {
            bail!("path must stay inside the project: {rel}");
        }
        Ok(self.root.join(p))
    }

    pub fn read(&self, rel: &str) -> Result<String> {
        std::fs::read_to_string(self.resolve(rel)?).with_context(|| format!("reading {rel}"))
    }

    pub fn write(&self, rel: &str, content: &str) -> Result<()> {
        let path = self.resolve(rel)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, content).with_context(|| format!("writing {rel}"))
    }

    /// Environment names, from `environments/*.toml` without `*.local.toml`.
    pub fn environments(&self) -> Vec<String> {
        let mut names: Vec<String> = list(&self.root.join("environments"))
            .into_iter()
            .filter_map(|p| {
                let name = p.file_name()?.to_str()?;
                let stem = name.strip_suffix(".toml")?;
                (!stem.ends_with(".local")).then(|| stem.to_string())
            })
            .collect();
        names.sort();
        names.dedup();
        names
    }

    pub fn default_environment(&self) -> Option<String> {
        self.config.default_environment.clone().or_else(|| self.environments().into_iter().next())
    }

    /// Flow files relative to the root, using `/` separators.
    pub fn flows(&self) -> Vec<String> {
        let mut flows: Vec<String> = list(&self.root.join("flows"))
            .into_iter()
            .filter(|p| p.extension().is_some_and(|e| e == "toml"))
            .filter_map(|p| self.relative(&p))
            .collect();
        flows.sort();
        flows
    }

    /// Every file a user would edit: TOML, JSON and PEM files outside hidden and build directories.
    pub fn files(&self) -> Vec<String> {
        let mut files: Vec<String> = list(&self.root)
            .into_iter()
            .filter(|p| p.extension().is_some_and(|e| ["toml", "json", "pem", "crt", "key", "md"].contains(&e.to_str().unwrap_or(""))))
            .filter_map(|p| self.relative(&p))
            .collect();
        files.sort();
        files
    }

    fn relative(&self, p: &Path) -> Option<String> {
        let rel = p.strip_prefix(&self.root).ok()?;
        Some(rel.components().map(|c| c.as_os_str().to_string_lossy()).collect::<Vec<_>>().join("/"))
    }

    pub fn load_environment(&self, name: &str) -> Result<EnvironmentFile> {
        let base_rel = format!("environments/{name}.toml");
        let mut env: EnvironmentFile = parse(&base_rel, &self.read(&base_rel)?)?;
        let local_rel = format!("environments/{name}.local.toml");
        if let Ok(src) = self.read(&local_rel) {
            let local: EnvironmentFile = parse(&local_rel, &src)?;
            env.vars.extend(local.vars);
            env.secrets.extend(local.secrets);
            env.client = env.client.merged(&local.client);
        }
        Ok(env)
    }

    pub fn load_flow(&self, rel: &str) -> Result<Flow> {
        parse(rel, &self.read(rel)?)
    }

    /// Parses every environment and flow file.
    pub fn validate(&self) -> Vec<Diagnostic> {
        let mut out = vec![];
        if let Ok(s) = std::fs::read_to_string(self.root.join(PROJECT_FILE))
            && let Err(e) = parse::<ProjectFile>(PROJECT_FILE, &s)
        {
            out.push(Diagnostic { file: PROJECT_FILE.into(), message: format!("{e:#}") });
        }
        for env in self.environments() {
            if let Err(e) = self.load_environment(&env) {
                out.push(Diagnostic { file: format!("environments/{env}.toml"), message: format!("{e:#}") });
            }
        }
        for flow in self.flows() {
            if let Err(e) = self.load_flow(&flow) {
                out.push(Diagnostic { file: flow, message: format!("{e:#}") });
            }
        }
        out
    }
}

/// Parses a TOML file; the error message carries line, column and a source excerpt.
pub fn parse<T: serde::de::DeserializeOwned>(name: &str, src: &str) -> Result<T> {
    toml::from_str(src).map_err(|e| anyhow::anyhow!("{name}: {e}"))
}

fn list(dir: &Path) -> Vec<PathBuf> {
    let mut out = vec![];
    let Ok(rd) = std::fs::read_dir(dir) else { return out };
    for entry in rd.flatten() {
        let p = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') || name == "target" || name == "node_modules" {
            continue;
        }
        if p.is_dir() {
            out.extend(list(&p));
        } else {
            out.push(p);
        }
    }
    out
}

/// Files written by `grantcentral init`.
pub const SCAFFOLD: &[(&str, &str)] = &[
    (PROJECT_FILE, include_str!("../scaffold/grantcentral.toml")),
    (".gitignore", include_str!("../scaffold/gitignore")),
    ("environments/dev.toml", include_str!("../scaffold/environments/dev.toml")),
    ("environments/dev.local.toml", include_str!("../scaffold/environments/dev.local.toml")),
    ("flows/authorization-code.toml", include_str!("../scaffold/flows/authorization-code.toml")),
    ("flows/client-credentials.toml", include_str!("../scaffold/flows/client-credentials.toml")),
    ("flows/audit.toml", include_str!("../scaffold/flows/audit.toml")),
];

/// Writes the scaffold into `dir`, skipping files that already exist. Returns the files written.
pub fn init(dir: &Path) -> Result<Vec<String>> {
    let mut written = vec![];
    for (rel, content) in SCAFFOLD {
        let path = dir.join(rel);
        if path.exists() {
            continue;
        }
        std::fs::create_dir_all(path.parent().unwrap())?;
        std::fs::write(&path, content)?;
        written.push(rel.to_string());
    }
    write_schemas(dir)?;
    Ok(written)
}

/// Writes JSON schemas to `.grantcentral/schema/`, referenced by the `#:schema` comments in the scaffold.
pub fn write_schemas(dir: &Path) -> Result<()> {
    let schema_dir = dir.join(".grantcentral/schema");
    std::fs::create_dir_all(&schema_dir)?;
    for (name, schema) in crate::schemas() {
        std::fs::write(schema_dir.join(format!("{name}.json")), serde_json::to_string_pretty(&schema)?)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_refuses_escape() {
        let p = Project { root: "/x".into(), config: Default::default() };
        assert!(p.resolve("../etc/passwd").is_err());
        assert!(p.resolve("/etc/passwd").is_err());
        assert_eq!(p.resolve("flows/a.toml").unwrap(), PathBuf::from("/x/flows/a.toml"));
    }

    #[test]
    fn scaffold_parses() {
        let dir = std::env::temp_dir().join(format!("gc-scaffold-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        init(&dir).unwrap();
        let p = Project::open(&dir).unwrap();
        assert_eq!(p.environments(), vec!["dev"]);
        assert_eq!(p.flows().len(), 3);
        let diags = p.validate();
        assert!(diags.is_empty(), "{diags:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
