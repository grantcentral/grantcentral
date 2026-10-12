//! Git integration by shelling out to the user's `git`, so SSH keys,
//! credential helpers and config work exactly as in their terminal. Branching
//! and conflict resolution are left to their usual tools; pull is fast-forward only.

use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Serialize)]
pub struct FileStatus {
    pub path: String,
    /// Two-letter porcelain code, e.g. " M", "A ", "??".
    pub code: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub branch: Option<String>,
    pub upstream: Option<String>,
    pub ahead: u32,
    pub behind: u32,
    pub files: Vec<FileStatus>,
}

fn git(dir: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        // Never block a GUI on a terminal prompt; credential helpers still run.
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .context("running git (is it installed?)")?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let msg = if err.trim().is_empty() { String::from_utf8_lossy(&out.stdout).into_owned() } else { err.into_owned() };
        bail!("git {}: {}", args.join(" "), msg.trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub fn is_repo(dir: &Path) -> bool {
    git(dir, &["rev-parse", "--is-inside-work-tree"]).is_ok()
}

/// Status of the project directory. Porcelain paths are relative to the
/// repository root, so they are rebased onto `dir` (a project may live in a
/// subdirectory of the repository).
pub fn status(dir: &Path) -> Result<Status> {
    let prefix = git(dir, &["rev-parse", "--show-prefix"])?.trim().to_string();
    let out = git(dir, &["status", "--porcelain=v1", "--branch", "-z", "--untracked-files=all", "--", "."])?;
    let mut st = Status { branch: None, upstream: None, ahead: 0, behind: 0, files: vec![] };
    let mut entries = out.split('\0').filter(|s| !s.is_empty());
    while let Some(e) = entries.next() {
        if let Some(head) = e.strip_prefix("## ") {
            parse_branch(head, &mut st);
            continue;
        }
        let (code, path) = e.split_at(3.min(e.len()));
        if code.starts_with('R') || code.starts_with('C') {
            entries.next(); // original path of a rename
        }
        let path = path.strip_prefix(prefix.as_str()).unwrap_or(path);
        st.files.push(FileStatus { path: path.to_string(), code: code[..2.min(code.len())].to_string() });
    }
    Ok(st)
}

fn parse_branch(head: &str, st: &mut Status) {
    // "main...origin/main [ahead 1, behind 2]" or "No commits yet on main"
    let (names, counts) = head.split_once(" [").unwrap_or((head, ""));
    let names = names.strip_prefix("No commits yet on ").unwrap_or(names);
    let (branch, upstream) = names.split_once("...").map(|(b, u)| (b, Some(u))).unwrap_or((names, None));
    st.branch = Some(branch.to_string());
    st.upstream = upstream.map(str::to_string);
    for part in counts.trim_end_matches(']').split(", ") {
        if let Some(n) = part.strip_prefix("ahead ") {
            st.ahead = n.parse().unwrap_or(0);
        } else if let Some(n) = part.strip_prefix("behind ") {
            st.behind = n.parse().unwrap_or(0);
        }
    }
}

/// Diff of the working tree against HEAD, for one file or all. Untracked files show in full.
pub fn diff(dir: &Path, path: Option<&str>) -> Result<String> {
    let mut args = vec!["diff", "HEAD", "--no-color", "--"];
    if let Some(p) = path {
        args.push(p);
    }
    let tracked = git(dir, &args).or_else(|_| {
        // No HEAD yet: diff against the empty tree.
        let mut a = vec!["diff", "--cached", "--no-color", "--"];
        a.extend(path);
        git(dir, &a)
    })?;
    let mut out = tracked;
    for f in status(dir)?.files.iter().filter(|f| f.code == "??" && path.is_none_or(|p| p == f.path)) {
        if let Ok(text) = std::fs::read_to_string(dir.join(&f.path)) {
            out.push_str(&format!("--- /dev/null\n+++ b/{}\n", f.path));
            for line in text.lines() {
                out.push('+');
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    Ok(out)
}

/// Stages `paths` (all changes when empty) and commits.
pub fn commit(dir: &Path, message: &str, paths: &[String]) -> Result<String> {
    if message.trim().is_empty() {
        bail!("commit message is empty");
    }
    let mut add = vec!["add", "--"];
    if paths.is_empty() {
        add.push(".");
    } else {
        add.extend(paths.iter().map(String::as_str));
    }
    git(dir, &add)?;
    git(dir, &["commit", "-m", message])
}

pub fn pull(dir: &Path) -> Result<String> {
    git(dir, &["pull", "--ff-only"])
}

pub fn push(dir: &Path) -> Result<String> {
    git(dir, &["push"])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branch_header() {
        let mut st = Status { branch: None, upstream: None, ahead: 0, behind: 0, files: vec![] };
        parse_branch("main...origin/main [ahead 1, behind 2]", &mut st);
        assert_eq!((st.branch.as_deref(), st.upstream.as_deref(), st.ahead, st.behind), (Some("main"), Some("origin/main"), 1, 2));
        parse_branch("No commits yet on dev", &mut st);
        assert_eq!(st.branch.as_deref(), Some("dev"));
    }

    #[test]
    fn status_commit_roundtrip() {
        let dir = std::env::temp_dir().join(format!("gc-git-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        git(&dir, &["init", "-q"]).unwrap();
        git(&dir, &["config", "user.email", "t@example.com"]).unwrap();
        git(&dir, &["config", "user.name", "t"]).unwrap();
        std::fs::write(dir.join("a.toml"), "x = 1\n").unwrap();
        let st = status(&dir).unwrap();
        assert_eq!(st.files.len(), 1);
        assert_eq!(st.files[0].code, "??");
        assert!(diff(&dir, None).unwrap().contains("+x = 1"));
        commit(&dir, "first", &[]).unwrap();
        assert!(status(&dir).unwrap().files.is_empty());
        std::fs::write(dir.join("a.toml"), "x = 2\n").unwrap();
        assert!(diff(&dir, Some("a.toml")).unwrap().contains("+x = 2"));
        // A project in a subdirectory sees its own paths, and only its own files.
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub/b.toml"), "y = 1\n").unwrap();
        let sub = status(&dir.join("sub")).unwrap();
        assert_eq!(sub.files.iter().map(|f| f.path.as_str()).collect::<Vec<_>>(), vec!["b.toml"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
