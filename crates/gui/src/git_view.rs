//! The git panel: status, per-file diff, commit all, pull and push.

use grantcentral_core::git;
use iced::widget::{Column, button, column, container, row, rule, scrollable, text, text_input};
use iced::{Element, Fill, Font, Task};
use std::path::Path;

#[derive(Debug, Clone)]
pub enum GitMsg {
    Refresh,
    Status(Result<git::Status, String>),
    Select(String),
    Diff(Result<String, String>),
    Message(String),
    Commit,
    Pull,
    Push,
    Done(&'static str, Result<String, String>),
}

#[derive(Debug, Default)]
pub struct GitState {
    status: Option<git::Status>,
    selected: Option<String>,
    diff: String,
    message: String,
    output: Option<Result<String, String>>,
    busy: bool,
}

/// Runs blocking work (git, file system) off the UI thread.
pub async fn blocking<T: Send + 'static>(f: impl FnOnce() -> anyhow::Result<T> + Send + 'static) -> Result<T, String> {
    tokio::task::spawn_blocking(f).await.map_err(|e| e.to_string())?.map_err(|e| format!("{e:#}"))
}

impl GitState {
    pub fn update(&mut self, root: &Path, msg: GitMsg) -> Task<GitMsg> {
        let root = root.to_path_buf();
        match msg {
            GitMsg::Refresh => return Task::perform(blocking(move || git::status(&root)), GitMsg::Status),
            GitMsg::Status(Ok(st)) => {
                let still = self.selected.as_ref().filter(|p| st.files.iter().any(|f| &f.path == *p)).cloned();
                self.status = Some(st);
                match still {
                    Some(p) => return self.update(&root, GitMsg::Select(p)),
                    None => {
                        self.selected = None;
                        self.diff.clear();
                    }
                }
            }
            GitMsg::Status(Err(e)) => self.output = Some(Err(e)),
            GitMsg::Select(p) => {
                self.selected = Some(p.clone());
                return Task::perform(blocking(move || git::diff(&root, Some(&p))), GitMsg::Diff);
            }
            GitMsg::Diff(r) => self.diff = r.unwrap_or_else(|e| e),
            GitMsg::Message(m) => self.message = m,
            GitMsg::Commit => {
                self.busy = true;
                let m = self.message.clone();
                return Task::perform(blocking(move || git::commit(&root, &m, &[])), |r| GitMsg::Done("commit", r));
            }
            GitMsg::Pull => {
                self.busy = true;
                return Task::perform(blocking(move || git::pull(&root)), |r| GitMsg::Done("pull", r));
            }
            GitMsg::Push => {
                self.busy = true;
                return Task::perform(blocking(move || git::push(&root)), |r| GitMsg::Done("push", r));
            }
            GitMsg::Done(op, r) => {
                self.busy = false;
                if op == "commit" && r.is_ok() {
                    self.message.clear();
                }
                self.output = Some(r.map(|out| if out.trim().is_empty() { format!("{op}: done") } else { out }));
                return self.update(&root, GitMsg::Refresh);
            }
        }
        Task::none()
    }

    pub fn view(&self) -> Element<'_, GitMsg> {
        let Some(st) = &self.status else { return text("Loading git status…").into() };
        let mut branch = format!("Branch: {}", st.branch.as_deref().unwrap_or("(detached)"));
        match &st.upstream {
            Some(u) => branch.push_str(&format!("  →  {u}  (ahead {}, behind {})", st.ahead, st.behind)),
            None => branch.push_str("  (no upstream)"),
        }
        let act = |m: GitMsg| (!self.busy).then_some(m);
        let actions = row![
            button("Refresh").style(button::secondary).on_press_maybe(act(GitMsg::Refresh)),
            button("Pull").on_press_maybe(act(GitMsg::Pull)),
            button("Push").on_press_maybe(act(GitMsg::Push)),
        ]
        .spacing(8);

        let files: Element<_> = if st.files.is_empty() {
            text("Working tree clean").style(text::secondary).into()
        } else {
            Column::with_children(st.files.iter().map(|f| {
                button(row![mono(&f.code).width(30), mono(&f.path)].spacing(8))
                    .width(Fill)
                    .style(if self.selected.as_ref() == Some(&f.path) { button::secondary } else { button::text })
                    .on_press(GitMsg::Select(f.path.clone()))
                    .into()
            }))
            .into()
        };

        let can_commit = !self.busy && !st.files.is_empty() && !self.message.trim().is_empty();
        let commit = row![
            text_input("Commit message", &self.message).on_input(GitMsg::Message).on_submit_maybe(can_commit.then_some(GitMsg::Commit)),
            button("Commit all").on_press_maybe(can_commit.then_some(GitMsg::Commit)),
        ]
        .spacing(8);

        let mut col = column![text(branch), actions, scrollable(files).height(iced::Length::Shrink), commit].spacing(8);
        match &self.output {
            Some(Ok(out)) => col = col.push(mono(out.trim())),
            Some(Err(e)) => col = col.push(mono(e).style(text::danger)),
            None => {}
        }
        if self.selected.is_some() {
            let lines = Column::with_children(self.diff.lines().map(|l| {
                let t = mono(l);
                let t = if l.starts_with("+++") || l.starts_with("---") {
                    t.style(text::primary)
                } else if l.starts_with('+') {
                    t.style(text::success)
                } else if l.starts_with('-') {
                    t.style(text::danger)
                } else if l.starts_with("@@") {
                    t.style(text::secondary)
                } else {
                    t
                };
                t.into()
            }));
            col = col.push(rule::horizontal(1)).push(scrollable(container(lines).padding([0, 12])).height(Fill));
        }
        col.into()
    }
}

fn mono<'a>(s: impl text::IntoFragment<'a>) -> text::Text<'a> {
    // Long URLs and tokens have no spaces; break them anywhere.
    text(s).font(Font::MONOSPACE).size(13).wrapping(text::Wrapping::WordOrGlyph)
}
