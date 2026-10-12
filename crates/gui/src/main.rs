//! GrantCentral desktop app: edit a project's TOML files, run flows, and
//! commit/pull/push the project with git.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod git_view;
mod run_view;

use git_view::{GitMsg, GitState, blocking};
use grantcentral_core::{Project, RunOptions};
use iced::futures::{SinkExt, Stream};
use iced::widget::{Column, button, column, container, pick_list, row, rule, scrollable, text, text_editor};
use iced::{Element, Fill, Font, Subscription, Task, event, keyboard};
use run_view::{RunMsg, RunState};
use std::path::{Path, PathBuf};
use std::time::Duration;

fn main() -> iced::Result {
    iced::application(App::boot, App::update, App::view)
        .title(App::title)
        .subscription(App::subscription)
        .window_size((1400.0, 900.0))
        .run()
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Tab {
    Run,
    Git,
}

struct OpenFile {
    rel: String,
    content: text_editor::Content,
    /// The text as last loaded from or saved to disk.
    saved: String,
    dirty: bool,
}

#[derive(Default)]
struct App {
    project: Option<Project>,
    envs: Vec<String>,
    env: Option<String>,
    flows: Vec<String>,
    files: Vec<String>,
    open: Option<OpenFile>,
    diagnostics: Vec<String>,
    /// The open file changed on disk while it had unsaved edits.
    disk_changed: bool,
    run: Option<RunState>,
    git: Option<GitState>,
    tab: Option<Tab>,
    status: Option<String>,
}

#[derive(Debug, Clone)]
enum Message {
    OpenFolder,
    NewProject,
    FolderPicked(Option<PathBuf>),
    NewPicked(Option<PathBuf>),
    SelectEnv(String),
    OpenFile(String),
    Edit(text_editor::Action),
    Save,
    Revert,
    KeepMine,
    RunFlow,
    Run(RunMsg),
    Git(GitMsg),
    IsRepo(PathBuf, bool),
    Tab(Tab),
    FsChanged,
    WatchError(String),
}

impl App {
    fn boot() -> (App, Task<Message>) {
        let mut app = App::default();
        let task = match std::env::args_os().nth(1) {
            Some(dir) => app.load(Path::new(&dir)),
            // Only pick up the working directory when it is (inside) a project.
            None => match std::env::current_dir().ok().and_then(|d| Project::open(d).ok()) {
                Some(p) if p.root.join(grantcentral_core::project::PROJECT_FILE).is_file() => app.load(&p.root),
                _ => Task::none(),
            },
        };
        (app, task)
    }

    fn title(&self) -> String {
        match &self.project {
            Some(p) => format!("GrantCentral — {}", p.name()),
            None => "GrantCentral".into(),
        }
    }

    fn dirty(&self) -> bool {
        self.open.as_ref().is_some_and(|f| f.dirty)
    }

    /// Opens the project at `dir`, replacing the current one.
    fn load(&mut self, dir: &Path) -> Task<Message> {
        if self.dirty() {
            self.status = Some("Save or revert the open file first".into());
            return Task::none();
        }
        match Project::open(dir) {
            Ok(p) => {
                if let Some(r) = &mut self.run {
                    r.cancel();
                }
                let root = p.root.clone();
                self.env = p.default_environment();
                self.project = Some(p);
                self.open = None;
                self.run = None;
                self.git = None;
                self.tab = None;
                self.diagnostics.clear();
                self.disk_changed = false;
                self.status = None;
                self.refresh_lists();
                let r2 = root.clone();
                Task::perform(blocking(move || Ok(grantcentral_core::git::is_repo(&r2))), move |ok| {
                    Message::IsRepo(root.clone(), ok.unwrap_or(false))
                })
            }
            Err(e) => {
                self.status = Some(format!("{e:#}"));
                Task::none()
            }
        }
    }

    fn refresh_lists(&mut self) {
        let Some(p) = &self.project else { return };
        self.envs = p.environments();
        self.flows = p.flows();
        self.files = p.files().into_iter().filter(|f| !self.flows.contains(f)).collect();
        if self.env.as_ref().is_some_and(|e| !self.envs.contains(e)) {
            self.env = p.default_environment();
        }
    }

    /// Diagnostics for the open file, from validating the whole project.
    fn validate(&mut self) {
        self.diagnostics.clear();
        let (Some(p), Some(f)) = (&self.project, &self.open) else { return };
        self.diagnostics = p.validate().into_iter().filter(|d| d.file == f.rel || d.message.contains(&f.rel)).map(|d| d.message).collect();
    }

    fn save(&mut self) -> bool {
        let (Some(p), Some(f)) = (&self.project, &mut self.open) else { return false };
        let content = f.content.text();
        match p.write(&f.rel, &content) {
            Ok(()) => {
                f.saved = content;
                f.dirty = false;
                self.disk_changed = false;
                self.status = Some(format!("Saved {}", f.rel));
                self.validate();
                true
            }
            Err(e) => {
                self.status = Some(format!("{e:#}"));
                false
            }
        }
    }

    fn update(&mut self, msg: Message) -> Task<Message> {
        match msg {
            Message::OpenFolder => {
                return Task::perform(pick_folder("Open GrantCentral project"), Message::FolderPicked);
            }
            Message::NewProject => {
                return Task::perform(pick_folder("Choose a folder for the new project"), Message::NewPicked);
            }
            Message::FolderPicked(Some(dir)) => return self.load(&dir),
            Message::NewPicked(Some(dir)) => match grantcentral_core::project::init(&dir) {
                Ok(_) => return self.load(&dir),
                Err(e) => self.status = Some(format!("{e:#}")),
            },
            Message::FolderPicked(None) | Message::NewPicked(None) => {}
            Message::SelectEnv(e) => self.env = Some(e),
            Message::OpenFile(rel) => {
                if self.dirty() {
                    self.status = Some("Save or revert the open file first".into());
                } else if let Some(p) = &self.project {
                    match p.read(&rel) {
                        Ok(s) => {
                            self.open = Some(OpenFile { rel, content: text_editor::Content::with_text(&s), saved: s, dirty: false });
                            self.disk_changed = false;
                            self.status = None;
                            self.validate();
                        }
                        Err(e) => self.status = Some(format!("{e:#}")),
                    }
                }
            }
            Message::Edit(action) => {
                if let Some(f) = &mut self.open {
                    let edit = action.is_edit();
                    f.content.perform(action);
                    if edit {
                        f.dirty = f.content.text() != f.saved;
                    }
                }
            }
            Message::Save => {
                self.save();
            }
            Message::Revert => {
                if let (Some(p), Some(f)) = (&self.project, &mut self.open) {
                    let s = p.read(&f.rel).unwrap_or_else(|_| f.saved.clone());
                    f.content = text_editor::Content::with_text(&s);
                    f.saved = s;
                    f.dirty = false;
                    self.disk_changed = false;
                    self.validate();
                }
            }
            Message::KeepMine => self.disk_changed = false,
            Message::RunFlow => {
                let Some(rel) = self.open.as_ref().map(|f| f.rel.clone()).filter(|r| self.flows.contains(r)) else {
                    return Task::none();
                };
                if self.dirty() && !self.save() {
                    return Task::none();
                }
                let Some(p) = self.project.clone() else { return Task::none() };
                if let Some(r) = &mut self.run {
                    r.cancel();
                }
                let opts = RunOptions { environment: self.env.clone(), ..Default::default() };
                let (state, stream) = run_view::start(p, rel, opts);
                self.run = Some(state);
                self.tab = Some(Tab::Run);
                return Task::run(stream, Message::Run);
            }
            Message::Run(m) => {
                if let Some(r) = &mut self.run {
                    r.update(m);
                }
            }
            Message::Git(m) => {
                if let (Some(g), Some(p)) = (&mut self.git, &self.project) {
                    return g.update(&p.root, m).map(Message::Git);
                }
            }
            Message::IsRepo(root, is_repo) => {
                // Ignore answers for a project that has since been replaced.
                if self.project.as_ref().is_some_and(|p| p.root == root) {
                    self.git = None;
                    if is_repo {
                        let mut g = GitState::default();
                        let task = g.update(&root, GitMsg::Refresh).map(Message::Git);
                        self.git = Some(g);
                        return task;
                    }
                }
            }
            Message::Tab(t) => self.tab = Some(t),
            Message::FsChanged => return self.on_disk_change(),
            Message::WatchError(e) => self.status = Some(format!("file watching unavailable: {e}")),
        }
        Task::none()
    }

    fn on_disk_change(&mut self) -> Task<Message> {
        let Some(p) = &self.project else { return Task::none() };
        // Pick up grantcentral.toml edits; keep the old config while it does not parse.
        if let Ok(np) = Project::open(&p.root) {
            self.project = Some(np);
        }
        self.refresh_lists();
        let p = self.project.as_ref().unwrap();
        if let Some(f) = &mut self.open
            && let Ok(disk) = p.read(&f.rel)
            && disk != f.saved
        {
            if f.dirty {
                self.disk_changed = true;
            } else {
                f.content = text_editor::Content::with_text(&disk);
                f.saved = disk;
                self.validate();
            }
        }
        match (&mut self.git, &self.project) {
            (Some(g), Some(p)) => g.update(&p.root, GitMsg::Refresh).map(Message::Git),
            _ => Task::none(),
        }
    }

    fn subscription(&self) -> Subscription<Message> {
        let keys = event::listen_with(|e, _status, _window| match e {
            iced::Event::Keyboard(keyboard::Event::KeyPressed { key, modifiers, .. })
                if modifiers.command() && key.as_ref() == keyboard::Key::Character("s") =>
            {
                Some(Message::Save)
            }
            _ => None,
        });
        match &self.project {
            Some(p) => Subscription::batch([keys, Subscription::run_with(p.root.clone(), watch)]),
            None => keys,
        }
    }

    fn view(&self) -> Element<'_, Message> {
        let Some(p) = &self.project else {
            let welcome = column![
                text("GrantCentral").size(28),
                text("Open a project folder, or create a new project from the scaffold."),
                row![button("Open folder…").on_press(Message::OpenFolder), button("New project…").on_press(Message::NewProject)].spacing(8),
            ]
            .push(self.status.as_ref().map(|s| text(s).style(text::danger)))
            .spacing(16);
            return container(welcome).center(Fill).into();
        };

        let sidebar = self.sidebar(p);
        let editor = self.editor();
        let mut right = column![].spacing(8).padding(8).width(Fill).height(Fill);
        let tab = self.tab.unwrap_or(if self.git.is_some() && self.run.is_none() { Tab::Git } else { Tab::Run });
        if self.git.is_some() {
            let tab_button =
                |label, t| button(text(label)).style(if tab == t { button::primary } else { button::secondary }).on_press(Message::Tab(t));
            right = right.push(row![tab_button("Run", Tab::Run), tab_button("Git", Tab::Git)].spacing(4));
        }
        right = right.push(match (tab, &self.git, &self.run) {
            (Tab::Git, Some(g), _) => g.view().map(Message::Git),
            (_, _, Some(r)) => r.view().map(Message::Run),
            _ => text("Open a flow and press Run.").style(text::secondary).into(),
        });

        let main = row![
            container(sidebar).width(260).height(Fill).padding(8),
            rule::vertical(1),
            container(editor).width(Fill).height(Fill).padding(8),
            rule::vertical(1),
            right,
        ];
        let status_bar = container(text(self.status.as_deref().unwrap_or("")).size(13)).padding([2, 8]);
        column![main.height(Fill), rule::horizontal(1), status_bar].into()
    }

    fn sidebar<'a>(&'a self, p: &'a Project) -> Element<'a, Message> {
        let selected = self.open.as_ref().map(|f| f.rel.as_str());
        let entry = |rel: &'a String, label: &'a str| -> Element<'a, Message> {
            button(text(label).size(14))
                .width(Fill)
                .padding([2, 6])
                .style(if selected == Some(rel.as_str()) { button::secondary } else { button::text })
                .on_press(Message::OpenFile(rel.clone()))
                .into()
        };
        let flows = Column::with_children(self.flows.iter().map(|f| entry(f, f.strip_prefix("flows/").unwrap_or(f))));
        let files = Column::with_children(self.files.iter().map(|f| entry(f, f)));
        column![
            text(p.name()).size(20),
            row![
                button(text("Open…").size(13)).style(button::secondary).on_press(Message::OpenFolder),
                button(text("New…").size(13)).style(button::secondary).on_press(Message::NewProject),
            ]
            .spacing(4),
            text("Environment").size(13).style(text::secondary),
            pick_list(self.envs.as_slice(), self.env.as_ref(), Message::SelectEnv).placeholder("none").width(Fill),
            scrollable(
                column![text("Flows").size(13).style(text::secondary), flows, text("Files").size(13).style(text::secondary), files]
                    .spacing(4)
            )
            .height(Fill),
        ]
        .spacing(8)
        .into()
    }

    fn editor(&self) -> Element<'_, Message> {
        let Some(f) = &self.open else {
            return container(text("Select a file to edit.").style(text::secondary)).center(Fill).into();
        };
        let is_flow = self.flows.contains(&f.rel);
        let running = self.run.as_ref().is_some_and(|r| r.running);
        let toolbar = row![
            text(format!("{}{}", f.rel, if f.dirty { " •" } else { "" })).size(16).width(Fill),
            button("Revert").style(button::secondary).on_press_maybe(f.dirty.then_some(Message::Revert)),
            button("Save").on_press_maybe(f.dirty.then_some(Message::Save)),
            button("Run").style(button::success).on_press_maybe((is_flow && !running).then_some(Message::RunFlow)),
        ]
        .spacing(8)
        .align_y(iced::Center);

        let mut col = column![toolbar].spacing(8);
        if self.disk_changed {
            col = col.push(
                container(
                    row![
                        text("Changed on disk.").width(Fill),
                        button("Reload").style(button::danger).on_press(Message::Revert),
                        button("Keep mine").style(button::secondary).on_press(Message::KeepMine),
                    ]
                    .spacing(8)
                    .align_y(iced::Center),
                )
                .padding(8)
                .style(container::warning),
            );
        }
        let syntax = f.rel.rsplit('.').next().unwrap_or("txt");
        col = col.push(
            text_editor(&f.content)
                .on_action(Message::Edit)
                .font(Font::MONOSPACE)
                .size(14)
                .height(Fill)
                .highlight(syntax, iced::highlighter::Theme::SolarizedDark),
        );
        if !self.diagnostics.is_empty() {
            let diags =
                Column::with_children(self.diagnostics.iter().map(|d| text(d).font(Font::MONOSPACE).size(13).style(text::danger).into()))
                    .spacing(6);
            col = col.push(container(scrollable(diags).width(Fill)).max_height(220).padding(8).style(container::bordered_box));
        }
        col.into()
    }
}

async fn pick_folder(title: &'static str) -> Option<PathBuf> {
    rfd::AsyncFileDialog::new().set_title(title).pick_folder().await.map(|h| h.path().to_path_buf())
}

/// Bridges notify events into the app, debounced, ignoring `.git/` and build output.
#[allow(clippy::ptr_arg)] // Subscription::run_with wants fn(&PathBuf)
fn watch(root: &PathBuf) -> impl Stream<Item = Message> + use<> {
    let root = root.clone();
    iced::stream::channel(10, async move |mut out: iced::futures::channel::mpsc::Sender<Message>| {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            let Ok(ev) = res else { return };
            let ignored = |p: &PathBuf| p.components().any(|c| matches!(c.as_os_str().to_str(), Some(".git" | "target" | "node_modules")));
            if !ev.kind.is_access() && !ev.paths.iter().all(ignored) {
                let _ = tx.send(());
            }
        });
        let mut watcher = match watcher {
            Ok(w) => w,
            Err(e) => {
                let _ = out.send(Message::WatchError(e.to_string())).await;
                return;
            }
        };
        if let Err(e) = notify::Watcher::watch(&mut watcher, &root, notify::RecursiveMode::Recursive) {
            let _ = out.send(Message::WatchError(e.to_string())).await;
            return;
        }
        while rx.recv().await.is_some() {
            tokio::time::sleep(Duration::from_millis(300)).await;
            while rx.try_recv().is_ok() {}
            if out.send(Message::FsChanged).await.is_err() {
                break;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boots_against_scaffold() {
        let dir = std::env::temp_dir().join(format!("gc-gui-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        grantcentral_core::project::init(&dir).unwrap();

        let mut app = App::default();
        let _ = app.load(&dir);
        assert_eq!(app.flows.len(), 3, "{:?}", app.flows);
        assert!(app.flows.iter().all(|f| f.starts_with("flows/")));
        assert!(app.files.contains(&"environments/dev.toml".to_string()));
        assert_eq!(app.env.as_deref(), Some("dev"));

        // Open, break, save: dirty tracking and diagnostics for that file.
        let rel = app.flows[0].clone();
        let _ = app.update(Message::OpenFile(rel.clone()));
        assert!(!app.dirty() && app.diagnostics.is_empty());
        let _ = app.update(Message::Edit(text_editor::Action::Edit(text_editor::Edit::Insert('['))));
        assert!(app.dirty());
        let _ = app.update(Message::OpenFile(app.flows[1].clone()));
        assert_eq!(app.open.as_ref().unwrap().rel, rel, "dirty file is not replaced");
        let _ = app.update(Message::Save);
        assert!(!app.dirty());
        assert!(!app.diagnostics.is_empty(), "broken TOML is reported");

        // An external change reloads a clean file.
        std::fs::write(dir.join(&rel), "name = \"x\"\n").unwrap();
        let _ = app.update(Message::FsChanged);
        assert_eq!(app.open.as_ref().unwrap().content.text(), "name = \"x\"\n");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
