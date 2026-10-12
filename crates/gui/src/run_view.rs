//! The run panel: streams engine events into a step list with details.

use grantcentral_core::http::Exchange;
use grantcentral_core::report::Severity;
use grantcentral_core::{Event, Project, RunOptions, RunReport, StepReport, StepStatus};
use iced::futures::{SinkExt, Stream};
use iced::widget::{Column, button, column, container, row, rule, scrollable, text, text_input};
use iced::{Element, Fill, Font};
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::AbortHandle;

#[derive(Debug, Clone)]
pub enum RunMsg {
    /// The run started: where to send prompt answers, and how to cancel it.
    Ready(UnboundedSender<String>, AbortHandle),
    Event(Box<Event>),
    /// The engine task ended; `Some` when it did not finish normally (cancelled, panicked).
    Ended(Option<String>),
    Select(usize),
    PromptInput(String),
    PromptSubmit,
    OpenUrl(String),
    Cancel,
}

#[derive(Debug)]
pub enum StepState {
    Pending,
    Running,
    Done(Box<StepReport>),
}

#[derive(Debug)]
pub struct Step {
    pub name: String,
    pub state: StepState,
    /// Live log lines, until the step report replaces them.
    pub logs: Vec<String>,
}

#[derive(Debug, Default)]
pub struct RunState {
    pub flow: String,
    pub steps: Vec<Step>,
    pub selected: Option<usize>,
    /// Follow the running step until the user picks one.
    follow: bool,
    pub notices: Vec<(String, Option<String>)>,
    pub prompt: Option<(String, Option<String>)>,
    pub prompt_input: String,
    input: Option<UnboundedSender<String>>,
    abort: Option<AbortHandle>,
    pub report: Option<RunReport>,
    /// Why the run ended abnormally.
    pub ended: Option<String>,
    pub running: bool,
}

/// Starts `flow` and returns the run state plus the stream of its messages.
pub fn start(project: Project, flow: String, opts: RunOptions) -> (RunState, impl Stream<Item = RunMsg>) {
    let state = RunState { flow: flow.clone(), follow: true, running: true, ..Default::default() };
    let stream = iced::stream::channel(100, async move |mut out: iced::futures::channel::mpsc::Sender<RunMsg>| {
        // Runs on iced's tokio executor, so start_run can spawn.
        let mut h = grantcentral_core::start_run(project, flow, opts);
        let _ = out.send(RunMsg::Ready(h.input.clone(), h.task.abort_handle())).await;
        while let Some(e) = h.events.recv().await {
            if out.send(RunMsg::Event(Box::new(e))).await.is_err() {
                h.task.abort();
                return;
            }
        }
        let ended = h.task.await.err().map(|e| if e.is_cancelled() { "cancelled".to_string() } else { e.to_string() });
        let _ = out.send(RunMsg::Ended(ended)).await;
    });
    (state, stream)
}

impl RunState {
    pub fn update(&mut self, msg: RunMsg) {
        match msg {
            RunMsg::Ready(input, abort) => {
                self.input = Some(input);
                self.abort = Some(abort);
            }
            RunMsg::Event(e) => self.apply(*e),
            RunMsg::Ended(why) => {
                self.running = false;
                self.prompt = None;
                if self.report.is_none() {
                    self.ended = Some(why.unwrap_or_else(|| "run ended without a report".into()));
                }
                for s in &mut self.steps {
                    if matches!(s.state, StepState::Running) {
                        s.state = StepState::Pending;
                    }
                }
            }
            RunMsg::Select(i) => {
                self.selected = Some(i);
                self.follow = false;
            }
            RunMsg::PromptInput(s) => self.prompt_input = s,
            RunMsg::PromptSubmit => {
                if let Some(tx) = &self.input {
                    let _ = tx.send(std::mem::take(&mut self.prompt_input).trim().to_string());
                    self.prompt = None;
                }
            }
            RunMsg::OpenUrl(url) => {
                if let Err(e) = open::that(&url) {
                    self.notices.push((format!("could not open browser: {e}"), None));
                }
            }
            RunMsg::Cancel => self.cancel(),
        }
    }

    pub fn cancel(&mut self) {
        if let Some(a) = &self.abort {
            a.abort();
        }
    }

    pub fn apply(&mut self, e: Event) {
        match e {
            Event::RunStarted { flow, steps, .. } => {
                self.flow = flow;
                self.steps = steps.into_iter().map(|name| Step { name, state: StepState::Pending, logs: vec![] }).collect();
            }
            Event::StepStarted { index, name } => {
                let s = self.step(index, name);
                s.state = StepState::Running;
                if self.follow {
                    self.selected = Some(index);
                }
            }
            Event::Log { index, message } => self.step(index, String::new()).logs.push(message),
            Event::Notice { index, message, url } => {
                let line = match &url {
                    Some(u) => format!("{message} {u}"),
                    None => message.clone(),
                };
                self.step(index, String::new()).logs.push(line);
                self.notices.push((message, url));
            }
            Event::Prompt { message, url, .. } => self.prompt = Some((message, url)),
            Event::StepFinished { report } => {
                self.prompt = None;
                let (index, name) = (report.index, report.name.clone());
                self.step(index, name).state = StepState::Done(Box::new(report));
            }
            Event::RunFinished { report } => {
                self.running = false;
                self.prompt = None;
                self.report = Some(report);
            }
        }
    }

    /// The step at `index`, created if events arrive out of order.
    fn step(&mut self, index: usize, name: String) -> &mut Step {
        while self.steps.len() <= index {
            self.steps.push(Step { name: name.clone(), state: StepState::Pending, logs: vec![] });
        }
        &mut self.steps[index]
    }

    pub fn view(&self) -> Element<'_, RunMsg> {
        let summary: Element<_> = if self.running {
            text("Running…").into()
        } else if let Some(why) = &self.ended {
            text(format!("Stopped: {why}")).style(text::warning).into()
        } else if let Some(r) = &self.report {
            let (p, f, s) = r.counts();
            let label =
                format!("{} — {p} passed, {f} failed, {s} skipped — {} ms", if r.passed { "PASSED" } else { "FAILED" }, r.duration_ms);
            text(label).style(if r.passed { text::success } else { text::danger }).into()
        } else {
            text("").into()
        };
        let mut status = row![summary].spacing(12).align_y(iced::Center);
        if self.running {
            status = status.push(button("Cancel").style(button::danger).on_press(RunMsg::Cancel));
        }
        let mut col = column![text(&self.flow).size(18).width(Fill), status].spacing(8);

        if let Some(err) = self.report.as_ref().and_then(|r| r.error.as_ref()) {
            col = col.push(mono(err).style(text::danger));
        }
        for (message, url) in &self.notices {
            let mut r = column![row![text(message)].spacing(8).align_y(iced::Center)].spacing(4);
            if let Some(u) = url {
                r = column![
                    row![text(message), button("Open").on_press(RunMsg::OpenUrl(u.clone()))].spacing(8).align_y(iced::Center),
                    mono(u)
                ]
                .spacing(4);
            }
            col = col.push(r);
        }
        if let Some((message, url)) = &self.prompt {
            let mut p = column![text(message).style(text::primary)].spacing(6);
            if let Some(u) = url {
                p = p.push(row![button("Open").on_press(RunMsg::OpenUrl(u.clone())), mono(u)].spacing(8));
            }
            p = p.push(
                row![
                    text_input("Paste the redirect URL…", &self.prompt_input).on_input(RunMsg::PromptInput).on_submit(RunMsg::PromptSubmit),
                    button("Submit").on_press(RunMsg::PromptSubmit),
                ]
                .spacing(8),
            );
            col = col.push(container(p).padding(8).style(container::bordered_box).width(Fill));
        }

        let steps = Column::with_children(self.steps.iter().enumerate().map(|(i, s)| {
            let (label, style): (String, fn(&iced::Theme) -> text::Style) = match &s.state {
                StepState::Pending => ("·".into(), text::secondary),
                StepState::Running => ("RUN".into(), text::primary),
                StepState::Done(r) => match r.status {
                    StepStatus::Passed => (format!("PASS {} ms", r.duration_ms), text::success),
                    StepStatus::Failed => (format!("FAIL {} ms", r.duration_ms), text::danger),
                    StepStatus::Skipped => ("SKIP".into(), text::secondary),
                },
            };
            let line = row![text(label).style(style).width(110).font(Font::MONOSPACE), text(&s.name)].spacing(8);
            button(line)
                .width(Fill)
                .style(if self.selected == Some(i) { button::secondary } else { button::text })
                .on_press(RunMsg::Select(i))
                .into()
        }));
        col = col.push(scrollable(steps).height(iced::Length::Shrink)).push(rule::horizontal(1));

        let detail: Element<_> = match self.selected.and_then(|i| self.steps.get(i)) {
            Some(s) => step_detail(s),
            None => text("Select a step").into(),
        };
        col.push(scrollable(container(detail).padding([0, 12])).height(Fill)).into()
    }
}

fn mono<'a>(s: impl text::IntoFragment<'a>) -> text::Text<'a> {
    // Long URLs and tokens have no spaces; break them anywhere.
    text(s).font(Font::MONOSPACE).size(13).wrapping(text::Wrapping::WordOrGlyph)
}

fn heading(s: &str) -> text::Text<'_> {
    text(s).size(15).style(text::primary)
}

/// Pretty-prints JSON, leaving anything else as is.
pub fn pretty(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .filter(|v| v.is_object() || v.is_array())
        .and_then(|v| serde_json::to_string_pretty(&v).ok())
        .unwrap_or_else(|| body.to_string())
}

fn step_detail(s: &Step) -> Element<'_, RunMsg> {
    let StepState::Done(r) = &s.state else {
        let mut c = column![text(&s.name).size(17)].spacing(4);
        for l in &s.logs {
            c = c.push(mono(l));
        }
        return c.into();
    };
    let mut c = column![text(format!("{} ({}) — {:?} — {} ms", r.name, r.kind, r.status, r.duration_ms)).size(17)].spacing(6);
    if let Some(f) = &r.failure {
        c = c.push(mono(format!("Failure: {f}")).style(text::danger));
    }
    if let Some(e) = &r.error {
        c = c.push(mono(format!("Error: {e}")).style(text::warning));
    }
    if !r.checks.is_empty() {
        c = c.push(heading("Checks"));
        for ch in &r.checks {
            let (label, style): (&str, fn(&iced::Theme) -> text::Style) = match (ch.passed, ch.severity) {
                (true, _) => ("PASS", text::success),
                (false, Severity::Error) => ("FAIL", text::danger),
                (false, Severity::Warning) => ("WARN", text::warning),
                (false, Severity::Info) => ("INFO", text::secondary),
            };
            let mut col = column![row![mono(label).style(style).width(50), text(format!("{} ({:?})", ch.name, ch.severity))].spacing(8)];
            if !ch.detail.is_empty() {
                col = col.push(mono(&ch.detail).style(text::secondary));
            }
            if let Some(spec) = &ch.spec {
                col = col.push(text(spec).size(12).style(text::secondary));
            }
            c = c.push(col);
        }
    }
    if !r.assertions.is_empty() {
        c = c.push(heading("Assertions"));
        for a in &r.assertions {
            let label = if a.passed { mono("PASS").style(text::success) } else { mono("FAIL").style(text::danger) };
            let mut line = row![label.width(50), mono(&a.expr)].spacing(8);
            if let Some(m) = &a.message {
                line = line.push(mono(m).style(text::danger));
            }
            c = c.push(line);
        }
    }
    if !r.logs.is_empty() {
        c = c.push(heading("Logs"));
        for l in &r.logs {
            c = c.push(mono(l));
        }
    }
    if !r.exchanges.is_empty() {
        c = c.push(heading("HTTP"));
        for ex in &r.exchanges {
            c = c.push(exchange(ex));
        }
    }
    if !r.result.is_null() {
        c = c.push(heading("Result")).push(mono(serde_json::to_string_pretty(&r.result).unwrap_or_default()));
    }
    c.into()
}

fn exchange(ex: &Exchange) -> Element<'_, RunMsg> {
    let status_style = match ex.status {
        200..=299 => text::success,
        0 | 400.. => text::danger,
        _ => text::warning,
    };
    let headers = |h: &[(String, String)]| mono(h.iter().map(|(k, v)| format!("{k}: {v}")).collect::<Vec<_>>().join("\n"));
    let mut c = column![
        row![mono(&ex.method), mono(&ex.url), mono(ex.status.to_string()).style(status_style), mono(format!("{} ms", ex.duration_ms))]
            .spacing(8)
            .wrap()
    ]
    .spacing(4);
    if let Some(e) = &ex.error {
        c = c.push(mono(e).style(text::danger));
    }
    c = c.push(text("Request").size(13).style(text::secondary)).push(headers(&ex.request_headers));
    if let Some(b) = &ex.request_body {
        c = c.push(mono(pretty(b)));
    }
    c = c.push(text("Response").size(13).style(text::secondary)).push(headers(&ex.response_headers));
    if !ex.response_body.is_empty() {
        c = c.push(mono(pretty(&ex.response_body)));
    }
    container(c).padding(8).style(container::bordered_box).width(Fill).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(index: usize, status: StepStatus) -> StepReport {
        StepReport {
            index,
            id: None,
            name: format!("s{index}"),
            kind: "token".into(),
            status,
            duration_ms: 5,
            error: None,
            failure: None,
            checks: vec![],
            assertions: vec![],
            exchanges: vec![],
            logs: vec![],
            result: serde_json::Value::Null,
        }
    }

    #[test]
    fn events_update_steps() {
        let mut r = RunState { follow: true, running: true, ..Default::default() };
        r.apply(Event::RunStarted { flow: "f".into(), file: "flows/f.toml".into(), steps: vec!["a".into(), "b".into()] });
        assert_eq!(r.steps.len(), 2);
        r.apply(Event::StepStarted { index: 0, name: "a".into() });
        assert!(matches!(r.steps[0].state, StepState::Running));
        assert_eq!(r.selected, Some(0));
        r.apply(Event::Log { index: 0, message: "hi".into() });
        assert_eq!(r.steps[0].logs, ["hi"]);
        r.apply(Event::Prompt { index: 0, message: "paste".into(), url: None });
        assert!(r.prompt.is_some());
        r.apply(Event::StepFinished { report: report(0, StepStatus::Passed) });
        assert!(r.prompt.is_none());
        r.apply(Event::StepFinished { report: report(1, StepStatus::Failed) });
        assert!(matches!(&r.steps[0].state, StepState::Done(s) if s.status == StepStatus::Passed));
        assert!(matches!(&r.steps[1].state, StepState::Done(s) if s.status == StepStatus::Failed));
        r.update(RunMsg::Select(1));
        r.apply(Event::StepStarted { index: 1, name: "b".into() });
        assert_eq!(r.selected, Some(1), "user selection wins over follow");
        assert!(r.running);
        r.apply(Event::RunFinished {
            report: RunReport {
                flow: "f".into(),
                file: "flows/f.toml".into(),
                environment: None,
                started_at: 0,
                duration_ms: 1,
                passed: false,
                error: None,
                steps: vec![],
                redactions: vec![],
            },
        });
        assert!(!r.running && r.report.is_some());
    }

    #[test]
    fn pretty_json_only() {
        assert_eq!(pretty("{\"a\":1}"), "{\n  \"a\": 1\n}");
        assert_eq!(pretty("a=1&b=2"), "a=1&b=2");
        assert_eq!(pretty("42"), "42");
    }
}

#[cfg(test)]
mod stream_tests {
    use super::*;
    use iced::futures::StreamExt;

    #[tokio::test]
    async fn stream_drives_state() {
        let dir = std::env::temp_dir().join(format!("gc-gui-run-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("flows")).unwrap();
        // Unreachable issuer with a short timeout: fails fast without network.
        std::fs::write(
            dir.join("flows/f.toml"),
            "[client]\nissuer = \"http://127.0.0.1:1\"\ntimeout = 1\n\n[[steps]]\ntype = \"discover\"\n",
        )
        .unwrap();
        let project = Project::open(&dir).unwrap();
        let (mut state, stream) = start(project, "flows/f.toml".into(), RunOptions::default());
        let msgs: Vec<RunMsg> = stream.collect().await;
        assert!(matches!(msgs.first(), Some(RunMsg::Ready(..))));
        assert!(matches!(msgs.last(), Some(RunMsg::Ended(None))));
        for m in msgs {
            state.update(m);
        }
        assert!(!state.running);
        assert_eq!(state.steps.len(), 1);
        assert!(matches!(&state.steps[0].state, StepState::Done(s) if s.status == StepStatus::Failed), "{:?}", state.steps);
        assert!(state.report.as_ref().is_some_and(|r| !r.passed));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
