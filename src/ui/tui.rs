//! Interactive terminal UI: tabs, scrolling cards, masking and JSON snapshots.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Layout, Margin};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Tabs};
use ratatui::{DefaultTerminal, Frame};

use crate::changes::{self, Baseline};
use crate::overview;
use crate::report::{Report, Section, Tab};
use crate::ui::view::{self, Opts, theme::*};

pub enum Exit {
    Quit,
    Elevate,
}

const TOAST_TIME: Duration = Duration::from_secs(3);

struct App<'a> {
    collect: &'a dyn Fn() -> Report,
    report: Report,
    baseline: Option<Baseline>,
    /// Derived from `report`/`baseline`/`mask`; rebuilt by `update`, not per frame.
    overview: Vec<Section>,
    changes: Vec<Section>,
    tab: usize,
    scroll: usize,
    max_scroll: usize,
    page: usize,
    mask: bool,
    toast: Option<(String, Instant)>,
}

/// `baseline`: snapshot to compare against from the start (opens the Changes tab).
pub fn run(collect: &dyn Fn() -> Report, baseline: Option<Baseline>) -> std::io::Result<Exit> {
    let tab = if baseline.is_some() { Tab::ALL.len() - 1 } else { 0 };
    let mut app = App {
        collect,
        report: collect(),
        baseline,
        overview: Vec::new(),
        changes: Vec::new(),
        tab,
        scroll: 0,
        max_scroll: 0,
        page: 10,
        mask: false,
        toast: None,
    };
    app.update();
    let mut terminal = ratatui::init();
    let result = app.run(&mut terminal);
    ratatui::restore();
    result
}

impl App<'_> {
    fn run(&mut self, terminal: &mut DefaultTerminal) -> std::io::Result<Exit> {
        loop {
            if self.toast.as_ref().is_some_and(|(_, t)| t.elapsed() > TOAST_TIME) {
                self.toast = None;
            }
            terminal.draw(|f| self.draw(f))?;
            // Only wake up on a timer while a toast needs to expire; keys and
            // resizes arrive as events.
            let timeout = match &self.toast {
                Some((_, t)) => TOAST_TIME.saturating_sub(t.elapsed()) + Duration::from_millis(50),
                None => Duration::from_secs(3600),
            };
            if !event::poll(timeout)? {
                continue;
            }
            let Event::Key(key) = event::read()? else { continue };
            if key.kind != KeyEventKind::Press {
                continue;
            }
            let tabs = Tab::ALL.len();
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(Exit::Quit),
                KeyCode::Right | KeyCode::Tab | KeyCode::Char('l') => self.set_tab((self.tab + 1) % tabs),
                KeyCode::Left | KeyCode::BackTab | KeyCode::Char('h') => self.set_tab((self.tab + tabs - 1) % tabs),
                KeyCode::Char(c @ '1'..='9') => {
                    let i = c as usize - '1' as usize;
                    if i < tabs {
                        self.set_tab(i);
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => self.scroll_by(1),
                KeyCode::Up | KeyCode::Char('k') => self.scroll_by(-1),
                KeyCode::PageDown | KeyCode::Char(' ') => self.scroll_by(self.page as isize),
                KeyCode::PageUp => self.scroll_by(-(self.page as isize)),
                KeyCode::Home | KeyCode::Char('g') => self.scroll = 0,
                KeyCode::End | KeyCode::Char('G') => self.scroll = self.max_scroll,
                KeyCode::Char('m') => {
                    self.mask = !self.mask;
                    self.update();
                    self.notify(if self.mask { "Identifiers masked" } else { "Identifiers visible" });
                }
                KeyCode::Char('r') => {
                    self.notify("Refreshing…");
                    terminal.draw(|f| self.draw(f))?;
                    self.report = (self.collect)();
                    self.update();
                    self.notify("Refreshed");
                }
                KeyCode::Char('s') => self.save(),
                KeyCode::Char('c') => {
                    if let Some(path) = pick_file() {
                        match changes::load(&path) {
                            Ok(b) => {
                                self.baseline = Some(b);
                                self.update();
                                self.set_tab(Tab::ALL.len() - 1);
                                self.notify("Snapshot loaded");
                            }
                            Err(e) => self.notify(e),
                        }
                    }
                }
                KeyCode::Char('a') if !self.report.admin => return Ok(Exit::Elevate),
                _ => {}
            }
        }
    }

    fn update(&mut self) {
        self.overview = overview::sections(&self.report);
        self.changes = changes::sections(self.baseline.as_ref(), &self.report, self.mask);
    }

    fn set_tab(&mut self, i: usize) {
        self.tab = i;
        self.scroll = 0;
    }

    fn scroll_by(&mut self, d: isize) {
        self.scroll = self.scroll.saturating_add_signed(d).min(self.max_scroll);
    }

    fn notify(&mut self, msg: impl Into<String>) {
        self.toast = Some((msg.into(), Instant::now()));
    }

    fn save(&mut self) {
        let name = format!("hwid-{}.json", crate::util::timestamp_compact());
        let (digest, _) = overview::digest(&self.report);
        match std::fs::write(&name, self.report.to_json(&digest)) {
            Ok(()) => self.notify(format!("Saved {name}")),
            Err(e) => self.notify(format!("Save failed: {e}")),
        }
    }

    fn draw(&mut self, f: &mut Frame) {
        let [header, tabs, body, footer] =
            Layout::vertical([Constraint::Length(1), Constraint::Length(2), Constraint::Min(0), Constraint::Length(1)])
                .areas(f.area());

        // Header: brand + host on the left, badges on the right.
        let mut spans = view::header_spans(&self.report);
        if self.mask {
            spans.push(Span::raw(" "));
            spans.push(Span::styled(" MASKED ", Style::new().fg(Color::Black).bg(IDENT).bold()));
        }
        f.render_widget(Paragraph::new(Line::from(spans)), header);

        let titles = Tab::ALL.iter().enumerate().map(|(i, t)| {
            Line::from(vec![Span::styled(format!("{} ", i + 1), Style::new().fg(FAINT)), Span::raw(t.title())])
        });
        f.render_widget(
            Tabs::new(titles)
                .select(self.tab)
                .style(Style::new().fg(MUTED))
                .highlight_style(Style::new().fg(ACCENT).add_modifier(Modifier::BOLD | Modifier::UNDERLINED))
                .divider(Span::styled("│", Style::new().fg(FAINT)))
                .padding(" ", " ")
                .block(Block::new().borders(Borders::BOTTOM).border_style(Style::new().fg(FAINT))),
            tabs,
        );

        // Body: cards for the current tab, scrollable.
        let content = body.inner(Margin { horizontal: 1, vertical: 0 });
        let width = content.width.saturating_sub(2) as usize;
        let opts = Opts { mask: self.mask };
        let tab = Tab::ALL[self.tab];
        let mut lines = vec![Line::default()];
        lines.extend(match tab {
            Tab::Overview => view::cards(&self.overview, width, &opts),
            Tab::Changes => view::cards(&self.changes, width, &opts),
            _ => view::cards(self.report.in_tab(tab), width, &opts),
        });
        self.page = (body.height as usize).saturating_sub(2).max(1);
        self.max_scroll = lines.len().saturating_sub(body.height as usize);
        self.scroll = self.scroll.min(self.max_scroll);
        f.render_widget(Paragraph::new(lines).scroll((self.scroll as u16, 0)), content);
        if self.max_scroll > 0 {
            let mut state = ScrollbarState::new(self.max_scroll).position(self.scroll);
            f.render_stateful_widget(
                Scrollbar::new(ScrollbarOrientation::VerticalRight)
                    .begin_symbol(None)
                    .end_symbol(None)
                    .track_symbol(Some("│"))
                    .track_style(Style::new().fg(FAINT))
                    .thumb_style(Style::new().fg(MUTED)),
                body,
                &mut state,
            );
        }

        // Footer: key hints + transient message.
        let key = |k: &'static str, d: &'static str| {
            [Span::styled(k, Style::new().fg(ACCENT).bold()), Span::styled(format!(" {d}   "), Style::new().fg(MUTED))]
        };
        let mut hints: Vec<Span> = vec![Span::raw(" ")];
        for (k, d) in [("←→", "tabs"), ("↑↓", "scroll"), ("r", "refresh"), ("m", "mask"), ("s", "save"), ("c", "compare")] {
            hints.extend(key(k, d));
        }
        if !self.report.admin {
            hints.extend(key("a", "run as admin"));
        }
        hints.extend(key("q", "quit"));
        f.render_widget(Paragraph::new(Line::from(hints)), footer);
        if let Some((msg, _)) = &self.toast {
            f.render_widget(
                Paragraph::new(Span::styled(format!("{msg} "), Style::new().fg(GOOD).italic())).right_aligned(),
                footer,
            );
        }
    }
}

/// Lets the user pick a snapshot with the standard Windows open dialog.
fn pick_file() -> Option<PathBuf> {
    use windows::Win32::System::Console::GetConsoleWindow;
    use windows::Win32::UI::Controls::Dialogs::{
        GetOpenFileNameW, OFN_FILEMUSTEXIST, OFN_NOCHANGEDIR, OFN_PATHMUSTEXIST, OPENFILENAMEW,
    };
    use windows::core::{PCWSTR, PWSTR, w};

    let filter: Vec<u16> = "Snapshots (*.json)\0*.json\0All files\0*.*\0\0".encode_utf16().collect();
    let mut file = [0u16; 1024];
    let mut ofn = OPENFILENAMEW {
        lStructSize: size_of::<OPENFILENAMEW>() as u32,
        hwndOwner: unsafe { GetConsoleWindow() },
        lpstrFilter: PCWSTR(filter.as_ptr()),
        lpstrFile: PWSTR(file.as_mut_ptr()),
        nMaxFile: file.len() as u32,
        lpstrTitle: w!("Choose a snapshot to compare with"),
        Flags: OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR,
        ..Default::default()
    };
    unsafe { GetOpenFileNameW(&mut ofn) }.as_bool().then(|| PathBuf::from(crate::util::from_wide(&file)))
}
