use crate::{
    broker::{self, Operation, Request},
    catalog,
    store::Store,
    tui_auth::Protection,
    tui_backup,
    tui_client::{self, Client, Identity},
    tui_gate::Exit,
};
use anyhow::{Result, ensure};
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
        MouseEventKind,
    },
    execute,
};
use ratatui::{
    layout::{Alignment, Constraint, Layout},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{
        Block, Borders, Clear, LineGauge, List, ListItem, ListState, Paragraph, Sparkline, Wrap,
    },
};
use serde_json::Value;
use std::{
    io::{self, IsTerminal},
    time::Duration,
};

const BG: Color = Color::Rgb(24, 24, 26);
const FG: Color = Color::Rgb(215, 215, 220);
const MUTED: Color = Color::Rgb(150, 150, 158);
const ACCENT: Color = Color::Rgb(105, 155, 255);
const OK: Color = Color::Rgb(80, 200, 140);
const WARN: Color = Color::Rgb(235, 180, 60);
const BAD: Color = Color::Rgb(240, 100, 100);
fn health_color(health: &str) -> Color {
    match health {
        "offline" => BAD,
        "healthy" | "online" | "ok" => OK,
        _ => WARN,
    }
}
fn load_color(percent: f64) -> Color {
    if percent >= 90.0 {
        BAD
    } else if percent >= 70.0 {
        WARN
    } else {
        OK
    }
}
/// Bold first line; short bracketed keys such as `[i]` are drawn as keycaps.
fn styled(text: &str) -> Vec<Line<'static>> {
    text.lines()
        .enumerate()
        .map(|(n, line)| {
            let mut spans = Vec::new();
            let mut rest = line;
            while let Some(start) = rest.find('[') {
                let Some(end) = rest[start..].find(']').map(|e| start + e) else {
                    break;
                };
                if end - start > 4 {
                    spans.push(Span::raw(rest[..=end].to_owned()));
                    rest = &rest[end + 1..];
                    continue;
                }
                spans.push(Span::raw(rest[..start].to_owned()));
                spans.push(Span::styled(
                    rest[start..=end].to_owned(),
                    Style::default().fg(ACCENT).bold(),
                ));
                rest = &rest[end + 1..];
            }
            spans.push(Span::raw(rest.to_owned()));
            let line = Line::from(spans);
            if n == 0 { line.bold() } else { line }
        })
        .collect()
}
fn load_backups(store: &Store, node: usize, tx: &tokio::sync::mpsc::UnboundedSender<Reply>) {
    let (store, tx) = (store.clone(), tx.clone());
    tokio::spawn(async move {
        let _ = tx.send(Reply::Backups(tui_backup::load(&store, node).await));
    });
}

enum Reply {
    Backups(tui_backup::Loaded),
    Readback(String, Result<Value>),
    Telemetry(Result<Value>, Result<Value>),
    Review(String, Operation, Result<Value>),
    Result(String, Result<Value>),
}
struct Restore;
impl Drop for Restore {
    fn drop(&mut self) {
        let _ = execute!(io::stdout(), DisableMouseCapture);
        ratatui::restore();
    }
}
pub fn run(store: &Store, mouse: bool, client: &mut Client, me: &Identity) -> Result<Exit> {
    ensure!(
        io::stdin().is_terminal() && io::stdout().is_terminal(),
        "Use a terminal for interactive mode, or kagnode status --json"
    );
    let mut outcome = Exit::Quit;
    let mut settings = store.settings()?;
    let managed = store.managed_root();
    let mut terminal = ratatui::init();
    let _restore = Restore;
    if mouse {
        execute!(io::stdout(), EnableMouseCapture)?;
    }
    let mut selected = 0usize;
    let mut folder = None::<usize>;
    let mut nav = ListState::default();
    let mut search = String::new();
    let mut searching = false;
    let mut palette = false;
    let mut command_index = 0usize;
    let commands = [
        "Overview",
        "Applications",
        "Backups (read-only)",
        "CPU history · one hour",
        "Retention policy",
        "Refresh health",
        "Quit terminal (Daemon keeps running)",
    ];
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
    let mut pending = false;
    let mut review = None::<(String, Operation, Value)>;
    let mut feedback = String::new();
    let mut scroll = 0u16;
    let mut snapshot = Value::Null;
    let mut cpu_history = Vec::<u64>::new();
    let mut monitor_error = String::new();
    let mut refreshing = false;
    let mut refreshed = std::time::Instant::now() - Duration::from_secs(10);
    let mut backups = None::<tui_backup::State>;
    let mut backups_refreshed = std::time::Instant::now();
    'ui: loop {
        if !refreshing && refreshed.elapsed() >= Duration::from_secs(5) {
            refreshing = true;
            let reader = client.reader();
            let tx = sender.clone();
            tokio::task::spawn_blocking(move || {
                let overview = reader.overview();
                let now = crate::auth::now();
                let history = reader.metrics("cpu.percent", now - 3600, now);
                let _ = tx.send(Reply::Telemetry(overview, history));
            });
        }
        if let Some(b) = backups.as_mut()
            && !b.loading
            && backups_refreshed.elapsed() >= Duration::from_secs(30)
        {
            b.loading = true;
            backups_refreshed = std::time::Instant::now();
            load_backups(store, b.node, &sender);
        }
        while let Ok(reply) = receiver.try_recv() {
            if let Reply::Backups(data) = reply {
                if let Some(b) = backups.as_mut() {
                    b.loading = false;
                    b.data = Some(data);
                }
                continue;
            }
            if let Reply::Telemetry(overview, history) = reply {
                refreshing = false;
                refreshed = std::time::Instant::now();
                match overview {
                    Ok(v) => {
                        snapshot = v;
                        monitor_error.clear();
                    }
                    Err(e) => {
                        if tui_client::is_signed_out(&e) {
                            outcome = Exit::SignedOut;
                            break 'ui;
                        }
                        monitor_error = e.to_string();
                        snapshot = Value::Null;
                    }
                }
                cpu_history = history
                    .ok()
                    .and_then(|v| v["points"].as_array().cloned())
                    .unwrap_or_default()
                    .iter()
                    .map(|p| p["average"].as_f64().unwrap_or(0.0).clamp(0.0, 100.0) as u64)
                    .collect();
                continue;
            }
            if let Reply::Readback(label, result) = reply {
                feedback = match result {
                    Ok(value) => format!("{label}\n{}", serde_json::to_string_pretty(&value)?),
                    Err(e) => e.to_string(),
                };
                scroll = 0;
                continue;
            }
            pending = false;
            match reply {
                Reply::Telemetry(_, _) | Reply::Readback(_, _) | Reply::Backups(_) => {
                    unreachable!()
                }
                Reply::Review(id, op, Ok(plan))
                    if folder.is_some_and(|i| catalog::PRODUCTS[i].id == id) =>
                {
                    feedback = format!(
                        "Review {} for {id}\n\n{}\n\nPress y to apply this exact reviewed operation, or Esc to cancel.",
                        plan["operation"].as_str().unwrap_or("operation"),
                        serde_json::to_string_pretty(&plan)?
                    );
                    review = Some((id, op, plan));
                }
                Reply::Review(_, _, Ok(_)) => {
                    feedback = "Review cancelled after navigation; no service changed.".into();
                }
                Reply::Review(_, _, Err(error)) | Reply::Result(_, Err(error)) => {
                    feedback = error.to_string();
                }
                Reply::Result(id, Ok(value)) => {
                    feedback = format!("{id}\n{}", serde_json::to_string_pretty(&value)?);
                }
            }
            scroll = 0;
        }
        let entries: Vec<_> = catalog::PRODUCTS
            .iter()
            .enumerate()
            .filter(|(_, p)| p.name.to_lowercase().contains(&search.to_lowercase()))
            .collect();
        selected = selected.min(entries.len().saturating_sub(1));
        nav.select((!entries.is_empty()).then_some(selected));
        let health = snapshot["nodes"][0]["health"].as_str().unwrap_or("offline");
        terminal.draw(|f| {
            let area = f.area();
            f.render_widget(
                Block::default().style(Style::default().bg(BG).fg(FG)),
                area,
            );
            let vertical = Layout::vertical([
                Constraint::Length(2),
                Constraint::Min(4),
                Constraint::Length(1),
            ])
            .split(area);
            // Header: product and place on the left, live status on the right.
            let crumb = if backups.is_some() {
                "Backups".to_owned()
            } else if let Some(i) = folder {
                format!("KagNode. {}", catalog::PRODUCTS[i].name)
            } else {
                "Infrastructure".to_owned()
            };
            let header_block = Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(Color::Rgb(70, 70, 78)));
            let header_inner = header_block.inner(vertical[0]);
            f.render_widget(header_block, vertical[0]);
            // The status gets its own area so a narrow terminal truncates the
            // breadcrumb instead of overlapping it.
            let mut status_spans = vec![
                Span::styled("● ", Style::default().fg(health_color(health))),
                Span::raw(if area.width >= 90 {
                    format!("Daemon {health}")
                } else {
                    health.to_owned()
                }),
            ];
            if me.who.protection == Protection::Owner {
                status_spans.push(Span::styled(
                    if area.width >= 90 { "   UNPROTECTED · owner mode" } else { "  unprotected" },
                    Style::default().fg(WARN).bold(),
                ));
            } else if area.width >= 90 {
                status_spans.push(Span::styled(
                    format!("   {} · {}", me.who.account, me.who.role.label()),
                    Style::default().fg(MUTED),
                ));
            }
            if area.width >= 130 {
                status_spans.push(Span::styled("   Web dashboard ", Style::default().fg(MUTED)));
                status_spans.push(Span::styled(
                    if settings.web_enabled { "on" } else { "off" },
                    Style::default().fg(if settings.web_enabled { OK } else { MUTED }),
                ));
            }
            let status_width = status_spans
                .iter()
                .map(|span| span.content.chars().count() as u16)
                .sum::<u16>()
                + 1;
            let halves = Layout::horizontal([
                Constraint::Min(1),
                Constraint::Length(status_width.min(header_inner.width / 2)),
            ])
            .split(header_inner);
            f.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled("KagNode. Daemon", Style::default().fg(Color::White).bold()),
                    Span::styled("  ›  ", Style::default().fg(MUTED)),
                    Span::styled(crumb, Style::default().fg(ACCENT)),
                ])),
                halves[0],
            );
            f.render_widget(
                Paragraph::new(Line::from(status_spans)).alignment(Alignment::Right),
                halves[1],
            );
            let columns = Layout::horizontal([
                Constraint::Length(if area.width >= 90 { 28 } else { area.width * 32 / 100 }),
                Constraint::Min(1),
            ])
            .split(vertical[1]);
            let installed = entries
                .iter()
                .filter(|(_, p)| catalog::installed(managed, p))
                .count();
            let rows = entries.iter().map(|(_, p)| {
                let on = catalog::installed(managed, p);
                ListItem::new(Line::from(vec![
                    Span::raw(" "),
                    Span::styled(if on { "● " } else { "○ " }, Style::default().fg(if on { OK } else { MUTED })),
                    Span::styled(p.name, Style::default().fg(if on { FG } else { Color::Rgb(175, 175, 182) })),
                ]))
            });
            f.render_stateful_widget(
                List::new(rows)
                    .block(
                        Block::default()
                            .title(if searching {
                                format!(" Search: {search}▏")
                            } else {
                                format!(" Applications ({installed}/{}) ", entries.len())
                            })
                            .title_style(Style::default().fg(FG))
                            .borders(Borders::ALL)
                            .border_style(Style::default().fg(Color::Rgb(90, 90, 100))),
                    )
                    .highlight_style(Style::default().fg(Color::LightBlue).bg(Color::Rgb(35, 48, 70)))
                    .highlight_symbol("› "),
                columns[0],
                &mut nav,
            );
            let text = if let Some(index) = folder {
                let p = &catalog::PRODUCTS[index];
                format!("← Back to applications\n\nKagNode. {}\nRepository: every-lemon/{}\nInstalled state: {}\n\n[i] Inspect services   [h] Operation history\n[s] Start   [t] Stop   [r] Restart\nEvery change requires a reviewed plan and confirmation.\n\nHA durable state: {}\n\n{}{}", p.name, p.repository, if catalog::installed(managed, p) { "detected" } else { "not detected; services may require root enrollment" }, p.ha_state, if pending { "Waiting for the local broker…\n" } else { "" }, feedback)
            } else {
                format!("Your KagNode workspace\n\nSigned in as {}{}\nProfile: {:?}\nWeb dashboard: {}\n\nSelect an application and press Enter.\n[b] Backups: status, nodes, snapshots and policy (read-only).\n[w] Toggle Daemon dashboard (application UIs stay running).\n[u] Users and roles.  [a] Web administration on/off.  [o] Sign out.\n\nExisting services retain their data and native ownership.\nHA requires qualified networking, fencing, quorum and replication.\n\n{}", me.who.account, if me.who.protection == Protection::Owner { " (owner mode, unprotected)".to_owned() } else { format!(" · {}", me.who.role.label()) }, settings.profile, if settings.web_enabled { "enabled" } else { "disabled" }, feedback)
            };
            let panel = |title: &str| {
                Block::default()
                    .title(title.to_owned())
                    .title_style(Style::default().fg(FG))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Rgb(90, 90, 100)))
            };
            if let Some(b) = &backups {
                tui_backup::render(f, columns[1], b);
            } else if folder.is_none() && !searching && columns[1].height >= 17 {
                let areas = Layout::vertical([
                    Constraint::Length(7),
                    Constraint::Length(6),
                    Constraint::Min(4),
                ])
                .split(columns[1]);
                let node = &snapshot["nodes"][0];
                let values = &node["last_sample"]["values"];
                let block = panel(" Node health ");
                let inner = block.inner(areas[0]);
                f.render_widget(block, areas[0]);
                let rows = Layout::vertical([
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Min(1),
                ])
                .split(inner);
                f.render_widget(
                    Paragraph::new(Line::from(vec![
                        Span::raw(format!("{}  ", node["name"].as_str().unwrap_or("Local node"))),
                        Span::styled(
                            format!(" {health} "),
                            Style::default().fg(Color::Black).bg(health_color(health)),
                        ),
                    ])),
                    rows[0],
                );
                for (row, label, key) in [(rows[1], "CPU ", "cpu.percent"), (rows[2], "Mem ", "memory.used_percent")] {
                    match values[key].as_f64() {
                        Some(v) => f.render_widget(
                            LineGauge::default()
                                .filled_style(Style::default().fg(load_color(v)))
                                .unfilled_style(Style::default().fg(Color::Rgb(60, 60, 66)))
                                .label(format!("{label}{v:>5.1}%"))
                                .ratio((v / 100.0).clamp(0.0, 1.0)),
                            row,
                        ),
                        None => f.render_widget(Paragraph::new(format!("{label} —")).fg(MUTED), row),
                    }
                }
                let load = values["load.1"].as_f64().map(|v| format!("{v:.2}")).unwrap_or_else(|| "—".into());
                f.render_widget(
                    Paragraph::new(if monitor_error.is_empty() {
                        format!("Load {load}   ·   last hour, 10-second observations")
                    } else {
                        monitor_error.clone()
                    })
                    .wrap(Wrap { trim: false })
                    .fg(if monitor_error.is_empty() { MUTED } else { BAD }),
                    rows[3],
                );
                let (low, high, mean) = if cpu_history.is_empty() {
                    (0, 0, 0)
                } else {
                    (
                        *cpu_history.iter().min().unwrap_or(&0),
                        *cpu_history.iter().max().unwrap_or(&0),
                        cpu_history.iter().sum::<u64>() / cpu_history.len() as u64,
                    )
                };
                f.render_widget(
                    Sparkline::default()
                        .data(&cpu_history)
                        .max(100)
                        .style(Style::default().fg(ACCENT))
                        .block(panel(&if cpu_history.is_empty() {
                            " CPU · no samples yet ".to_owned()
                        } else {
                            format!(" CPU · min {low}%  avg {mean}%  max {high}% ")
                        })),
                    areas[1],
                );
                f.render_widget(
                    Paragraph::new(styled(&text)).scroll((scroll, 0)).wrap(Wrap { trim: false }).block(panel(" Workspace ")),
                    areas[2],
                );
            } else {
                f.render_widget(
                    Paragraph::new(styled(&text)).scroll((scroll, 0)).wrap(Wrap { trim: false }).block(panel(" Workspace ")),
                    columns[1],
                );
            }
            let mut hints: Vec<(&str, &str)> = if let Some(b) = &backups {
                vec![("←/→", "Tab"), ("↑/↓", "Node"), ("r", "Refresh"), ("Esc", "Back"), ("q", "Quit")]
                    .into_iter()
                    .filter(|(k, _)| !(b.tab > 2 && *k == "↑/↓"))
                    .collect()
            } else if folder.is_some() {
                vec![("i", "Inspect"), ("h", "History"), ("s/t/r", "Start·Stop·Restart"), ("Esc", "Back"), ("Ctrl+P", "Commands"), ("q", "Quit")]
            } else {
                vec![("↑↓", "Navigate"), ("Enter", "Open"), ("b", "Backups"), ("u", "Users"), ("o", "Sign out"), ("Ctrl+P", "Commands"), ("/", "Search"), ("PgUp/PgDn", "Scroll"), ("q", "Quit")]
            };
            if backups.is_none() && !pending && review.is_none() && folder.is_none() && searching {
                hints = vec![("type", "to filter"), ("Enter", "Open"), ("Esc", "Cancel")];
            }
            // Whole hints only: when the terminal is narrow the least important
            // trailing ones are dropped instead of being cut mid-word.
            let mut spans = Vec::new();
            let mut used = 0usize;
            let reserve = if pending { 10 } else { 0 } + if backups.is_some() { 32 } else { 0 };
            for (key, label) in hints {
                let width = key.chars().count() + label.chars().count() + 4;
                if used + width + reserve > usize::from(area.width) && !spans.is_empty() {
                    break;
                }
                used += width;
                spans.push(Span::styled(key.to_owned(), Style::default().fg(ACCENT).bold()));
                spans.push(Span::styled(format!(" {label}   "), Style::default().fg(MUTED)));
            }
            if pending {
                spans.push(Span::styled("working…", Style::default().fg(WARN)));
            }
            if backups.is_some() {
                spans.push(Span::styled("changes need the web dashboard", Style::default().fg(MUTED)));
            }
            f.render_widget(Paragraph::new(Line::from(spans)), vertical[2]);
            if palette {
                let width = area.width.saturating_sub(4).min(66);
                let height = area.height.saturating_sub(2).min(commands.len() as u16 + 4);
                let rect = ratatui::layout::Rect::new((area.width - width) / 2, (area.height - height) / 2, width, height);
                f.render_widget(Clear, rect);
                let mut state = ListState::default().with_selected(Some(command_index));
                f.render_stateful_widget(
                    List::new(commands.iter().map(|c| ListItem::new(*c)))
                        .block(
                            Block::default()
                                .title(" Commands · Esc closes ")
                                .borders(Borders::ALL)
                                .border_style(Style::default().fg(ACCENT))
                                .style(Style::default().bg(Color::Rgb(35, 35, 38))),
                        )
                        .highlight_style(Style::default().bg(Color::Rgb(43, 68, 108)).fg(Color::White))
                        .highlight_symbol("› "),
                    rect,
                    &mut state,
                );
            }
        })?;
        if !event::poll(Duration::from_millis(250))? {
            continue;
        }
        let input = event::read()?;
        if palette {
            if let Event::Key(key) = input {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Esc => palette = false,
                    KeyCode::Up => command_index = command_index.saturating_sub(1),
                    KeyCode::Down => command_index = (command_index + 1).min(commands.len() - 1),
                    KeyCode::Enter => {
                        palette = false;
                        folder = None;
                        searching = false;
                        search.clear();
                        review = None;
                        feedback.clear();
                        scroll = 0;
                        backups = None;
                        match command_index {
                            1 => searching = true,
                            2 => {
                                backups = Some(tui_backup::State {
                                    loading: true,
                                    ..Default::default()
                                });
                                backups_refreshed = std::time::Instant::now();
                                load_backups(store, 0, &sender);
                            }
                            3 | 4 => {
                                let root = store.root.clone();
                                let tx = sender.clone();
                                let index = command_index;
                                tokio::task::spawn_blocking(move || {
                                    let now = crate::auth::now();
                                    let req = if index == 3 {
                                        crate::runtime::Request::Metrics {
                                            name: "cpu.percent".into(),
                                            since: now - 3600,
                                            until: now,
                                        }
                                    } else {
                                        crate::runtime::Request::Retention
                                    };
                                    let result = crate::runtime::request(&root, &req);
                                    let _ = tx.send(Reply::Readback(
                                        if index == 3 {
                                            "CPU history"
                                        } else {
                                            "Retention policy"
                                        }
                                        .into(),
                                        result,
                                    ));
                                });
                            }
                            5 => refreshed = std::time::Instant::now() - Duration::from_secs(10),
                            6 => break,
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
            continue;
        }
        match input {
            Event::Key(k) if k.kind == KeyEventKind::Press => match k.code {
                KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => break,
                KeyCode::Esc if backups.is_some() => backups = None,
                KeyCode::Left | KeyCode::BackTab if backups.is_some() => {
                    backups.as_mut().unwrap().previous_tab()
                }
                KeyCode::Right | KeyCode::Tab if backups.is_some() => {
                    backups.as_mut().unwrap().next_tab()
                }
                KeyCode::Up | KeyCode::Down if backups.is_some() => {
                    let b = backups.as_mut().unwrap();
                    if b.move_node(k.code == KeyCode::Down) {
                        b.loading = true;
                        backups_refreshed = std::time::Instant::now();
                        load_backups(store, b.node, &sender);
                    }
                }
                KeyCode::Char('r') if backups.is_some() => {
                    let b = backups.as_mut().unwrap();
                    b.loading = true;
                    backups_refreshed = std::time::Instant::now();
                    load_backups(store, b.node, &sender);
                }
                KeyCode::Char('u')
                    if backups.is_none() && folder.is_none() && !searching && !pending =>
                {
                    if me.can("user_list") {
                        match crate::tui_gate::users(&mut terminal, client, me)? {
                            Exit::SignedOut => {
                                outcome = Exit::SignedOut;
                                break 'ui;
                            }
                            Exit::Quit => {}
                        }
                    } else {
                        feedback = "Only Operators manage users.".into();
                    }
                }
                KeyCode::Char('a')
                    if backups.is_none() && folder.is_none() && !searching && !pending =>
                {
                    if me.can("security_set") {
                        let (exit, message) =
                            crate::tui_gate::toggle_admin(&mut terminal, client, me)?;
                        if exit == Exit::SignedOut {
                            outcome = Exit::SignedOut;
                            break 'ui;
                        }
                        feedback = message;
                    } else {
                        feedback = "Only Operators change web administration.".into();
                    }
                }
                KeyCode::Char('o') if !searching && !pending => {
                    outcome = Exit::SignedOut;
                    break 'ui;
                }
                KeyCode::Char('b')
                    if backups.is_none() && folder.is_none() && !searching && !pending =>
                {
                    backups = Some(tui_backup::State {
                        loading: true,
                        ..Default::default()
                    });
                    review = None;
                    feedback.clear();
                    scroll = 0;
                    backups_refreshed = std::time::Instant::now();
                    load_backups(store, 0, &sender);
                }
                KeyCode::Esc if review.is_some() => {
                    review = None;
                    feedback = "Operation cancelled. No service changed.".into();
                }
                KeyCode::Esc => {
                    folder = None;
                    feedback.clear();
                    searching = false;
                    search.clear();
                }
                KeyCode::Char('q') if !searching => break,
                KeyCode::Char('y') if review.is_some() && !pending => {
                    let (product, operation, plan) = review.take().unwrap();
                    let expected_sha256 = plan["sha256"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("Invalid broker review"))?
                        .to_owned();
                    let id = crate::auth::random()?;
                    let request_id = id[..32].to_owned();
                    let tx = sender.clone();
                    let label = product.clone();
                    pending = true;
                    tokio::spawn(async move {
                        let r = broker::request(Request::Apply {
                            product,
                            operation,
                            expected_sha256,
                            request_id,
                        })
                        .await;
                        let _ = tx.send(Reply::Result(label, r));
                    });
                }
                KeyCode::Char('w') if folder.is_none() && !searching && !pending => {
                    let mut next = store.settings()?;
                    next.web_enabled = !next.web_enabled;
                    match store.set_settings("local-terminal", next) {
                        Ok(saved) => {
                            settings = saved;
                            feedback="Dashboard preference saved. Enabling takes effect when the Daemon starts; application services remain unchanged.".into();
                        }
                        Err(error) => feedback = error.to_string(),
                    }
                }
                KeyCode::Char(action @ ('i' | 'h' | 's' | 't' | 'r'))
                    if folder.is_some() && !searching && !pending && review.is_none() =>
                {
                    let product = catalog::PRODUCTS[folder.unwrap()].id.to_owned();
                    let tx = sender.clone();
                    pending = true;
                    feedback.clear();
                    scroll = 0;
                    tokio::spawn(async move {
                        let operation = match action {
                            's' => Some(Operation::Start),
                            't' => Some(Operation::Stop),
                            'r' => Some(Operation::Restart),
                            _ => None,
                        };
                        let reply = if let Some(operation) = operation {
                            let result = broker::request(Request::Plan {
                                product: product.clone(),
                                operation,
                            })
                            .await;
                            Reply::Review(product, operation, result)
                        } else {
                            let request = if action == 'i' {
                                Request::Status {
                                    product: product.clone(),
                                }
                            } else {
                                Request::History {
                                    product: product.clone(),
                                }
                            };
                            Reply::Result(product, broker::request(request).await)
                        };
                        let _ = tx.send(reply);
                    });
                }
                KeyCode::PageDown => scroll = scroll.saturating_add(10),
                KeyCode::PageUp => scroll = scroll.saturating_sub(10),
                KeyCode::Char('p') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                    palette = true;
                    command_index = 0;
                }
                KeyCode::Char('/') if !searching => {
                    searching = true;
                    backups = None;
                    folder = None;
                    review = None;
                    feedback.clear();
                    scroll = 0;
                }
                KeyCode::Char(c) if searching => {
                    search.push(c);
                    selected = 0;
                }
                KeyCode::Backspace if searching => {
                    search.pop();
                    selected = 0;
                }
                KeyCode::Up => selected = selected.saturating_sub(1),
                KeyCode::Down => selected = (selected + 1).min(entries.len().saturating_sub(1)),
                KeyCode::Enter | KeyCode::Right => {
                    if review.is_none() {
                        folder = entries.get(selected).map(|(i, _)| *i);
                        searching = false;
                        feedback.clear();
                        scroll = 0;
                    }
                }
                KeyCode::Left => {
                    folder = None;
                    review = None;
                    feedback.clear();
                    scroll = 0;
                }
                _ => {}
            },
            Event::Mouse(m) if mouse => match m.kind {
                MouseEventKind::ScrollUp => selected = selected.saturating_sub(1),
                MouseEventKind::ScrollDown => {
                    selected = (selected + 1).min(entries.len().saturating_sub(1))
                }
                MouseEventKind::Down(event::MouseButton::Left) => {
                    let area = terminal.size()?;
                    if m.column
                        < (if area.width >= 90 {
                            28
                        } else {
                            area.width * 32 / 100
                        })
                        && m.row >= 3
                    {
                        let index = nav.offset() + usize::from(m.row - 3);
                        if index < entries.len() {
                            selected = index;
                            folder = Some(entries[index].0);
                            review = None;
                            feedback.clear();
                            scroll = 0;
                        }
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }
    Ok(outcome)
}
