use crate::{
    broker::{self, Operation, Request},
    catalog,
    store::Store,
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
    layout::{Constraint, Layout},
    style::{Color, Style, Stylize},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Sparkline, Wrap},
};
use serde_json::Value;
use std::{
    io::{self, IsTerminal},
    time::Duration,
};

enum Reply {
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
pub fn run(store: &Store, mouse: bool) -> Result<()> {
    ensure!(
        io::stdin().is_terminal() && io::stdout().is_terminal(),
        "Use a terminal for interactive mode, or kagnode status --json"
    );
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
    loop {
        if !refreshing && refreshed.elapsed() >= Duration::from_secs(5) {
            refreshing = true;
            let root = store.root.clone();
            let tx = sender.clone();
            tokio::task::spawn_blocking(move || {
                let overview = crate::runtime::request(&root, &crate::runtime::Request::Overview);
                let now = crate::auth::now();
                let history = crate::runtime::request(
                    &root,
                    &crate::runtime::Request::Metrics {
                        name: "cpu.percent".into(),
                        since: now - 3600,
                        until: now,
                    },
                );
                let _ = tx.send(Reply::Telemetry(overview, history));
            });
        }
        while let Ok(reply) = receiver.try_recv() {
            if let Reply::Telemetry(overview, history) = reply {
                refreshing = false;
                refreshed = std::time::Instant::now();
                match overview {
                    Ok(v) => {
                        snapshot = v;
                        monitor_error.clear();
                    }
                    Err(e) => {
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
                Reply::Telemetry(_, _) | Reply::Readback(_, _) => unreachable!(),
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
        terminal.draw(|f| {
            let vertical=Layout::vertical([Constraint::Length(3),Constraint::Min(4),Constraint::Length(2)]).split(f.area());
            f.render_widget(Paragraph::new("KagNode. Daemon  /  Infrastructure").bold().fg(Color::Rgb(230,230,232)).block(Block::default().borders(Borders::BOTTOM)),vertical[0]);
            f.render_widget(Block::default().style(Style::default().bg(Color::Rgb(24,24,26)).fg(Color::Rgb(215,215,220))),f.area());
            f.render_widget(Paragraph::new("KagNode. Daemon  /  Infrastructure").bold().fg(Color::Rgb(230,230,232)),vertical[0]);
            let columns=Layout::horizontal([Constraint::Length(if f.area().width >= 90 {28} else {f.area().width * 32 / 100}),Constraint::Min(1)]).split(vertical[1]);
            let rows=entries.iter().map(|(_,p)|ListItem::new(format!(" {}  {}",if catalog::installed(managed,p){"●"}else{"○"},p.name)));
            f.render_stateful_widget(List::new(rows).block(Block::default().title(if searching{format!("Search: {search}")}else{"Applications".into()}).borders(Borders::ALL)).highlight_style(Style::default().fg(Color::LightBlue).bg(Color::Rgb(35,48,70))).highlight_symbol("› "),columns[0],&mut nav);
            let text=if let Some(index)=folder {
                let p=&catalog::PRODUCTS[index];
                format!("← Back to applications\n\nKagNode. {}\nRepository: every-lemon/{}\nInstalled state: {}\n\n[i] Inspect services   [h] Operation history\n[s] Start   [t] Stop   [r] Restart\nEvery change requires a reviewed plan and confirmation.\n\nHA durable state: {}\n\n{}{}",p.name,p.repository,if catalog::installed(managed,p){"detected"}else{"not detected; services may require root enrollment"},p.ha_state,if pending {"Waiting for the local broker…\n"}else{""},feedback)
            } else {format!("Your KagNode workspace\n\nProfile: {:?}\nWeb dashboard: {}\n\nSelect an application and press Enter.\n[w] Toggle Daemon dashboard (application UIs stay running).\n\nExisting services retain their data and native ownership.\nHA requires qualified networking, fencing, quorum and replication.\n\n{}",settings.profile,if settings.web_enabled{"enabled"}else{"disabled"},feedback)};
            if folder.is_none() && !searching && columns[1].height >= 17 {
                let areas = Layout::vertical([Constraint::Length(6), Constraint::Length(5), Constraint::Min(3)]).split(columns[1]);
                let node = &snapshot["nodes"][0]; let values = &node["last_sample"]["values"];
                let number = |key: &str| values[key].as_f64().map(|v|format!("{v:.1}")).unwrap_or_else(||"—".into());
                let health = node["health"].as_str().unwrap_or("offline");
                let status = format!("{}  ·  {}\nCPU {}%     Memory {}%     Load {}\nHistory: last hour  ·  10-second observations\n{}",node["name"].as_str().unwrap_or("Local node"),health,number("cpu.percent"),number("memory.used_percent"),number("load.1"),monitor_error);
                f.render_widget(Paragraph::new(status).wrap(Wrap{trim:false}).block(Block::default().title(" Node health ").borders(Borders::ALL)),areas[0]);
                f.render_widget(Sparkline::default().data(&cpu_history).max(100).style(Style::default().fg(Color::Rgb(105,155,255))).block(Block::default().title(" CPU · observed samples · 0–100% ").borders(Borders::ALL)),areas[1]);
                f.render_widget(Paragraph::new(text).scroll((scroll,0)).wrap(Wrap{trim:false}).block(Block::default().title(" Workspace ").borders(Borders::ALL)),areas[2]);
            } else { f.render_widget(Paragraph::new(text).scroll((scroll,0)).wrap(Wrap{trim:false}).block(Block::default().title("Workspace").borders(Borders::ALL)),columns[1]); }
            f.render_widget(Paragraph::new("↑↓ Navigate  Enter Open  Esc Back  Ctrl+P Commands  / Search  PgUp/PgDn Scroll  q Quit").fg(Color::Gray),vertical[2]);
            if palette {
                let area=f.area();let width=area.width.saturating_sub(4).min(66);let height=area.height.saturating_sub(2).min(11);
                let rect=ratatui::layout::Rect::new((area.width-width)/2,(area.height-height)/2,width,height);
                f.render_widget(Clear,rect);
                let mut state=ListState::default().with_selected(Some(command_index));
                f.render_stateful_widget(List::new(commands.iter().map(|c|ListItem::new(*c))).block(Block::default().title(" Commands · Esc closes ").borders(Borders::ALL).style(Style::default().bg(Color::Rgb(35,35,38)))).highlight_style(Style::default().bg(Color::Rgb(43,68,108)).fg(Color::White)).highlight_symbol("› "),rect,&mut state);
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
                        match command_index {
                            1 => searching = true,
                            2 | 3 => {
                                let root = store.root.clone();
                                let tx = sender.clone();
                                let index = command_index;
                                tokio::task::spawn_blocking(move || {
                                    let now = crate::auth::now();
                                    let req = if index == 2 {
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
                                        if index == 2 {
                                            "CPU history"
                                        } else {
                                            "Retention policy"
                                        }
                                        .into(),
                                        result,
                                    ));
                                });
                            }
                            4 => refreshed = std::time::Instant::now() - Duration::from_secs(10),
                            5 => break,
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
                        && m.row >= 4
                    {
                        let index = nav.offset() + usize::from(m.row - 4);
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
    Ok(())
}
