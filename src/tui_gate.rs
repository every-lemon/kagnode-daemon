//! The interactive part of terminal sign-in: the entry gate, the Operator's
//! Users screen and the read-only view for Managers and Viewers.
//!
//! Screens are drawn by `tui_auth`; requests go through `tui_client`; the
//! Daemon decides everything. A session the Daemon ends (idle timeout, role
//! change, password reset) sends the person back to the sign-in screen.
use crate::{
    store::Store,
    tui,
    tui_auth::{
        CreateForm, CreateOutcome, Grant, Level, LoginOutcome, NewUser, PasswordPrompt,
        PromptOutcome, Protection, Role, UserRow, Users, UsersMode, render_login, render_prompt,
        render_users,
    },
    tui_client::{Client, Identity, is_signed_out},
};
use anyhow::{Result, ensure};
use crossterm::event::{self, DisableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind};
use ratatui::{
    DefaultTerminal,
    layout::{Alignment, Constraint, Layout},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Sparkline},
};
use std::{
    io::{self, IsTerminal},
    path::Path,
    time::{Duration, Instant},
};

const BG: Color = Color::Rgb(24, 24, 26);
const FG: Color = Color::Rgb(215, 215, 220);
const MUTED: Color = Color::Rgb(150, 150, 158);
const ACCENT: Color = Color::Rgb(105, 155, 255);
const OK: Color = Color::Rgb(80, 200, 140);
const WARN: Color = Color::Rgb(235, 180, 60);

/// How a signed-in terminal screen ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// Leave the terminal; the Daemon keeps running.
    Quit,
    /// Back to the sign-in screen (sign out, idle timeout, role change).
    SignedOut,
}
pub enum Entry {
    In(Client, Identity),
    Quit,
}
fn press(wait: Duration) -> Result<Option<KeyEvent>> {
    if event::poll(wait)?
        && let Event::Key(key) = event::read()?
        && key.kind == KeyEventKind::Press
    {
        return Ok(Some(key));
    }
    Ok(None)
}
struct Restore;
impl Drop for Restore {
    fn drop(&mut self) {
        let _ = crossterm::execute!(io::stdout(), DisableMouseCapture);
        ratatui::restore();
    }
}

/// Entry point for `kagnode` / `kagnode tui`: sign in, then show the screens the
/// signed-in role is allowed to use. Only Operators open the local store; other
/// roles work entirely through the Daemon's authenticated socket.
pub fn entry(root: &Path, mouse: bool) -> Result<()> {
    ensure!(
        io::stdin().is_terminal() && io::stdout().is_terminal(),
        "Use a terminal for interactive mode, or kagnode status --json"
    );
    loop {
        let mut terminal = ratatui::init();
        let restore = Restore;
        let signed = sign_in(&mut terminal, root);
        let (mut client, me) = match signed? {
            Entry::Quit => return Ok(()),
            Entry::In(client, me) => (client, me),
        };
        drop(restore);
        drop(terminal);
        let exit = if me.who.role == Role::Operator {
            let store = Store::open(root)?;
            tui::run(&store, mouse, &mut client, &me)?
        } else {
            let mut terminal = ratatui::init();
            let _restore = Restore;
            lite(&mut terminal, &client, &me)?
        };
        client.logout();
        if exit == Exit::Quit {
            return Ok(());
        }
    }
}

pub fn sign_in(terminal: &mut DefaultTerminal, root: &Path) -> Result<Entry> {
    let mut client = Client::new(root.to_path_buf());
    // Owner mode: the Daemon accepts the machine's owner without a password.
    let first = client.owner_session();
    if let Ok(me) = first {
        return Ok(Entry::In(client, me));
    }
    let mut form = crate::tui_auth::LoginForm::default();
    if let Err(e) = first
        && e.to_string().starts_with("Daemon is offline")
    {
        form.error = Some(e.to_string());
    }
    loop {
        terminal.draw(|f| {
            f.render_widget(
                Block::default().style(Style::default().bg(BG).fg(FG)),
                f.area(),
            );
            render_login(f, f.area(), &form);
        })?;
        let Some(key) = press(Duration::from_millis(250))? else {
            continue;
        };
        match form.key(key) {
            LoginOutcome::Quit => return Ok(Entry::Quit),
            LoginOutcome::Submit => {
                terminal.draw(|f| {
                    f.render_widget(
                        Block::default().style(Style::default().bg(BG).fg(FG)),
                        f.area(),
                    );
                    render_login(f, f.area(), &form);
                })?;
                match client.login(&form.account, &form.password) {
                    Ok(me) => return Ok(Entry::In(client, me)),
                    Err(e) => form.refused(&e.to_string(), None),
                }
            }
            LoginOutcome::None => {}
        }
    }
}

// ------------------------------------------------------------ Users screen
enum Pending {
    Create(NewUser),
    Edit(UserRow, NewUser),
    Toggle(UserRow),
    Reset(UserRow),
}
fn grants_of(row: &UserRow) -> Vec<(String, Level)> {
    row.grants
        .iter()
        .map(|Grant { product, level }| (product.clone(), *level))
        .collect()
}
fn run_pending(client: &Client, pending: &Pending, prompt: &PasswordPrompt) -> Result<String> {
    match pending {
        Pending::Create(new) => {
            client.create_user(new, &prompt.values[0])?;
            Ok(format!("Created {}.", new.account))
        }
        Pending::Edit(row, new) => {
            client.update_user(row, new.role, &new.grants, row.disabled, &prompt.values[0])?;
            Ok(format!("Updated {}.", row.account))
        }
        Pending::Toggle(row) => {
            client.update_user(
                row,
                row.role,
                &grants_of(row),
                !row.disabled,
                &prompt.values[0],
            )?;
            Ok(format!(
                "{} {}.",
                row.account,
                if row.disabled { "enabled" } else { "disabled" }
            ))
        }
        Pending::Reset(row) => {
            client.reset_password(row, &prompt.values[0], &prompt.values[1])?;
            Ok(format!(
                "Password reset for {}. They sign in again with the new password.",
                row.account
            ))
        }
    }
}
fn reload(client: &Client, users: &mut Users) -> Result<()> {
    users.rows = client.list_users()?;
    users.selected = users.selected.min(users.rows.len().saturating_sub(1));
    Ok(())
}
/// The Operator's Users screen. Every change asks for the Operator's own password
/// again; the Daemon verifies it and the change itself.
pub fn users(terminal: &mut DefaultTerminal, client: &Client, me: &Identity) -> Result<Exit> {
    let mut state = match client.list_users() {
        Ok(rows) => Users::new(rows),
        Err(e) if is_signed_out(&e) => return Ok(Exit::SignedOut),
        Err(e) => {
            let mut s = Users::new(vec![]);
            s.message = Some(e.to_string());
            s
        }
    };
    let mut prompt = None::<(PasswordPrompt, Pending)>;
    loop {
        terminal.draw(|f| {
            f.render_widget(
                Block::default().style(Style::default().bg(BG).fg(FG)),
                f.area(),
            );
            render_users(f, f.area(), &state, &me.who.account);
            if let Some((p, _)) = &prompt {
                render_prompt(f, f.area(), p);
            }
        })?;
        let Some(key) = press(Duration::from_millis(250))? else {
            continue;
        };
        if let Some((p, pending)) = prompt.as_mut() {
            match p.key(key) {
                PromptOutcome::Cancel => prompt = None,
                PromptOutcome::None => {}
                PromptOutcome::Submit => {
                    terminal.draw(|f| {
                        f.render_widget(
                            Block::default().style(Style::default().bg(BG).fg(FG)),
                            f.area(),
                        );
                        render_users(f, f.area(), &state, &me.who.account);
                        render_prompt(f, f.area(), p);
                    })?;
                    match run_pending(client, pending, p) {
                        Ok(message) => {
                            prompt = None;
                            state.mode = UsersMode::List;
                            state.message = Some(message);
                            if let Err(e) = reload(client, &mut state) {
                                if is_signed_out(&e) {
                                    return Ok(Exit::SignedOut);
                                }
                                state.message = Some(e.to_string());
                            }
                        }
                        Err(e) if is_signed_out(&e) => return Ok(Exit::SignedOut),
                        Err(e) => p.refused(&e.to_string()),
                    }
                }
            }
            continue;
        }
        if let UsersMode::Create(form) = &mut state.mode {
            let editing = form.editing.clone();
            match form.key(key) {
                CreateOutcome::Cancel => state.mode = UsersMode::List,
                CreateOutcome::None => {}
                CreateOutcome::Submit(new) => {
                    let verb = if editing.is_some() {
                        "Change"
                    } else {
                        "Create"
                    };
                    let explain = format!("{verb} {} as {}.", new.account, new.role.label());
                    let pending = match editing {
                        Some(row) => Pending::Edit(row, new),
                        None => Pending::Create(new),
                    };
                    prompt = Some((
                        PasswordPrompt::new("Confirm with your password", &explain, &["Password"]),
                        pending,
                    ));
                }
            }
            continue;
        }
        let row = state.rows.get(state.selected).cloned();
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => return Ok(Exit::Quit),
            KeyCode::Up => state.selected = state.selected.saturating_sub(1),
            KeyCode::Down => {
                state.selected = (state.selected + 1).min(state.rows.len().saturating_sub(1))
            }
            KeyCode::Char('n') => {
                state.message = None;
                state.mode = UsersMode::Create(CreateForm::default());
            }
            KeyCode::Char('e') => {
                if let Some(row) = row {
                    state.message = None;
                    state.mode = UsersMode::Create(CreateForm::editing(&row));
                }
            }
            KeyCode::Char('d') => {
                if let Some(row) = row {
                    state.message = None;
                    let verb = if row.disabled { "Enable" } else { "Disable" };
                    prompt = Some((
                        PasswordPrompt::new(
                            "Confirm with your password",
                            &format!("{verb} {}.", row.account),
                            &["Password"],
                        ),
                        Pending::Toggle(row),
                    ));
                }
            }
            KeyCode::Char('p') => {
                if let Some(row) = row {
                    state.message = None;
                    prompt = Some((
                        PasswordPrompt::new(
                            "Reset password",
                            &format!(
                                "Choose a new password for {}, then confirm with yours.",
                                row.account
                            ),
                            &["New", "Yours"],
                        ),
                        Pending::Reset(row),
                    ));
                }
            }
            _ => {}
        }
    }
}

// ------------------------------------------------- Manager / Viewer screen
/// What Managers and Viewers see: server analytics (and, for Managers, the status
/// of the services they were granted). Read-only; no action is offered here.
pub fn lite(terminal: &mut DefaultTerminal, client: &Client, me: &Identity) -> Result<Exit> {
    let mut overview = serde_json::Value::Null;
    let mut cpu = Vec::<u64>::new();
    let mut services = Vec::<(String, String)>::new();
    let mut error = String::new();
    let mut refreshed = Instant::now() - Duration::from_secs(60);
    loop {
        if refreshed.elapsed() >= Duration::from_secs(5) {
            refreshed = Instant::now();
            let now = crate::auth::now();
            match client.overview() {
                Ok(v) => {
                    overview = v;
                    error.clear();
                }
                Err(e) if is_signed_out(&e) => return Ok(Exit::SignedOut),
                Err(e) => {
                    error = e.to_string();
                    overview = serde_json::Value::Null;
                }
            }
            cpu = client
                .metrics("cpu.percent", now - 3600, now)
                .ok()
                .and_then(|v| v["points"].as_array().cloned())
                .unwrap_or_default()
                .iter()
                .map(|p| p["average"].as_f64().unwrap_or(0.0).clamp(0.0, 100.0) as u64)
                .collect();
            services = me
                .products
                .iter()
                .map(|id| match client.product_status(id) {
                    Ok(v) => (
                        v["name"].as_str().unwrap_or(id).to_owned(),
                        "granted".to_owned(),
                    ),
                    Err(e) => (id.clone(), e.to_string()),
                })
                .collect();
        }
        let node = &overview["nodes"][0];
        let health = node["health"].as_str().unwrap_or("offline").to_owned();
        let values = &node["last_sample"]["values"];
        terminal.draw(|f| {
            let area = f.area();
            f.render_widget(Block::default().style(Style::default().bg(BG).fg(FG)), area);
            let [head, body, foot] = Layout::vertical([
                Constraint::Length(2),
                Constraint::Min(4),
                Constraint::Length(1),
            ])
            .areas(area);
            let head_block = Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(Color::Rgb(70, 70, 78)));
            let inner = head_block.inner(head);
            f.render_widget(head_block, head);
            let who = format!("{} · {}", me.who.account, me.who.role.label());
            let [left, right] = Layout::horizontal([
                Constraint::Min(1),
                Constraint::Length((who.chars().count() as u16 + 1).min(inner.width / 2)),
            ])
            .areas(inner);
            f.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled("KagNode. Daemon", Style::default().fg(Color::White).bold()),
                    Span::styled("  ›  ", Style::default().fg(MUTED)),
                    Span::styled("Analytics (read-only)", Style::default().fg(ACCENT)),
                ])),
                left,
            );
            f.render_widget(
                Paragraph::new(Span::styled(who, Style::default().fg(MUTED)))
                    .alignment(Alignment::Right),
                right,
            );
            let mut lines = vec![Line::from(vec![
                Span::styled(
                    "● ",
                    Style::default().fg(if health == "online" { OK } else { WARN }),
                ),
                Span::raw(format!("Daemon {health}")),
            ])];
            for (label, key) in [
                ("CPU", "cpu.percent"),
                ("Memory", "memory.used_percent"),
                ("Load", "load.1"),
            ] {
                lines.push(Line::from(vec![
                    Span::styled(format!("{label:<8}"), Style::default().fg(MUTED)),
                    Span::raw(
                        values[key]
                            .as_f64()
                            .map(|v| format!("{v:.1}"))
                            .unwrap_or_else(|| "—".into()),
                    ),
                ]));
            }
            if !error.is_empty() {
                lines.push(Line::from(Span::styled(
                    error.clone(),
                    Style::default().fg(WARN),
                )));
            }
            if me.who.role == Role::Manager {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "Your services",
                    Style::default().bold(),
                )));
                if services.is_empty() {
                    lines.push(Line::from(Span::styled(
                        "None granted yet. Ask an Operator.",
                        Style::default().fg(MUTED),
                    )));
                }
                for (name, state) in &services {
                    lines.push(Line::from(vec![
                        Span::raw(format!("  {name:<28}")),
                        Span::styled(state.clone(), Style::default().fg(MUTED)),
                    ]));
                }
            }
            let [text, graph] =
                Layout::vertical([Constraint::Min(5), Constraint::Length(5)]).areas(body);
            f.render_widget(
                Paragraph::new(lines).block(
                    Block::default()
                        .title(" Server ")
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Rgb(90, 90, 100))),
                ),
                text,
            );
            f.render_widget(
                Sparkline::default()
                    .block(
                        Block::default()
                            .title(" CPU · last hour ")
                            .borders(Borders::ALL)
                            .border_style(Style::default().fg(Color::Rgb(90, 90, 100))),
                    )
                    .data(&cpu)
                    .max(100)
                    .style(Style::default().fg(ACCENT)),
                graph,
            );
            let owner = me.who.protection == Protection::Owner;
            f.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled("o", Style::default().fg(ACCENT).bold()),
                    Span::styled(" Sign out   ", Style::default().fg(MUTED)),
                    Span::styled("q", Style::default().fg(ACCENT).bold()),
                    Span::styled(" Quit", Style::default().fg(MUTED)),
                    Span::styled(
                        if owner { "   unprotected" } else { "" },
                        Style::default().fg(WARN),
                    ),
                ])),
                foot,
            );
        })?;
        if let Some(key) = press(Duration::from_millis(250))? {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(Exit::Quit),
                KeyCode::Char('o') => return Ok(Exit::SignedOut),
                KeyCode::Char('c')
                    if key
                        .modifiers
                        .contains(crossterm::event::KeyModifiers::CONTROL) =>
                {
                    return Ok(Exit::Quit);
                }
                _ => {}
            }
        }
    }
}
