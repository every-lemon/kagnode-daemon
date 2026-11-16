//! Terminal account screens: sign-in, role-aware access and the Operator's user
//! management. Everything here is a pure state machine plus a render function,
//! tested on a `TestBackend`. It draws what the Daemon decides and never decides
//! anything itself: the server enforces roles, and [`Access`] only hides or
//! disables controls the signed-in role cannot use. Passwords live in
//! zeroizing buffers, are drawn as dots, and never reach a log or the screen.
use crate::catalog;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Row, Table, TableState, Wrap},
};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

const OK: Color = Color::Rgb(80, 200, 140);
const WARN: Color = Color::Rgb(235, 180, 60);
const BAD: Color = Color::Rgb(240, 100, 100);
const MUTED: Color = Color::Rgb(150, 150, 158);
const ACCENT: Color = Color::Rgb(105, 155, 255);
const FG: Color = Color::Rgb(215, 215, 220);
/// Placeholder until the Daemon publishes its password policy; the server's
/// answer always wins and is shown verbatim.
pub const MIN_PASSWORD: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Operator,
    Manager,
    Viewer,
}
impl Role {
    pub const ALL: [Role; 3] = [Role::Operator, Role::Manager, Role::Viewer];
    pub fn label(self) -> &'static str {
        match self {
            Role::Operator => "Operator",
            Role::Manager => "Manager",
            Role::Viewer => "Viewer",
        }
    }
    pub fn explain(self) -> &'static str {
        match self {
            Role::Operator => "Everything, including users and Daemon settings",
            Role::Manager => "Chosen services, each at a chosen level",
            Role::Viewer => "Read-only server analytics; no logs or actions",
        }
    }
}
/// Ordered: a higher level includes everything below it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    View,
    Operate,
    Manage,
}
impl Level {
    pub fn label(self) -> &'static str {
        match self {
            Level::View => "view",
            Level::Operate => "operate",
            Level::Manage => "manage",
        }
    }
    fn next(current: Option<Level>) -> Option<Level> {
        match current {
            None => Some(Level::View),
            Some(Level::View) => Some(Level::Operate),
            Some(Level::Operate) => Some(Level::Manage),
            Some(Level::Manage) => None,
        }
    }
    fn previous(current: Option<Level>) -> Option<Level> {
        match current {
            None => Some(Level::Manage),
            Some(Level::Manage) => Some(Level::Operate),
            Some(Level::Operate) => Some(Level::View),
            Some(Level::View) => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protection {
    Protected,
    Owner,
}
#[derive(Clone, Debug)]
pub struct Grant {
    pub product: String,
    pub level: Level,
}
/// What the Daemon says about the signed-in user (`whoami`).
#[derive(Clone, Debug)]
pub struct Whoami {
    pub account: String,
    pub role: Role,
    pub protection: Protection,
    pub grants: Vec<Grant>,
}
/// The actions a screen may offer. Mirrors the specification's permission
/// matrix for hiding controls only; the server remains authoritative.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Analytics,
    Users,
    DaemonSettings,
    ProductHealth,
    ProductLogs,
    ProductOperate,
    ProductManage,
    BackupView,
    BackupPin,
    BackupManage,
}
pub struct Access<'a>(pub &'a Whoami);
impl Access<'_> {
    fn level(&self, product: &str) -> Option<Level> {
        self.0
            .grants
            .iter()
            .find(|g| g.product == product)
            .map(|g| g.level)
    }
    pub fn allows(&self, action: Action, product: Option<&str>) -> bool {
        let at_least = |p: &str, need: Level| self.level(p).is_some_and(|l| l >= need);
        match (self.0.role, action) {
            (Role::Operator, _) => true,
            (_, Action::Analytics) => true,
            (Role::Viewer, _) => false,
            (Role::Manager, Action::Users | Action::DaemonSettings) => false,
            (Role::Manager, Action::ProductHealth) => {
                product.is_some_and(|p| at_least(p, Level::View))
            }
            (Role::Manager, Action::ProductLogs | Action::ProductOperate) => {
                product.is_some_and(|p| at_least(p, Level::Operate))
            }
            (Role::Manager, Action::ProductManage) => {
                product.is_some_and(|p| at_least(p, Level::Manage))
            }
            (Role::Manager, Action::BackupView) => at_least("backup", Level::View),
            (Role::Manager, Action::BackupPin) => at_least("backup", Level::Operate),
            (Role::Manager, Action::BackupManage) => at_least("backup", Level::Manage),
        }
    }
}

// ---------------------------------------------------------------- sign-in
pub struct LoginForm {
    pub account: String,
    pub password: Zeroizing<String>,
    pub focus: usize,
    pub busy: bool,
    pub error: Option<String>,
    pub wait_seconds: Option<u64>,
    /// Shown above the form, for example the unprotected owner-mode warning.
    pub banner: Option<String>,
}
impl Default for LoginForm {
    fn default() -> Self {
        Self {
            account: String::new(),
            password: Zeroizing::new(String::new()),
            focus: 0,
            busy: false,
            error: None,
            wait_seconds: None,
            banner: None,
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum LoginOutcome {
    None,
    Submit,
    Quit,
}
impl LoginForm {
    /// The server's refusal is shown without saying which part was wrong.
    pub fn refused(&mut self, message: &str, wait: Option<u64>) {
        self.busy = false;
        self.error = Some(message.to_owned());
        self.wait_seconds = wait;
        self.password.clear();
        self.focus = 1;
    }
    pub fn key(&mut self, key: KeyEvent) -> LoginOutcome {
        if self.busy {
            return LoginOutcome::None;
        }
        match key.code {
            KeyCode::Esc => return LoginOutcome::Quit,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                return LoginOutcome::Quit;
            }
            KeyCode::Tab | KeyCode::Down | KeyCode::BackTab | KeyCode::Up => {
                self.focus = 1 - self.focus
            }
            KeyCode::Enter if self.focus == 0 && !self.account.is_empty() => self.focus = 1,
            KeyCode::Enter => {
                if self.account.trim().is_empty() || self.password.is_empty() {
                    self.error = Some("Enter your account and password.".into());
                    return LoginOutcome::None;
                }
                self.busy = true;
                self.error = None;
                return LoginOutcome::Submit;
            }
            KeyCode::Backspace => {
                if self.focus == 0 {
                    self.account.pop();
                } else {
                    self.password.pop();
                }
            }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                if self.focus == 0 {
                    if self.account.chars().count() < 254 {
                        self.account.push(c);
                    }
                } else if self.password.chars().count() < 1024 {
                    self.password.push(c);
                }
            }
            _ => {}
        }
        LoginOutcome::None
    }
}
fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    )
}
fn field(label: &str, value: &str, focused: bool, secret: bool) -> Line<'static> {
    let shown = if secret {
        "•".repeat(value.chars().count())
    } else {
        value.to_owned()
    };
    let cursor = if focused { "▏" } else { "" };
    Line::from(vec![
        Span::styled(
            format!("{label:<10}"),
            Style::default().fg(if focused { ACCENT } else { MUTED }),
        ),
        Span::styled(format!("{shown}{cursor}"), Style::default().fg(FG)),
    ])
}
pub fn render_login(f: &mut Frame, area: Rect, form: &LoginForm) {
    let rect = centered(area, 60, 14);
    f.render_widget(Clear, rect);
    let block = Block::default()
        .title(" KagNode. Daemon · Sign in ")
        .title_style(Style::default().fg(FG).bold())
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT));
    let inner = block.inner(rect);
    f.render_widget(block, rect);
    let mut lines: Vec<Line> = Vec::new();
    if let Some(b) = &form.banner {
        lines.push(Line::from(Span::styled(
            format!(" {b} "),
            Style::default().fg(Color::Black).bg(WARN),
        )));
        lines.push(Line::from(""));
    }
    lines.push(field("Account", &form.account, form.focus == 0, false));
    lines.push(field("Password", &form.password, form.focus == 1, true));
    lines.push(Line::from(""));
    if form.busy {
        lines.push(Line::from(Span::styled(
            "Signing in…",
            Style::default().fg(MUTED),
        )));
    } else if let Some(e) = &form.error {
        lines.push(Line::from(Span::styled(
            e.clone(),
            Style::default().fg(BAD),
        )));
        if let Some(w) = form.wait_seconds {
            lines.push(Line::from(Span::styled(
                format!("Try again in {w} s."),
                Style::default().fg(MUTED),
            )));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("Enter", Style::default().fg(ACCENT).bold()),
        Span::styled(" sign in   ", Style::default().fg(MUTED)),
        Span::styled("Tab", Style::default().fg(ACCENT).bold()),
        Span::styled(" switch field   ", Style::default().fg(MUTED)),
        Span::styled("Esc", Style::default().fg(ACCENT).bold()),
        Span::styled(" quit", Style::default().fg(MUTED)),
    ]));
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

// ---------------------------------------------------------- user management
#[derive(Clone, Debug)]
pub struct UserRow {
    pub id: String,
    pub revision: i64,
    pub account: String,
    pub role: Role,
    pub disabled: bool,
    pub grants: Vec<Grant>,
}
pub struct CreateForm {
    pub account: String,
    pub password: Zeroizing<String>,
    pub confirm: Zeroizing<String>,
    pub role: Role,
    /// Product id -> level; only used for Managers.
    pub grants: BTreeMap<String, Option<Level>>,
    pub focus: usize,
    pub grant_row: usize,
    pub error: Option<String>,
}
const FIELD_ACCOUNT: usize = 0;
const FIELD_PASSWORD: usize = 1;
const FIELD_CONFIRM: usize = 2;
const FIELD_ROLE: usize = 3;
const FIELD_GRANTS: usize = 4;
impl Default for CreateForm {
    fn default() -> Self {
        let mut grants: BTreeMap<String, Option<Level>> = catalog::PRODUCTS
            .iter()
            .map(|p| (p.id.to_owned(), None))
            .collect();
        grants.insert("backup".into(), None);
        Self {
            account: String::new(),
            password: Zeroizing::new(String::new()),
            confirm: Zeroizing::new(String::new()),
            role: Role::Viewer,
            grants,
            focus: 0,
            grant_row: 0,
            error: None,
        }
    }
}
/// The request the terminal would send; validation here is a convenience, the
/// server validates again and its message is authoritative.
#[derive(Debug)]
pub struct NewUser {
    pub account: String,
    pub password: Zeroizing<String>,
    pub role: Role,
    pub grants: Vec<(String, Level)>,
}
#[derive(Debug)]
pub enum CreateOutcome {
    None,
    Cancel,
    Submit(NewUser),
}
impl CreateForm {
    fn last_field(&self) -> usize {
        if self.role == Role::Manager {
            FIELD_GRANTS
        } else {
            FIELD_ROLE
        }
    }
    fn validate(&self) -> Result<NewUser, String> {
        let account = self.account.trim().to_owned();
        if account.is_empty() || account.chars().count() > 254 {
            return Err("Enter an account name (up to 254 characters).".into());
        }
        if self.password.chars().count() < MIN_PASSWORD {
            return Err(format!(
                "Use a password of at least {MIN_PASSWORD} characters."
            ));
        }
        if *self.password != *self.confirm {
            return Err("The two passwords do not match.".into());
        }
        let grants: Vec<(String, Level)> = self
            .grants
            .iter()
            .filter_map(|(p, l)| l.map(|l| (p.clone(), l)))
            .collect();
        if self.role == Role::Manager && grants.is_empty() {
            return Err("Choose at least one service for a Manager.".into());
        }
        Ok(NewUser {
            account,
            password: self.password.clone(),
            role: self.role,
            grants: if self.role == Role::Manager {
                grants
            } else {
                Vec::new()
            },
        })
    }
    pub fn key(&mut self, key: KeyEvent) -> CreateOutcome {
        match key.code {
            KeyCode::Esc => return CreateOutcome::Cancel,
            KeyCode::Tab | KeyCode::Down
                if self.focus == FIELD_GRANTS && key.code == KeyCode::Down =>
            {
                self.grant_row = (self.grant_row + 1).min(self.grants.len() - 1);
            }
            KeyCode::Up if self.focus == FIELD_GRANTS && self.grant_row > 0 => self.grant_row -= 1,
            KeyCode::Tab | KeyCode::Down => self.focus = (self.focus + 1).min(self.last_field()),
            KeyCode::BackTab | KeyCode::Up => self.focus = self.focus.saturating_sub(1),
            KeyCode::Left | KeyCode::Right if self.focus == FIELD_ROLE => {
                let at = Role::ALL.iter().position(|r| *r == self.role).unwrap_or(0);
                let next = if key.code == KeyCode::Right {
                    (at + 1) % 3
                } else {
                    (at + 2) % 3
                };
                self.role = Role::ALL[next];
            }
            KeyCode::Left | KeyCode::Right | KeyCode::Char(' ') if self.focus == FIELD_GRANTS => {
                if let Some(level) = self.grants.values_mut().nth(self.grant_row) {
                    *level = if key.code == KeyCode::Left {
                        Level::previous(*level)
                    } else {
                        Level::next(*level)
                    };
                }
            }
            KeyCode::Enter => {
                if self.focus < self.last_field() {
                    self.focus += 1;
                } else {
                    return match self.validate() {
                        Ok(user) => CreateOutcome::Submit(user),
                        Err(e) => {
                            self.error = Some(e);
                            CreateOutcome::None
                        }
                    };
                }
            }
            KeyCode::Backspace => match self.focus {
                FIELD_ACCOUNT => {
                    self.account.pop();
                }
                FIELD_PASSWORD => {
                    self.password.pop();
                }
                FIELD_CONFIRM => {
                    self.confirm.pop();
                }
                _ => {}
            },
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                match self.focus {
                    FIELD_ACCOUNT => self.account.push(c),
                    FIELD_PASSWORD => self.password.push(c),
                    FIELD_CONFIRM => self.confirm.push(c),
                    _ => {}
                }
            }
            _ => {}
        }
        self.error = None;
        CreateOutcome::None
    }
}
pub enum UsersMode {
    List,
    Create(CreateForm),
}
pub struct Users {
    pub rows: Vec<UserRow>,
    pub selected: usize,
    pub mode: UsersMode,
    pub message: Option<String>,
}
impl Users {
    pub fn new(rows: Vec<UserRow>) -> Self {
        Self {
            rows,
            selected: 0,
            mode: UsersMode::List,
            message: None,
        }
    }
}
fn grants_text(row: &UserRow) -> String {
    match row.role {
        Role::Operator => "all services".into(),
        Role::Viewer => "analytics only".into(),
        Role::Manager if row.grants.is_empty() => "none".into(),
        Role::Manager => row
            .grants
            .iter()
            .map(|g| format!("{}:{}", g.product, g.level.label()))
            .collect::<Vec<_>>()
            .join(", "),
    }
}
fn role_color(role: Role) -> Color {
    match role {
        Role::Operator => ACCENT,
        Role::Manager => OK,
        Role::Viewer => MUTED,
    }
}
pub fn render_users(f: &mut Frame, area: Rect, users: &Users, you: &str) {
    let block = Block::default()
        .title(" Users ")
        .title_style(Style::default().fg(FG))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(90, 90, 100)));
    let inner = block.inner(area);
    f.render_widget(block, area);
    if let UsersMode::Create(form) = &users.mode {
        render_create(f, inner, form);
        return;
    }
    let [table_area, hint] =
        Layout::vertical([Constraint::Min(2), Constraint::Length(2)]).areas(inner);
    let rows: Vec<Row> = users
        .rows
        .iter()
        .map(|u| {
            let name = if u.account == you {
                format!("{} (you)", u.account)
            } else {
                u.account.clone()
            };
            Row::new(vec![
                Line::from(name),
                Line::from(Span::styled(
                    format!(" {} ", u.role.label()),
                    Style::default().fg(role_color(u.role)).bold(),
                )),
                Line::from(grants_text(u)),
                Line::from(if u.disabled {
                    Span::styled("disabled", Style::default().fg(BAD))
                } else {
                    Span::styled("active", Style::default().fg(OK))
                }),
            ])
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Length(30),
            Constraint::Length(12),
            Constraint::Min(16),
            Constraint::Length(10),
        ],
    )
    .header(
        Row::new(["Account", "Role", "Services", "Status"])
            .style(Style::default().fg(MUTED).bold()),
    )
    .row_highlight_style(Style::default().bg(Color::Rgb(35, 48, 70)))
    .highlight_symbol("› ");
    let mut state =
        TableState::default().with_selected((!users.rows.is_empty()).then_some(users.selected));
    f.render_stateful_widget(table, table_area, &mut state);
    let mut lines = vec![Line::from(vec![
        Span::styled("n", Style::default().fg(ACCENT).bold()),
        Span::styled(" New user   ", Style::default().fg(MUTED)),
        Span::styled("d", Style::default().fg(ACCENT).bold()),
        Span::styled(" Disable/enable   ", Style::default().fg(MUTED)),
        Span::styled("p", Style::default().fg(ACCENT).bold()),
        Span::styled(" Reset password   ", Style::default().fg(MUTED)),
        Span::styled("Esc", Style::default().fg(ACCENT).bold()),
        Span::styled(" Back", Style::default().fg(MUTED)),
    ])];
    if let Some(m) = &users.message {
        lines.push(Line::from(Span::styled(
            m.clone(),
            Style::default().fg(WARN),
        )));
    }
    f.render_widget(Paragraph::new(lines), hint);
}
fn render_create(f: &mut Frame, area: Rect, form: &CreateForm) {
    let mut lines = vec![
        Line::from(Span::styled("New user", Style::default().bold())),
        Line::from(""),
        field("Account", &form.account, form.focus == FIELD_ACCOUNT, false),
        field(
            "Password",
            &form.password,
            form.focus == FIELD_PASSWORD,
            true,
        ),
        field("Confirm", &form.confirm, form.focus == FIELD_CONFIRM, true),
    ];
    let mut roles = vec![Span::styled(
        format!("{:<10}", "Role"),
        Style::default().fg(if form.focus == FIELD_ROLE {
            ACCENT
        } else {
            MUTED
        }),
    )];
    for r in Role::ALL {
        let on = r == form.role;
        roles.push(Span::styled(
            format!(" {} ", r.label()),
            if on {
                Style::default().fg(Color::Black).bg(role_color(r))
            } else {
                Style::default().fg(MUTED)
            },
        ));
        roles.push(Span::raw(" "));
    }
    lines.push(Line::from(roles));
    lines.push(Line::from(Span::styled(
        format!("{:<10}{}", "", form.role.explain()),
        Style::default().fg(MUTED),
    )));
    if form.role == Role::Manager {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Services and level (←/→ or Space changes, ↑/↓ moves)",
            Style::default().fg(if form.focus == FIELD_GRANTS {
                ACCENT
            } else {
                MUTED
            }),
        )));
        for (i, (product, level)) in form.grants.iter().enumerate() {
            let here = form.focus == FIELD_GRANTS && i == form.grant_row;
            lines.push(Line::from(vec![
                Span::raw(if here { "› " } else { "  " }),
                Span::styled(
                    format!("{product:<16}"),
                    Style::default()
                        .fg(if here { FG } else { MUTED })
                        .add_modifier(if here {
                            Modifier::BOLD
                        } else {
                            Modifier::empty()
                        }),
                ),
                match level {
                    Some(l) => Span::styled(
                        format!(" {} ", l.label()),
                        Style::default().fg(Color::Black).bg(OK),
                    ),
                    None => Span::styled("no access", Style::default().fg(MUTED)),
                },
            ]));
        }
    }
    lines.push(Line::from(""));
    if let Some(e) = &form.error {
        lines.push(Line::from(Span::styled(
            e.clone(),
            Style::default().fg(BAD),
        )));
    }
    lines.push(Line::from(vec![
        Span::styled("Enter", Style::default().fg(ACCENT).bold()),
        Span::styled(" next / create   ", Style::default().fg(MUTED)),
        Span::styled("Esc", Style::default().fg(ACCENT).bold()),
        Span::styled(" cancel", Style::default().fg(MUTED)),
    ]));
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
}

// ------------------------------------------------- password confirmation
/// A small modal asking for one or more passwords (confirming a risky change with
/// your own password, or choosing a new password). Values are never drawn.
pub struct PasswordPrompt {
    pub title: String,
    pub explain: String,
    pub labels: Vec<&'static str>,
    pub values: Vec<Zeroizing<String>>,
    pub focus: usize,
    pub busy: bool,
    pub error: Option<String>,
}
#[derive(Debug, PartialEq, Eq)]
pub enum PromptOutcome {
    None,
    Cancel,
    Submit,
}
impl PasswordPrompt {
    pub fn new(title: &str, explain: &str, labels: &[&'static str]) -> Self {
        Self {
            title: title.into(),
            explain: explain.into(),
            labels: labels.to_vec(),
            values: labels
                .iter()
                .map(|_| Zeroizing::new(String::new()))
                .collect(),
            focus: 0,
            busy: false,
            error: None,
        }
    }
    pub fn refused(&mut self, message: &str) {
        self.busy = false;
        self.error = Some(message.to_owned());
        for v in &mut self.values {
            v.clear();
        }
        self.focus = 0;
    }
    pub fn key(&mut self, key: KeyEvent) -> PromptOutcome {
        if self.busy {
            return PromptOutcome::None;
        }
        match key.code {
            KeyCode::Esc => return PromptOutcome::Cancel,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                return PromptOutcome::Cancel;
            }
            KeyCode::Tab | KeyCode::Down => self.focus = (self.focus + 1) % self.values.len(),
            KeyCode::BackTab | KeyCode::Up => {
                self.focus = (self.focus + self.values.len() - 1) % self.values.len()
            }
            KeyCode::Enter if self.focus + 1 < self.values.len() => self.focus += 1,
            KeyCode::Enter => {
                if self.values.iter().any(|v| v.is_empty()) {
                    self.error = Some("Fill in every password.".into());
                    return PromptOutcome::None;
                }
                self.busy = true;
                self.error = None;
                return PromptOutcome::Submit;
            }
            KeyCode::Backspace => {
                self.values[self.focus].pop();
            }
            KeyCode::Char(c)
                if !key.modifiers.contains(KeyModifiers::CONTROL)
                    && self.values[self.focus].chars().count() < 1024 =>
            {
                self.values[self.focus].push(c);
            }
            _ => {}
        }
        PromptOutcome::None
    }
}
pub fn render_prompt(f: &mut Frame, area: Rect, prompt: &PasswordPrompt) {
    let rect = centered(area, 62, 11 + prompt.values.len() as u16);
    f.render_widget(Clear, rect);
    let block = Block::default()
        .title(format!(" {} ", prompt.title))
        .title_style(Style::default().fg(FG).bold())
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT));
    let inner = block.inner(rect);
    f.render_widget(block, rect);
    let mut lines = vec![
        Line::from(Span::styled(
            prompt.explain.clone(),
            Style::default().fg(MUTED),
        )),
        Line::from(""),
    ];
    for (n, label) in prompt.labels.iter().enumerate() {
        lines.push(field(label, &prompt.values[n], prompt.focus == n, true));
    }
    lines.push(Line::from(""));
    if prompt.busy {
        lines.push(Line::from(Span::styled(
            "Working…",
            Style::default().fg(MUTED),
        )));
    } else if let Some(e) = &prompt.error {
        lines.push(Line::from(Span::styled(
            e.clone(),
            Style::default().fg(BAD),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("Enter", Style::default().fg(ACCENT).bold()),
        Span::styled(" continue   ", Style::default().fg(MUTED)),
        Span::styled("Esc", Style::default().fg(ACCENT).bold()),
        Span::styled(" cancel", Style::default().fg(MUTED)),
    ]));
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }
    fn type_text<T>(form: &mut T, text: &str, key: impl Fn(&mut T, KeyEvent)) {
        for c in text.chars() {
            key(form, press(KeyCode::Char(c)));
        }
    }
    fn screen(width: u16, height: u16, draw: impl FnOnce(&mut Frame)) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|f| draw(f)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol().to_owned())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
    fn who(role: Role, grants: &[(&str, Level)]) -> Whoami {
        Whoami {
            account: "someone".into(),
            role,
            protection: Protection::Protected,
            grants: grants
                .iter()
                .map(|(p, l)| Grant {
                    product: (*p).into(),
                    level: *l,
                })
                .collect(),
        }
    }

    #[test]
    fn login_masks_the_password_and_never_draws_it() {
        let mut form = LoginForm::default();
        type_text(&mut form, "owner@example.invalid", |f, k| {
            f.key(k);
        });
        form.key(press(KeyCode::Tab));
        type_text(&mut form, "correct horse battery", |f, k| {
            f.key(k);
        });
        let s = screen(80, 20, |f| render_login(f, f.area(), &form));
        assert!(s.contains("owner@example.invalid"), "{s}");
        assert!(s.contains("•••••••••••••••••••••"), "{s}");
        assert!(
            !s.contains("correct") && !s.contains("horse"),
            "password leaked to the screen:\n{s}"
        );
    }
    #[test]
    fn login_flow_submits_once_and_refusals_clear_the_password() {
        let mut form = LoginForm::default();
        assert_eq!(form.key(press(KeyCode::Enter)), LoginOutcome::None); // empty account: stays
        type_text(&mut form, "a@b.invalid", |f, k| {
            f.key(k);
        });
        assert_eq!(form.key(press(KeyCode::Enter)), LoginOutcome::None); // moves to password
        assert_eq!(form.focus, 1);
        assert_eq!(form.key(press(KeyCode::Enter)), LoginOutcome::None);
        assert!(form.error.is_some(), "empty password is refused locally");
        type_text(&mut form, "pw", |f, k| {
            f.key(k);
        });
        assert_eq!(form.key(press(KeyCode::Enter)), LoginOutcome::Submit);
        assert!(form.busy);
        assert_eq!(
            form.key(press(KeyCode::Enter)),
            LoginOutcome::None,
            "no double submit while busy"
        );
        form.refused("Sign-in failed.", Some(30));
        assert!(form.password.is_empty(), "password cleared after a refusal");
        let s = screen(80, 20, |f| render_login(f, f.area(), &form));
        assert!(
            s.contains("Sign-in failed.") && s.contains("Try again in 30 s."),
            "{s}"
        );
        assert!(
            !s.to_lowercase().contains("unknown account")
                && !s.to_lowercase().contains("wrong password")
        );
        assert_eq!(form.key(press(KeyCode::Esc)), LoginOutcome::Quit);
    }
    #[test]
    fn owner_mode_is_announced_as_unprotected() {
        let form = LoginForm {
            banner: Some("Unprotected: anyone using this account can control the Daemon".into()),
            ..Default::default()
        };
        let s = screen(100, 20, |f| render_login(f, f.area(), &form));
        assert!(s.contains("Unprotected"), "{s}");
    }
    #[test]
    fn access_mirrors_the_specification_matrix() {
        let op = who(Role::Operator, &[]);
        let viewer = who(Role::Viewer, &[]);
        let mgr = who(
            Role::Manager,
            &[
                ("proxy-manager", Level::Operate),
                ("vpn", Level::View),
                ("backup", Level::Manage),
            ],
        );
        for action in [
            Action::Users,
            Action::DaemonSettings,
            Action::BackupManage,
            Action::ProductLogs,
        ] {
            assert!(Access(&op).allows(action, Some("vpn")), "{action:?}");
        }
        assert!(Access(&viewer).allows(Action::Analytics, None));
        for action in [
            Action::Users,
            Action::ProductHealth,
            Action::ProductLogs,
            Action::ProductOperate,
            Action::BackupView,
            Action::BackupPin,
        ] {
            assert!(
                !Access(&viewer).allows(action, Some("vpn")),
                "viewer must not {action:?}"
            );
        }
        let m = Access(&mgr);
        assert!(m.allows(Action::Analytics, None));
        assert!(!m.allows(Action::Users, None) && !m.allows(Action::DaemonSettings, None));
        assert!(
            m.allows(Action::ProductHealth, Some("vpn"))
                && !m.allows(Action::ProductLogs, Some("vpn"))
        );
        assert!(
            m.allows(Action::ProductOperate, Some("proxy-manager"))
                && !m.allows(Action::ProductManage, Some("proxy-manager"))
        );
        assert!(
            !m.allows(Action::ProductHealth, Some("mail")),
            "no grant denies"
        );
        assert!(
            !m.allows(Action::ProductHealth, None),
            "a product action needs a product"
        );
        assert!(
            m.allows(Action::BackupView, None)
                && m.allows(Action::BackupPin, None)
                && m.allows(Action::BackupManage, None)
        );
        assert!(
            !Access(&who(Role::Manager, &[("backup", Level::View)]))
                .allows(Action::BackupPin, None)
        );
    }
    #[test]
    fn create_form_validates_and_only_managers_get_services() {
        let mut f = CreateForm::default();
        assert!(matches!(f.validate(), Err(e) if e.contains("account")));
        f.account = "ops@example.invalid".into();
        f.password = Zeroizing::new("short".into());
        assert!(matches!(f.validate(), Err(e) if e.contains("at least")));
        f.password = Zeroizing::new("long enough password".into());
        f.confirm = Zeroizing::new("different password!!".into());
        assert!(matches!(f.validate(), Err(e) if e.contains("do not match")));
        f.confirm = Zeroizing::new("long enough password".into());
        let viewer = f.validate().unwrap();
        assert_eq!(viewer.role, Role::Viewer);
        assert!(viewer.grants.is_empty());
        f.role = Role::Manager;
        assert!(matches!(f.validate(), Err(e) if e.contains("at least one service")));
        *f.grants.get_mut("vpn").unwrap() = Some(Level::Operate);
        let manager = f.validate().unwrap();
        assert_eq!(manager.grants, vec![("vpn".to_owned(), Level::Operate)]);
        f.role = Role::Operator;
        *f.grants.get_mut("vpn").unwrap() = Some(Level::Manage);
        assert!(
            f.validate().unwrap().grants.is_empty(),
            "grants are dropped for non-Managers"
        );
    }
    #[test]
    fn create_form_keyboard_flow_picks_role_and_levels() {
        let mut f = CreateForm::default();
        type_text(&mut f, "ops@example.invalid", |f, k| {
            f.key(k);
        });
        f.key(press(KeyCode::Enter));
        type_text(&mut f, "long enough password", |f, k| {
            f.key(k);
        });
        f.key(press(KeyCode::Enter));
        type_text(&mut f, "long enough password", |f, k| {
            f.key(k);
        });
        f.key(press(KeyCode::Enter));
        assert_eq!(f.focus, FIELD_ROLE);
        f.key(press(KeyCode::Left)); // Viewer -> Manager
        assert_eq!(f.role, Role::Manager);
        f.key(press(KeyCode::Enter));
        assert_eq!(f.focus, FIELD_GRANTS);
        f.key(press(KeyCode::Right)); // none -> view
        f.key(press(KeyCode::Right)); // view -> operate
        f.key(press(KeyCode::Down));
        f.key(press(KeyCode::Char(' '))); // next product none -> view
        let CreateOutcome::Submit(user) = f.key(press(KeyCode::Enter)) else {
            panic!("expected submit")
        };
        assert_eq!(user.role, Role::Manager);
        assert_eq!(user.grants.len(), 2);
        assert!(
            user.grants.iter().any(|(_, l)| *l == Level::Operate)
                && user.grants.iter().any(|(_, l)| *l == Level::View)
        );
        assert!(matches!(f.key(press(KeyCode::Esc)), CreateOutcome::Cancel));
    }
    #[test]
    fn users_screens_show_roles_services_and_hide_passwords() {
        let rows = vec![
            UserRow {
                id: String::new(),
                revision: 1,
                account: "owner@example.invalid".into(),
                role: Role::Operator,
                disabled: false,
                grants: vec![],
            },
            UserRow {
                id: String::new(),
                revision: 1,
                account: "ops@example.invalid".into(),
                role: Role::Manager,
                disabled: false,
                grants: vec![Grant {
                    product: "vpn".into(),
                    level: Level::Operate,
                }],
            },
            UserRow {
                id: String::new(),
                revision: 1,
                account: "watch@example.invalid".into(),
                role: Role::Viewer,
                disabled: true,
                grants: vec![],
            },
        ];
        let users = Users::new(rows);
        let s = screen(110, 14, |f| {
            render_users(f, f.area(), &users, "owner@example.invalid")
        });
        assert!(
            s.contains("(you)")
                && s.contains("Operator")
                && s.contains("Manager")
                && s.contains("Viewer"),
            "{s}"
        );
        assert!(
            s.contains("vpn:operate") && s.contains("analytics only") && s.contains("disabled"),
            "{s}"
        );
        let mut form = CreateForm {
            role: Role::Manager,
            ..Default::default()
        };
        form.password = Zeroizing::new("secretvalue123".into());
        let create = Users {
            mode: UsersMode::Create(form),
            ..Users::new(vec![])
        };
        let s = screen(110, 30, |f| render_users(f, f.area(), &create, "x"));
        assert!(
            s.contains("Services and level") && s.contains("no access"),
            "{s}"
        );
        assert!(!s.contains("secretvalue"), "password must never be drawn");
    }
    /// Review aid, not an assertion: with TUI_DUMP_DIR set, write the screens as ANSI dumps.
    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn dump_screens_for_review() {
        let Ok(dir) = std::env::var("TUI_DUMP_DIR") else {
            return;
        };
        let code = |c: Color, fg: bool| -> String {
            let b = if fg { 30 } else { 40 };
            match c {
                Color::Rgb(r, g, bl) => format!("{};2;{r};{g};{bl}", if fg { 38 } else { 48 }),
                Color::Black => b.to_string(),
                Color::Red => (b + 1).to_string(),
                _ => String::new(),
            }
        };
        let write = |name: &str, width: u16, height: u16, draw: &dyn Fn(&mut Frame)| {
            let mut t = Terminal::new(TestBackend::new(width, height)).unwrap();
            t.draw(|f| draw(f)).unwrap();
            let buffer = t.backend().buffer().clone();
            let mut out = String::new();
            for y in 0..height {
                for x in 0..width {
                    let c = &buffer[(x, y)];
                    let mut codes = vec!["0".to_owned()];
                    for v in [code(c.fg, true), code(c.bg, false)] {
                        if !v.is_empty() {
                            codes.push(v);
                        }
                    }
                    if c.modifier.contains(Modifier::BOLD) {
                        codes.push("1".into());
                    }
                    out.push_str(&format!("\x1b[{}m{}", codes.join(";"), c.symbol()));
                }
                out.push_str("\x1b[0m\n");
            }
            std::fs::write(format!("{dir}/auth-{name}.ansi"), out).unwrap();
        };
        let mut login = LoginForm::default();
        login.account = "ops@example.invalid".into();
        login.focus = 1;
        login.password = Zeroizing::new("hunter2 hunter2".into());
        write("1-login", 90, 20, &|f| render_login(f, f.area(), &login));
        let mut refused = LoginForm::default();
        refused.account = "ops@example.invalid".into();
        refused.refused("Sign-in failed.", Some(45));
        write("2-login-refused", 90, 20, &|f| {
            render_login(f, f.area(), &refused)
        });
        let owner = LoginForm {
            banner: Some("Unprotected: this account has no password".into()),
            ..Default::default()
        };
        write("3-login-unprotected", 90, 20, &|f| {
            render_login(f, f.area(), &owner)
        });
        let rows = vec![
            UserRow {
                id: String::new(),
                revision: 1,
                account: "owner@example.invalid".into(),
                role: Role::Operator,
                disabled: false,
                grants: vec![],
            },
            UserRow {
                id: String::new(),
                revision: 1,
                account: "ops@example.invalid".into(),
                role: Role::Manager,
                disabled: false,
                grants: vec![
                    Grant {
                        product: "vpn".into(),
                        level: Level::Operate,
                    },
                    Grant {
                        product: "backup".into(),
                        level: Level::View,
                    },
                ],
            },
            UserRow {
                id: String::new(),
                revision: 1,
                account: "watch@example.invalid".into(),
                role: Role::Viewer,
                disabled: true,
                grants: vec![],
            },
        ];
        let users = Users::new(rows);
        write("4-users", 110, 14, &|f| {
            render_users(f, f.area(), &users, "owner@example.invalid")
        });
        let mut form = CreateForm::default();
        form.account = "new.manager@example.invalid".into();
        form.password = Zeroizing::new("long enough password".into());
        form.confirm = Zeroizing::new("long enough password".into());
        form.role = Role::Manager;
        form.focus = FIELD_GRANTS;
        *form.grants.get_mut("vpn").unwrap() = Some(Level::Operate);
        *form.grants.get_mut("backup").unwrap() = Some(Level::View);
        let create = Users {
            mode: UsersMode::Create(form),
            ..Users::new(vec![])
        };
        write("5-create-manager", 110, 32, &|f| {
            render_users(f, f.area(), &create, "x")
        });
    }

    #[test]
    fn tiny_terminals_do_not_panic() {
        let form = LoginForm::default();
        let users = Users::new(vec![UserRow {
            id: String::new(),
            revision: 1,
            account: "a".into(),
            role: Role::Viewer,
            disabled: false,
            grants: vec![],
        }]);
        for (w, h) in [(1, 1), (10, 3), (20, 6)] {
            let _ = screen(w, h, |f| render_login(f, f.area(), &form));
            let _ = screen(w, h, |f| render_users(f, f.area(), &users, "a"));
            let create = Users {
                mode: UsersMode::Create(CreateForm::default()),
                ..Users::new(vec![])
            };
            let _ = screen(w, h, |f| render_users(f, f.area(), &create, "a"));
        }
    }

    #[test]
    fn password_prompt_hides_values_and_clears_them_when_refused() {
        let mut prompt = PasswordPrompt::new(
            "Reset password",
            "For ops@example.invalid",
            &["New", "Yours"],
        );
        type_text(&mut prompt, "secret-new-password", |p, k| {
            p.key(k);
        });
        assert_eq!(prompt.key(press(KeyCode::Enter)), PromptOutcome::None);
        assert_eq!(prompt.focus, 1);
        // Both fields are required before anything is sent.
        assert_eq!(prompt.key(press(KeyCode::Enter)), PromptOutcome::None);
        assert!(prompt.error.is_some());
        type_text(&mut prompt, "my-own-password", |p, k| {
            p.key(k);
        });
        let text = screen(100, 24, |f| render_prompt(f, f.area(), &prompt));
        assert!(!text.contains("secret-new-password") && !text.contains("my-own-password"));
        assert!(text.contains("•••••"));
        assert_eq!(prompt.key(press(KeyCode::Enter)), PromptOutcome::Submit);
        // Busy prompts ignore further keys until the Daemon answers.
        assert_eq!(prompt.key(press(KeyCode::Esc)), PromptOutcome::None);
        prompt.refused("Authentication refused");
        assert!(prompt.values.iter().all(|v| v.is_empty()));
        assert_eq!(prompt.focus, 0);
        assert_eq!(prompt.key(press(KeyCode::Esc)), PromptOutcome::Cancel);
    }
}
