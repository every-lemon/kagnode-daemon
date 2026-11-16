//! Read-only Backups view for the terminal dashboard. It shows the same local
//! administrator data as the web page and never changes anything: approvals,
//! revocation, retention and policy changes need the web dashboard's password
//! confirmation. Rendering is a pure function of [`State`] so it can be tested
//! on a `TestBackend` without a terminal.
use crate::{
    backup_service::{control::AdminRequest, supervisor},
    store::Store,
};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, LineGauge, Paragraph, Row, Table, TableState, Tabs, Wrap},
};
use serde_json::{Value, json};

pub const TABS: [&str; 5] = ["Overview", "Nodes", "Snapshots", "Sending", "Policy"];
const OK: Color = Color::Rgb(80, 200, 140);
const WARN: Color = Color::Rgb(235, 180, 60);
const BAD: Color = Color::Rgb(240, 100, 100);
const MUTED: Color = Color::Rgb(150, 150, 158);
const ACCENT: Color = Color::Rgb(105, 155, 255);

/// Everything one refresh read. Errors are kept as text so the view can show a
/// clear message instead of an empty panel.
pub struct Loaded {
    pub server: Result<Value, String>,
    pub nodes: Result<Value, String>,
    pub snapshots: Option<Result<Value, String>>,
    pub agent: Value,
}
#[derive(Default)]
pub struct State {
    pub tab: usize,
    pub node: usize,
    pub loading: bool,
    pub data: Option<Loaded>,
}
impl State {
    pub fn next_tab(&mut self) {
        self.tab = (self.tab + 1) % TABS.len();
    }
    pub fn previous_tab(&mut self) {
        self.tab = (self.tab + TABS.len() - 1) % TABS.len();
    }
    pub fn node_count(&self) -> usize {
        self.data
            .as_ref()
            .and_then(|d| d.nodes.as_ref().ok())
            .and_then(|v| v["nodes"].as_array())
            .map_or(0, Vec::len)
    }
    pub fn node_name(&self) -> Option<String> {
        self.data
            .as_ref()?
            .nodes
            .as_ref()
            .ok()?
            .get("nodes")?
            .get(self.node)?
            .get("node")?
            .as_str()
            .map(str::to_owned)
    }
    pub fn move_node(&mut self, down: bool) -> bool {
        let count = self.node_count();
        let next = if down {
            (self.node + 1).min(count.saturating_sub(1))
        } else {
            self.node.saturating_sub(1)
        };
        let changed = next != self.node;
        self.node = next;
        changed
    }
}

/// Read every view from the local controller. `node` selects the snapshot list.
pub async fn load(store: &Store, node: usize) -> Loaded {
    let ask = |request: AdminRequest| async move {
        supervisor::request(store, &request)
            .await
            .map_err(|e| e.to_string())
    };
    let server = ask(AdminRequest::Status).await;
    let nodes = match &server {
        Ok(_) => ask(AdminRequest::Nodes).await,
        Err(e) => Err(e.clone()),
    };
    let snapshots = match nodes
        .as_ref()
        .ok()
        .and_then(|v| v["nodes"].get(node))
        .and_then(|n| n["node"].as_str())
    {
        Some(name) => Some(
            ask(AdminRequest::Snapshots {
                node: name.to_owned(),
            })
            .await,
        ),
        None => None,
    };
    let agent = store
        .document("backup-agent-status")
        .ok()
        .flatten()
        .map(|(_, value)| value)
        .unwrap_or_else(|| json!({"state": "not_observed"}));
    Loaded {
        server,
        nodes,
        snapshots,
        agent,
    }
}

pub fn bytes(n: f64) -> String {
    let units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let (mut v, mut i) = (n, 0);
    while v >= 1024.0 && i < units.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{v:.0} B")
    } else {
        format!("{v:.1} {}", units[i])
    }
}
pub fn duration(seconds: u64) -> String {
    let mut parts = Vec::new();
    let mut rest = seconds;
    for (unit, size) in [("d", 86_400), ("h", 3_600), ("min", 60)] {
        if rest >= size {
            parts.push(format!("{} {unit}", rest / size));
            rest %= size;
        }
    }
    if parts.is_empty() {
        format!("{seconds} s")
    } else {
        parts.truncate(2);
        parts.join(" ")
    }
}
pub fn when(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| "—".into())
}
fn badge(text: &str, color: Color) -> Span<'static> {
    Span::styled(
        format!(" {text} "),
        Style::default().fg(Color::Black).bg(color),
    )
}
fn muted(text: impl Into<String>) -> Span<'static> {
    Span::styled(text.into(), Style::default().fg(MUTED))
}
fn heading(text: &str) -> Line<'static> {
    Line::from(Span::styled(
        text.to_owned(),
        Style::default().add_modifier(Modifier::BOLD),
    ))
}
fn error_lines(message: &str) -> Vec<Line<'static>> {
    if message.contains("not configured") {
        vec![
            Line::from(badge("not configured", WARN)),
            Line::from(""),
            Line::from("This host is not set up as a backup server. Nothing is stored here."),
            Line::from(muted(
                "Setup is done locally by the administrator; see the backup server documentation.",
            )),
        ]
    } else {
        vec![
            Line::from(badge("unavailable", BAD)),
            Line::from(""),
            Line::from(Span::styled(message.to_owned(), Style::default().fg(BAD))),
            Line::from(muted(
                "Nothing here is current, and this is not a sign that backups are healthy.",
            )),
        ]
    }
}

fn overview(data: &Loaded) -> Vec<Line<'static>> {
    let status = match &data.server {
        Ok(v) => v,
        Err(e) => return error_lines(e),
    };
    let mut lines = vec![
        Line::from(vec![
            Span::raw("Site "),
            Span::styled(
                status["site"].as_str().unwrap_or("—").to_owned(),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw("   Server "),
            Span::styled(
                status["server"].as_str().unwrap_or("—").to_owned(),
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
    ];
    let total = status["storage_total_bytes"].as_f64().unwrap_or(0.0);
    let free = status["storage_available_bytes"].as_f64().unwrap_or(0.0);
    lines.push(Line::from(format!(
        "Storage  {} free of {}",
        bytes(free),
        bytes(total)
    )));
    lines.push(Line::from("")); // the usage gauge is drawn on this row
    if total > 0.0 && free / total < 0.1 {
        lines.push(Line::from(vec![
            badge("low free space", WARN),
            muted("  review retention before new snapshots are refused"),
        ]));
    }
    let pending = status["pending_catalog_cleanups"].as_i64().unwrap_or(0);
    if pending > 0 {
        lines.push(Line::from(vec![
            badge(&format!("{pending} cleanup pending"), WARN),
            muted("  deleted snapshot data is removed automatically"),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(muted(
        "A ciphertext receipt proves the stored copy matches what was sent. It is not a restore test.",
    )));
    lines
}

fn storage_ratio(data: &Loaded) -> Option<(f64, Color)> {
    let v = data.server.as_ref().ok()?;
    let total = v["storage_total_bytes"].as_f64()?;
    let free = v["storage_available_bytes"].as_f64()?;
    (total > 0.0).then(|| {
        let used = ((total - free) / total).clamp(0.0, 1.0);
        let color = if used > 0.9 {
            BAD
        } else if used > 0.75 {
            WARN
        } else {
            OK
        };
        (used, color)
    })
}

fn table_block(title: String) -> Block<'static> {
    Block::default()
        .title(title)
        .title_style(Style::default().fg(Color::Rgb(215, 215, 220)))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(90, 90, 100)))
}
fn highlight() -> Style {
    Style::default()
        .bg(Color::Rgb(35, 48, 70))
        .fg(Color::LightBlue)
}

fn nodes_table(data: &Loaded, selected: usize) -> (Table<'static>, TableState) {
    let nodes = data
        .nodes
        .as_ref()
        .ok()
        .and_then(|v| v["nodes"].as_array().cloned())
        .unwrap_or_default();
    let rows: Vec<Row> = nodes
        .iter()
        .map(|n| {
            let state = if n["revoked"].as_bool().unwrap_or(false) {
                badge("revoked", BAD)
            } else if n["enrolled"].as_bool().unwrap_or(false) {
                badge("enrolled", OK)
            } else {
                badge("waiting for enrollment", WARN)
            };
            let cert = n["certificate_sha256"].as_str().unwrap_or("");
            Row::new(vec![
                Line::from(n["node"].as_str().unwrap_or("—").to_owned()),
                Line::from(format!("{}…", &cert[..cert.len().min(16)])),
                Line::from(state),
            ])
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Length(22),
            Constraint::Length(20),
            Constraint::Min(10),
        ],
    )
    .header(Row::new(["Node", "Certificate", "State"]).style(Style::default().fg(MUTED).bold()))
    .row_highlight_style(highlight())
    .highlight_symbol("› ")
    .block(table_block(format!(" Nodes ({}) ", nodes.len())));
    (table, TableState::default().with_selected(Some(selected)))
}

fn snapshots_table(data: &Loaded, node: &str) -> Table<'static> {
    let (snapshots, protected) = match &data.snapshots {
        Some(Ok(v)) => (
            v["snapshots"].as_array().cloned().unwrap_or_default(),
            v["protected"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_owned))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
        ),
        _ => (Vec::new(), Vec::new()),
    };
    let rows: Vec<Row> = snapshots
        .iter()
        .map(|s| {
            let id = s["id"].as_str().unwrap_or("—").to_owned();
            let mut status = Vec::new();
            if s["pinned"].as_bool().unwrap_or(false) {
                status.push(badge("pinned", OK));
                status.push(Span::raw(" "));
            }
            if protected.contains(&id) {
                status.push(badge("protected", MUTED));
                status.push(Span::raw(" "));
            }
            status.push(if s["restore_tested"].as_bool().unwrap_or(false) {
                badge("restore tested", OK)
            } else {
                badge("not restore tested", WARN)
            });
            Row::new(vec![
                Line::from(id),
                Line::from(when(s["received_at"].as_i64().unwrap_or(0))),
                Line::from(status),
            ])
        })
        .collect();
    Table::new(
        rows,
        [
            Constraint::Length(24),
            Constraint::Length(22),
            Constraint::Min(10),
        ],
    )
    .header(Row::new(["Snapshot", "Received", "Status"]).style(Style::default().fg(MUTED).bold()))
    .block(table_block(format!(
        " Snapshots for {node} · newest received first "
    )))
}

fn sending(agent: &Value) -> (Vec<Line<'static>>, Vec<Row<'static>>) {
    let status = &agent["status"];
    let state = status["state"].as_str().unwrap_or("not_observed");
    let (color, text) = match state {
        "blocked" | "source_blocked" => (BAD, "The agent configuration or queue needs review."),
        "deferred" => (
            WARN,
            "Transfers are waiting for the host to be ready; they resume automatically.",
        ),
        "paused" => (
            WARN,
            "Scheduled transfers are paused in the local configuration.",
        ),
        "transferring" => (OK, "A snapshot is being sent to a backup server."),
        "scheduled" => (
            OK,
            "The next snapshot is scheduled. Nothing is transferring now.",
        ),
        "disabled" => (MUTED, "This host is not set up to send backups."),
        _ => (MUTED, "No agent status has been recorded on this host yet."),
    };
    let mut lines = vec![
        Line::from(badge(&state.replace('_', " "), color)),
        Line::from(text),
    ];
    if let Some(e) = status["error"].as_str() {
        lines.push(Line::from(Span::styled(
            e.to_owned(),
            Style::default().fg(BAD),
        )));
    }
    if let Some(e) = status["source_error"].as_str() {
        lines.push(Line::from(Span::styled(
            format!("The next backup cannot be queued: {e}"),
            Style::default().fg(BAD),
        )));
    }
    if let Some(h) = status["queue"]["history"].as_object()
        && h.get("compacted_identities")
            .and_then(Value::as_i64)
            .unwrap_or(0)
            > 0
    {
        lines.push(Line::from(muted(format!(
            "Older completed transfers are summarised: {} compacted, newest {} kept.",
            h["compacted_identities"], h["completed_job_limit"]
        ))));
    }
    lines.push(Line::from(muted(
        "Last recorded worker observation; this view does not probe remote servers.",
    )));
    let rows = status["queue"]["transfers"]
        .as_array()
        .map(|t| {
            t.iter()
                .map(|t| {
                    let st = t["state"].as_str().unwrap_or("—");
                    let tone = match st {
                        "completed" => OK,
                        "blocked" => BAD,
                        _ => MUTED,
                    };
                    let receipt = t["receipt"]["verified_at"]
                        .as_i64()
                        .map(|v| format!("receipt {} · not a restore test", when(v)))
                        .unwrap_or_else(|| "—".into());
                    Row::new(vec![
                        Line::from(t["snapshot"].as_str().unwrap_or("—").to_owned()),
                        Line::from(badge(st, tone)),
                        Line::from(t["attempts"].to_string()),
                        Line::from(receipt),
                    ])
                })
                .collect()
        })
        .unwrap_or_default();
    (lines, rows)
}

fn policy(data: &Loaded) -> Vec<Line<'static>> {
    let p = match &data.server {
        Ok(v) => &v["policy"],
        Err(e) => return error_lines(e),
    };
    let number = |key: &str| p[key].as_u64();
    let secs = |key: &str| number(key).map(duration).unwrap_or_else(|| "—".into());
    let size = |key: &str| {
        p[key]
            .as_f64()
            .map(bytes)
            .unwrap_or_else(|| "no limit".into())
    };
    let row = |label: &str, value: String| {
        Line::from(vec![
            Span::styled(format!("{label:<28}"), Style::default().fg(MUTED)),
            Span::raw(value),
        ])
    };
    vec![
        heading(&format!("Revision {}", number("revision").unwrap_or(0))),
        Line::from(""),
        row("Backup interval", secs("interval_seconds")),
        row("Recovery point goal", secs("recovery_point_seconds")),
        row(
            "Snapshots to keep",
            number("keep_snapshots").map_or("—".into(), |v| v.to_string()),
        ),
        row("Reserve space", size("reserve_bytes")),
        row("Longest allowed deferral", secs("max_deferral_seconds")),
        row(
            "Bandwidth share",
            number("bandwidth_percent").map_or("—".into(), |v| format!("{v} %")),
        ),
        row("Monthly limit per node", size("monthly_node_bytes")),
        row("Monthly limit for server", size("monthly_server_bytes")),
        row(
            "Required copies",
            number("required_copies").map_or("—".into(), |v| v.to_string()),
        ),
        Line::from(""),
        Line::from(muted("A policy does not start a schedule by itself.")),
    ]
}

pub fn hint(state: &State) -> &'static str {
    match state.tab {
        1 | 2 => "←/→ Tab  ↑/↓ Node  r Refresh  Esc Back  — changes need the web dashboard",
        _ => "←/→ Tab  r Refresh  Esc Back  — changes need the web dashboard",
    }
}

pub fn render(f: &mut Frame, area: Rect, state: &State) {
    let block = table_block(
        if state.loading {
            " Backups · reading… "
        } else {
            " Backups "
        }
        .to_owned(),
    );
    let inner = block.inner(area);
    f.render_widget(block, area);
    let [tabs_area, body] =
        Layout::vertical([Constraint::Length(2), Constraint::Min(1)]).areas(inner);
    f.render_widget(
        Tabs::new(TABS.iter().map(|t| Line::from(*t)))
            .select(state.tab)
            .style(Style::default().fg(MUTED))
            .highlight_style(
                Style::default()
                    .fg(ACCENT)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            )
            .divider(" │ "),
        tabs_area,
    );
    let Some(data) = &state.data else {
        f.render_widget(Paragraph::new("Reading backup status…").fg(MUTED), body);
        return;
    };
    match state.tab {
        0 => {
            f.render_widget(
                Paragraph::new(overview(data)).wrap(Wrap { trim: false }),
                body,
            );
            if let Some((used, color)) = storage_ratio(data)
                && body.height > 3
            {
                f.render_widget(
                    LineGauge::default()
                        .filled_style(Style::default().fg(color))
                        .unfilled_style(Style::default().fg(Color::Rgb(60, 60, 66)))
                        .label(format!("{:.0}% used", used * 100.0))
                        .ratio(used),
                    Rect {
                        x: body.x,
                        y: body.y + 3,
                        width: body.width.min(60),
                        height: 1,
                    },
                );
            }
        }
        1 => match &data.nodes {
            Ok(_) => {
                let (table, mut ts) = nodes_table(data, state.node);
                f.render_stateful_widget(table, body, &mut ts);
            }
            Err(e) => f.render_widget(
                Paragraph::new(error_lines(e)).wrap(Wrap { trim: false }),
                body,
            ),
        },
        2 => match (&data.nodes, state.node_name()) {
            (Err(e), _) => f.render_widget(
                Paragraph::new(error_lines(e)).wrap(Wrap { trim: false }),
                body,
            ),
            (Ok(_), None) => {
                f.render_widget(Paragraph::new("No nodes have been approved yet."), body)
            }
            (Ok(_), Some(node)) => match &data.snapshots {
                Some(Err(e)) => f.render_widget(Paragraph::new(error_lines(e)), body),
                _ => f.render_widget(snapshots_table(data, &node), body),
            },
        },
        3 => {
            let (lines, rows) = sending(&data.agent);
            let [text, table] = Layout::vertical([
                Constraint::Length(lines.len() as u16 + 1),
                Constraint::Min(0),
            ])
            .areas(body);
            f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), text);
            if !rows.is_empty() {
                f.render_widget(
                    Table::new(
                        rows,
                        [
                            Constraint::Length(20),
                            Constraint::Length(14),
                            Constraint::Length(10),
                            Constraint::Min(10),
                        ],
                    )
                    .header(
                        Row::new(["Snapshot", "State", "Attempts", "Receipt"])
                            .style(Style::default().fg(MUTED).bold()),
                    )
                    .block(table_block(" Latest transfers ".into())),
                    table,
                );
            }
        }
        _ => f.render_widget(
            Paragraph::new(policy(data)).alignment(Alignment::Left),
            body,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    fn loaded() -> Loaded {
        Loaded {
            server: Ok(
                json!({"site":"home","server":"main","storage_total_bytes":2.0e12,"storage_available_bytes":1.5e11,
                "pending_catalog_cleanups":2,
                "policy":{"revision":3,"interval_seconds":3600,"recovery_point_seconds":7200,"keep_snapshots":3,
                    "reserve_bytes":1073741824u64,"max_deferral_seconds":86400,"bandwidth_percent":25,
                    "monthly_node_bytes":null,"monthly_server_bytes":5497558138880u64,"required_copies":1}}),
            ),
            nodes: Ok(json!({"nodes":[
                {"node":"alpha","certificate_sha256":"a".repeat(64),"enrolled":true,"revoked":false},
                {"node":"beta","certificate_sha256":"b".repeat(64),"enrolled":false,"revoked":false}]})),
            snapshots: Some(Ok(json!({"snapshots":[
                {"id":"snap-0003","received_at":1700000310,"pinned":false,"restore_tested":false},
                {"id":"snap-0002","received_at":1700000210,"pinned":true,"restore_tested":true}],
                "protected":["snap-0003","snap-0002"]}))),
            agent: json!({"status":{"state":"deferred","source_error":"manifest changed",
                "queue":{"history":{"completed_job_limit":256,"compacted_identities":5},
                "transfers":[{"snapshot":"snap-0003","state":"completed","attempts":1,
                    "receipt":{"verified_at":1700000400}}]}}}),
        }
    }
    fn screen(state: &State, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|f| render(f, f.area(), state)).unwrap();
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
    fn state(tab: usize) -> State {
        State {
            tab,
            node: 0,
            loading: false,
            data: Some(loaded()),
        }
    }

    #[test]
    fn overview_shows_storage_cleanup_and_the_restore_caveat() {
        let s = screen(&state(0), 100, 18);
        assert!(
            s.contains("150.0 GiB free") || s.contains("139.7 GiB free"),
            "{s}"
        );
        assert!(s.contains("2 cleanup pending"), "{s}");
        assert!(s.contains("not a restore test"), "{s}");
    }
    #[test]
    fn nodes_distinguish_enrolled_and_pending() {
        let s = screen(&state(1), 100, 12);
        assert!(s.contains("alpha") && s.contains("enrolled"), "{s}");
        assert!(s.contains("waiting for enrollment"), "{s}");
    }
    #[test]
    fn snapshots_are_honest_about_restore_testing() {
        let s = screen(&state(2), 110, 12);
        assert!(s.contains("Snapshots for alpha"), "{s}");
        assert!(
            s.contains("not restore tested") && s.contains("restore tested"),
            "{s}"
        );
        assert!(s.contains("pinned") && s.contains("protected"), "{s}");
    }
    #[test]
    fn sending_shows_source_error_history_and_receipt_caveat() {
        let s = screen(&state(3), 120, 16);
        assert!(s.contains("deferred"), "{s}");
        assert!(
            s.contains("The next backup cannot be queued: manifest changed"),
            "{s}"
        );
        assert!(s.contains("5 compacted"), "{s}");
        assert!(s.contains("not a restore test"), "{s}");
    }
    #[test]
    fn policy_uses_human_units_and_no_limit() {
        let s = screen(&state(4), 100, 16);
        assert!(
            s.contains("Revision 3") && s.contains("1 h") && s.contains("1.0 GiB"),
            "{s}"
        );
        assert!(s.contains("no limit") && s.contains("5.0 TiB"), "{s}");
    }
    #[test]
    fn unconfigured_server_is_explained_not_blank() {
        let mut st = state(0);
        st.data.as_mut().unwrap().server = Err("Backup service is not configured".into());
        st.data.as_mut().unwrap().nodes = Err("Backup service is not configured".into());
        assert!(screen(&st, 100, 12).contains("not set up as a backup server"));
        st.tab = 1;
        assert!(screen(&st, 100, 12).contains("Nothing is stored here"));
    }
    #[test]
    fn server_outage_is_not_shown_as_healthy() {
        let mut st = state(0);
        st.data.as_mut().unwrap().server = Err("connection refused".into());
        let s = screen(&st, 100, 12);
        assert!(
            s.contains("unavailable") && s.contains("not a sign that backups are healthy"),
            "{s}"
        );
    }
    /// Review aid, not an assertion: with TUI_DUMP_DIR set, write every tab as an
    /// ANSI dump so it can be turned into an image and looked at.
    #[test]
    fn dump_screens_for_review() {
        let Ok(dir) = std::env::var("TUI_DUMP_DIR") else {
            return;
        };
        let sgr = |c: Color, fg: bool| -> String {
            let base = if fg { 30 } else { 40 };
            match c {
                Color::Rgb(r, g, b) => format!("{};2;{r};{g};{b}", if fg { 38 } else { 48 }),
                Color::Indexed(n) => format!("{};5;{n}", if fg { 38 } else { 48 }),
                Color::Black => format!("{}", base),
                Color::Red => format!("{}", base + 1),
                Color::Green => format!("{}", base + 2),
                Color::Yellow => format!("{}", base + 3),
                Color::Blue => format!("{}", base + 4),
                Color::Magenta => format!("{}", base + 5),
                Color::Cyan => format!("{}", base + 6),
                Color::Gray => format!("{}", base + 7),
                Color::LightBlue => format!("{}", base + 64 + 4),
                Color::White => format!("{}", base + 67),
                _ => String::new(),
            }
        };
        for (n, name) in TABS.iter().enumerate() {
            let st = state(n);
            let mut terminal = Terminal::new(TestBackend::new(110, 22)).unwrap();
            terminal.draw(|f| render(f, f.area(), &st)).unwrap();
            let buffer = terminal.backend().buffer().clone();
            let mut out = String::new();
            for y in 0..22 {
                for x in 0..110 {
                    let cell = &buffer[(x, y)];
                    let mut codes = vec!["0".to_owned()];
                    let fg = sgr(cell.fg, true);
                    let bg = sgr(cell.bg, false);
                    if !fg.is_empty() {
                        codes.push(fg);
                    }
                    if !bg.is_empty() {
                        codes.push(bg);
                    }
                    if cell.modifier.contains(Modifier::BOLD) {
                        codes.push("1".into());
                    }
                    if cell.modifier.contains(Modifier::UNDERLINED) {
                        codes.push("4".into());
                    }
                    out.push_str(&format!("\x1b[{}m{}", codes.join(";"), cell.symbol()));
                }
                out.push_str("\x1b[0m\n");
            }
            std::fs::write(
                format!("{dir}/backups-{n}-{}.ansi", name.to_lowercase()),
                out,
            )
            .unwrap();
        }
    }

    #[test]
    fn tiny_terminals_do_not_panic() {
        for tab in 0..TABS.len() {
            let _ = screen(&state(tab), 20, 6);
            let _ = screen(&state(tab), 1, 1);
        }
    }
    #[test]
    fn node_selection_is_bounded() {
        let mut st = state(1);
        assert!(!st.move_node(false));
        assert!(st.move_node(true));
        assert!(!st.move_node(true));
        assert_eq!(st.node_name().as_deref(), Some("beta"));
        assert_eq!(duration(90), "1 min");
        assert_eq!(duration(3600), "1 h");
        assert_eq!(duration(45), "45 s");
    }
}
