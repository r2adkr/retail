//! `retail tui`: the daemon in a terminal, for servers over SSH and small
//! machines without a desktop. It asks the local API every two seconds and
//! after each key, and redraws only then, so it idles at no CPU.

use std::time::Duration;

use anyhow::Result;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Tabs, Wrap,
};
use ratatui::{DefaultTerminal, Frame};
use retail_proto::api::{
    BackendState, InviteRequest, InviteResponse, PrefsRequest, ServerSelect, ServerStartRequest,
    ServerStatus, StatusResponse, UpRequest,
};

use crate::Client;

const TABS: [&str; 3] = ["Network", "Server", "Servers"];
const REFRESH: Duration = Duration::from_secs(2);

enum Popup {
    /// A code to copy from the screen
    Invite(String),
    /// A question; `y` runs the action
    Confirm(String, Action),
    Help,
}

#[derive(Clone)]
enum Action {
    StopServer,
    RemoveDevice(i64),
    Forget(String),
}

struct App {
    tab: usize,
    status: Option<StatusResponse>,
    server: Option<ServerStatus>,
    /// Shown in the footer: (text, is_error)
    note: Option<(String, bool)>,
    popup: Option<Popup>,
    rows: [TableState; 3],
}

pub async fn run(client: &Client) -> Result<()> {
    let mut term = ratatui::init();
    let result = app(&mut term, client).await;
    ratatui::restore();
    result
}

async fn app(term: &mut DefaultTerminal, client: &Client) -> Result<()> {
    // Keys come from a thread that blocks in read(), so nothing polls
    let (tx, mut keys) = tokio::sync::mpsc::channel::<Event>(16);
    std::thread::spawn(move || {
        while let Ok(ev) = event::read() {
            if tx.blocking_send(ev).is_err() {
                break;
            }
        }
    });
    let mut app = App {
        tab: 0,
        status: None,
        server: None,
        note: None,
        popup: None,
        rows: Default::default(),
    };
    app.refresh(client).await;
    let mut tick = tokio::time::interval(REFRESH);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        term.draw(|f| app.draw(f))?;
        tokio::select! {
            ev = keys.recv() => {
                match ev {
                    Some(Event::Key(k)) if k.kind == KeyEventKind::Press => {
                        if !app.key(k, client, term).await {
                            return Ok(());
                        }
                    }
                    Some(_) => {}
                    None => return Ok(()),
                }
            }
            _ = tick.tick() => app.refresh(client).await,
        }
    }
}

impl App {
    async fn refresh(&mut self, client: &Client) {
        match client.get::<StatusResponse>("/status").await {
            Ok(s) => self.status = Some(s),
            Err(e) => {
                self.status = None;
                self.note = Some((format!("{e:#}"), true));
            }
        }
        self.server = client.get::<ServerStatus>("/server").await.ok();
    }

    fn peers_len(&self) -> usize {
        self.status.as_ref().map_or(0, |s| s.peers.len())
    }

    fn list_len(&self) -> usize {
        match self.tab {
            0 => self.peers_len(),
            1 => self.server.as_ref().map_or(0, |s| s.nodes.len()),
            _ => self.status.as_ref().map_or(0, |s| s.servers.len()),
        }
    }

    /// False to quit
    async fn key(&mut self, k: KeyEvent, client: &Client, term: &mut DefaultTerminal) -> bool {
        if let Some(popup) = self.popup.take() {
            if let (Popup::Confirm(_, action), KeyCode::Char('y' | 'Y')) = (&popup, k.code) {
                self.run(action.clone(), client, term).await;
            }
            return true;
        }
        let ctrl_c = k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL);
        match k.code {
            _ if ctrl_c => return false,
            KeyCode::Char('q') | KeyCode::Esc => return false,
            KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => {
                self.tab = (self.tab + 1) % TABS.len()
            }
            KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => {
                self.tab = (self.tab + TABS.len() - 1) % TABS.len()
            }
            KeyCode::Char(c @ '1'..='3') => self.tab = c as usize - '1' as usize,
            KeyCode::Down | KeyCode::Char('j') => {
                let n = self.list_len();
                let t = &mut self.rows[self.tab];
                t.select(Some(
                    t.selected().map_or(0, |i| (i + 1).min(n.saturating_sub(1))),
                ));
            }
            KeyCode::Up | KeyCode::Char('k') => {
                let t = &mut self.rows[self.tab];
                t.select(Some(t.selected().map_or(0, |i| i.saturating_sub(1))));
            }
            KeyCode::Char('?') => self.popup = Some(Popup::Help),
            KeyCode::Char('r') => self.note = None,
            _ => self.tab_key(k.code, client, term).await,
        }
        self.refresh(client).await;
        true
    }

    async fn tab_key(&mut self, code: KeyCode, client: &Client, term: &mut DefaultTerminal) {
        let selected = self.rows[self.tab].selected();
        match (self.tab, code) {
            // Network
            (0, KeyCode::Char(' ' | 'c')) => {
                let Some(s) = self.status.clone() else { return };
                if s.state == BackendState::Running {
                    self.busy(term, "Disconnecting…");
                    self.done(
                        client
                            .post::<(), StatusResponse>("/down", None)
                            .await
                            .map(|_| "Disconnected".into()),
                    );
                } else if let Some(server) = s.server {
                    self.busy(term, "Connecting…");
                    let req = UpRequest {
                        server,
                        ..Default::default()
                    };
                    self.done(
                        client
                            .post::<_, StatusResponse>("/up", Some(&req))
                            .await
                            .map(|_| "Connected".into()),
                    );
                } else {
                    self.note = Some(("Not logged in: retail up --invite <code>".into(), true));
                }
            }
            (0, KeyCode::Char('e')) => {
                let Some(p) = selected.and_then(|i| self.status.as_ref()?.peers.get(i).cloned())
                else {
                    return;
                };
                let using =
                    self.status.as_ref().and_then(|s| s.prefs.exit_node) == Some(p.node_key);
                let req = PrefsRequest {
                    exit_node: Some(if using {
                        String::new()
                    } else {
                        p.node_key.to_base64()
                    }),
                    ..Default::default()
                };
                let what = if using {
                    "Stopped using the exit node".to_string()
                } else {
                    format!("Internet traffic now goes through {}", p.hostname)
                };
                self.done(
                    client
                        .post::<_, StatusResponse>("/prefs", Some(&req))
                        .await
                        .map(|_| what),
                );
            }
            // Server
            (1, KeyCode::Char('s')) => {
                if self.server.as_ref().is_some_and(|s| s.running) {
                    self.popup = Some(Popup::Confirm(
                        "Stop the server? Every device is disconnected until it starts again."
                            .into(),
                        Action::StopServer,
                    ));
                } else {
                    self.busy(term, "Starting the server…");
                    let req = ServerStartRequest {
                        join: true,
                        ..Default::default()
                    };
                    self.done(
                        client
                            .post::<_, ServerStatus>("/server/start", Some(&req))
                            .await
                            .map(|_| "Server started".into()),
                    );
                }
            }
            (1, KeyCode::Char('i')) => {
                match client
                    .post::<_, InviteResponse>("/server/invite", Some(&InviteRequest::default()))
                    .await
                {
                    Ok(inv) => self.popup = Some(Popup::Invite(inv.code)),
                    Err(e) => self.note = Some((format!("{e:#}"), true)),
                }
            }
            (1, KeyCode::Char('d') | KeyCode::Delete) => {
                let Some(n) = selected.and_then(|i| self.server.as_ref()?.nodes.get(i).cloned())
                else {
                    return;
                };
                self.popup = Some(Popup::Confirm(
                    format!(
                        "Remove {} from the network? It needs a new invite to come back.",
                        n.hostname
                    ),
                    Action::RemoveDevice(n.id),
                ));
            }
            // Saved servers
            (2, KeyCode::Enter) => {
                let Some(srv) =
                    selected.and_then(|i| self.status.as_ref()?.servers.get(i).cloned())
                else {
                    return;
                };
                if srv.current {
                    return;
                }
                self.busy(term, "Switching…");
                let req = ServerSelect {
                    server: srv.server.clone(),
                };
                self.done(
                    client
                        .post::<_, StatusResponse>("/servers/switch", Some(&req))
                        .await
                        .map(|_| format!("Switched to {}", srv.server)),
                );
            }
            (2, KeyCode::Char('d') | KeyCode::Delete) => {
                let Some(srv) =
                    selected.and_then(|i| self.status.as_ref()?.servers.get(i).cloned())
                else {
                    return;
                };
                let q = if srv.current {
                    format!("Log out of {} and remove it?", srv.server)
                } else {
                    format!("Remove {} from the list?", srv.server)
                };
                self.popup = Some(Popup::Confirm(q, Action::Forget(srv.server)));
            }
            _ => {}
        }
    }

    async fn run(&mut self, action: Action, client: &Client, term: &mut DefaultTerminal) {
        match action {
            Action::StopServer => {
                self.busy(term, "Stopping the server…");
                self.done(
                    client
                        .post::<(), ServerStatus>("/server/stop", None)
                        .await
                        .map(|_| "Server stopped".into()),
                );
            }
            Action::RemoveDevice(id) => {
                self.done(
                    client
                        .post::<(), ServerStatus>(&format!("/server/nodes/{id}/delete"), None)
                        .await
                        .map(|_| "Device removed".into()),
                );
            }
            Action::Forget(server) => {
                let req = ServerSelect { server };
                self.done(
                    client
                        .post::<_, StatusResponse>("/servers/forget", Some(&req))
                        .await
                        .map(|_| "Removed from the list".into()),
                );
            }
        }
        self.refresh(client).await;
    }

    /// Shows a note at once, before a slow call
    fn busy(&mut self, term: &mut DefaultTerminal, text: &str) {
        self.note = Some((text.to_string(), false));
        let _ = term.draw(|f| self.draw(f));
    }

    fn done(&mut self, r: Result<String>) {
        self.note = Some(match r {
            Ok(m) => (m, false),
            Err(e) => (format!("{e:#}"), true),
        });
    }

    fn draw(&mut self, f: &mut Frame) {
        let [head, tabs, body, foot] = Layout::vertical([
            Constraint::Length(2),
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(2),
        ])
        .areas(f.area());
        f.render_widget(Paragraph::new(self.header()), head);
        f.render_widget(
            Tabs::new(
                TABS.iter()
                    .enumerate()
                    .map(|(i, t)| format!("{} {t}", i + 1)),
            )
            .select(self.tab)
            .highlight_style(Style::new().add_modifier(Modifier::BOLD | Modifier::REVERSED)),
            tabs,
        );
        match self.tab {
            0 => self.network(f, body),
            1 => self.server_tab(f, body),
            _ => self.servers(f, body),
        }
        f.render_widget(Paragraph::new(self.footer()), foot);
        if let Some(p) = &self.popup {
            popup(f, p);
        }
    }

    fn header(&self) -> Vec<Line<'static>> {
        let Some(s) = &self.status else {
            return vec![Line::from(Span::styled(
                "retaild is not running",
                Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
            ))];
        };
        let (state, color) = match s.state {
            BackendState::Running if s.control_connected => ("● connected", Color::Green),
            BackendState::Running => ("● connected, server unreachable", Color::Yellow),
            BackendState::Stopped => ("○ disconnected", Color::Gray),
            BackendState::NeedsLogin => ("○ not logged in", Color::Yellow),
        };
        let me = s.self_node.as_ref().map_or_else(String::new, |n| {
            format!(
                "  {} {}",
                n.ip,
                if n.dns_name.is_empty() {
                    &n.hostname
                } else {
                    &n.dns_name
                }
            )
        });
        let mut second = Vec::new();
        if let Some(srv) = &s.server {
            second.push(Span::raw(srv.trim_start_matches("https://").to_string()));
        }
        if s.update.available {
            second.push(Span::styled(
                format!(
                    "   update {} available (retail update)",
                    s.update.latest.clone().unwrap_or_default()
                ),
                Style::new().fg(Color::Cyan),
            ));
        }
        vec![
            Line::from(vec![
                Span::styled("retail ", Style::new().add_modifier(Modifier::BOLD)),
                Span::styled(state, Style::new().fg(color)),
                Span::raw(me),
            ]),
            Line::from(second),
        ]
    }

    fn footer(&self) -> Vec<Line<'static>> {
        let keys = match self.tab {
            0 => "space connect/disconnect · e exit node",
            1 if self.server.as_ref().is_some_and(|s| s.running) => {
                "i invite · d remove device · s stop server"
            }
            1 => "s start a server here",
            _ => "enter switch · d remove",
        };
        let note = match &self.note {
            Some((t, true)) => Span::styled(t.clone(), Style::new().fg(Color::Red)),
            Some((t, false)) => Span::styled(t.clone(), Style::new().fg(Color::Green)),
            None => Span::raw(""),
        };
        vec![
            Line::from(note),
            Line::from(Span::styled(
                format!("{keys} · tab/1-3 switch · ? help · q quit"),
                Style::new().fg(Color::DarkGray),
            )),
        ]
    }

    fn network(&mut self, f: &mut Frame, area: Rect) {
        let Some(s) = &self.status else { return };
        let exit = s.prefs.exit_node;
        let rows = s.peers.iter().map(|p| {
            let name = if p.dns_name.is_empty() {
                p.hostname.clone()
            } else {
                p.dns_name.trim_end_matches(".retail.internal").to_string()
            };
            let path = p.path.clone().unwrap_or_else(|| {
                if p.online {
                    "connecting".into()
                } else {
                    "offline".into()
                }
            });
            let hs = p
                .last_handshake_secs
                .map_or_else(|| "-".into(), |s| format!("{s}s"));
            let mut flags = Vec::new();
            if exit == Some(p.node_key) {
                flags.push("using as exit");
            } else if p.exit_node {
                flags.push("exit node");
            }
            if p.restricted {
                flags.push("limited");
            }
            if !p.routes.is_empty() {
                flags.push("routes");
            }
            let style = if p.online {
                Style::new()
            } else {
                Style::new().fg(Color::DarkGray)
            };
            Row::new(vec![
                Cell::from(name),
                Cell::from(p.ip.to_string()),
                Cell::from(path),
                Cell::from(hs),
                Cell::from(flags.join(", ")),
            ])
            .style(style)
        });
        let table = Table::new(
            rows,
            [
                Constraint::Fill(2),
                Constraint::Length(15),
                Constraint::Fill(3),
                Constraint::Length(9),
                Constraint::Length(20),
            ],
        )
        .header(
            Row::new(["DEVICE", "IP", "PATH", "HANDSHAKE", ""])
                .style(Style::new().add_modifier(Modifier::BOLD)),
        )
        .block(Block::new().borders(Borders::TOP).title(if s.key_expired {
            " this device's key expired: ask the server's administrator to renew it ".to_string()
        } else {
            format!(" {} devices ", s.peers.len())
        }))
        .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED));
        f.render_stateful_widget(table, area, &mut self.rows[0]);
    }

    fn server_tab(&mut self, f: &mut Frame, area: Rect) {
        let Some(s) = &self.server else {
            f.render_widget(Paragraph::new("Cannot read the server status."), area);
            return;
        };
        if !s.running {
            let mut text = vec![Line::from(
                "No server runs on this machine. Press s to start one; this device joins it.",
            )];
            text.push(Line::from(
                "For a server that does not join (a VPS): retail server start --no-join",
            ));
            if let Some(e) = &s.last_error {
                text.push(Line::from(Span::styled(
                    e.clone(),
                    Style::new().fg(Color::Red),
                )));
            }
            f.render_widget(Paragraph::new(text).wrap(Wrap { trim: true }), area);
            return;
        }
        let mut info = vec![Line::from(format!(
            "address {}   router {}",
            s.public
                .clone()
                .unwrap_or_else(|| "not reachable from other networks".into()),
            s.port_mapping.clone().unwrap_or_else(|| "-".into())
        ))];
        if let Some(w) = &s.warning {
            info.push(Line::from(Span::styled(
                w.clone(),
                Style::new().fg(Color::Yellow),
            )));
        }
        let named = s.invites.iter().filter(|i| i.name.is_some()).count();
        info.push(Line::from(format!(
            "{} invites ({named} named; manage named ones with retail server invite --name)   access {}",
            s.invites.len(),
            if s.acl.is_some() { "limited by rules" } else { "open" }
        )));
        let lines = info.len() as u16 + 1;
        let [top, list] =
            Layout::vertical([Constraint::Length(lines), Constraint::Min(2)]).areas(area);
        f.render_widget(Paragraph::new(info).wrap(Wrap { trim: true }), top);
        let rows = s.nodes.iter().map(|n| {
            let style = if n.online {
                Style::new()
            } else {
                Style::new().fg(Color::DarkGray)
            };
            let name = if n.dns_name.is_empty() {
                n.hostname.clone()
            } else {
                n.dns_name.clone()
            };
            let tags = n
                .tags
                .iter()
                .map(|t| format!("#{t}"))
                .collect::<Vec<_>>()
                .join(" ");
            Row::new(vec![
                name,
                n.ip.to_string(),
                n.os.clone(),
                if n.online {
                    "online".into()
                } else {
                    "offline".into()
                },
                tags,
            ])
            .style(style)
        });
        let table = Table::new(
            rows,
            [
                Constraint::Fill(3),
                Constraint::Length(15),
                Constraint::Length(9),
                Constraint::Length(8),
                Constraint::Fill(2),
            ],
        )
        .header(
            Row::new(["DEVICE", "IP", "OS", "", "TAGS"])
                .style(Style::new().add_modifier(Modifier::BOLD)),
        )
        .block(
            Block::new()
                .borders(Borders::TOP)
                .title(format!(" {} devices in this network ", s.nodes.len())),
        )
        .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED));
        f.render_stateful_widget(table, list, &mut self.rows[1]);
    }

    fn servers(&mut self, f: &mut Frame, area: Rect) {
        let Some(s) = &self.status else { return };
        let rows = s.servers.iter().map(|srv| {
            let mark = if srv.current { "● current" } else { "" };
            Row::new(vec![
                srv.server.trim_start_matches("https://").to_string(),
                srv.ip.map(|i| i.to_string()).unwrap_or_default(),
                mark.into(),
            ])
        });
        let table = Table::new(
            rows,
            [
                Constraint::Fill(1),
                Constraint::Length(15),
                Constraint::Length(10),
            ],
        )
        .header(
            Row::new(["SERVER", "THIS DEVICE", ""])
                .style(Style::new().add_modifier(Modifier::BOLD)),
        )
        .block(
            Block::new()
                .borders(Borders::TOP)
                .title(" servers this device joined (add one: retail up --invite <code>) "),
        )
        .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED));
        f.render_stateful_widget(table, area, &mut self.rows[2]);
    }
}

fn popup(f: &mut Frame, p: &Popup) {
    let (title, text) = match p {
        Popup::Invite(code) => (" One-time invite (24 h) ", format!("{code}\n\nOn the other device: retail up --invite <code>, or paste it in Settings.\nAny key closes this.")),
        Popup::Confirm(q, _) => (" Confirm ", format!("{q}\n\ny: yes   any other key: no")),
        Popup::Help => (
            " Keys ",
            "tab, ←/→, 1-3   switch tabs\n↑/↓ (j/k)        select\n\nNetwork   space: connect or disconnect   e: use the selected device as exit node (again: stop)\nServer    s: start or stop   i: one-time invite   d: remove the selected device\nServers   enter: switch to the selected server   d: remove it from the list\n\nq or esc  quit"
                .to_string(),
        ),
    };
    let area = f.area();
    let w = area.width.saturating_sub(4).min(90);
    let h = (text.lines().count() as u16 + 4).min(area.height);
    let r = Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height.saturating_sub(h)) / 2,
        w,
        h,
    );
    f.render_widget(Clear, r);
    f.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .block(Block::new().borders(Borders::ALL).title(title)),
        r,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn sample() -> App {
        let status: StatusResponse = serde_json::from_value(serde_json::json!({
            "state": "running", "server": "https://vpn.example.com", "control_connected": true,
            "self_node": {"hostname": "laptop", "ip": "100.64.0.1", "node_key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", "endpoints": [], "dns_name": "laptop.retail.internal"},
            "peers": [
                {"hostname": "nas", "ip": "100.64.0.2", "node_key": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=", "online": true, "endpoint": null,
                 "path": "direct 203.0.113.2:41641", "candidates": [], "last_handshake_secs": 12, "exit_node": true, "tx_bytes": 0, "rx_bytes": 0,
                 "dns_name": "nas.retail.internal", "restricted": true},
                {"hostname": "phone", "ip": "100.64.0.3", "node_key": "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=", "online": false, "endpoint": null,
                 "candidates": [], "last_handshake_secs": null, "tx_bytes": 0, "rx_bytes": 0}
            ],
            "last_error": null,
            "update": {"current": "1.0.0", "latest": "1.1.0", "available": true, "installing": false, "error": null, "supported": true}
        }))
        .unwrap();
        App {
            tab: 0,
            status: Some(status),
            server: None,
            note: Some(("Connected".into(), false)),
            popup: None,
            rows: Default::default(),
        }
    }

    fn render(app: &mut App, w: u16, h: u16) -> String {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| app.draw(f)).unwrap();
        let buf = term.backend().buffer().clone();
        (0..h)
            .map(|y| {
                (0..w)
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn draws_the_network_tab() {
        let mut app = sample();
        let screen = render(&mut app, 100, 14);
        println!("{screen}");
        assert!(screen.contains("● connected"));
        assert!(screen.contains("laptop.retail.internal"));
        assert!(screen.contains("update 1.1.0 available"));
        assert!(screen.contains("nas") && screen.contains("exit node, limited"));
        assert!(screen.contains("offline"));
    }

    #[test]
    fn fits_a_small_terminal() {
        // 40x10, as on a serial console: nothing panics
        let mut app = sample();
        app.popup = Some(Popup::Help);
        render(&mut app, 40, 10);
        app.tab = 1;
        render(&mut app, 20, 5);
    }
}
