use std::time::{Duration, Instant};

use retail_proto::api::{
    BackendState, PathReason, PeerStatus, PortState, SavedServer, StatusResponse,
};
use tiny_skia::{Color, Pixmap, Rect};

use crate::config::ThemePref;
use crate::draw::{Canvas, Theme, contains, shade, with_alpha};
use crate::i18n::{LangPref, tr, trf};
use crate::input::TextInput;
use crate::text::{Fonts, Weight};
use crate::ui::View;

pub const WIDTH: f32 = 440.0;
const PAD: f32 = 24.0;
const FIELD_H: f32 = 36.0;
const BUTTON_H: f32 = 34.0;
/// The line under the first field
const HINT_H: f32 = 18.0;

pub const SERVER: usize = 0;
pub const AUTH_KEY: usize = 1;
pub const DEVICE: usize = 2;

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum Tab {
    #[default]
    General,
    /// Usage and how each device is reached
    Info,
}

#[derive(Clone, Debug, PartialEq)]
pub enum SettingsAction {
    Tab(Tab),
    Focus(usize),
    Connect,
    /// Shows the saved servers
    StartChange,
    /// Leaves the server list or the form
    Cancel,
    /// Shows the form for joining another server
    AddServer,
    SwitchServer(String),
    /// Opens or closes the ⋯ menu of the n-th saved server
    ServerMenu(usize),
    ForgetServer(String),
    Logout,
    Theme(ThemePref),
    Lang(LangPref),
    /// Opens or closes the language list
    LangMenu,
    AdvertiseExit(bool),
    OpenRouterPort(bool),
    /// Mbit/s, 0 for none
    UploadLimit(u32),
    CheckUpdate,
    InstallUpdate,
    AutoUpdate(bool),
    /// Starts retaild with administrator permission
    StartDaemon,
}

const NETWORK_H: f32 = 204.0;
/// What clicking the upload limit steps through, in Mbit/s (0: none)
const UPLOAD_STEPS: [u32; 9] = [0, 5, 10, 20, 50, 100, 200, 500, 1000];
/// The About card: version, then the update row and the automatic-update toggle
const ABOUT_H: f32 = 60.0 + 64.0 + 60.0;
const ROW_H: f32 = 50.0;
/// Saved servers shown at once; more scroll
const MAX_ROWS: usize = 4;
/// The usage card: totals, time connected, this connection, memory
const USAGE_H: f32 = 212.0;
/// The line under the usage card
const USAGE_HINT_H: f32 = 26.0;
const PEER_ROW_H: f32 = 50.0;
/// Devices shown at once on the Info tab; more scroll
const MAX_PEERS: usize = 6;

#[derive(Clone, Copy, PartialEq)]
enum Style {
    Primary,
    Secondary,
    Danger,
}

pub struct Settings {
    pub tab: Tab,
    /// The first device shown on the Info tab, when there are more than fit
    pub peer_scroll: usize,
    pub view: View,
    pub dark: bool,
    pub theme: ThemePref,
    pub lang: LangPref,
    /// The language list is showing
    pub lang_open: bool,
    pub cursor: Option<(f32, f32)>,
    pub inputs: [TextInput; 3],
    pub focus: Option<usize>,
    /// Showing the saved servers while logged in ("Change server")
    pub changing: bool,
    /// Showing the form for joining another server
    pub adding: bool,
    /// The saved server whose ⋯ menu is open
    pub server_menu: Option<usize>,
    /// The first saved server shown, when there are more than fit
    pub server_scroll: usize,
    /// A login or logout is in flight
    pub busy: Option<Instant>,
    /// "Check now" is waiting for the release list
    pub checking: Option<Instant>,
    /// Result line under the server card: (text, is_error)
    pub message: Option<(String, bool)>,
    /// First click on "Log out" arms it, and a second click within 4 s confirms
    pub confirm_logout: Option<Instant>,
    /// Whether the daemon is coming back from an update, or being started
    pub daemon: crate::ui::DaemonWait,
    regions: Vec<(Rect, SettingsAction)>,
}

impl Settings {
    pub fn new(dark: bool, theme: ThemePref, lang: LangPref) -> Self {
        Settings {
            tab: Tab::General,
            peer_scroll: 0,
            view: View::Loading,
            dark,
            theme,
            lang,
            lang_open: false,
            cursor: None,
            inputs: [
                TextInput::new("retail1.…", false),
                TextInput::new("rtl-auth-…", true),
                TextInput::new("This computer's name", false),
            ],
            focus: None,
            changing: false,
            adding: false,
            server_menu: None,
            server_scroll: 0,
            busy: None,
            checking: None,
            message: None,
            confirm_logout: None,
            daemon: Default::default(),
            regions: Vec::new(),
        }
    }

    fn status(&self) -> Option<&StatusResponse> {
        match &self.view {
            View::Status(s) => Some(s),
            _ => None,
        }
    }

    pub fn logged_in(&self) -> bool {
        self.status()
            .is_some_and(|s| s.state != BackendState::NeedsLogin)
    }

    /// Servers joined before, the current one included
    pub fn servers(&self) -> &[SavedServer] {
        self.status().map_or(&[], |s| &s.servers)
    }

    pub fn show_form(&self) -> bool {
        matches!(self.view, View::Status(_))
            && (self.adding || (!self.logged_in() && self.servers().is_empty()))
    }

    /// Scrolls the saved servers by `rows`; true if anything moved
    pub fn scroll_servers(&mut self, rows: i32) -> bool {
        let max = self.servers().len().saturating_sub(MAX_ROWS);
        let next = (self.server_scroll as i32 + rows).clamp(0, max as i32) as usize;
        let moved = next != self.server_scroll;
        self.server_scroll = next;
        if moved {
            self.server_menu = None;
        }
        moved
    }

    /// Whether (x, y) is over the saved servers
    pub fn over_server_list(&self, x: f32, y: f32) -> bool {
        let top = 76.0 + 14.0 + 8.0;
        let bottom = top + self.servers().len().min(MAX_ROWS) as f32 * ROW_H;
        self.tab == Tab::General
            && self.show_list()
            && (PAD..=WIDTH - PAD).contains(&x)
            && (top..=bottom).contains(&y)
    }

    /// The other devices, while connected
    fn peers(&self) -> &[PeerStatus] {
        self.status()
            .filter(|s| s.state == BackendState::Running)
            .map_or(&[], |s| &s.peers)
    }

    /// The Info tab has data once connected
    fn connected(&self) -> bool {
        self.status()
            .is_some_and(|s| s.state == BackendState::Running)
    }

    /// The top of the device list on the Info tab
    fn peers_top(&self) -> f32 {
        76.0 + 14.0 + USAGE_H + USAGE_HINT_H + 40.0 + 14.0
    }

    pub fn over_peer_list(&self, x: f32, y: f32) -> bool {
        let top = self.peers_top();
        let bottom = top + 8.0 + self.peers().len().min(MAX_PEERS) as f32 * PEER_ROW_H;
        self.tab == Tab::Info && (PAD..=WIDTH - PAD).contains(&x) && (top..=bottom).contains(&y)
    }

    /// Scrolls the devices on the Info tab by `rows`; true if anything moved
    pub fn scroll_peers(&mut self, rows: i32) -> bool {
        let max = self.peers().len().saturating_sub(MAX_PEERS);
        let next = (self.peer_scroll as i32 + rows).clamp(0, max as i32) as usize;
        let moved = next != self.peer_scroll;
        self.peer_scroll = next;
        moved
    }

    /// The saved servers, to switch between
    pub fn show_list(&self) -> bool {
        matches!(self.view, View::Status(_))
            && !self.show_form()
            && (self.changing || !self.logged_in())
    }

    pub fn is_busy(&self) -> bool {
        self.busy
            .is_some_and(|t| t.elapsed() < Duration::from_secs(45))
    }

    pub fn is_checking(&self) -> bool {
        self.checking
            .is_some_and(|t| t.elapsed() < Duration::from_secs(45))
    }

    /// A server address instead of an invite code also needs its auth key
    fn with_auth_key(&self) -> bool {
        let first = self.inputs[SERVER].trimmed();
        first.starts_with("https://") || first.starts_with("http://")
    }

    /// The form's fields in order, the auth key only when it is needed
    pub fn form_fields(&self) -> &'static [usize] {
        if self.with_auth_key() {
            &[SERVER, AUTH_KEY, DEVICE]
        } else {
            &[SERVER, DEVICE]
        }
    }

    pub fn logout_armed(&self) -> bool {
        self.confirm_logout
            .is_some_and(|t| t.elapsed() < Duration::from_secs(4))
    }

    /// Pre-fills the device name from the current registration
    pub fn prefill(&mut self) {
        if self.inputs[DEVICE].value.is_empty()
            && let Some(me) = self.status().and_then(|s| s.self_node.clone())
        {
            self.inputs[DEVICE].set(&me.hostname);
        }
    }

    /// The about card has the update rows only while retaild answers
    fn about_h(&self) -> f32 {
        if matches!(self.view, View::Status(_)) {
            ABOUT_H
        } else {
            60.0
        }
    }

    fn card_h(&self) -> f32 {
        match &self.view {
            View::Status(_) if self.show_form() => {
                16.0 + self.form_fields().len() as f32 * (20.0 + FIELD_H + 14.0)
                    + HINT_H
                    + BUTTON_H
                    + 18.0
            }
            View::Status(_) if self.show_list() => {
                8.0 + self.servers().len().min(MAX_ROWS) as f32 * ROW_H + 14.0 + BUTTON_H + 18.0
            }
            View::Status(_) => 16.0 + 2.0 * 50.0 + BUTTON_H + 26.0,
            // Room for the start button, or for the progress bar
            View::Offline if self.daemon.text().2.is_some() => 92.0 + 16.0,
            View::Offline => 92.0 + 48.0,
            _ => 92.0,
        }
    }

    /// The "this device" section (exit-node offer) shows once logged in
    fn show_network(&self) -> bool {
        self.logged_in() && !self.show_form() && !self.show_list()
    }

    pub fn height(&self) -> f32 {
        if self.tab == Tab::Info {
            if !self.connected() {
                return 76.0 + 14.0 + 60.0 + 24.0;
            }
            let rows = self.peers().len().min(MAX_PEERS);
            let list = if rows == 0 {
                60.0
            } else {
                16.0 + rows as f32 * PEER_ROW_H
            };
            return self.peers_top() + list + 24.0;
        }
        // Mirrors `render`: title, then the sections (label 14 + content),
        // 40 between sections, 24 bottom padding
        let message = self
            .message
            .as_ref()
            .map_or(0.0, |(m, _)| 30.0 + 18.0 * m.matches('\n').count() as f32);
        let network = if self.show_network() {
            40.0 + 14.0 + NETWORK_H
        } else {
            0.0
        };
        76.0 + (14.0 + self.card_h() + message)
            + network
            + 40.0
            + (14.0 + 44.0)
            + 40.0
            + (14.0 + 44.0)
            + 40.0
            + (14.0 + self.about_h())
            + 24.0
    }

    pub fn action_at(&self, x: f32, y: f32) -> Option<SettingsAction> {
        // Last drawn is on top (the open language list)
        self.regions
            .iter()
            .rev()
            .find(|(r, _)| contains(r, x, y))
            .map(|(_, a)| a.clone())
    }

    fn hovered(&self, r: &Rect) -> bool {
        self.cursor.is_some_and(|(x, y)| contains(r, x, y))
    }

    pub fn render(&mut self, fonts: &Fonts, pix: &mut Pixmap, scale: f32) {
        let t = Theme::new(self.dark);
        let mut c = Canvas { pix, fonts, scale };
        self.regions.clear();
        let h = self.height();
        c.fill_rect(0.0, 0.0, WIDTH, h, t.bg);

        c.text(
            tr("Settings"),
            PAD,
            44.0,
            20.0,
            Weight::Semibold,
            t.text,
            None,
        );
        self.tabs(&mut c, &t);
        if self.tab == Tab::Info {
            self.info(&mut c, &t);
            return;
        }
        let mut y = 76.0;

        section(&mut c, &t, tr("Connection"), y);
        y += 14.0;
        let card_h = self.card_h();
        c.fill_rrect(PAD, y, WIDTH - 2.0 * PAD, card_h, 12.0, t.surface);
        let inner_x = PAD + 16.0;
        let inner_w = WIDTH - 2.0 * PAD - 32.0;
        match self.view.clone() {
            View::Loading => {
                c.text(
                    tr("Connecting to retaild…"),
                    inner_x,
                    y + 36.0,
                    13.5,
                    Weight::Regular,
                    t.dim,
                    None,
                );
            }
            View::Offline => {
                let (title, hint, bar) = self.daemon.text();
                c.text(
                    &title,
                    inner_x,
                    y + 36.0,
                    14.0,
                    Weight::Semibold,
                    t.text,
                    None,
                );
                c.text(
                    &hint,
                    inner_x,
                    y + 60.0,
                    12.5,
                    Weight::Regular,
                    t.dim,
                    Some(inner_w),
                );
                match bar {
                    Some(f) => crate::ui::progress_bar(&mut c, &t, inner_x, y + 84.0, inner_w, f),
                    None => {
                        let label = tr("Start retaild");
                        let bw = c.measure(label, 13.0, Weight::Semibold) + 28.0;
                        let busy = self.daemon.is_starting();
                        self.button(
                            &mut c,
                            &t,
                            label,
                            inner_x,
                            y + 80.0,
                            bw,
                            Style::Primary,
                            !busy,
                            SettingsAction::StartDaemon,
                        );
                    }
                }
            }
            View::Status(_) if self.show_form() => {
                self.form(&mut c, &t, inner_x, y + 16.0, inner_w)
            }
            View::Status(_) if self.show_list() => self.server_list(&mut c, &t, y),
            View::Status(s) => self.account(&mut c, &t, &s, inner_x, y + 16.0, inner_w),
        }
        y += card_h;
        if let Some((msg, error)) = &self.message {
            let color = if *error { t.red } else { t.accent };
            // A second line is the hint under an error
            for (i, line) in msg.lines().enumerate() {
                let color = if i == 0 { color } else { t.dim };
                c.text(
                    line,
                    PAD + 4.0,
                    y + 22.0,
                    12.5,
                    Weight::Regular,
                    color,
                    Some(WIDTH - 2.0 * PAD - 8.0),
                );
                y += if i == 0 { 30.0 } else { 18.0 };
            }
        }

        if self.show_network()
            && let View::Status(s) = self.view.clone()
        {
            y += 40.0;
            section(&mut c, &t, tr("This device"), y);
            y += 14.0;
            self.network(&mut c, &t, &s, y);
            y += NETWORK_H;
        }

        y += 40.0;
        section(&mut c, &t, tr("Appearance"), y);
        y += 14.0;
        let themes = [ThemePref::System, ThemePref::Light, ThemePref::Dark]
            .map(|p| (p == self.theme, theme_label(p), SettingsAction::Theme(p)));
        self.segmented(&mut c, &t, y, &themes);
        y += 44.0;

        y += 40.0;
        section(&mut c, &t, tr("Language"), y);
        y += 14.0;
        let lang_y = y;
        self.dropdown(&mut c, &t, y);
        y += 44.0;

        y += 40.0;
        section(&mut c, &t, tr("About"), y);
        y += 14.0;
        c.fill_rrect(PAD, y, WIDTH - 2.0 * PAD, self.about_h(), 12.0, t.surface);
        c.text(
            &format!("retail {}", env!("CARGO_PKG_VERSION")),
            inner_x,
            y + 26.0,
            13.5,
            Weight::Semibold,
            t.text,
            None,
        );
        let daemon = match &self.view {
            View::Status(s) => match s.state {
                BackendState::Running => tr("retaild running · connected"),
                BackendState::Stopped => tr("retaild running · disconnected"),
                BackendState::NeedsLogin => tr("retaild running · login needed"),
            },
            View::Offline if self.daemon.restarting() => tr("Restarting retail…"),
            View::Offline => tr("retaild is not running"),
            View::Loading => tr("Checking retaild…"),
        };
        c.text(
            daemon,
            inner_x,
            y + 45.0,
            12.0,
            Weight::Regular,
            t.dim,
            Some(inner_w),
        );
        if let View::Status(s) = self.view.clone() {
            self.updates(&mut c, &t, &s, y + 60.0);
        }

        if self.lang_open {
            self.lang_list(&mut c, &t, lang_y);
        }
        if let Some(i) = self.server_menu
            && self.show_list()
        {
            self.server_popover(&mut c, &t, i);
        }
    }

    /// General | Info, at the right of the title
    fn tabs(&mut self, c: &mut Canvas, t: &Theme) {
        let tabs = [(Tab::General, tr("General")), (Tab::Info, tr("Info"))];
        let seg = tabs
            .iter()
            .map(|(_, l)| c.measure(l, 12.5, Weight::Semibold))
            .fold(0.0, f32::max)
            + 28.0;
        // Beside the title, clear of the window buttons at the top right
        let (h, y) = (32.0, 22.0);
        let x = PAD + c.measure(tr("Settings"), 20.0, Weight::Semibold) + 16.0;
        c.fill_rrect(x, y, seg * tabs.len() as f32 + 8.0, h, 9.0, t.surface);
        for (i, (tab, label)) in tabs.into_iter().enumerate() {
            let sx = x + 4.0 + i as f32 * seg;
            let r = Rect::from_xywh(sx, y + 4.0, seg, h - 8.0).unwrap();
            let selected = tab == self.tab;
            if selected {
                c.fill_rrect(
                    sx,
                    y + 4.0,
                    seg,
                    h - 8.0,
                    6.0,
                    if self.dark { t.hover } else { t.bg },
                );
            } else if self.hovered(&r) {
                c.fill_rrect(sx, y + 4.0, seg, h - 8.0, 6.0, with_alpha(t.hover, 0.6));
            }
            let weight = if selected {
                Weight::Semibold
            } else {
                Weight::Regular
            };
            let lw = c.measure(label, 12.5, weight);
            c.text(
                label,
                sx + (seg - lw) / 2.0,
                y + 20.5,
                12.5,
                weight,
                if selected { t.text } else { t.dim },
                None,
            );
            self.regions.push((r, SettingsAction::Tab(tab)));
        }
    }

    /// Traffic and memory, then each device's path and why
    fn info(&mut self, c: &mut Canvas, t: &Theme) {
        let (x, w) = (PAD, WIDTH - 2.0 * PAD);
        let (ix, iw) = (x + 16.0, w - 32.0);
        let mut y = 76.0;
        section(c, t, tr("Usage"), y);
        y += 14.0;
        let Some(s) = self.status().filter(|_| self.connected()).cloned() else {
            c.fill_rrect(x, y, w, 60.0, 12.0, t.surface);
            c.text(
                tr("Connect to see usage and paths."),
                ix,
                y + 35.0,
                13.0,
                Weight::Regular,
                t.dim,
                Some(iw),
            );
            return;
        };
        c.fill_rrect(x, y, w, USAGE_H, 12.0, t.surface);
        let tx: u64 = s.peers.iter().map(|p| p.tx_bytes).sum();
        let rx: u64 = s.peers.iter().map(|p| p.rx_bytes).sum();
        let col = iw / 2.0;
        // An older retaild counts only this connection
        let total = s.usage_total;
        label_value(
            c,
            t,
            tr("Total sent"),
            &bytes(total.map_or(tx, |u| u.tx_bytes)),
            ix,
            y + 8.0,
            col - 8.0,
        );
        label_value(
            c,
            t,
            tr("Total received"),
            &bytes(total.map_or(rx, |u| u.rx_bytes)),
            ix + col,
            y + 8.0,
            col,
        );
        let time = |secs: Option<u64>| secs.map_or_else(|| "—".to_string(), crate::ui::duration);
        label_value(
            c,
            t,
            tr("Total connected"),
            &time(total.map(|u| u.connected_secs)),
            ix,
            y + 58.0,
            col - 8.0,
        );
        label_value(
            c,
            t,
            tr("Connected this time"),
            &time(s.connected_secs),
            ix + col,
            y + 58.0,
            col,
        );
        let now = format!("↑ {}  ↓ {}", bytes(tx), bytes(rx));
        label_value(c, t, tr("This connection"), &now, ix, y + 108.0, col - 8.0);
        let count = |kind: &str| {
            s.peers
                .iter()
                .filter(|p| p.path.as_deref().is_some_and(|v| v.starts_with(kind)))
                .count()
        };
        let paths = trf(
            "Direct {d} · Relay {r}",
            &[("d", &count("direct")), ("r", &count("relay"))],
        );
        label_value(c, t, tr("Paths"), &paths, ix + col, y + 108.0, col);
        let memory = s.memory_peak.map_or_else(|| "—".to_string(), bytes);
        label_value(c, t, tr("Memory peak"), &memory, ix, y + 158.0, col - 8.0);
        y += USAGE_H;
        if let Some(u) = total {
            let hint = trf(
                "Totals and each device's usage since {date}.",
                &[("date", &date(u.since))],
            );
            c.text(
                &hint,
                x + 4.0,
                y + 18.0,
                11.5,
                Weight::Regular,
                t.dim,
                Some(w - 8.0),
            );
        }
        y += USAGE_HINT_H;

        y += 40.0;
        section(c, t, tr("By device"), y);
        y += 14.0;
        let peers = &s.peers;
        if peers.is_empty() {
            c.fill_rrect(x, y, w, 60.0, 12.0, t.surface);
            c.text(
                tr("No other devices yet."),
                ix,
                y + 35.0,
                13.0,
                Weight::Regular,
                t.dim,
                Some(iw),
            );
            return;
        }
        self.peer_scroll = self.peer_scroll.min(peers.len().saturating_sub(MAX_PEERS));
        let rows = peers.len().min(MAX_PEERS);
        let card_h = 16.0 + rows as f32 * PEER_ROW_H;
        c.fill_rrect(x, y, w, card_h, 12.0, t.surface);
        let top = y;
        y += 8.0;
        let right = x + w - 16.0;
        for (i, p) in peers
            .iter()
            .enumerate()
            .skip(self.peer_scroll)
            .take(MAX_PEERS)
        {
            if i > self.peer_scroll {
                c.hline(ix, right, y, t.border);
            }
            let (badge, color) = match p.path.as_deref() {
                Some(v) if v.starts_with("direct") => (tr("Direct"), t.accent),
                Some(_) => (tr("Relay"), t.amber),
                None if !p.online => (tr("Offline"), t.dim),
                None => (tr("Connecting"), t.dim),
            };
            let traffic = format!(
                "↑ {}  ↓ {}",
                bytes(p.total_tx_bytes.unwrap_or(p.tx_bytes)),
                bytes(p.total_rx_bytes.unwrap_or(p.rx_bytes))
            );
            let badge = match p.rtt_ms {
                Some(ms) => format!("{ms} ms · {badge}"),
                None => badge.to_string(),
            };
            let bw = c.measure(&badge, 12.5, Weight::Semibold);
            let tw = c.measure(&traffic, 11.5, Weight::Regular);
            let graph = if p.rtt_history.is_empty() {
                0.0
            } else {
                GRAPH_W + 12.0
            };
            if graph > 0.0 {
                rtt_graph(c, t, &p.rtt_history, right - bw - graph, y + 8.0);
            }
            let name = if p.dns_name.is_empty() {
                p.hostname.as_str()
            } else {
                p.dns_name.trim_end_matches(".retail.internal")
            };
            c.text(
                name,
                ix,
                y + 21.0,
                13.5,
                Weight::Semibold,
                t.text,
                Some(iw - bw - graph - 12.0),
            );
            c.text(
                &badge,
                right - bw,
                y + 21.0,
                12.5,
                Weight::Semibold,
                color,
                None,
            );
            c.text(
                reason_text(p),
                ix,
                y + 38.0,
                11.5,
                Weight::Regular,
                t.dim,
                Some(iw - tw - 12.0),
            );
            c.text(
                &traffic,
                right - tw,
                y + 38.0,
                11.5,
                Weight::Regular,
                t.dim,
                None,
            );
            y += PEER_ROW_H;
        }
        if peers.len() > MAX_PEERS {
            let track_h = card_h - 16.0;
            let thumb_h = (track_h * MAX_PEERS as f32 / peers.len() as f32).max(24.0);
            let max = (peers.len() - MAX_PEERS) as f32;
            let ty = top + 8.0 + (track_h - thumb_h) * self.peer_scroll as f32 / max;
            c.fill_rrect(x + w - 7.0, ty, 3.0, thumb_h, 1.5, with_alpha(t.dim, 0.5));
        }
    }

    /// Saved servers: a click switches, ⋯ removes; + joins another
    fn server_list(&mut self, c: &mut Canvas, t: &Theme, card_y: f32) {
        let (x, w) = (PAD, WIDTH - 2.0 * PAD);
        let busy = self.is_busy();
        let servers = self.servers().to_vec();
        // The list may have shrunk since it was scrolled
        self.server_scroll = self
            .server_scroll
            .min(servers.len().saturating_sub(MAX_ROWS));
        let first = self.server_scroll;
        let mut y = card_y + 8.0;
        for (i, srv) in servers.iter().enumerate().skip(first).take(MAX_ROWS) {
            let row = Rect::from_xywh(x + 6.0, y, w - 12.0, ROW_H).unwrap();
            let more = Rect::from_xywh(x + w - 50.0, y + 8.0, 38.0, ROW_H - 16.0).unwrap();
            let open = self.server_menu == Some(i);
            if !srv.current && !busy && self.hovered(&row) && !self.hovered(&more) {
                c.fill_rrect(row.x(), row.y(), row.width(), row.height(), 8.0, t.hover);
            }
            c.circle(
                x + 20.0,
                y + ROW_H / 2.0,
                4.0,
                if srv.current { t.accent } else { t.gray },
            );
            let weight = if srv.current {
                Weight::Semibold
            } else {
                Weight::Regular
            };
            c.text(
                &server_label(&srv.server),
                x + 34.0,
                y + 21.0,
                13.5,
                weight,
                t.text,
                Some(w - 100.0),
            );
            let ip = srv.ip.map(|ip| ip.to_string()).unwrap_or_default();
            let sub = if srv.current {
                format!("{ip} · {}", tr("Current"))
            } else {
                ip
            };
            c.text(
                &sub,
                x + 34.0,
                y + 38.0,
                11.5,
                Weight::Regular,
                t.dim,
                Some(w - 100.0),
            );
            if open || self.hovered(&more) {
                c.fill_rrect(
                    more.x(),
                    more.y(),
                    more.width(),
                    more.height(),
                    6.0,
                    t.hover,
                );
            }
            let dy = y + ROW_H / 2.0;
            for k in -1..=1 {
                c.circle(
                    more.x() + more.width() / 2.0 + k as f32 * 5.0,
                    dy,
                    1.6,
                    t.dim,
                );
            }
            if !srv.current && !busy {
                self.regions
                    .push((row, SettingsAction::SwitchServer(srv.server.clone())));
            }
            self.regions.push((more, SettingsAction::ServerMenu(i)));
            y += ROW_H;
        }
        if servers.len() > MAX_ROWS {
            // Scroll bar along the right edge of the list
            let track_h = MAX_ROWS as f32 * ROW_H - 8.0;
            let thumb_h = (track_h * MAX_ROWS as f32 / servers.len() as f32).max(24.0);
            let max = (servers.len() - MAX_ROWS) as f32;
            let ty = card_y + 12.0 + (track_h - thumb_h) * first as f32 / max;
            c.fill_rrect(x + w - 7.0, ty, 3.0, thumb_h, 1.5, with_alpha(t.dim, 0.5));
        }
        y += 14.0;
        let ix = x + 16.0;
        let add = format!("+  {}", tr("Add server"));
        let aw = c.measure(&add, 13.0, Weight::Semibold) + 32.0;
        self.button(
            c,
            t,
            &add,
            ix,
            y,
            aw,
            Style::Secondary,
            !busy,
            SettingsAction::AddServer,
        );
        if self.logged_in() {
            let done = tr("Done");
            let dw = c.measure(done, 13.0, Weight::Semibold).max(56.0) + 32.0;
            self.button(
                c,
                t,
                done,
                x + w - 16.0 - dw,
                y,
                dw,
                Style::Secondary,
                true,
                SettingsAction::Cancel,
            );
        }
    }

    /// The ⋯ menu of a saved server, under its button
    fn server_popover(&mut self, c: &mut Canvas, t: &Theme, i: usize) {
        let Some(srv) = self.servers().get(i).cloned() else {
            return;
        };
        let card_y = 76.0 + 14.0;
        let label = if srv.current {
            tr("Log out and remove")
        } else {
            tr("Remove from list")
        };
        let w = c.measure(label, 13.0, Weight::Regular) + 40.0;
        let row = i.saturating_sub(self.server_scroll) as f32;
        let (x, y) = (
            WIDTH - PAD - 12.0 - w,
            card_y + 8.0 + (row + 1.0) * ROW_H - 6.0,
        );
        let h = 36.0 + 8.0;
        c.fill_rrect(
            x - 1.0,
            y + 1.0,
            w + 2.0,
            h + 3.0,
            11.0,
            with_alpha(Color::BLACK, if self.dark { 0.45 } else { 0.12 }),
        );
        c.fill_rrect(x, y, w, h, 10.0, if self.dark { t.surface } else { t.bg });
        c.stroke_rrect(x + 0.5, y + 0.5, w - 1.0, h - 1.0, 10.0, t.border);
        let r = Rect::from_xywh(x + 4.0, y + 4.0, w - 8.0, 36.0).unwrap();
        if self.hovered(&r) {
            c.fill_rrect(r.x(), r.y(), r.width(), r.height(), 7.0, t.hover);
        }
        c.text(
            label,
            x + 16.0,
            y + 27.0,
            13.0,
            Weight::Regular,
            t.red,
            None,
        );
        self.regions.push((
            Rect::from_xywh(x, y, w, h).unwrap(),
            SettingsAction::ServerMenu(i),
        ));
        self.regions
            .push((r, SettingsAction::ForgetServer(srv.server)));
    }

    /// The closed picker: the current language and a chevron
    fn dropdown(&mut self, c: &mut Canvas, t: &Theme, y: f32) {
        let (x, w) = (PAD, WIDTH - 2.0 * PAD);
        let r = Rect::from_xywh(x, y, w, 40.0).unwrap();
        let bg = if self.hovered(&r) || self.lang_open {
            t.hover
        } else {
            t.surface
        };
        c.fill_rrect(x, y, w, 40.0, 10.0, bg);
        if self.lang_open {
            c.stroke_rrect_w(x + 0.75, y + 0.75, w - 1.5, 38.5, 10.0, 1.5, t.accent);
        }
        c.text(
            self.lang.label(),
            x + 16.0,
            y + 25.0,
            13.5,
            Weight::Regular,
            t.text,
            Some(w - 56.0),
        );
        let (cx, cy) = (x + w - 22.0, y + 20.0);
        let (dx, dy) = if self.lang_open {
            (5.0, -2.5)
        } else {
            (5.0, 2.5)
        };
        c.line((cx - dx, cy - dy), (cx, cy + dy), 1.6, t.dim);
        c.line((cx, cy + dy), (cx + dx, cy - dy), 1.6, t.dim);
        self.regions.push((r, SettingsAction::LangMenu));
    }

    /// The open list, drawn over the page above the picker since the window
    /// has little room below it
    fn lang_list(&mut self, c: &mut Canvas, t: &Theme, picker_y: f32) {
        const ITEM_H: f32 = 34.0;
        let (x, w) = (PAD, WIDTH - 2.0 * PAD);
        let h = LangPref::ALL.len() as f32 * ITEM_H + 8.0;
        let y = picker_y - 6.0 - h;
        // A soft shadow, then the card
        c.fill_rrect(
            x - 1.0,
            y + 1.0,
            w + 2.0,
            h + 3.0,
            12.0,
            with_alpha(Color::BLACK, if self.dark { 0.45 } else { 0.12 }),
        );
        c.fill_rrect(x, y, w, h, 11.0, if self.dark { t.surface } else { t.bg });
        c.stroke_rrect(x + 0.5, y + 0.5, w - 1.0, h - 1.0, 11.0, t.border);
        // The whole card catches clicks, so a click between items doesn't fall through
        self.regions.push((
            Rect::from_xywh(x, y, w, h).unwrap(),
            SettingsAction::LangMenu,
        ));
        for (i, pref) in LangPref::ALL.into_iter().enumerate() {
            let iy = y + 4.0 + i as f32 * ITEM_H;
            let r = Rect::from_xywh(x + 4.0, iy, w - 8.0, ITEM_H).unwrap();
            if self.hovered(&r) {
                c.fill_rrect(x + 4.0, iy, w - 8.0, ITEM_H, 7.0, t.hover);
            }
            let selected = pref == self.lang;
            let weight = if selected {
                Weight::Semibold
            } else {
                Weight::Regular
            };
            c.text(
                pref.label(),
                x + 16.0,
                iy + 22.0,
                13.5,
                weight,
                t.text,
                Some(w - 60.0),
            );
            if selected {
                let (cx, cy) = (x + w - 26.0, iy + ITEM_H / 2.0);
                c.line((cx - 5.0, cy), (cx - 1.5, cy + 3.5), 1.8, t.accent);
                c.line((cx - 1.5, cy + 3.5), (cx + 5.0, cy - 3.5), 1.8, t.accent);
            }
            self.regions.push((r, SettingsAction::Lang(pref)));
        }
    }

    /// New releases: where things stand, a button, and the automatic toggle
    fn updates(&mut self, c: &mut Canvas, t: &Theme, s: &StatusResponse, y: f32) {
        let (x, w) = (PAD, WIDTH - 2.0 * PAD);
        let ix = x + 16.0;
        c.hline(ix, x + w - 16.0, y, t.border);
        let u = &s.update;
        let latest = u.latest.clone().unwrap_or_default();
        let staged = u.installing.then_some(u.stage).flatten();
        let (line, sub, color) = if !u.supported {
            (
                tr("Updates are not available here").to_string(),
                tr("There are no official builds for this system.").to_string(),
                t.dim,
            )
        } else if let Some(stage) = staged {
            (
                trf("Installing retail {version}…", &[("version", &latest)]),
                crate::ui::stage_text(stage, u.done_bytes, u.total_bytes),
                t.text,
            )
        } else if u.installing {
            (
                trf("Installing retail {version}…", &[("version", &latest)]),
                tr("retail restarts when it is done.").to_string(),
                t.text,
            )
        } else if u.available {
            (
                trf("retail {version} is available", &[("version", &latest)]),
                trf("You have {version}.", &[("version", &u.current)]),
                t.accent,
            )
        } else if let Some(e) = &u.error {
            (
                tr("Could not check for updates").to_string(),
                e.clone(),
                t.red,
            )
        } else if u.latest.is_some() {
            (
                tr("Up to date").to_string(),
                trf(
                    "You have the newest version, {version}.",
                    &[("version", &u.current)],
                ),
                t.text,
            )
        } else {
            (
                tr("Not checked yet").to_string(),
                tr("retail looks for new versions every few hours.").to_string(),
                t.text,
            )
        };
        let busy = self.is_checking() || u.installing;
        let (label, style, action) = if u.available {
            (
                tr("Update now"),
                Style::Primary,
                SettingsAction::InstallUpdate,
            )
        } else if self.is_checking() {
            (
                tr("Checking…"),
                Style::Secondary,
                SettingsAction::CheckUpdate,
            )
        } else {
            (
                tr("Check now"),
                Style::Secondary,
                SettingsAction::CheckUpdate,
            )
        };
        let bw = c.measure(label, 13.0, Weight::Semibold) + 28.0;
        c.text(
            &line,
            ix,
            y + 27.0,
            13.5,
            Weight::Regular,
            color,
            Some(w - 48.0 - bw),
        );
        c.text(
            &sub,
            ix,
            y + 45.0,
            11.5,
            Weight::Regular,
            t.dim,
            Some(w - 48.0 - bw),
        );
        if let Some(stage) = staged {
            crate::ui::progress_bar(
                c,
                t,
                ix,
                y + 53.0,
                w - 48.0 - bw,
                crate::ui::stage_fraction(stage, u.done_bytes, u.total_bytes),
            );
        }
        if u.supported {
            self.button(
                c,
                t,
                label,
                x + w - 16.0 - bw,
                y + 15.0,
                bw,
                style,
                !busy,
                action,
            );
        }

        let y = y + 64.0;
        c.hline(ix, x + w - 16.0, y, t.border);
        c.text(
            tr("Install updates automatically"),
            ix,
            y + 26.0,
            13.5,
            Weight::Regular,
            t.text,
            Some(w - 100.0),
        );
        c.text(
            tr("Otherwise retail lets you know when one is out."),
            ix,
            y + 44.0,
            11.5,
            Weight::Regular,
            t.dim,
            Some(w - 100.0),
        );
        let on = s.prefs.auto_update;
        let (tw, th) = (42.0, 24.0);
        let (tx, ty) = (x + w - 16.0 - tw, y + 18.0);
        let r = Rect::from_xywh(tx - 6.0, ty - 6.0, tw + 12.0, th + 12.0).unwrap();
        let track = if on { t.accent } else { t.gray };
        let track = if self.hovered(&r) {
            shade(track, if self.dark { 1.12 } else { 0.92 })
        } else {
            track
        };
        let track = if u.supported {
            track
        } else {
            with_alpha(track, 0.5)
        };
        c.fill_rrect(tx, ty, tw, th, th / 2.0, track);
        let kx = if on {
            tx + tw - th / 2.0
        } else {
            tx + th / 2.0
        };
        c.circle(kx, ty + th / 2.0, th / 2.0 - 3.0, t.knob);
        if u.supported {
            self.regions.push((r, SettingsAction::AutoUpdate(!on)));
        }
    }

    fn network(&mut self, c: &mut Canvas, t: &Theme, s: &StatusResponse, y: f32) {
        let (x, w) = (PAD, WIDTH - 2.0 * PAD);
        c.fill_rrect(x, y, w, NETWORK_H, 12.0, t.surface);
        let ix = x + 16.0;
        c.text(
            tr("Offer as exit node"),
            ix,
            y + 32.0,
            13.5,
            Weight::Regular,
            t.text,
            None,
        );
        c.text(
            tr("Other devices can reach the internet through this one."),
            ix,
            y + 50.0,
            11.5,
            Weight::Regular,
            t.dim,
            Some(w - 100.0),
        );
        let on = s.prefs.advertise_exit_node;
        let (tw, th) = (42.0, 24.0);
        let (tx, ty) = (x + w - 16.0 - tw, y + 22.0);
        let r = Rect::from_xywh(tx - 6.0, ty - 6.0, tw + 12.0, th + 12.0).unwrap();
        let track = if on { t.accent } else { t.gray };
        let track = if self.hovered(&r) {
            shade(track, if self.dark { 1.12 } else { 0.92 })
        } else {
            track
        };
        c.fill_rrect(tx, ty, tw, th, th / 2.0, track);
        let kx = if on {
            tx + tw - th / 2.0
        } else {
            tx + th / 2.0
        };
        c.circle(kx, ty + th / 2.0, th / 2.0 - 3.0, t.knob);
        self.regions.push((r, SettingsAction::AdvertiseExit(!on)));

        let y = y + 76.0;
        c.hline(ix, x + w - 16.0, y, t.border);
        c.text(
            tr("Open a router port"),
            ix,
            y + 26.0,
            13.5,
            Weight::Regular,
            t.text,
            Some(w - 100.0),
        );
        let on = s.prefs.open_router_port;
        let (sub, color) = match s.router_port.as_ref().filter(|_| on) {
            Some(PortState::Opened { method, port }) => (
                trf(
                    "Opened with {method} · UDP {port}",
                    &[("method", method), ("port", port)],
                ),
                t.text,
            ),
            Some(PortState::Unavailable { port }) => (
                trf(
                    "Refused: turn on UPnP or forward UDP {port}",
                    &[("port", port)],
                ),
                t.amber,
            ),
            None => (
                tr("Devices elsewhere connect directly, not via the relay.").to_string(),
                t.dim,
            ),
        };
        c.text(
            &sub,
            ix,
            y + 44.0,
            11.5,
            Weight::Regular,
            color,
            Some(w - 100.0),
        );
        let (tw, th) = (42.0, 24.0);
        let (tx, ty) = (x + w - 16.0 - tw, y + 18.0);
        let r = Rect::from_xywh(tx - 6.0, ty - 6.0, tw + 12.0, th + 12.0).unwrap();
        let track = if on { t.accent } else { t.gray };
        let track = if self.hovered(&r) {
            shade(track, if self.dark { 1.12 } else { 0.92 })
        } else {
            track
        };
        c.fill_rrect(tx, ty, tw, th, th / 2.0, track);
        let kx = if on {
            tx + tw - th / 2.0
        } else {
            tx + th / 2.0
        };
        c.circle(kx, ty + th / 2.0, th / 2.0 - 3.0, t.knob);
        self.regions.push((r, SettingsAction::OpenRouterPort(!on)));

        let y = y + 64.0;
        c.hline(ix, x + w - 16.0, y, t.border);
        c.text(
            tr("Upload limit"),
            ix,
            y + 26.0,
            13.5,
            Weight::Regular,
            t.text,
            Some(w - 140.0),
        );
        let sub = tr("Keeps games quick during downloads.");
        c.text(
            sub,
            ix,
            y + 44.0,
            11.5,
            Weight::Regular,
            t.dim,
            Some(w - 140.0),
        );
        let now = s.prefs.upload_limit_mbit.unwrap_or(0);
        let label = if now == 0 {
            tr("None").to_string()
        } else {
            format!("{now} Mbit/s")
        };
        let next = UPLOAD_STEPS.iter().copied().find(|&m| m > now).unwrap_or(0);
        let bw = c.measure(&label, 13.0, Weight::Semibold).max(64.0) + 28.0;
        self.button(
            c,
            t,
            &label,
            x + w - 16.0 - bw,
            y + 14.0,
            bw,
            Style::Secondary,
            true,
            SettingsAction::UploadLimit(next),
        );
    }

    fn account(&mut self, c: &mut Canvas, t: &Theme, s: &StatusResponse, x: f32, y: f32, w: f32) {
        let server = s.server.as_deref().unwrap_or("—");
        label_value(c, t, tr("Server address"), server, x, y, w);
        let device = match &s.self_node {
            Some(me) => format!("{} · {}", me.hostname, me.ip),
            None => "—".into(),
        };
        label_value(c, t, tr("This device"), &device, x, y + 50.0, w);

        let by = y + 2.0 * 50.0 + 10.0;
        let change = tr("Change server");
        let change_w = c.measure(change, 13.0, Weight::Semibold).max(104.0) + 32.0;
        self.button(
            c,
            t,
            change,
            x,
            by,
            change_w,
            Style::Secondary,
            true,
            SettingsAction::StartChange,
        );
        let (label, style) = if self.logout_armed() {
            (tr("Click again to log out"), Style::Danger)
        } else if self.is_busy() {
            (tr("Logging out…"), Style::Secondary)
        } else {
            (tr("Log out"), Style::Secondary)
        };
        let lw = c.measure(label, 13.0, Weight::Semibold) + 32.0;
        self.button(
            c,
            t,
            label,
            x + w - lw,
            by,
            lw,
            style,
            !self.is_busy(),
            SettingsAction::Logout,
        );
    }

    fn form(&mut self, c: &mut Canvas, t: &Theme, x: f32, y: f32, w: f32) {
        let auth = self.with_auth_key();
        let mut fy = y;
        for &i in self.form_fields() {
            let label = match i {
                SERVER if auth => tr("Server address"),
                SERVER => tr("Invite code"),
                AUTH_KEY => tr("Auth key"),
                _ => tr("Device name (optional)"),
            };
            c.text(label, x, fy + 13.0, 12.0, Weight::Regular, t.dim, None);
            self.field(c, t, i, x, fy + 20.0, w);
            fy += 20.0 + FIELD_H + 14.0;
            if i == SERVER {
                let hint = if auth {
                    tr("Joining with the server's auth key instead of an invite code.")
                } else {
                    tr("From the network's administrator. It starts with retail1.")
                };
                c.text(hint, x, fy + 2.0, 11.5, Weight::Regular, t.dim, Some(w));
                fy += HINT_H;
            }
        }
        let busy = self.is_busy();
        let label = if busy {
            tr("Connecting…")
        } else {
            tr("Connect")
        };
        let first = self.inputs[SERVER].trimmed();
        let ready = first.starts_with("retail1.")
            || (!first.is_empty() && !self.inputs[AUTH_KEY].trimmed().is_empty());
        let cw = c.measure(label, 13.0, Weight::Semibold).max(56.0) + 48.0;
        self.button(
            c,
            t,
            label,
            x,
            fy + 4.0,
            cw,
            Style::Primary,
            ready && !busy,
            SettingsAction::Connect,
        );
        if self.logged_in() || !self.servers().is_empty() {
            self.button(
                c,
                t,
                tr("Cancel"),
                x + cw + 12.0,
                fy + 4.0,
                96.0,
                Style::Secondary,
                !busy,
                SettingsAction::Cancel,
            );
        }
    }

    fn field(&mut self, c: &mut Canvas, t: &Theme, i: usize, x: f32, y: f32, w: f32) {
        let focused = self.focus == Some(i);
        let r = Rect::from_xywh(x, y, w, FIELD_H).unwrap();
        c.fill_rrect(x, y, w, FIELD_H, 8.0, t.bg);
        if focused {
            c.stroke_rrect_w(
                x + 0.75,
                y + 0.75,
                w - 1.5,
                FIELD_H - 1.5,
                8.0,
                1.5,
                t.accent,
            );
        } else {
            let border = if self.hovered(&r) {
                shade(t.border, if self.dark { 1.4 } else { 0.85 })
            } else {
                t.border
            };
            c.stroke_rrect(x + 0.5, y + 0.5, w - 1.0, FIELD_H - 1.0, 8.0, border);
        }
        self.regions.push((r, SettingsAction::Focus(i)));

        let input = &self.inputs[i];
        let (shown, caret) = input.display();
        let px = 13.5;
        let tx = x + 12.0;
        let baseline = y + FIELD_H / 2.0 + 5.0;
        let avail = w - 24.0;
        if shown.is_empty() {
            c.text(
                tr(input.placeholder),
                tx,
                baseline,
                px,
                Weight::Regular,
                with_alpha(t.dim, 0.7),
                Some(avail),
            );
        } else {
            // Keep the caret in view by sliding long text to the left
            let before: String = shown.chars().take(caret).collect();
            let caret_x = c.measure(&before, px, Weight::Regular);
            let shift = (caret_x - avail + 2.0).max(0.0);
            if input.is_all_selected() {
                let sw = c.measure(&shown, px, Weight::Regular).min(avail);
                c.fill_rrect(
                    tx - 2.0,
                    y + 8.0,
                    sw + 4.0,
                    FIELD_H - 16.0,
                    3.0,
                    with_alpha(t.accent, 0.28),
                );
            }
            let mut dropped = 0;
            let mut skipped_w = 0.0;
            for ch in shown.chars() {
                if skipped_w >= shift {
                    break;
                }
                skipped_w += c.measure(ch.encode_utf8(&mut [0; 4]), px, Weight::Regular);
                dropped += 1;
            }
            let visible: String = shown.chars().skip(dropped).collect();
            c.text(
                &visible,
                tx,
                baseline,
                px,
                Weight::Regular,
                t.text,
                Some(avail),
            );
            if focused {
                let caret_vis: String = visible
                    .chars()
                    .take(caret.saturating_sub(dropped))
                    .collect();
                let cx = tx + c.measure(&caret_vis, px, Weight::Regular);
                c.fill_rect(cx, y + 9.0, 1.5, FIELD_H - 18.0, t.text);
            }
        }
        if focused && shown.is_empty() {
            c.fill_rect(tx, y + 9.0, 1.5, FIELD_H - 18.0, t.text);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn button(
        &mut self,
        c: &mut Canvas,
        t: &Theme,
        label: &str,
        x: f32,
        y: f32,
        w: f32,
        style: Style,
        enabled: bool,
        action: SettingsAction,
    ) {
        let r = Rect::from_xywh(x, y, w, BUTTON_H).unwrap();
        let hover = enabled && self.hovered(&r);
        let (bg, fg, border) = match style {
            Style::Primary => (t.accent, Color::WHITE, None),
            Style::Danger => (t.red, Color::WHITE, None),
            Style::Secondary => (t.bg, t.text, Some(t.border)),
        };
        let bg = if hover {
            shade(
                bg,
                if self.dark || style != Style::Secondary {
                    1.1
                } else {
                    0.96
                },
            )
        } else {
            bg
        };
        let (bg, fg) = if enabled {
            (bg, fg)
        } else {
            (with_alpha(bg, 0.5), with_alpha(fg, 0.6))
        };
        c.fill_rrect(x, y, w, BUTTON_H, 8.0, bg);
        if let Some(b) = border {
            c.stroke_rrect(x + 0.5, y + 0.5, w - 1.0, BUTTON_H - 1.0, 8.0, b);
        }
        let lw = c.measure(label, 13.0, Weight::Semibold);
        c.text(
            label,
            x + (w - lw) / 2.0,
            y + BUTTON_H / 2.0 + 4.5,
            13.0,
            Weight::Semibold,
            fg,
            None,
        );
        if enabled {
            self.regions.push((r, action));
        }
    }

    /// A row of choices: (selected, label, action) each
    fn segmented(
        &mut self,
        c: &mut Canvas,
        t: &Theme,
        y: f32,
        options: &[(bool, &str, SettingsAction)],
    ) {
        let w = WIDTH - 2.0 * PAD;
        c.fill_rrect(PAD, y, w, 40.0, 10.0, t.surface);
        let seg = (w - 8.0) / options.len() as f32;
        for (i, (selected, label, action)) in options.iter().enumerate() {
            let sx = PAD + 4.0 + i as f32 * seg;
            let r = Rect::from_xywh(sx, y + 4.0, seg, 32.0).unwrap();
            let selected = *selected;
            if selected {
                c.fill_rrect(
                    sx,
                    y + 4.0,
                    seg,
                    32.0,
                    7.0,
                    if self.dark { t.hover } else { t.bg },
                );
            } else if self.hovered(&r) {
                c.fill_rrect(sx, y + 4.0, seg, 32.0, 7.0, with_alpha(t.hover, 0.6));
            }
            let weight = if selected {
                Weight::Semibold
            } else {
                Weight::Regular
            };
            let lw = c.measure(label, 13.0, weight);
            let color = if selected { t.text } else { t.dim };
            c.text(
                label,
                sx + (seg - lw) / 2.0,
                y + 25.0,
                13.0,
                weight,
                color,
                None,
            );
            self.regions.push((r, action.clone()));
        }
    }
}

/// A server URL as people say it: no scheme, no default port
pub fn server_label(url: &str) -> String {
    let s = url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');
    s.strip_suffix(":443").unwrap_or(s).to_string()
}

fn reason_text(p: &PeerStatus) -> &'static str {
    match p.path_reason {
        Some(PathReason::Lan) => tr("Same local network"),
        Some(PathReason::Internet) => tr("Directly across the internet"),
        Some(PathReason::PeerOffline) => tr("That device is offline"),
        Some(PathReason::Connecting) => tr("Looking for a path…"),
        Some(PathReason::DirectLost) => tr("Direct path went quiet, retrying"),
        Some(PathReason::OneWay) => tr("Its replies don't arrive over UDP"),
        Some(PathReason::UdpBlockedHere) => tr("UDP is blocked on this network"),
        Some(PathReason::PeerNoAddress) => tr("That device has no public address"),
        Some(PathReason::PunchFailed) => tr("A router or firewall blocked direct UDP"),
        // An older retaild gives no reason
        None => "",
    }
}

pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

fn theme_label(p: ThemePref) -> &'static str {
    match p {
        ThemePref::System => tr("System"),
        ThemePref::Light => tr("Light"),
        ThemePref::Dark => tr("Dark"),
    }
}

fn section(c: &mut Canvas, t: &Theme, title: &str, y: f32) {
    c.text(title, PAD + 4.0, y, 10.5, Weight::Semibold, t.dim, None);
}

/// `YYYY-MM-DD` of a Unix time, in UTC
fn date(unix: i64) -> String {
    // Howard Hinnant's civil_from_days
    let z = unix.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

fn label_value(c: &mut Canvas, t: &Theme, label: &str, value: &str, x: f32, y: f32, w: f32) {
    c.text(label, x, y + 14.0, 12.0, Weight::Regular, t.dim, None);
    c.text(value, x, y + 34.0, 14.0, Weight::Regular, t.text, Some(w));
}

/// The last two minutes of round trips (one bar per 2 s ping), taller when
/// slower; a red tick for a ping with no answer
const GRAPH_W: f32 = 90.0;
const GRAPH_H: f32 = 16.0;

fn rtt_graph(c: &mut Canvas, t: &Theme, history: &[u16], x: f32, y: f32) {
    let n = (GRAPH_W / 1.5) as usize;
    let shown = &history[history.len().saturating_sub(n)..];
    let x0 = x + GRAPH_W - shown.len() as f32 * 1.5;
    c.fill_rect(x, y + GRAPH_H, GRAPH_W, 1.0, t.border);
    for (i, &ms) in shown.iter().enumerate() {
        let bx = x0 + i as f32 * 1.5;
        if ms == u16::MAX {
            c.fill_rect(bx, y, 1.0, GRAPH_H, t.red);
            continue;
        }
        // Square root, so 20 ms and 300 ms both read
        let h = (f32::from(ms.min(400)) / 400.0).sqrt() * (GRAPH_H - 2.0) + 2.0;
        let color = if ms < 80 {
            t.accent
        } else if ms < 200 {
            t.amber
        } else {
            t.red
        };
        c.fill_rect(bx, y + GRAPH_H - h, 1.0, h, color);
    }
}
