//! The popup: layout, drawing and hit-testing. All coordinates here are
//! logical pixels, and `render` scales to the device.

use std::time::{Duration, Instant};

use retail_proto::Key;
use retail_proto::api::{BackendState, FailReason, PeerStatus, StatusResponse, UpdateStage};
use tiny_skia::{Color, Pixmap, Rect};

use crate::draw::{Canvas, Theme, contains, shade, with_alpha};
use crate::i18n::{tr, trf};
use crate::text::{Fonts, Weight};

pub const WIDTH: f32 = 340.0;
const PAD: f32 = 16.0;
const HEADER_H: f32 = 72.0;
const FOOTER_H: f32 = 48.0;
const CARD_H: f32 = 64.0;
const SECTION_H: f32 = 36.0;
const ROW_H: f32 = 52.0;
const MAX_ROWS: usize = 6;
const MESSAGE_H: f32 = 132.0;
const NOTE_H: f32 = 84.0;
const MENU_ITEM_H: f32 = 34.0;
const MENU_W: f32 = 200.0;
const BANNER_H: f32 = 66.0;
/// Handshakes older than this show in a device's row (keys renew every 120 s)
const STALE_HANDSHAKE: u64 = 180;

/// Windows 11 rounds the window itself (8 px, see `round_corners`). Elsewhere
/// the window is a plain rectangle.
pub const CORNER: f32 = if cfg!(windows) { 8.0 } else { 0.0 };

#[derive(Clone)]
pub enum View {
    Loading,
    /// The local API could not be reached
    Offline,
    Status(Box<StatusResponse>),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Action {
    Toggle,
    Copy(String),
    OpenSettings,
    /// The server dashboard (hosting a network here)
    OpenServer,
    Quit,
    /// Open (or close) the "⋯" menu of the device with this node key
    Menu(Key),
    /// Use this exit node (node key, base64), or none ("")
    SetExit(String),
    /// A click that hit nothing, which closes an open menu
    Dismiss,
    /// Open (or close) the menu behind the gear at the bottom right
    Gear,
    /// Install the new release
    Update,
    /// Start retaild with administrator permission
    StartDaemon,
    /// Turn on a device that is off (hostname)
    Wake(String),
    SendFile(std::net::Ipv4Addr, String),
}

/// The daemon going away during an update, and coming back
#[derive(Clone, Default)]
pub struct DaemonWait {
    /// The last answer had an update installing
    pub installing: bool,
    /// Since when it has been gone after that
    pub since: Option<Instant>,
    /// Since when it is being started with administrator permission
    pub starting: Option<Instant>,
}

/// An update's restart usually takes a few seconds; Task Scheduler's
/// one-minute trigger is the slowest way back
const RESTART_WAIT: Duration = Duration::from_secs(75);
const START_WAIT: Duration = Duration::from_secs(30);

impl DaemonWait {
    /// Called with every answer (or its absence)
    pub fn seen(&mut self, s: Option<&StatusResponse>) {
        match s {
            Some(s) => {
                self.installing = s.update.installing;
                self.since = None;
                self.starting = None;
            }
            None if self.installing => {
                self.since.get_or_insert_with(Instant::now);
            }
            None => {}
        }
    }

    /// Restarting after an update, within the time that may take
    pub fn restarting(&self) -> bool {
        self.since.is_some_and(|t| t.elapsed() < RESTART_WAIT)
    }

    pub fn is_starting(&self) -> bool {
        self.starting.is_some_and(|t| t.elapsed() < START_WAIT)
    }

    /// Title, explanation, and the progress shown instead of the start button
    pub fn text(&self) -> (String, String, Option<f32>) {
        if self.is_starting() {
            return (
                tr("Starting retaild…").into(),
                tr("Waiting for retaild to answer.").into(),
                Some(0.5),
            );
        }
        if let Some(t) = self.since.filter(|_| self.restarting()) {
            let s = t.elapsed().as_secs_f32();
            // Most restarts are over within ten seconds; the bar slows down
            // as it nears the end rather than stopping full
            let f = 0.6 + 0.38 * (1.0 - (-s / 12.0).exp());
            return (
                tr("Restarting retail…").into(),
                trf(
                    "The update is installed. retail starts again in a moment ({n} s).",
                    &[("n", &(s as u64))],
                ),
                Some(f),
            );
        }
        let hint = if self.since.is_some() {
            tr("retail did not start again after the update. Start it here.")
        } else if cfg!(windows) {
            tr("Start it here, or run retaild.exe as administrator.")
        } else {
            tr("Start it here, or run it with sudo retaild.")
        };
        (tr("retaild is not running").into(), hint.into(), None)
    }
}

/// A thin bar `f` (0 to 1) full
pub fn progress_bar(c: &mut Canvas, t: &Theme, x: f32, y: f32, w: f32, f: f32) {
    c.fill_rrect(x, y, w, 4.0, 2.0, t.border);
    c.fill_rrect(x, y, (w * f.clamp(0.0, 1.0)).max(4.0), 4.0, 2.0, t.accent);
}

/// What an installation is doing, in words
pub fn stage_text(stage: UpdateStage, done: u64, total: Option<u64>) -> String {
    let mb = |b: u64| format!("{:.1}", b as f64 / 1_048_576.0);
    match (stage, total) {
        (UpdateStage::Downloading, Some(t)) => trf(
            "Downloading {done} / {total} MB",
            &[("done", &mb(done)), ("total", &mb(t))],
        ),
        (UpdateStage::Downloading, None) => trf("Downloading {done} MB", &[("done", &mb(done))]),
        (UpdateStage::Checking, _) => tr("Checking the download…").into(),
        (UpdateStage::Replacing, _) => tr("Putting the new programs in place…").into(),
        (UpdateStage::Restarting, _) => tr("Restarting…").into(),
    }
}

/// How far along the whole installation is: the download is most of it
pub fn stage_fraction(stage: UpdateStage, done: u64, total: Option<u64>) -> f32 {
    match stage {
        UpdateStage::Downloading => {
            0.05 + 0.75
                * total
                    .filter(|t| *t > 0)
                    .map_or(0.0, |t| done as f32 / t as f32)
        }
        UpdateStage::Checking => 0.85,
        UpdateStage::Replacing => 0.9,
        UpdateStage::Restarting => 0.95,
    }
}

struct MenuItem {
    label: String,
    action: Action,
}

pub struct Ui {
    pub view: View,
    pub dark: bool,
    pub cursor: Option<(f32, f32)>,
    /// First visible device row
    pub scroll: usize,
    pub toast: Option<(String, Instant)>,
    /// Target state of a clicked toggle, shown until the daemon confirms it
    pub pending: Option<(bool, Instant)>,
    /// Leave the area outside the rounded corners transparent (PNG previews)
    pub transparent_corners: bool,
    /// Device whose "⋯" menu is open
    pub menu: Option<Key>,
    /// The gear menu is open
    pub gear: bool,
    pub daemon: DaemonWait,
    regions: Vec<(Rect, Action)>,
}

impl Ui {
    pub fn new(dark: bool) -> Self {
        Ui {
            view: View::Loading,
            dark,
            cursor: None,
            scroll: 0,
            toast: None,
            pending: None,
            transparent_corners: false,
            menu: None,
            gear: false,
            daemon: DaemonWait::default(),
            regions: Vec::new(),
        }
    }

    fn status(&self) -> Option<&StatusResponse> {
        match &self.view {
            View::Status(s) => Some(s),
            _ => None,
        }
    }

    pub fn is_running(&self) -> bool {
        self.status()
            .is_some_and(|s| s.state == BackendState::Running)
    }

    fn toggle_state(&self) -> bool {
        match self.pending {
            Some((target, at)) if at.elapsed() < Duration::from_secs(8) => target,
            _ => self.is_running(),
        }
    }

    pub fn height(&self) -> f32 {
        let body = match self.status() {
            Some(s) if s.state == BackendState::Stopped => CARD_H + 12.0 + NOTE_H,
            Some(s) if s.state != BackendState::NeedsLogin => {
                let rows = s.peers.len().clamp(1, MAX_ROWS) as f32;
                let error = match error_text(s) {
                    Some((_, Some(_))) => 60.0,
                    Some(_) => 44.0,
                    None => 0.0,
                };
                CARD_H + 12.0 + SECTION_H + rows * ROW_H + error + 8.0
            }
            Some(_) => MESSAGE_H,
            // Room for a hint over two lines
            None => MESSAGE_H + 18.0,
        };
        HEADER_H + self.banner_h() + body + FOOTER_H
    }

    /// The new-release banner under the header
    fn banner_h(&self) -> f32 {
        if self.status().is_some_and(|s| s.update.available) {
            BANNER_H
        } else {
            0.0
        }
    }

    pub fn needs_timer(&self) -> Option<Instant> {
        let toast = self
            .toast
            .as_ref()
            .map(|(_, at)| *at + Duration::from_millis(1500));
        let pending = self.pending.map(|(_, at)| at + Duration::from_secs(8));
        toast.into_iter().chain(pending).min()
    }

    pub fn action_at(&self, x: f32, y: f32) -> Option<Action> {
        // The open menu is drawn last and sits on top, so check it first
        let hit = self
            .regions
            .iter()
            .rev()
            .find(|(r, _)| contains(r, x, y))
            .map(|(_, a)| a.clone());
        match hit {
            None if self.menu.is_some() || self.gear => Some(Action::Dismiss),
            hit => hit,
        }
    }

    pub fn scroll_by(&mut self, rows: i32) -> bool {
        let n = self.status().map_or(0, |s| s.peers.len());
        let max = n.saturating_sub(MAX_ROWS);
        let next = (self.scroll as i32 + rows).clamp(0, max as i32) as usize;
        let changed = next != self.scroll;
        self.scroll = next;
        changed
    }

    fn hovered(&self, r: &Rect) -> bool {
        self.cursor.is_some_and(|(x, y)| contains(r, x, y))
    }

    pub fn render(&mut self, fonts: &Fonts, pix: &mut Pixmap, scale: f32) {
        if self
            .toast
            .as_ref()
            .is_some_and(|(_, at)| at.elapsed() > Duration::from_millis(1500))
        {
            self.toast = None;
        }
        let t = Theme::new(self.dark);
        let mut c = Canvas { pix, fonts, scale };
        self.regions.clear();
        let h = self.height();
        if self.transparent_corners {
            c.pix.fill(Color::TRANSPARENT);
            c.fill_rrect(0.0, 0.0, WIDTH, h, CORNER, t.bg);
        } else {
            c.fill_rect(0.0, 0.0, WIDTH, h, t.bg);
        }
        // Hairline border, visible on both themes and on platforms without a window shadow
        c.stroke_rrect(
            0.5,
            0.5,
            WIDTH - 1.0,
            h - 1.0,
            (CORNER - 0.5).max(0.0),
            t.border,
        );

        self.header(&mut c, &t);
        let mut y = HEADER_H;
        if self.banner_h() > 0.0
            && let View::Status(s) = self.view.clone()
        {
            self.banner(&mut c, &t, &s, y);
            y += BANNER_H;
        }
        match self.view.clone() {
            View::Loading => {
                self.message(&mut c, &t, y, tr("Connecting to retaild…"), "", None);
            }
            View::Offline => {
                let (title, hint, bar) = self.daemon.text();
                match bar {
                    Some(f) => {
                        let below = self.message(&mut c, &t, y, &title, &hint, None);
                        progress_bar(&mut c, &t, PAD, below + 4.0, WIDTH - 2.0 * PAD, f);
                    }
                    None => {
                        self.message(
                            &mut c,
                            &t,
                            y,
                            &title,
                            &hint,
                            Some((tr("Start retaild"), Action::StartDaemon)),
                        );
                    }
                }
            }
            View::Status(s) if s.state == BackendState::NeedsLogin => {
                self.message(
                    &mut c,
                    &t,
                    y,
                    tr("This device hasn't logged in yet"),
                    tr("Connect with an invite code to join the network."),
                    Some((tr("Log in…"), Action::OpenSettings)),
                );
            }
            View::Status(s) if s.state == BackendState::Stopped => {
                y = self.device_card(&mut c, &t, &s, y + 4.0);
                c.text(
                    tr("The connection is off"),
                    PAD,
                    y + 36.0,
                    14.0,
                    Weight::Semibold,
                    t.text,
                    None,
                );
                c.text(
                    tr("Turn on retail to connect to your other devices."),
                    PAD,
                    y + 57.0,
                    12.5,
                    Weight::Regular,
                    t.dim,
                    Some(WIDTH - 2.0 * PAD),
                );
            }
            View::Status(s) => {
                y = self.device_card(&mut c, &t, &s, y + 4.0);
                y = self.devices(&mut c, &t, &s, y + 8.0);
                if let Some((err, hint)) = &error_text(&s) {
                    let h = if hint.is_some() { 52.0 } else { 36.0 };
                    c.fill_rrect(
                        PAD,
                        y + 4.0,
                        WIDTH - 2.0 * PAD,
                        h,
                        8.0,
                        with_alpha(t.red, 0.12),
                    );
                    c.text(
                        err,
                        PAD + 12.0,
                        y + 26.0,
                        12.0,
                        Weight::Regular,
                        t.red,
                        Some(WIDTH - 2.0 * PAD - 24.0),
                    );
                    if let Some(hint) = hint {
                        c.text(
                            hint,
                            PAD + 12.0,
                            y + 43.0,
                            11.5,
                            Weight::Regular,
                            t.dim,
                            Some(WIDTH - 2.0 * PAD - 24.0),
                        );
                    }
                }
            }
        }
        self.footer(&mut c, &t, h);
    }

    fn banner(&mut self, c: &mut Canvas, t: &Theme, s: &StatusResponse, y: f32) {
        let (x, w) = (PAD, WIDTH - 2.0 * PAD);
        c.fill_rrect(
            x,
            y + 14.0,
            w,
            40.0,
            10.0,
            with_alpha(t.accent, if self.dark { 0.22 } else { 0.1 }),
        );
        let latest = s.update.latest.clone().unwrap_or_default();
        if s.update.installing {
            let text = trf("Installing retail {version}…", &[("version", &latest)]);
            c.text(
                &text,
                x + 12.0,
                y + 39.0,
                12.5,
                Weight::Semibold,
                t.text,
                Some(w - 24.0),
            );
            return;
        }
        let label = tr("Update");
        let bw = c.measure(label, 12.5, Weight::Semibold) + 24.0;
        let text = trf("retail {version} is available", &[("version", &latest)]);
        c.text(
            &text,
            x + 12.0,
            y + 39.0,
            12.5,
            Weight::Semibold,
            t.text,
            Some(w - 36.0 - bw),
        );
        let r = Rect::from_xywh(x + w - 8.0 - bw, y + 20.0, bw, 28.0).unwrap();
        let bg = if self.hovered(&r) {
            shade(t.accent, 1.1)
        } else {
            t.accent
        };
        c.fill_rrect(r.x(), r.y(), r.width(), r.height(), 7.0, bg);
        c.text(
            label,
            r.x() + 12.0,
            r.y() + 18.5,
            12.5,
            Weight::Semibold,
            Color::WHITE,
            None,
        );
        self.regions.push((r, Action::Update));
    }

    fn header(&mut self, c: &mut Canvas, t: &Theme) {
        let (lx, ly) = (PAD, 22.0);
        let logo = if self.is_running() { t.accent } else { t.gray };
        c.fill_rrect(lx, ly, 28.0, 28.0, 8.0, logo);
        let nodes = [
            (lx + 8.0, ly + 9.0),
            (lx + 20.0, ly + 9.0),
            (lx + 14.0, ly + 20.0),
        ];
        for (a, b) in [(0, 1), (1, 2), (2, 0)] {
            c.line(nodes[a], nodes[b], 1.6, t.knob);
        }
        for (x, y) in nodes {
            c.circle(x, y, 2.8, t.knob);
        }

        c.text(
            "retail",
            lx + 40.0,
            35.0,
            16.0,
            Weight::Semibold,
            t.text,
            None,
        );
        let (label, color) = match &self.view {
            View::Loading => (tr("Starting…"), t.gray),
            View::Offline if self.daemon.restarting() => (tr("Restarting retail…"), t.amber),
            View::Offline => (tr("retaild is not running"), t.red),
            View::Status(s) => match (s.state, s.control_connected) {
                (BackendState::NeedsLogin, _) => (tr("Login needed"), t.amber),
                (BackendState::Stopped, _) => (tr("Disconnected"), t.gray),
                (BackendState::Running, true) => match exit_in_use(s) {
                    Some((_, false)) => (tr("Connected · internet via exit node"), t.accent),
                    Some((_, true)) => (tr("Exit node offline · internet blocked"), t.red),
                    None => (tr("Connected"), t.accent),
                },
                (BackendState::Running, false) => {
                    (tr("Connected · can't reach the server"), t.amber)
                }
            },
        };
        let label = match self.pending {
            Some((true, at)) if at.elapsed() < Duration::from_secs(8) && !self.is_running() => {
                tr("Connecting…")
            }
            Some((false, at)) if at.elapsed() < Duration::from_secs(8) && self.is_running() => {
                tr("Disconnecting…")
            }
            _ => label,
        };
        c.circle(lx + 44.0, 50.0, 3.5, color);
        c.text(
            label,
            lx + 52.0,
            54.5,
            12.0,
            Weight::Regular,
            t.dim,
            Some(WIDTH - lx - 52.0 - 80.0),
        );

        let enabled = self
            .status()
            .is_some_and(|s| s.state != BackendState::NeedsLogin && s.server.is_some());
        let on = self.toggle_state();
        let (tw, th) = (46.0, 26.0);
        let (tx, ty) = (WIDTH - PAD - tw, 23.0);
        let r = Rect::from_xywh(tx - 6.0, ty - 6.0, tw + 12.0, th + 12.0).unwrap();
        let track = if !enabled {
            with_alpha(t.gray, 0.5)
        } else if on {
            t.accent
        } else {
            t.gray
        };
        let track = if enabled && self.hovered(&r) {
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
        if enabled {
            self.regions.push((r, Action::Toggle));
        }
        c.hline(0.0, WIDTH, HEADER_H - 0.5, t.border);
    }

    fn device_card(&mut self, c: &mut Canvas, t: &Theme, s: &StatusResponse, y: f32) -> f32 {
        let Some(me) = &s.self_node else {
            return y;
        };
        let (x, w) = (PAD, WIDTH - 2.0 * PAD);
        let r = Rect::from_xywh(x, y + 8.0, w, CARD_H - 8.0).unwrap();
        let hover = self.hovered(&r);
        c.fill_rrect(
            x,
            y + 8.0,
            w,
            CARD_H - 8.0,
            10.0,
            if hover { t.hover } else { t.surface },
        );
        c.text(
            tr("This device"),
            x + 14.0,
            y + 27.0,
            10.0,
            Weight::Semibold,
            t.dim,
            None,
        );
        c.text(
            &me.hostname,
            x + 14.0,
            y + 47.0,
            14.0,
            Weight::Semibold,
            t.text,
            Some(w - 140.0),
        );
        let ip = me.ip.to_string();
        let ipw = c.measure(&ip, 13.0, Weight::Regular);
        c.text(
            &ip,
            x + w - 14.0 - ipw,
            y + 47.0,
            13.0,
            Weight::Regular,
            t.dim,
            None,
        );
        let corner = if hover {
            Some(tr("Click to copy").to_string())
        } else {
            s.connected_secs
                .filter(|_| s.state == BackendState::Running)
                .map(|n| trf("Connected for {time}", &[("time", &duration(n))]))
        };
        if let Some(corner) = corner {
            let hw = c.measure(&corner, 10.0, Weight::Regular);
            c.text(
                &corner,
                x + w - 14.0 - hw,
                y + 27.0,
                10.0,
                Weight::Regular,
                t.dim,
                None,
            );
        }
        self.regions.push((r, Action::Copy(ip)));
        y + CARD_H
    }

    fn devices(&mut self, c: &mut Canvas, t: &Theme, s: &StatusResponse, y: f32) -> f32 {
        let online = s.peers.iter().filter(|p| p.online).count();
        c.text(
            tr("Devices"),
            PAD,
            y + 22.0,
            10.0,
            Weight::Semibold,
            t.dim,
            None,
        );
        let count = trf(
            "{online} of {total} connected",
            &[("online", &online), ("total", &s.peers.len())],
        );
        let cw = c.measure(&count, 11.0, Weight::Regular);
        c.text(
            &count,
            WIDTH - PAD - cw,
            y + 22.0,
            11.0,
            Weight::Regular,
            t.dim,
            None,
        );
        let mut y = y + SECTION_H;

        if s.peers.is_empty() {
            c.text(
                tr("No other devices yet."),
                PAD,
                y + 30.0,
                13.0,
                Weight::Regular,
                t.dim,
                None,
            );
            return y + ROW_H;
        }
        let visible: Vec<&PeerStatus> = s.peers.iter().skip(self.scroll).take(MAX_ROWS).collect();
        let mut menu_at = None;
        for p in visible {
            let r = Rect::from_xywh(PAD - 8.0, y, WIDTH - 2.0 * PAD + 16.0, ROW_H).unwrap();
            if self.hovered(&r) {
                c.fill_rrect(
                    PAD - 8.0,
                    y + 2.0,
                    WIDTH - 2.0 * PAD + 16.0,
                    ROW_H - 4.0,
                    8.0,
                    t.hover,
                );
            }
            let relayed = p.path.as_deref() == Some("relay");
            let (dot, path) = match (p.online, p.endpoint) {
                (_, Some(_)) => (t.accent, tr("Direct").to_string()),
                (_, None) if relayed && p.relay_via.is_some() => {
                    let via = p.relay_via.as_deref().unwrap_or_default();
                    (t.accent, trf("Via {name}", &[("name", &via)]))
                }
                // The relay is the server: down with it
                (_, None) if relayed && !s.control_connected => {
                    (t.amber, tr("Relay unavailable").to_string())
                }
                (_, None) if relayed => (t.accent, tr("Relay").to_string()),
                (true, None) => (t.amber, tr("Connecting…").to_string()),
                (false, None) => (t.gray, tr("Offline").to_string()),
            };
            c.circle(PAD + 5.0, y + ROW_H / 2.0, 4.5, dot);
            c.text(
                &p.hostname,
                PAD + 20.0,
                y + 23.0,
                14.0,
                Weight::Regular,
                t.text,
                Some(WIDTH - 2.0 * PAD - 120.0),
            );
            // WireGuard renews its keys every 2 minutes, so a fresh handshake
            // is not news (and its age, starting over, looked like reconnects);
            // an old one means the device has gone quiet
            let detail = match p.last_handshake_secs {
                Some(secs)
                    if secs > STALE_HANDSHAKE
                        && (p.endpoint.is_some() || (relayed && s.control_connected)) =>
                {
                    format!("{path} · {}", ago(secs))
                }
                _ => path,
            };
            let in_use = s.prefs.exit_node == Some(p.node_key);
            let (detail, detail_color) = match (in_use, p.online && p.exit_node) {
                (true, true) => (
                    trf("{detail} · used as exit node", &[("detail", &detail)]),
                    t.accent,
                ),
                (true, false) => (
                    tr("Exit node offline · internet blocked").to_string(),
                    t.red,
                ),
                (false, _) if p.exit_node => (
                    trf("{detail} · can be an exit node", &[("detail", &detail)]),
                    t.dim,
                ),
                _ => (detail, t.dim),
            };
            c.text(
                &detail,
                PAD + 20.0,
                y + 40.0,
                11.5,
                Weight::Regular,
                detail_color,
                Some(WIDTH - 2.0 * PAD - 120.0),
            );
            let ip = p.ip.to_string();
            let iw = c.measure(&ip, 12.5, Weight::Regular);
            c.text(
                &ip,
                WIDTH - PAD - 30.0 - iw,
                y + 31.0,
                12.5,
                Weight::Regular,
                t.dim,
                None,
            );
            self.regions.push((r, Action::Copy(ip)));
            let open = self.menu == Some(p.node_key);
            let b = Rect::from_xywh(WIDTH - PAD - 26.0, y + 12.0, 28.0, 28.0).unwrap();
            if open || self.hovered(&b) {
                c.fill_rrect(
                    b.x(),
                    b.y(),
                    b.width(),
                    b.height(),
                    7.0,
                    if self.dark { t.border } else { t.surface },
                );
            }
            for i in 0..3 {
                c.circle(
                    b.x() + 8.0 + i as f32 * 6.0,
                    b.y() + 14.0,
                    1.6,
                    if open { t.text } else { t.dim },
                );
            }
            self.regions.push((b, Action::Menu(p.node_key)));
            if open {
                menu_at = Some((p.clone(), y + 40.0));
            }
            y += ROW_H;
        }
        if let Some((p, top)) = menu_at {
            self.device_menu(c, t, s, &p, top);
        }
        if s.peers.len() > MAX_ROWS {
            let track_h = MAX_ROWS as f32 * ROW_H - 8.0;
            let frac = MAX_ROWS as f32 / s.peers.len() as f32;
            let top = y - MAX_ROWS as f32 * ROW_H
                + 4.0
                + track_h * (self.scroll as f32 / s.peers.len() as f32);
            c.fill_rrect(
                WIDTH - 5.0,
                top,
                3.0,
                track_h * frac,
                1.5,
                with_alpha(t.dim, 0.5),
            );
        }
        y
    }

    /// The "⋯" menu of a device, under its button (or above it near the bottom)
    fn device_menu(
        &mut self,
        c: &mut Canvas,
        t: &Theme,
        s: &StatusResponse,
        p: &PeerStatus,
        top: f32,
    ) {
        let mut items = vec![MenuItem {
            label: tr("Copy IP address").into(),
            action: Action::Copy(p.ip.to_string()),
        }];
        if !p.dns_name.is_empty() {
            items.push(MenuItem {
                label: tr("Copy name").into(),
                action: Action::Copy(p.dns_name.clone()),
            });
        }
        if p.online {
            items.push(MenuItem {
                label: tr("Send a file…").into(),
                action: Action::SendFile(p.ip, p.hostname.clone()),
            });
        }
        if !p.online && p.can_wake {
            items.push(MenuItem {
                label: tr("Wake up").into(),
                action: Action::Wake(p.hostname.clone()),
            });
        }
        let in_use = s.prefs.exit_node == Some(p.node_key);
        if in_use {
            items.push(MenuItem {
                label: tr("Stop using exit node").into(),
                action: Action::SetExit(String::new()),
            });
        } else if p.exit_node && p.online {
            items.push(MenuItem {
                label: tr("Use as exit node").into(),
                action: Action::SetExit(p.node_key.to_base64()),
            });
        }
        let h = items.len() as f32 * MENU_ITEM_H + 8.0;
        let x = WIDTH - PAD - MENU_W;
        let y = if top + h > self.height() - FOOTER_H {
            top - 36.0 - h
        } else {
            top
        };
        c.fill_rrect(
            x,
            y + 2.0,
            MENU_W,
            h,
            10.0,
            with_alpha(Color::BLACK, if self.dark { 0.4 } else { 0.12 }),
        );
        c.fill_rrect(x, y, MENU_W, h, 10.0, t.bg);
        c.stroke_rrect(x + 0.5, y + 0.5, MENU_W - 1.0, h - 1.0, 10.0, t.border);
        // Swallow clicks on the panel's padding
        self.regions.push((
            Rect::from_xywh(x, y, MENU_W, h).unwrap(),
            Action::Menu(p.node_key),
        ));
        let mut iy = y + 4.0;
        for item in items {
            let r = Rect::from_xywh(x + 4.0, iy, MENU_W - 8.0, MENU_ITEM_H).unwrap();
            if self.hovered(&r) {
                c.fill_rrect(r.x(), r.y(), r.width(), r.height(), 7.0, t.hover);
            }
            c.text(
                &item.label,
                x + 14.0,
                iy + 22.0,
                13.0,
                Weight::Regular,
                t.text,
                Some(MENU_W - 28.0),
            );
            self.regions.push((r, item.action));
            iy += MENU_ITEM_H;
        }
    }

    #[allow(clippy::too_many_arguments)]
    /// A title, a wrapped explanation and maybe a button; returns where the
    /// space under the explanation starts
    fn message(
        &mut self,
        c: &mut Canvas,
        t: &Theme,
        y: f32,
        title: &str,
        body: &str,
        button: Option<(&str, Action)>,
    ) -> f32 {
        c.text(
            title,
            PAD,
            y + 34.0,
            15.0,
            Weight::Semibold,
            t.text,
            Some(WIDTH - 2.0 * PAD),
        );
        let below =
            crate::dashboard::paragraph(c, body, PAD, y + 56.0, WIDTH - 2.0 * PAD, 12.5, t.dim)
                + 20.0;
        if let Some((label, action)) = button {
            let y = below - 76.0;
            let bw = (c.measure(label, 13.0, Weight::Semibold) + 32.0).max(112.0);
            let bh = 34.0;
            let r = Rect::from_xywh(PAD, y + 76.0, bw, bh).unwrap();
            let bg = if self.hovered(&r) {
                shade(t.accent, 1.1)
            } else {
                t.accent
            };
            c.fill_rrect(PAD, y + 76.0, bw, bh, 8.0, bg);
            let lw = c.measure(label, 13.0, Weight::Semibold);
            c.text(
                label,
                PAD + (bw - lw) / 2.0,
                y + 76.0 + bh / 2.0 + 4.5,
                13.0,
                Weight::Semibold,
                Color::WHITE,
                None,
            );
            self.regions.push((r, action));
        }
        below
    }

    fn footer(&mut self, c: &mut Canvas, t: &Theme, h: f32) {
        let y = h - FOOTER_H;
        c.hline(0.0, WIDTH, y + 0.5, t.border);
        let left = match (&self.toast, self.status().and_then(|s| s.server.as_deref())) {
            (Some((msg, _)), _) => msg.clone(),
            (None, Some(server)) => server.split("://").nth(1).unwrap_or(server).to_string(),
            (None, None) => String::new(),
        };
        let color = if self.toast.is_some() {
            t.accent
        } else {
            t.dim
        };
        c.text(
            &left,
            PAD,
            y + 29.0,
            12.0,
            Weight::Regular,
            color,
            Some(WIDTH - 2.0 * PAD - 48.0),
        );

        let b = Rect::from_xywh(WIDTH - PAD - 30.0, y + 9.0, 30.0, 30.0).unwrap();
        if self.gear || self.hovered(&b) {
            c.fill_rrect(
                b.x(),
                b.y(),
                b.width(),
                b.height(),
                8.0,
                if self.dark { t.border } else { t.surface },
            );
        }
        c.gear(
            b.x() + 15.0,
            b.y() + 15.0,
            8.5,
            if self.gear { t.text } else { t.dim },
        );
        self.regions.push((b, Action::Gear));
        if self.gear {
            self.gear_menu(c, t, y);
        }
    }

    /// Opens upwards from the gear
    fn gear_menu(&mut self, c: &mut Canvas, t: &Theme, footer_y: f32) {
        let items = [
            (tr("Manage server"), Action::OpenServer),
            (tr("Settings"), Action::OpenSettings),
            (tr("Quit"), Action::Quit),
        ];
        let h = items.len() as f32 * MENU_ITEM_H + 8.0;
        let x = WIDTH - PAD - MENU_W;
        let y = footer_y - h + 4.0;
        c.fill_rrect(
            x,
            y + 2.0,
            MENU_W,
            h,
            10.0,
            with_alpha(Color::BLACK, if self.dark { 0.4 } else { 0.12 }),
        );
        c.fill_rrect(x, y, MENU_W, h, 10.0, t.bg);
        c.stroke_rrect(x + 0.5, y + 0.5, MENU_W - 1.0, h - 1.0, 10.0, t.border);
        self.regions
            .push((Rect::from_xywh(x, y, MENU_W, h).unwrap(), Action::Gear));
        let mut iy = y + 4.0;
        for (label, action) in items {
            let r = Rect::from_xywh(x + 4.0, iy, MENU_W - 8.0, MENU_ITEM_H).unwrap();
            if self.hovered(&r) {
                c.fill_rrect(r.x(), r.y(), r.width(), r.height(), 7.0, t.hover);
            }
            let color = if matches!(action, Action::Quit) {
                t.red
            } else {
                t.text
            };
            c.text(
                label,
                x + 14.0,
                iy + 22.0,
                13.0,
                Weight::Regular,
                color,
                Some(MENU_W - 28.0),
            );
            self.regions.push((r, action));
            iy += MENU_ITEM_H;
        }
    }
}

/// The exit node in use (hostname) and whether it is unreachable
/// What goes in the red box under the devices: a line, and maybe a hint
fn error_text(s: &StatusResponse) -> Option<(String, Option<String>)> {
    if s.key_expired {
        return Some((
            tr("Key expired · ask the admin to renew it").to_string(),
            None,
        ));
    }
    if let Some(p) = s
        .problem
        .as_ref()
        .filter(|_| s.state == BackendState::Running && !s.control_connected)
    {
        return Some(match reason_text(p.reason) {
            Some((what, hint)) => (what.to_string(), Some(hint.to_string())),
            None => (
                tr("Can't reach the server").to_string(),
                Some(p.detail.clone()),
            ),
        });
    }
    s.last_error.clone().map(|e| (e, None))
}

/// Why the server cannot be reached, and what to do: a line each
pub fn reason_text(r: FailReason) -> Option<(&'static str, &'static str)> {
    let (what, hint) = match r {
        FailReason::Timeout => (
            "No answer from the server",
            "The network may block it, or the server is off",
        ),
        FailReason::Refused => (
            "The server refused the connection",
            "Is retail running on the server's computer?",
        ),
        FailReason::Reset => (
            "The connection was cut on the way",
            "This network may be blocking VPN connections",
        ),
        FailReason::Dns => (
            "Could not look up the server's name",
            "Check this device's internet connection",
        ),
        FailReason::Unreachable => ("No route to the server", "Check that this device is online"),
        FailReason::Intercepted => (
            "Something answered in the server's place",
            "A filtering proxy or a Wi-Fi sign-in page",
        ),
        FailReason::Rejected => (
            "The server turned this device away",
            "Ask the administrator for a new invite",
        ),
        FailReason::ProxyAuth => (
            "The network's proxy wants a sign-in",
            "Set one with retail set --proxy",
        ),
        FailReason::ServerError => (
            "The server answered with an error",
            "It may be starting up; retail keeps trying",
        ),
        FailReason::Other => return None,
    };
    Some((tr(what), tr(hint)))
}

fn exit_in_use(s: &StatusResponse) -> Option<(String, bool)> {
    let key = s.prefs.exit_node?;
    Some(match s.peers.iter().find(|p| p.node_key == key) {
        Some(p) => (p.hostname.clone(), !(p.online && p.exit_node)),
        None => (String::new(), true),
    })
}

/// A length of time in its two largest units
pub fn duration(secs: u64) -> String {
    match secs {
        0..=59 => trf("{n} s", &[("n", &secs)]),
        60..=3599 => trf("{n} min", &[("n", &(secs / 60))]),
        3600..=86_399 => trf(
            "{h} h {m} min",
            &[("h", &(secs / 3600)), ("m", &(secs % 3600 / 60))],
        ),
        _ => trf(
            "{d} d {h} h",
            &[("d", &(secs / 86_400)), ("h", &(secs % 86_400 / 3600))],
        ),
    }
}

fn ago(secs: u64) -> String {
    match secs {
        0..=59 => trf("{n} s ago", &[("n", &secs)]),
        60..=3599 => trf("{n} min ago", &[("n", &(secs / 60))]),
        _ => trf("{n} h ago", &[("n", &(secs / 3600))]),
    }
}
