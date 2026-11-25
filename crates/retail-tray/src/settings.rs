use std::time::{Duration, Instant};

use retail_proto::api::{BackendState, SavedServer, StatusResponse};
use tiny_skia::{Color, Pixmap, Rect};

use crate::config::ThemePref;
use crate::i18n::{LangPref, tr, trf};
use crate::draw::{Canvas, Theme, contains, shade, with_alpha};
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

#[derive(Clone, Debug, PartialEq)]
pub enum SettingsAction {
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
    CheckUpdate,
    InstallUpdate,
    AutoUpdate(bool),
    /// Starts retaild with administrator permission
    StartDaemon,
}

const NETWORK_H: f32 = 76.0;
/// The About card: version, then the update row and the automatic-update toggle
const ABOUT_H: f32 = 60.0 + 64.0 + 60.0;
const ROW_H: f32 = 50.0;
/// Saved servers shown at once; more scroll
const MAX_ROWS: usize = 4;

#[derive(Clone, Copy, PartialEq)]
enum Style {
    Primary,
    Secondary,
    Danger,
}

pub struct Settings {
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
        self.status().is_some_and(|s| s.state != BackendState::NeedsLogin)
    }

    /// Servers joined before, the current one included
    pub fn servers(&self) -> &[SavedServer] {
        self.status().map_or(&[], |s| &s.servers)
    }

    pub fn show_form(&self) -> bool {
        matches!(self.view, View::Status(_)) && (self.adding || (!self.logged_in() && self.servers().is_empty()))
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
        self.show_list() && (PAD..=WIDTH - PAD).contains(&x) && (top..=bottom).contains(&y)
    }

    /// The saved servers, to switch between
    pub fn show_list(&self) -> bool {
        matches!(self.view, View::Status(_)) && !self.show_form() && (self.changing || !self.logged_in())
    }

    pub fn is_busy(&self) -> bool {
        self.busy.is_some_and(|t| t.elapsed() < Duration::from_secs(45))
    }

    pub fn is_checking(&self) -> bool {
        self.checking.is_some_and(|t| t.elapsed() < Duration::from_secs(45))
    }

    /// A server address instead of an invite code also needs its auth key
    fn with_auth_key(&self) -> bool {
        let first = self.inputs[SERVER].trimmed();
        first.starts_with("https://") || first.starts_with("http://")
    }

    /// The form's fields in order, the auth key only when it is needed
    pub fn form_fields(&self) -> &'static [usize] {
        if self.with_auth_key() { &[SERVER, AUTH_KEY, DEVICE] } else { &[SERVER, DEVICE] }
    }

    pub fn logout_armed(&self) -> bool {
        self.confirm_logout.is_some_and(|t| t.elapsed() < Duration::from_secs(4))
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
        if matches!(self.view, View::Status(_)) { ABOUT_H } else { 60.0 }
    }

    fn card_h(&self) -> f32 {
        match &self.view {
            View::Status(_) if self.show_form() => 16.0 + self.form_fields().len() as f32 * (20.0 + FIELD_H + 14.0) + HINT_H + BUTTON_H + 18.0,
            View::Status(_) if self.show_list() => 8.0 + self.servers().len().min(MAX_ROWS) as f32 * ROW_H + 14.0 + BUTTON_H + 18.0,
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
        // Mirrors `render`: title, then the sections (label 14 + content),
        // 40 between sections, 24 bottom padding
        let message = self.message.as_ref().map_or(0.0, |(m, _)| 30.0 + 18.0 * m.matches('\n').count() as f32);
        let network = if self.show_network() { 40.0 + 14.0 + NETWORK_H } else { 0.0 };
        76.0 + (14.0 + self.card_h() + message) + network + 40.0 + (14.0 + 44.0) + 40.0 + (14.0 + 44.0) + 40.0 + (14.0 + self.about_h()) + 24.0
    }

    pub fn action_at(&self, x: f32, y: f32) -> Option<SettingsAction> {
        // Last drawn is on top (the open language list)
        self.regions.iter().rev().find(|(r, _)| contains(r, x, y)).map(|(_, a)| a.clone())
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

        c.text(tr("Settings"), PAD, 44.0, 20.0, Weight::Semibold, t.text, None);
        let mut y = 76.0;

        section(&mut c, &t, tr("Connection"), y);
        y += 14.0;
        let card_h = self.card_h();
        c.fill_rrect(PAD, y, WIDTH - 2.0 * PAD, card_h, 12.0, t.surface);
        let inner_x = PAD + 16.0;
        let inner_w = WIDTH - 2.0 * PAD - 32.0;
        match self.view.clone() {
            View::Loading => {
                c.text(tr("Connecting to retaild…"), inner_x, y + 36.0, 13.5, Weight::Regular, t.dim, None);
            }
            View::Offline => {
                let (title, hint, bar) = self.daemon.text();
                c.text(&title, inner_x, y + 36.0, 14.0, Weight::Semibold, t.text, None);
                c.text(&hint, inner_x, y + 60.0, 12.5, Weight::Regular, t.dim, Some(inner_w));
                match bar {
                    Some(f) => crate::ui::progress_bar(&mut c, &t, inner_x, y + 84.0, inner_w, f),
                    None => {
                        let label = tr("Start retaild");
                        let bw = c.measure(label, 13.0, Weight::Semibold) + 28.0;
                        let busy = self.daemon.is_starting();
                        self.button(&mut c, &t, label, inner_x, y + 80.0, bw, Style::Primary, !busy, SettingsAction::StartDaemon);
                    }
                }
            }
            View::Status(_) if self.show_form() => self.form(&mut c, &t, inner_x, y + 16.0, inner_w),
            View::Status(_) if self.show_list() => self.server_list(&mut c, &t, y),
            View::Status(s) => self.account(&mut c, &t, &s, inner_x, y + 16.0, inner_w),
        }
        y += card_h;
        if let Some((msg, error)) = &self.message {
            let color = if *error { t.red } else { t.accent };
            // A second line is the hint under an error
            for (i, line) in msg.lines().enumerate() {
                let color = if i == 0 { color } else { t.dim };
                c.text(line, PAD + 4.0, y + 22.0, 12.5, Weight::Regular, color, Some(WIDTH - 2.0 * PAD - 8.0));
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
        let themes =
            [ThemePref::System, ThemePref::Light, ThemePref::Dark].map(|p| (p == self.theme, theme_label(p), SettingsAction::Theme(p)));
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
        c.text(daemon, inner_x, y + 45.0, 12.0, Weight::Regular, t.dim, Some(inner_w));
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

    /// Saved servers: a click switches, ⋯ removes; + joins another
    fn server_list(&mut self, c: &mut Canvas, t: &Theme, card_y: f32) {
        let (x, w) = (PAD, WIDTH - 2.0 * PAD);
        let busy = self.is_busy();
        let servers = self.servers().to_vec();
        // The list may have shrunk since it was scrolled
        self.server_scroll = self.server_scroll.min(servers.len().saturating_sub(MAX_ROWS));
        let first = self.server_scroll;
        let mut y = card_y + 8.0;
        for (i, srv) in servers.iter().enumerate().skip(first).take(MAX_ROWS) {
            let row = Rect::from_xywh(x + 6.0, y, w - 12.0, ROW_H).unwrap();
            let more = Rect::from_xywh(x + w - 50.0, y + 8.0, 38.0, ROW_H - 16.0).unwrap();
            let open = self.server_menu == Some(i);
            if !srv.current && !busy && self.hovered(&row) && !self.hovered(&more) {
                c.fill_rrect(row.x(), row.y(), row.width(), row.height(), 8.0, t.hover);
            }
            c.circle(x + 20.0, y + ROW_H / 2.0, 4.0, if srv.current { t.accent } else { t.gray });
            let weight = if srv.current { Weight::Semibold } else { Weight::Regular };
            c.text(&server_label(&srv.server), x + 34.0, y + 21.0, 13.5, weight, t.text, Some(w - 100.0));
            let ip = srv.ip.map(|ip| ip.to_string()).unwrap_or_default();
            let sub = if srv.current { format!("{ip} · {}", tr("Current")) } else { ip };
            c.text(&sub, x + 34.0, y + 38.0, 11.5, Weight::Regular, t.dim, Some(w - 100.0));
            if open || self.hovered(&more) {
                c.fill_rrect(more.x(), more.y(), more.width(), more.height(), 6.0, t.hover);
            }
            let dy = y + ROW_H / 2.0;
            for k in -1..=1 {
                c.circle(more.x() + more.width() / 2.0 + k as f32 * 5.0, dy, 1.6, t.dim);
            }
            if !srv.current && !busy {
                self.regions.push((row, SettingsAction::SwitchServer(srv.server.clone())));
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
        self.button(c, t, &add, ix, y, aw, Style::Secondary, !busy, SettingsAction::AddServer);
        if self.logged_in() {
            let done = tr("Done");
            let dw = c.measure(done, 13.0, Weight::Semibold).max(56.0) + 32.0;
            self.button(c, t, done, x + w - 16.0 - dw, y, dw, Style::Secondary, true, SettingsAction::Cancel);
        }
    }

    /// The ⋯ menu of a saved server, under its button
    fn server_popover(&mut self, c: &mut Canvas, t: &Theme, i: usize) {
        let Some(srv) = self.servers().get(i).cloned() else { return };
        let card_y = 76.0 + 14.0;
        let label = if srv.current { tr("Log out and remove") } else { tr("Remove from list") };
        let w = c.measure(label, 13.0, Weight::Regular) + 40.0;
        let row = i.saturating_sub(self.server_scroll) as f32;
        let (x, y) = (WIDTH - PAD - 12.0 - w, card_y + 8.0 + (row + 1.0) * ROW_H - 6.0);
        let h = 36.0 + 8.0;
        c.fill_rrect(x - 1.0, y + 1.0, w + 2.0, h + 3.0, 11.0, with_alpha(Color::BLACK, if self.dark { 0.45 } else { 0.12 }));
        c.fill_rrect(x, y, w, h, 10.0, if self.dark { t.surface } else { t.bg });
        c.stroke_rrect(x + 0.5, y + 0.5, w - 1.0, h - 1.0, 10.0, t.border);
        let r = Rect::from_xywh(x + 4.0, y + 4.0, w - 8.0, 36.0).unwrap();
        if self.hovered(&r) {
            c.fill_rrect(r.x(), r.y(), r.width(), r.height(), 7.0, t.hover);
        }
        c.text(label, x + 16.0, y + 27.0, 13.0, Weight::Regular, t.red, None);
        self.regions.push((Rect::from_xywh(x, y, w, h).unwrap(), SettingsAction::ServerMenu(i)));
        self.regions.push((r, SettingsAction::ForgetServer(srv.server)));
    }

    /// The closed picker: the current language and a chevron
    fn dropdown(&mut self, c: &mut Canvas, t: &Theme, y: f32) {
        let (x, w) = (PAD, WIDTH - 2.0 * PAD);
        let r = Rect::from_xywh(x, y, w, 40.0).unwrap();
        let bg = if self.hovered(&r) || self.lang_open { t.hover } else { t.surface };
        c.fill_rrect(x, y, w, 40.0, 10.0, bg);
        if self.lang_open {
            c.stroke_rrect_w(x + 0.75, y + 0.75, w - 1.5, 38.5, 10.0, 1.5, t.accent);
        }
        c.text(self.lang.label(), x + 16.0, y + 25.0, 13.5, Weight::Regular, t.text, Some(w - 56.0));
        let (cx, cy) = (x + w - 22.0, y + 20.0);
        let (dx, dy) = if self.lang_open { (5.0, -2.5) } else { (5.0, 2.5) };
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
        c.fill_rrect(x - 1.0, y + 1.0, w + 2.0, h + 3.0, 12.0, with_alpha(Color::BLACK, if self.dark { 0.45 } else { 0.12 }));
        c.fill_rrect(x, y, w, h, 11.0, if self.dark { t.surface } else { t.bg });
        c.stroke_rrect(x + 0.5, y + 0.5, w - 1.0, h - 1.0, 11.0, t.border);
        // The whole card catches clicks, so a click between items doesn't fall through
        self.regions.push((Rect::from_xywh(x, y, w, h).unwrap(), SettingsAction::LangMenu));
        for (i, pref) in LangPref::ALL.into_iter().enumerate() {
            let iy = y + 4.0 + i as f32 * ITEM_H;
            let r = Rect::from_xywh(x + 4.0, iy, w - 8.0, ITEM_H).unwrap();
            if self.hovered(&r) {
                c.fill_rrect(x + 4.0, iy, w - 8.0, ITEM_H, 7.0, t.hover);
            }
            let selected = pref == self.lang;
            let weight = if selected { Weight::Semibold } else { Weight::Regular };
            c.text(pref.label(), x + 16.0, iy + 22.0, 13.5, weight, t.text, Some(w - 60.0));
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
            (tr("Updates are not available here").to_string(), tr("There are no official builds for this system.").to_string(), t.dim)
        } else if let Some(stage) = staged {
            (trf("Installing retail {version}…", &[("version", &latest)]), crate::ui::stage_text(stage, u.done_bytes, u.total_bytes), t.text)
        } else if u.installing {
            (trf("Installing retail {version}…", &[("version", &latest)]), tr("retail restarts when it is done.").to_string(), t.text)
        } else if u.available {
            (trf("retail {version} is available", &[("version", &latest)]), trf("You have {version}.", &[("version", &u.current)]), t.accent)
        } else if let Some(e) = &u.error {
            (tr("Could not check for updates").to_string(), e.clone(), t.red)
        } else if u.latest.is_some() {
            (tr("Up to date").to_string(), trf("You have the newest version, {version}.", &[("version", &u.current)]), t.text)
        } else {
            (tr("Not checked yet").to_string(), tr("retail looks for new versions every few hours.").to_string(), t.text)
        };
        let busy = self.is_checking() || u.installing;
        let (label, style, action) = if u.available {
            (tr("Update now"), Style::Primary, SettingsAction::InstallUpdate)
        } else if self.is_checking() {
            (tr("Checking…"), Style::Secondary, SettingsAction::CheckUpdate)
        } else {
            (tr("Check now"), Style::Secondary, SettingsAction::CheckUpdate)
        };
        let bw = c.measure(label, 13.0, Weight::Semibold) + 28.0;
        c.text(&line, ix, y + 27.0, 13.5, Weight::Regular, color, Some(w - 48.0 - bw));
        c.text(&sub, ix, y + 45.0, 11.5, Weight::Regular, t.dim, Some(w - 48.0 - bw));
        if let Some(stage) = staged {
            crate::ui::progress_bar(c, t, ix, y + 53.0, w - 48.0 - bw, crate::ui::stage_fraction(stage, u.done_bytes, u.total_bytes));
        }
        if u.supported {
            self.button(c, t, label, x + w - 16.0 - bw, y + 15.0, bw, style, !busy, action);
        }

        let y = y + 64.0;
        c.hline(ix, x + w - 16.0, y, t.border);
        c.text(tr("Install updates automatically"), ix, y + 26.0, 13.5, Weight::Regular, t.text, Some(w - 100.0));
        c.text(tr("Otherwise retail lets you know when one is out."), ix, y + 44.0, 11.5, Weight::Regular, t.dim, Some(w - 100.0));
        let on = s.prefs.auto_update;
        let (tw, th) = (42.0, 24.0);
        let (tx, ty) = (x + w - 16.0 - tw, y + 18.0);
        let r = Rect::from_xywh(tx - 6.0, ty - 6.0, tw + 12.0, th + 12.0).unwrap();
        let track = if on { t.accent } else { t.gray };
        let track = if self.hovered(&r) { shade(track, if self.dark { 1.12 } else { 0.92 }) } else { track };
        let track = if u.supported { track } else { with_alpha(track, 0.5) };
        c.fill_rrect(tx, ty, tw, th, th / 2.0, track);
        let kx = if on { tx + tw - th / 2.0 } else { tx + th / 2.0 };
        c.circle(kx, ty + th / 2.0, th / 2.0 - 3.0, t.knob);
        if u.supported {
            self.regions.push((r, SettingsAction::AutoUpdate(!on)));
        }
    }

    fn network(&mut self, c: &mut Canvas, t: &Theme, s: &StatusResponse, y: f32) {
        let (x, w) = (PAD, WIDTH - 2.0 * PAD);
        c.fill_rrect(x, y, w, NETWORK_H, 12.0, t.surface);
        let ix = x + 16.0;
        c.text(tr("Offer as exit node"), ix, y + 32.0, 13.5, Weight::Regular, t.text, None);
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
        let track = if self.hovered(&r) { shade(track, if self.dark { 1.12 } else { 0.92 }) } else { track };
        c.fill_rrect(tx, ty, tw, th, th / 2.0, track);
        let kx = if on { tx + tw - th / 2.0 } else { tx + th / 2.0 };
        c.circle(kx, ty + th / 2.0, th / 2.0 - 3.0, t.knob);
        self.regions.push((r, SettingsAction::AdvertiseExit(!on)));

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
        self.button(c, t, change, x, by, change_w, Style::Secondary, true, SettingsAction::StartChange);
        let (label, style) = if self.logout_armed() {
            (tr("Click again to log out"), Style::Danger)
        } else if self.is_busy() {
            (tr("Logging out…"), Style::Secondary)
        } else {
            (tr("Log out"), Style::Secondary)
        };
        let lw = c.measure(label, 13.0, Weight::Semibold) + 32.0;
        self.button(c, t, label, x + w - lw, by, lw, style, !self.is_busy(), SettingsAction::Logout);
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
        let label = if busy { tr("Connecting…") } else { tr("Connect") };
        let first = self.inputs[SERVER].trimmed();
        let ready = first.starts_with("retail1.") || (!first.is_empty() && !self.inputs[AUTH_KEY].trimmed().is_empty());
        let cw = c.measure(label, 13.0, Weight::Semibold).max(56.0) + 48.0;
        self.button(c, t, label, x, fy + 4.0, cw, Style::Primary, ready && !busy, SettingsAction::Connect);
        if self.logged_in() || !self.servers().is_empty() {
            self.button(c, t, tr("Cancel"), x + cw + 12.0, fy + 4.0, 96.0, Style::Secondary, !busy, SettingsAction::Cancel);
        }
    }

    fn field(&mut self, c: &mut Canvas, t: &Theme, i: usize, x: f32, y: f32, w: f32) {
        let focused = self.focus == Some(i);
        let r = Rect::from_xywh(x, y, w, FIELD_H).unwrap();
        c.fill_rrect(x, y, w, FIELD_H, 8.0, t.bg);
        if focused {
            c.stroke_rrect_w(x + 0.75, y + 0.75, w - 1.5, FIELD_H - 1.5, 8.0, 1.5, t.accent);
        } else {
            let border = if self.hovered(&r) { shade(t.border, if self.dark { 1.4 } else { 0.85 }) } else { t.border };
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
            c.text(tr(input.placeholder), tx, baseline, px, Weight::Regular, with_alpha(t.dim, 0.7), Some(avail));
        } else {
            // Keep the caret in view by sliding long text to the left
            let before: String = shown.chars().take(caret).collect();
            let caret_x = c.measure(&before, px, Weight::Regular);
            let shift = (caret_x - avail + 2.0).max(0.0);
            if input.is_all_selected() {
                let sw = c.measure(&shown, px, Weight::Regular).min(avail);
                c.fill_rrect(tx - 2.0, y + 8.0, sw + 4.0, FIELD_H - 16.0, 3.0, with_alpha(t.accent, 0.28));
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
            c.text(&visible, tx, baseline, px, Weight::Regular, t.text, Some(avail));
            if focused {
                let caret_vis: String = visible.chars().take(caret.saturating_sub(dropped)).collect();
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
        let bg = if hover { shade(bg, if self.dark || style != Style::Secondary { 1.1 } else { 0.96 }) } else { bg };
        let (bg, fg) = if enabled { (bg, fg) } else { (with_alpha(bg, 0.5), with_alpha(fg, 0.6)) };
        c.fill_rrect(x, y, w, BUTTON_H, 8.0, bg);
        if let Some(b) = border {
            c.stroke_rrect(x + 0.5, y + 0.5, w - 1.0, BUTTON_H - 1.0, 8.0, b);
        }
        let lw = c.measure(label, 13.0, Weight::Semibold);
        c.text(label, x + (w - lw) / 2.0, y + BUTTON_H / 2.0 + 4.5, 13.0, Weight::Semibold, fg, None);
        if enabled {
            self.regions.push((r, action));
        }
    }

    /// A row of choices: (selected, label, action) each
    fn segmented(&mut self, c: &mut Canvas, t: &Theme, y: f32, options: &[(bool, &str, SettingsAction)]) {
        let w = WIDTH - 2.0 * PAD;
        c.fill_rrect(PAD, y, w, 40.0, 10.0, t.surface);
        let seg = (w - 8.0) / options.len() as f32;
        for (i, (selected, label, action)) in options.iter().enumerate() {
            let sx = PAD + 4.0 + i as f32 * seg;
            let r = Rect::from_xywh(sx, y + 4.0, seg, 32.0).unwrap();
            let selected = *selected;
            if selected {
                c.fill_rrect(sx, y + 4.0, seg, 32.0, 7.0, if self.dark { t.hover } else { t.bg });
            } else if self.hovered(&r) {
                c.fill_rrect(sx, y + 4.0, seg, 32.0, 7.0, with_alpha(t.hover, 0.6));
            }
            let weight = if selected { Weight::Semibold } else { Weight::Regular };
            let lw = c.measure(label, 13.0, weight);
            let color = if selected { t.text } else { t.dim };
            c.text(label, sx + (seg - lw) / 2.0, y + 25.0, 13.0, weight, color, None);
            self.regions.push((r, action.clone()));
        }
    }
}

/// A server URL as people say it: no scheme, no default port
pub fn server_label(url: &str) -> String {
    let s = url.trim_start_matches("https://").trim_start_matches("http://").trim_end_matches('/');
    s.strip_suffix(":443").unwrap_or(s).to_string()
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

fn label_value(c: &mut Canvas, t: &Theme, label: &str, value: &str, x: f32, y: f32, w: f32) {
    c.text(label, x, y + 14.0, 12.0, Weight::Regular, t.dim, None);
    c.text(value, x, y + 34.0, 14.0, Weight::Regular, t.text, Some(w));
}
