use std::time::{Duration, Instant};

use retail_proto::api::{BackendState, StatusResponse};
use tiny_skia::{Color, Pixmap, Rect};

use crate::config::ThemePref;
use crate::draw::{Canvas, Theme, contains, shade, with_alpha};
use crate::input::TextInput;
use crate::text::{Fonts, Weight};
use crate::ui::View;

pub const WIDTH: f32 = 440.0;
const PAD: f32 = 24.0;
const FIELD_H: f32 = 36.0;
const BUTTON_H: f32 = 34.0;

pub const SERVER: usize = 0;
pub const AUTH_KEY: usize = 1;
pub const DEVICE: usize = 2;

#[derive(Clone, Debug, PartialEq)]
pub enum SettingsAction {
    Focus(usize),
    Connect,
    StartChange,
    Cancel,
    Logout,
    Theme(ThemePref),
    AdvertiseExit(bool),
}

const NETWORK_H: f32 = 76.0;

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
    pub cursor: Option<(f32, f32)>,
    pub inputs: [TextInput; 3],
    pub focus: Option<usize>,
    /// Showing the login form while already logged in ("서버 바꾸기")
    pub changing: bool,
    /// A login or logout is in flight
    pub busy: Option<Instant>,
    /// Result line under the server card: (text, is_error)
    pub message: Option<(String, bool)>,
    /// First click on "Log out" arms it, and a second click within 4 s confirms
    pub confirm_logout: Option<Instant>,
    regions: Vec<(Rect, SettingsAction)>,
}

impl Settings {
    pub fn new(dark: bool, theme: ThemePref) -> Self {
        Settings {
            view: View::Loading,
            dark,
            theme,
            cursor: None,
            inputs: [
                TextInput::new("retail1.… or https://vpn.example.com", false),
                TextInput::new("rtl-auth-…", true),
                TextInput::new("이 컴퓨터의 이름", false),
            ],
            focus: None,
            changing: false,
            busy: None,
            message: None,
            confirm_logout: None,
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

    pub fn show_form(&self) -> bool {
        matches!(self.view, View::Status(_)) && (!self.logged_in() || self.changing)
    }

    pub fn is_busy(&self) -> bool {
        self.busy.is_some_and(|t| t.elapsed() < Duration::from_secs(45))
    }

    pub fn logout_armed(&self) -> bool {
        self.confirm_logout.is_some_and(|t| t.elapsed() < Duration::from_secs(4))
    }

    /// Pre-fills the form from the current registration
    pub fn prefill(&mut self) {
        if let Some(s) = self.status().cloned() {
            if self.inputs[SERVER].value.is_empty()
                && let Some(server) = &s.server
            {
                self.inputs[SERVER].set(server);
            }
            if self.inputs[DEVICE].value.is_empty()
                && let Some(me) = &s.self_node
            {
                self.inputs[DEVICE].set(&me.hostname);
            }
        }
    }

    fn card_h(&self) -> f32 {
        match &self.view {
            View::Status(_) if self.show_form() => 16.0 + 3.0 * (20.0 + FIELD_H + 14.0) + BUTTON_H + 18.0,
            View::Status(_) => 16.0 + 2.0 * 50.0 + BUTTON_H + 26.0,
            _ => 92.0,
        }
    }

    /// The "this device" section (exit-node offer) shows once logged in
    fn show_network(&self) -> bool {
        self.logged_in() && !self.show_form()
    }

    pub fn height(&self) -> f32 {
        // Mirrors `render`: title, then the sections (label 14 + content),
        // 40 between sections, 24 bottom padding
        let message = if self.message.is_some() { 30.0 } else { 0.0 };
        let network = if self.show_network() { 40.0 + 14.0 + NETWORK_H } else { 0.0 };
        76.0 + (14.0 + self.card_h() + message) + network + 40.0 + (14.0 + 44.0) + 40.0 + (14.0 + 60.0) + 24.0
    }

    pub fn action_at(&self, x: f32, y: f32) -> Option<SettingsAction> {
        self.regions.iter().find(|(r, _)| contains(r, x, y)).map(|(_, a)| a.clone())
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

        c.text("설정", PAD, 44.0, 20.0, Weight::Semibold, t.text, None);
        let mut y = 76.0;

        section(&mut c, &t, "연결", y);
        y += 14.0;
        let card_h = self.card_h();
        c.fill_rrect(PAD, y, WIDTH - 2.0 * PAD, card_h, 12.0, t.surface);
        let inner_x = PAD + 16.0;
        let inner_w = WIDTH - 2.0 * PAD - 32.0;
        match self.view.clone() {
            View::Loading => {
                c.text("retaild에 연결하는 중…", inner_x, y + 36.0, 13.5, Weight::Regular, t.dim, None);
            }
            View::Offline => {
                c.text("retaild가 꺼져 있습니다", inner_x, y + 36.0, 14.0, Weight::Semibold, t.text, None);
                let hint = if cfg!(windows) {
                    "retaild.exe를 관리자 권한으로 실행한 뒤 다시 시도하세요."
                } else {
                    "sudo retaild로 실행하세요."
                };
                c.text(hint, inner_x, y + 60.0, 12.5, Weight::Regular, t.dim, Some(inner_w));
            }
            View::Status(_) if self.show_form() => self.form(&mut c, &t, inner_x, y + 16.0, inner_w),
            View::Status(s) => self.account(&mut c, &t, &s, inner_x, y + 16.0, inner_w),
        }
        y += card_h;
        if let Some((msg, error)) = &self.message {
            let color = if *error { t.red } else { t.accent };
            c.text(msg, PAD + 4.0, y + 22.0, 12.5, Weight::Regular, color, Some(WIDTH - 2.0 * PAD - 8.0));
            y += 30.0;
        }

        if self.show_network()
            && let View::Status(s) = self.view.clone()
        {
            y += 40.0;
            section(&mut c, &t, "이 기기", y);
            y += 14.0;
            self.network(&mut c, &t, &s, y);
            y += NETWORK_H;
        }

        y += 40.0;
        section(&mut c, &t, "화면", y);
        y += 14.0;
        self.segmented(&mut c, &t, y);
        y += 44.0;

        y += 40.0;
        section(&mut c, &t, "정보", y);
        y += 14.0;
        c.fill_rrect(PAD, y, WIDTH - 2.0 * PAD, 60.0, 12.0, t.surface);
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
                BackendState::Running => "retaild 실행 중 · 연결됨",
                BackendState::Stopped => "retaild 실행 중 · 연결 꺼짐",
                BackendState::NeedsLogin => "retaild 실행 중 · 로그인 필요",
            },
            View::Offline => "retaild가 꺼져 있음",
            View::Loading => "retaild 확인 중…",
        };
        c.text(daemon, inner_x, y + 45.0, 12.0, Weight::Regular, t.dim, Some(inner_w));
    }

    fn network(&mut self, c: &mut Canvas, t: &Theme, s: &StatusResponse, y: f32) {
        let (x, w) = (PAD, WIDTH - 2.0 * PAD);
        c.fill_rrect(x, y, w, NETWORK_H, 12.0, t.surface);
        let ix = x + 16.0;
        c.text("Exit node로 제공", ix, y + 32.0, 13.5, Weight::Regular, t.text, None);
        c.text(
            "다른 기기가 이 기기를 거쳐 인터넷을 쓸 수 있습니다.",
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
        label_value(c, t, "서버 주소", server, x, y, w);
        let device = match &s.self_node {
            Some(me) => format!("{} · {}", me.hostname, me.ip),
            None => "—".into(),
        };
        label_value(c, t, "이 기기", &device, x, y + 50.0, w);

        let by = y + 2.0 * 50.0 + 10.0;
        let change_w = 136.0;
        self.button(c, t, "서버 바꾸기", x, by, change_w, Style::Secondary, true, SettingsAction::StartChange);
        let (label, style) = if self.logout_armed() {
            ("한 번 더 누르면 로그아웃", Style::Danger)
        } else if self.is_busy() {
            ("로그아웃하는 중…", Style::Secondary)
        } else {
            ("로그아웃", Style::Secondary)
        };
        let lw = c.measure(label, 13.0, Weight::Semibold) + 32.0;
        self.button(c, t, label, x + w - lw, by, lw, style, !self.is_busy(), SettingsAction::Logout);
    }

    fn form(&mut self, c: &mut Canvas, t: &Theme, x: f32, y: f32, w: f32) {
        let labels = ["초대 코드 또는 서버 주소", "인증 키 (초대 코드면 필요 없음)", "기기 이름 (선택)"];
        let mut fy = y;
        for (i, label) in labels.iter().enumerate() {
            c.text(label, x, fy + 13.0, 12.0, Weight::Regular, t.dim, None);
            self.field(c, t, i, x, fy + 20.0, w);
            fy += 20.0 + FIELD_H + 14.0;
        }
        let busy = self.is_busy();
        let label = if busy { "연결하는 중…" } else { "연결" };
        let first = self.inputs[SERVER].trimmed();
        let ready = first.starts_with("retail1.") || (!first.is_empty() && !self.inputs[AUTH_KEY].trimmed().is_empty());
        self.button(c, t, label, x, fy + 4.0, 120.0, Style::Primary, ready && !busy, SettingsAction::Connect);
        if self.logged_in() {
            self.button(c, t, "취소", x + 132.0, fy + 4.0, 96.0, Style::Secondary, !busy, SettingsAction::Cancel);
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
            c.text(input.placeholder, tx, baseline, px, Weight::Regular, with_alpha(t.dim, 0.7), Some(avail));
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

    fn segmented(&mut self, c: &mut Canvas, t: &Theme, y: f32) {
        let options = [(ThemePref::System, "시스템"), (ThemePref::Light, "밝게"), (ThemePref::Dark, "어둡게")];
        let w = WIDTH - 2.0 * PAD;
        c.fill_rrect(PAD, y, w, 40.0, 10.0, t.surface);
        let seg = (w - 8.0) / options.len() as f32;
        for (i, (pref, label)) in options.into_iter().enumerate() {
            let sx = PAD + 4.0 + i as f32 * seg;
            let r = Rect::from_xywh(sx, y + 4.0, seg, 32.0).unwrap();
            let selected = self.theme == pref;
            if selected {
                c.fill_rrect(sx, y + 4.0, seg, 32.0, 7.0, if self.dark { t.hover } else { t.bg });
            } else if self.hovered(&r) {
                c.fill_rrect(sx, y + 4.0, seg, 32.0, 7.0, with_alpha(t.hover, 0.6));
            }
            let weight = if selected { Weight::Semibold } else { Weight::Regular };
            let lw = c.measure(label, 13.0, weight);
            let color = if selected { t.text } else { t.dim };
            c.text(label, sx + (seg - lw) / 2.0, y + 25.0, 13.0, weight, color, None);
            self.regions.push((r, SettingsAction::Theme(pref)));
        }
    }
}

fn section(c: &mut Canvas, t: &Theme, title: &str, y: f32) {
    c.text(title, PAD + 4.0, y, 10.5, Weight::Semibold, t.dim, None);
}

fn label_value(c: &mut Canvas, t: &Theme, label: &str, value: &str, x: f32, y: f32, w: f32) {
    c.text(label, x, y + 14.0, 12.0, Weight::Regular, t.dim, None);
    c.text(value, x, y + 34.0, 14.0, Weight::Regular, t.text, Some(w));
}
