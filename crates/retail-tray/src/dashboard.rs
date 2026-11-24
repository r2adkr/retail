//! Hosting a network on this device. Opening the window does not start the
//! server.

use std::time::{Duration, Instant};

use retail_proto::api::{InviteResponse, RouterState, ServerNotice, ServerStatus};
use tiny_skia::{Color, Pixmap, Rect};

use crate::draw::{Canvas, Theme, contains, shade, with_alpha};
use crate::text::{Fonts, Weight};

pub const WIDTH: f32 = 460.0;
const PAD: f32 = 24.0;
const BUTTON_H: f32 = 34.0;
const ROW_H: f32 = 44.0;
const QR_SIZE: f32 = 150.0;

#[derive(Clone, Debug, PartialEq)]
pub enum DashAction {
    Start,
    Stop,
    Invite,
    CopyInvite,
    Remove(i64),
    OpenWeb,
}

#[derive(Clone, Copy, PartialEq)]
enum Style {
    Primary,
    Secondary,
    Danger,
}

pub struct Dashboard {
    pub dark: bool,
    pub cursor: Option<(f32, f32)>,
    /// Latest server status (`None` until the first answer)
    pub status: Option<Result<ServerStatus, String>>,
    /// Host of the server this device is connected to, if it is not the one
    /// hosted here.
    pub other_network: Option<String>,
    pub invite: Option<InviteResponse>,
    pub busy: Option<Instant>,
    pub message: Option<(String, bool)>,
    pub confirm_stop: Option<Instant>,
    pub confirm_remove: Option<(i64, Instant)>,
    height: f32,
    regions: Vec<(Rect, DashAction)>,
}

impl Dashboard {
    pub fn new(dark: bool) -> Self {
        Dashboard {
            dark,
            cursor: None,
            status: None,
            other_network: None,
            invite: None,
            busy: None,
            message: None,
            confirm_stop: None,
            confirm_remove: None,
            height: 420.0,
            regions: Vec::new(),
        }
    }

    pub fn height(&self) -> f32 {
        self.height
    }

    pub fn is_busy(&self) -> bool {
        self.busy.is_some_and(|t| t.elapsed() < Duration::from_secs(30))
    }

    pub fn stop_armed(&self) -> bool {
        self.confirm_stop.is_some_and(|t| t.elapsed() < Duration::from_secs(4))
    }

    pub fn remove_armed(&self, id: i64) -> bool {
        self.confirm_remove.is_some_and(|(i, t)| i == id && t.elapsed() < Duration::from_secs(4))
    }

    pub fn action_at(&self, x: f32, y: f32) -> Option<DashAction> {
        self.regions.iter().find(|(r, _)| contains(r, x, y)).map(|(_, a)| a.clone())
    }

    fn hovered(&self, r: &Rect) -> bool {
        self.cursor.is_some_and(|(x, y)| contains(r, x, y))
    }

    /// Returns true if the height changed, in which case it must be drawn again
    pub fn render(&mut self, fonts: &Fonts, pix: &mut Pixmap, scale: f32) -> bool {
        let t = Theme::new(self.dark);
        let mut c = Canvas { pix, fonts, scale };
        self.regions.clear();
        c.fill_rect(0.0, 0.0, WIDTH, self.height.max(2000.0), t.bg);
        let mut y = 44.0;
        let status = self.status.clone();
        let running = matches!(&status, Some(Ok(s)) if s.running);
        c.text(if running { "내 네트워크" } else { "네트워크 열기" }, PAD, y, 20.0, Weight::Semibold, t.text, None);
        y += 24.0;

        match status {
            None => {
                c.text("확인하는 중…", PAD, y + 20.0, 13.0, Weight::Regular, t.dim, None);
                y += 40.0;
            }
            Some(Err(e)) => {
                y = paragraph(&mut c, &e, PAD, y + 20.0, WIDTH - 2.0 * PAD, 13.0, t.red);
            }
            Some(Ok(s)) if !s.running => y = self.idle(&mut c, &t, &s, y),
            Some(Ok(s)) => y = self.running(&mut c, &t, &s, y),
        }
        if let Some((msg, error)) = self.message.clone() {
            y = paragraph(&mut c, &msg, PAD, y + 18.0, WIDTH - 2.0 * PAD, 12.5, if error { t.red } else { t.accent });
        }
        let h = (y + 24.0).ceil();
        let changed = (h - self.height).abs() > 0.5;
        self.height = h;
        changed
    }

    fn idle(&mut self, c: &mut Canvas, t: &Theme, s: &ServerStatus, y: f32) -> f32 {
        let w = WIDTH - 2.0 * PAD;
        let mut y = paragraph(
            c,
            "Run the server for your own network on this device. Other devices join with an invite code or QR code; \
             retail opens the ports on your router automatically where it can.",
            PAD,
            y + 22.0,
            w,
            13.0,
            t.dim,
        );
        if let Some(other) = &self.other_network {
            let note = format!("이 기기는 지금 {other}에 연결돼 있습니다. 서버를 열면 새 네트워크로 옮겨집니다.");
            y = paragraph(c, &note, PAD, y + 26.0, w, 12.5, t.amber);
        }
        if let Some(e) = &s.last_error {
            y = paragraph(c, e, PAD, y + 14.0, w, 12.5, t.red);
        }
        let busy = self.is_busy();
        let label = if busy { "여는 중…" } else { "서버 열기" };
        self.button(c, t, label, PAD, y + 18.0, 150.0, Style::Primary, !busy, DashAction::Start);
        y + 18.0 + BUTTON_H
    }

    fn running(&mut self, c: &mut Canvas, t: &Theme, s: &ServerStatus, y: f32) -> f32 {
        let w = WIDTH - 2.0 * PAD;
        let (x, ix) = (PAD, PAD + 16.0);
        let mut rows: Vec<(&str, String, Color)> = Vec::new();
        rows.push((
            "주소",
            s.public.clone().unwrap_or_else(|| "다른 네트워크에서는 접속할 수 없음".into()),
            if s.public.is_some() { t.text } else { t.amber },
        ));
        if let Some(lan) = s.lan.first() {
            rows.push(("이 네트워크", lan.clone(), t.text));
        }
        match &s.router {
            Some(RouterState::Opened { method, tcp, udp }) => {
                rows.push(("공유기 포트", format!("{method}로 열림 (TCP {tcp}, UDP {udp})"), t.text));
            }
            Some(RouterState::Unavailable) => rows.push(("공유기 포트", "자동으로 열지 못함".into(), t.amber)),
            None => {}
        }
        if let Some(site) = &s.reality {
            rows.push(("REALITY", format!("켜짐 · {site}처럼 보임"), t.text));
        }
        if let Some(helper) = &s.helper {
            let (state, color) = if s.helper_linked { ("연결됨", t.text) } else { ("연결 안 됨", t.amber) };
            rows.push(("보조 노드", format!("{helper} · {state}"), color));
        }
        if !s.fronts.is_empty() {
            rows.push(("CDN", s.fronts.join(", "), t.text));
        }
        let card_h = 16.0 + rows.len() as f32 * 42.0;
        let cy = y + 18.0;
        c.fill_rrect(x, cy, w, card_h, 12.0, t.surface);
        let mut ry = cy + 8.0;
        for (label, value, color) in rows {
            c.text(label, ix, ry + 16.0, 11.5, Weight::Regular, t.dim, None);
            c.text(&value, ix, ry + 34.0, 13.5, Weight::Regular, color, Some(w - 32.0));
            ry += 42.0;
        }
        let mut y = cy + card_h;
        if let Some(notice) = &s.notice {
            y = paragraph(c, &notice_text(notice), x + 4.0, y + 18.0, w - 8.0, 12.0, t.amber);
        }

        y += 34.0;
        c.text("기기 초대", x + 4.0, y, 10.5, Weight::Semibold, t.dim, None);
        y += 12.0;
        match self.invite.clone() {
            None => {
                let busy = self.is_busy();
                self.button(c, t, "초대 만들기", x, y, 140.0, Style::Primary, !busy, DashAction::Invite);
                y += BUTTON_H;
            }
            Some(inv) => {
                c.fill_rrect(x, y, w, QR_SIZE + 24.0, 12.0, t.surface);
                // White tile because scanners want dark-on-light
                let (qx, qy) = (x + 12.0, y + 12.0);
                c.fill_rrect(qx, qy, QR_SIZE, QR_SIZE, 8.0, Color::WHITE);
                draw_qr(c, &inv.code, qx + 8.0, qy + 8.0, QR_SIZE - 16.0);
                let tx = qx + QR_SIZE + 16.0;
                let tw = x + w - tx - 12.0;
                c.text("찍거나 코드를 복사하세요", tx, y + 30.0, 13.0, Weight::Semibold, t.text, Some(tw));
                c.text("상대 기기의 retail 설정에", tx, y + 50.0, 12.0, Weight::Regular, t.dim, Some(tw));
                c.text("붙여 넣으면 참여합니다.", tx, y + 66.0, 12.0, Weight::Regular, t.dim, Some(tw));
                let hours = ((inv.expires_at - unix_now()).max(0) + 1800) / 3600;
                c.text(&format!("1회용 · {hours}시간 뒤 만료"), tx, y + 92.0, 11.5, Weight::Regular, t.dim, Some(tw));
                self.button(c, t, "코드 복사", tx, y + QR_SIZE - 28.0, 104.0, Style::Secondary, true, DashAction::CopyInvite);
                y += QR_SIZE + 24.0;
                self.button(c, t, "새 초대", x, y + 12.0, 116.0, Style::Secondary, !self.is_busy(), DashAction::Invite);
                y += 12.0 + BUTTON_H;
            }
        }

        y += 34.0;
        let online = s.nodes.iter().filter(|n| n.online).count();
        c.text("기기", x + 4.0, y, 10.5, Weight::Semibold, t.dim, None);
        let count = format!("{}대 중 {online}대 연결", s.nodes.len());
        let cw = c.measure(&count, 11.0, Weight::Regular);
        c.text(&count, x + w - 4.0 - cw, y, 11.0, Weight::Regular, t.dim, None);
        y += 8.0;
        if s.nodes.is_empty() {
            c.text("아직 기기가 없습니다. 초대를 만들어 추가하세요.", x + 4.0, y + 28.0, 12.5, Weight::Regular, t.dim, None);
            y += ROW_H;
        }
        for n in &s.nodes {
            c.circle(x + 9.0, y + ROW_H / 2.0, 4.0, if n.online { t.accent } else { t.gray });
            let name = if n.exit_node { format!("{} · Exit node", n.hostname) } else { n.hostname.clone() };
            c.text(&name, x + 24.0, y + 20.0, 13.5, Weight::Regular, t.text, Some(w - 190.0));
            let seen = if n.online { "연결됨".to_string() } else { last_seen(n.last_seen) };
            c.text(&format!("{} · {} · {seen}", n.ip, n.os), x + 24.0, y + 37.0, 11.5, Weight::Regular, t.dim, Some(w - 190.0));
            let armed = self.remove_armed(n.id);
            let label = if armed { "눌러서 빼기" } else { "빼기" };
            let lw = c.measure(label, 12.5, Weight::Regular) + 20.0;
            let r = Rect::from_xywh(x + w - lw, y + 8.0, lw, 28.0).unwrap();
            if armed || self.hovered(&r) {
                c.fill_rrect(r.x(), r.y(), r.width(), r.height(), 6.0, if armed { with_alpha(t.red, 0.14) } else { t.hover });
            }
            c.text(label, r.x() + 10.0, y + 27.0, 12.5, Weight::Regular, if armed { t.red } else { t.dim }, None);
            self.regions.push((r, DashAction::Remove(n.id)));
            y += ROW_H;
        }

        y += 20.0;
        let (label, style) = if self.stop_armed() {
            ("한 번 더 누르면 서버 닫기", Style::Danger)
        } else {
            ("서버 닫기", Style::Secondary)
        };
        let lw = c.measure(label, 13.0, Weight::Semibold) + 32.0;
        self.button(c, t, label, x, y, lw, style, !self.is_busy(), DashAction::Stop);
        let web = "웹에서 관리";
        let ww = c.measure(web, 13.0, Weight::Semibold) + 32.0;
        self.button(c, t, web, x + lw + 8.0, y, ww, Style::Secondary, true, DashAction::OpenWeb);
        y + BUTTON_H
    }

    #[allow(clippy::too_many_arguments)]
    fn button(&mut self, c: &mut Canvas, t: &Theme, label: &str, x: f32, y: f32, w: f32, style: Style, enabled: bool, action: DashAction) {
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
}

/// Draws word-wrapped text and returns the baseline of the last line
fn paragraph(c: &mut Canvas, text: &str, x: f32, y: f32, w: f32, px: f32, color: Color) -> f32 {
    let mut line = String::new();
    let mut baseline = y;
    let mut first = true;
    for word in text.split_whitespace() {
        let candidate = if line.is_empty() { word.to_string() } else { format!("{line} {word}") };
        if !line.is_empty() && c.measure(&candidate, px, Weight::Regular) > w {
            if !first {
                baseline += px * 1.45;
            }
            c.text(&line, x, baseline, px, Weight::Regular, color, None);
            first = false;
            line = word.to_string();
        } else {
            line = candidate;
        }
    }
    if !line.is_empty() {
        if !first {
            baseline += px * 1.45;
        }
        c.text(&line, x, baseline, px, Weight::Regular, color, None);
    }
    baseline
}

fn draw_qr(c: &mut Canvas, data: &str, x: f32, y: f32, size: f32) {
    let Ok(code) = qrcode::QrCode::with_error_correction_level(data.as_bytes(), qrcode::EcLevel::M) else {
        return;
    };
    let n = code.width();
    let colors = code.to_colors();
    let cell = size / n as f32;
    for (i, color) in colors.iter().enumerate() {
        if *color == qrcode::Color::Dark {
            let (cx, cy) = ((i % n) as f32, (i / n) as f32);
            // A hair of overlap avoids seams between cells at fractional scales
            c.fill_rect(x + cx * cell, y + cy * cell, cell + 0.35, cell + 0.35, Color::BLACK);
        }
    }
}

/// The same wording as the web admin page
fn notice_text(n: &ServerNotice) -> String {
    match n {
        ServerNotice::Cgnat { router_ip } => format!(
            "공유기의 외부 주소({router_ip})가 사설 주소입니다. 통신사나 다른 공유기가 공인 주소를 나눠 쓰는 환경(CGNAT)이라,              다른 네트워크의 기기는 보조 노드 없이 이 서버에 접속할 수 없습니다. 같은 네트워크의 기기는 참여할 수 있습니다."
        ),
        ServerNotice::ForwardPorts { tcp, udp } => format!(
            "공유기가 포트를 자동으로 열지 않았습니다. 다른 네트워크의 기기가 접속하려면 공유기에서 TCP {tcp}와 UDP {udp}를              이 컴퓨터로 포트포워딩하거나 도메인을 지정하세요."
        ),
    }
}

fn last_seen(at: Option<i64>) -> String {
    let Some(at) = at else { return "접속 기록 없음".into() };
    let m = (unix_now() - at).max(0) / 60;
    match m {
        0 => "방금 접속".into(),
        1..60 => format!("{m}분 전 접속"),
        60..1440 => format!("{}시간 전 접속", m / 60),
        _ => format!("{}일 전 접속", m / 1440),
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}
