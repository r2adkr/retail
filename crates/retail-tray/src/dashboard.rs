//! Hosting a network on this device. Opening the window does not start the
//! server.

use std::time::{Duration, Instant};

use retail_proto::api::{InviteResponse, RouterState, ServerNotice, ServerStatus};
use tiny_skia::{Color, Pixmap, Rect};

use crate::draw::{Canvas, Theme, contains, shade, with_alpha};
use crate::i18n::{tr, trf};
use crate::text::{Fonts, Weight};

pub const WIDTH: f32 = 460.0;
const PAD: f32 = 24.0;
const BUTTON_H: f32 = 34.0;
const ROW_H: f32 = 44.0;
const QR_SIZE: f32 = 150.0;
/// Devices shown at once; more scroll
const MAX_ROWS: usize = 6;

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
    /// The first device shown, when there are more than fit
    pub node_scroll: usize,
    /// Where the device list was drawn, for the mouse wheel
    nodes_area: Option<Rect>,
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
            node_scroll: 0,
            nodes_area: None,
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
        self.nodes_area = None;
        c.fill_rect(0.0, 0.0, WIDTH, self.height.max(2000.0), t.bg);
        let mut y = 44.0;
        let status = self.status.clone();
        let running = matches!(&status, Some(Ok(s)) if s.running);
        c.text(if running { tr("My network") } else { tr("Open a network") }, PAD, y, 20.0, Weight::Semibold, t.text, None);
        y += 24.0;

        match status {
            None => {
                c.text(tr("Checking…"), PAD, y + 20.0, 13.0, Weight::Regular, t.dim, None);
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
            tr("Run the server for your own network on this device. Other devices join with an invite code or QR code; retail opens the ports on your router automatically where it can."),
            PAD,
            y + 22.0,
            w,
            13.0,
            t.dim,
        );
        if let Some(other) = &self.other_network {
            let note = trf("This device is connected to {other}. Opening a server moves it to the new network; {other} stays in the server list in Settings.", &[("other", other)]);
            y = paragraph(c, &note, PAD, y + 26.0, w, 12.5, t.amber);
        }
        if let Some(e) = &s.last_error {
            y = paragraph(c, e, PAD, y + 14.0, w, 12.5, t.red);
        }
        let busy = self.is_busy();
        let label = if busy { tr("Opening…") } else { tr("Open server") };
        self.button(c, t, label, PAD, y + 18.0, 150.0, Style::Primary, !busy, DashAction::Start);
        y + 18.0 + BUTTON_H
    }

    fn running(&mut self, c: &mut Canvas, t: &Theme, s: &ServerStatus, y: f32) -> f32 {
        let w = WIDTH - 2.0 * PAD;
        let (x, ix) = (PAD, PAD + 16.0);
        let mut rows: Vec<(&str, String, Color)> = Vec::new();
        rows.push((
            tr("Address"),
            s.public.clone().unwrap_or_else(|| tr("Not reachable from other networks").into()),
            if s.public.is_some() { t.text } else { t.amber },
        ));
        if let Some(lan) = s.lan.first() {
            rows.push((tr("This network"), lan.clone(), t.text));
        }
        match &s.router {
            Some(RouterState::Opened { method, tcp, udp }) => {
                rows.push((
                    tr("Router ports"),
                    trf("Opened with {method} (TCP {tcp}, UDP {udp})", &[("method", method), ("tcp", tcp), ("udp", udp)]),
                    t.text,
                ));
            }
            Some(RouterState::Unavailable) => rows.push((tr("Router ports"), tr("Could not open automatically").into(), t.amber)),
            None => {}
        }
        if let Some(site) = &s.reality {
            rows.push(("REALITY", trf("On · looks like {site}", &[("site", site)]), t.text));
        }
        if let Some(helper) = &s.helper {
            let (state, color) = if s.helper_linked { (tr("Connected"), t.text) } else { (tr("Not connected"), t.amber) };
            rows.push((tr("Helper node"), format!("{helper} · {state}"), color));
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
        c.text(tr("Invite devices"), x + 4.0, y, 10.5, Weight::Semibold, t.dim, None);
        y += 12.0;
        match self.invite.clone() {
            None => {
                let busy = self.is_busy();
                self.button(c, t, tr("Create invite"), x, y, 140.0, Style::Primary, !busy, DashAction::Invite);
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
                c.text(tr("Scan it or copy the code"), tx, y + 30.0, 13.0, Weight::Semibold, t.text, Some(tw));
                let ty = paragraph(c, tr("Paste it into retail settings on the other device to join."), tx, y + 50.0, tw, 12.0, t.dim);
                let hours = ((inv.expires_at - unix_now()).max(0) + 1800) / 3600;
                let expiry = trf("One-time · expires in {hours} h", &[("hours", &hours)]);
                c.text(&expiry, tx, ty + 24.0, 11.5, Weight::Regular, t.dim, Some(tw));
                self.button(c, t, tr("Copy code"), tx, y + QR_SIZE - 28.0, 104.0, Style::Secondary, true, DashAction::CopyInvite);
                y += QR_SIZE + 24.0;
                self.button(c, t, tr("New invite"), x, y + 12.0, 116.0, Style::Secondary, !self.is_busy(), DashAction::Invite);
                y += 12.0 + BUTTON_H;
            }
        }

        y += 34.0;
        let online = s.nodes.iter().filter(|n| n.online).count();
        c.text(tr("Devices"), x + 4.0, y, 10.5, Weight::Semibold, t.dim, None);
        let count = trf("{online} of {total} connected", &[("online", &online), ("total", &s.nodes.len())]);
        let cw = c.measure(&count, 11.0, Weight::Regular);
        c.text(&count, x + w - 4.0 - cw, y, 11.0, Weight::Regular, t.dim, None);
        y += 8.0;
        if s.nodes.is_empty() {
            c.text(tr("No devices yet. Create an invite to add one."), x + 4.0, y + 28.0, 12.5, Weight::Regular, t.dim, Some(w - 8.0));
            y += ROW_H;
        }
        let total = s.nodes.len();
        self.node_scroll = self.node_scroll.min(total.saturating_sub(MAX_ROWS));
        let first = self.node_scroll;
        if total > 0 {
            self.nodes_area = Rect::from_xywh(x, y, w, total.min(MAX_ROWS) as f32 * ROW_H);
        }
        if total > MAX_ROWS {
            // Scroll bar along the right edge of the list
            let track_h = MAX_ROWS as f32 * ROW_H - 8.0;
            let thumb_h = (track_h * MAX_ROWS as f32 / total as f32).max(24.0);
            let ty = y + 4.0 + (track_h - thumb_h) * first as f32 / (total - MAX_ROWS) as f32;
            c.fill_rrect(x + w + 8.0, ty, 3.0, thumb_h, 1.5, with_alpha(t.dim, 0.5));
        }
        for n in s.nodes.iter().skip(first).take(MAX_ROWS) {
            c.circle(x + 9.0, y + ROW_H / 2.0, 4.0, if n.online { t.accent } else { t.gray });
            let name = if n.exit_node { format!("{} · Exit node", n.hostname) } else { n.hostname.clone() };
            c.text(&name, x + 24.0, y + 20.0, 13.5, Weight::Regular, t.text, Some(w - 190.0));
            let seen = if n.online { tr("Connected").to_string() } else { last_seen(n.last_seen) };
            c.text(&format!("{} · {} · {seen}", n.ip, n.os), x + 24.0, y + 37.0, 11.5, Weight::Regular, t.dim, Some(w - 190.0));
            let armed = self.remove_armed(n.id);
            let label = if armed { tr("Click again to remove") } else { tr("Remove") };
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
            (tr("Click again to close the server"), Style::Danger)
        } else {
            (tr("Close server"), Style::Secondary)
        };
        let lw = c.measure(label, 13.0, Weight::Semibold) + 32.0;
        self.button(c, t, label, x, y, lw, style, !self.is_busy(), DashAction::Stop);
        let web = tr("Manage on the web");
        let ww = c.measure(web, 13.0, Weight::Semibold) + 32.0;
        self.button(c, t, web, x + lw + 8.0, y, ww, Style::Secondary, true, DashAction::OpenWeb);
        y + BUTTON_H
    }

    /// Scrolls the device list by `rows` when (x, y) is over it; true if it moved
    pub fn scroll_nodes(&mut self, x: f32, y: f32, rows: i32) -> bool {
        let total = match &self.status {
            Some(Ok(s)) => s.nodes.len(),
            _ => 0,
        };
        if !self.nodes_area.is_some_and(|r| contains(&r, x, y)) {
            return false;
        }
        let next = (self.node_scroll as i32 + rows).clamp(0, total.saturating_sub(MAX_ROWS) as i32) as usize;
        let moved = next != self.node_scroll;
        self.node_scroll = next;
        moved
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

/// Draws word-wrapped text and returns the baseline of the last line. Lines
/// break at spaces, or between any two characters where a word is too long
/// or the script has no spaces (Japanese, Chinese).
fn paragraph(c: &mut Canvas, text: &str, x: f32, y: f32, w: f32, px: f32, color: Color) -> f32 {
    let mut lines: Vec<String> = Vec::new();
    let mut line = String::new();
    for ch in text.chars() {
        line.push(ch);
        if c.measure(&line, px, Weight::Regular) <= w || line.chars().count() == 1 {
            continue;
        }
        // Back up to the last space if the line has one, else move just this character down
        let rest = match line.rfind(' ') {
            Some(i) if i > 0 && !is_wide(ch) => {
                let rest = line[i + 1..].to_string();
                line.truncate(i);
                rest
            }
            _ => {
                line.pop();
                ch.to_string()
            }
        };
        lines.push(std::mem::replace(&mut line, rest.trim_start().to_string()));
    }
    if !line.trim().is_empty() {
        lines.push(line);
    }
    let mut baseline = y;
    for (i, l) in lines.iter().enumerate() {
        if i > 0 {
            baseline += px * 1.45;
        }
        c.text(l.trim_end(), x, baseline, px, Weight::Regular, color, None);
    }
    baseline
}

/// Kana, CJK ideographs and full-width punctuation, which wrap anywhere
fn is_wide(ch: char) -> bool {
    matches!(ch as u32, 0x3000..=0x30ff | 0x3400..=0x9fff | 0xf900..=0xfaff | 0xff00..=0xffef)
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
        ServerNotice::Cgnat { router_ip } => trf(
            "The router's external address ({router_ip}) is private. Your provider or another router shares one public address (CGNAT), so devices on other networks can't reach this server without a helper node. Devices on the same network can still join.",
            &[("router_ip", router_ip)],
        ),
        ServerNotice::ForwardPorts { tcp, udp } => trf(
            "The router did not open ports automatically. For devices on other networks to connect, forward TCP {tcp} and UDP {udp} to this computer on the router, or set a domain.",
            &[("tcp", tcp), ("udp", udp)],
        ),
    }
}

fn last_seen(at: Option<i64>) -> String {
    let Some(at) = at else { return tr("Never connected").into() };
    let m = (unix_now() - at).max(0) / 60;
    match m {
        0 => tr("Seen just now").into(),
        1..60 => trf("Seen {n} min ago", &[("n", &m)]),
        60..1440 => trf("Seen {n} h ago", &[("n", &(m / 60))]),
        _ => trf("Seen {n} d ago", &[("n", &(m / 1440))]),
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}
