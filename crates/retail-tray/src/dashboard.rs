//! Hosting a network on this device. Opening the window does not start the
//! server.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use retail_proto::api::{RouterState, ServerInvite, ServerNotice, ServerStatus};
use tiny_skia::{Color, Pixmap, Rect};

use crate::draw::{Canvas, Theme, contains, shade, with_alpha};
use crate::i18n::{tr, trf};
use crate::input::TextInput;
use crate::text::{Fonts, Weight};

pub const WIDTH: f32 = 460.0;
const PAD: f32 = 24.0;
const BUTTON_H: f32 = 34.0;
const ROW_H: f32 = 44.0;
const QR_SIZE: f32 = 150.0;
/// Devices shown at once; more scroll
const MAX_ROWS: usize = 6;
/// Invites shown at once; more scroll
const MAX_INVITES: usize = 4;
const FIELD_H: f32 = 36.0;
const MENU_ITEM_H: f32 = 34.0;
/// Systems an installer can be made for: (`<os>-<arch>`, label)
pub const CLIENTS: [(&str, &str); 5] = [("windows-x86_64", "Windows"), ("linux-x86_64", "Linux"), ("linux-aarch64", "Linux ARM64"), ("macos-aarch64", "macOS (Apple silicon)"), ("macos-x86_64", "macOS (Intel)")];

#[derive(Clone, Debug, PartialEq)]
pub enum DashAction {
    Start,
    Stop,
    Remove(i64),
    OpenWeb,
    /// Opens the form for a new invite
    NewInvite,
    /// In the form: several devices (named) or one
    DraftMulti(bool),
    /// In the form: expiry in hours, `None` for never
    DraftTtl(Option<u64>),
    FocusName,
    CreateInvite,
    CancelDraft,
    /// Opens or closes the ⋯ menu of an invite
    InviteMenu(i64),
    ShowCode(i64),
    CopyCode(i64),
    NewCode(i64),
    /// First click arms, second expires
    Revoke(i64),
    /// Saves the installer of a named invite for one system
    Download(i64, &'static str),
    CopyShown,
    CloseShown,
    /// Shows the saved installer in the file manager
    Reveal,
}

/// A code on screen with its QR code
#[derive(Clone)]
pub struct Shown {
    pub title: String,
    pub code: String,
    /// One-time invites expire; named ones say so in the list
    pub expires_at: Option<i64>,
}

/// The new-invite form
pub struct Draft {
    pub multi: bool,
    pub ttl: Option<u64>,
    pub name: TextInput,
    pub focused: bool,
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
    /// The code on screen
    pub shown: Option<Shown>,
    pub draft: Option<Draft>,
    /// The invite whose ⋯ menu is open
    pub invite_menu: Option<i64>,
    pub confirm_revoke: Option<(i64, Instant)>,
    pub invite_scroll: usize,
    invites_area: Option<Rect>,
    /// About the invites (an installer saved, a code copied): (text, is_error)
    pub invite_note: Option<(String, bool)>,
    /// The installer saved last, for "Show in folder"
    pub saved: Option<PathBuf>,
    /// Title of the invite being made, and whether it is one-time
    pub creating: Option<(String, bool)>,
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
            shown: None,
            draft: None,
            invite_menu: None,
            confirm_revoke: None,
            invite_scroll: 0,
            invites_area: None,
            invite_note: None,
            saved: None,
            creating: None,
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

    pub fn revoke_armed(&self, id: i64) -> bool {
        self.confirm_revoke.is_some_and(|(i, t)| i == id && t.elapsed() < Duration::from_secs(4))
    }

    pub fn action_at(&self, x: f32, y: f32) -> Option<DashAction> {
        // Last drawn is on top (an open menu)
        self.regions.iter().rev().find(|(r, _)| contains(r, x, y)).map(|(_, a)| a.clone())
    }

    pub fn invite_name(&self, id: i64) -> Option<String> {
        let Some(Ok(s)) = &self.status else { return None };
        s.invites.iter().find(|i| i.id == id)?.name.clone()
    }

    fn invites(&self) -> Vec<ServerInvite> {
        let Some(Ok(s)) = &self.status else { return Vec::new() };
        let now = unix_now();
        // Named ones first, then one-time ones still open, newest first
        let mut list: Vec<ServerInvite> =
            s.invites.iter().filter(|i| i.name.is_some() || (i.expires_at > now && (!i.used || i.reusable))).cloned().collect();
        list.sort_by(|a, b| b.name.is_some().cmp(&a.name.is_some()).then(b.id.cmp(&a.id)));
        list
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
        self.invites_area = None;
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
        // An open invite menu may reach below the rest
        if let Some(bottom) = self.invite_popover(&mut c, &t) {
            y = y.max(bottom - 12.0);
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
        // Restoring a backup happens in the web admin page, which has a file picker
        self.button(c, t, tr("Restore from a backup…"), PAD + 158.0, y + 18.0, w - 158.0, Style::Secondary, !busy, DashAction::OpenWeb);
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
            Some(RouterState::Opened { method, tcp, udp, alt }) => {
                let tcp = tcp_ports(*tcp, *alt);
                rows.push((
                    tr("Router ports"),
                    trf("Opened with {method} (TCP {tcp}, UDP {udp})", &[("method", method), ("tcp", &tcp), ("udp", udp)]),
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
        y = self.invite_section(c, t, x, y, w);

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

    /// Invites: the form or the code on screen, then the list
    fn invite_section(&mut self, c: &mut Canvas, t: &Theme, x: f32, mut y: f32, w: f32) -> f32 {
        c.text(tr("Invites"), x + 4.0, y, 10.5, Weight::Semibold, t.dim, None);
        let busy = self.is_busy();
        if self.draft.is_none() {
            let label = format!("+  {}", tr("Create invite"));
            let bw = c.measure(&label, 13.0, Weight::Semibold) + 28.0;
            self.button(c, t, &label, x + w - bw, y - 22.0, bw, Style::Secondary, !busy, DashAction::NewInvite);
        }
        y += 26.0;

        if self.draft.is_some() {
            y = self.draft_form(c, t, x, y, w) + 16.0;
        } else if let Some(shown) = self.shown.clone() {
            c.fill_rrect(x, y, w, QR_SIZE + 24.0, 12.0, t.surface);
            // White tile because scanners want dark-on-light
            let (qx, qy) = (x + 12.0, y + 12.0);
            c.fill_rrect(qx, qy, QR_SIZE, QR_SIZE, 8.0, Color::WHITE);
            draw_qr(c, &shown.code, qx + 8.0, qy + 8.0, QR_SIZE - 16.0);
            let tx = qx + QR_SIZE + 16.0;
            let tw = x + w - tx - 12.0;
            c.text(&shown.title, tx, y + 30.0, 13.0, Weight::Semibold, t.text, Some(tw - 20.0));
            let ty = paragraph(c, tr("Paste it into retail settings on the other device to join."), tx, y + 50.0, tw, 12.0, t.dim);
            if let Some(at) = shown.expires_at {
                let hours = ((at - unix_now()).max(0) + 1800) / 3600;
                let expiry = trf("One-time · expires in {hours} h", &[("hours", &hours)]);
                c.text(&expiry, tx, ty + 24.0, 11.5, Weight::Regular, t.dim, Some(tw));
            }
            self.button(c, t, tr("Copy code"), tx, y + QR_SIZE - 28.0, 104.0, Style::Secondary, true, DashAction::CopyShown);
            // Close
            let r = Rect::from_xywh(x + w - 34.0, y + 8.0, 26.0, 26.0).unwrap();
            if self.hovered(&r) {
                c.fill_rrect(r.x(), r.y(), r.width(), r.height(), 6.0, t.hover);
            }
            let (cx, cy) = (r.x() + 13.0, r.y() + 13.0);
            c.line((cx - 5.0, cy - 5.0), (cx + 5.0, cy + 5.0), 1.6, t.dim);
            c.line((cx - 5.0, cy + 5.0), (cx + 5.0, cy - 5.0), 1.6, t.dim);
            self.regions.push((r, DashAction::CloseShown));
            y += QR_SIZE + 24.0 + 16.0;
        }

        let invites = self.invites();
        self.invite_scroll = self.invite_scroll.min(invites.len().saturating_sub(MAX_INVITES));
        let shown_rows = invites.len().clamp(1, MAX_INVITES);
        let card_h = 8.0 + shown_rows as f32 * ROW_H + 8.0;
        c.fill_rrect(x, y, w, card_h, 12.0, t.surface);
        let mut ry = y + 8.0;
        if invites.is_empty() {
            c.text(tr("No invites yet. Create one to add devices."), x + 16.0, ry + 27.0, 12.5, Weight::Regular, t.dim, Some(w - 32.0));
        } else {
            self.invites_area = Rect::from_xywh(x, y, w, card_h);
            if invites.len() > MAX_INVITES {
                let track_h = MAX_INVITES as f32 * ROW_H - 8.0;
                let thumb_h = (track_h * MAX_INVITES as f32 / invites.len() as f32).max(24.0);
                let ty = y + 12.0 + (track_h - thumb_h) * self.invite_scroll as f32 / (invites.len() - MAX_INVITES) as f32;
                c.fill_rrect(x + w - 6.0, ty, 3.0, thumb_h, 1.5, with_alpha(t.dim, 0.5));
            }
            for inv in invites.iter().skip(self.invite_scroll).take(MAX_INVITES) {
                let title = match &inv.name {
                    Some(n) => n.clone(),
                    None => format!("{} #{}", tr(if inv.reusable { "Reusable invite" } else { "One-time invite" }), inv.id),
                };
                c.text(&title, x + 16.0, ry + 19.0, 13.5, Weight::Regular, t.text, Some(w - 80.0));
                let meta = match &inv.name {
                    Some(_) => format!("{} · {} · {}", tr("Multi-device"), trf("{n} joined", &[("n", &inv.uses)]), expires(inv.expires_at)),
                    None if inv.reusable => format!("{} · {}", trf("{n} joined", &[("n", &inv.uses)]), expires(inv.expires_at)),
                    None => format!("{} · {}", tr("Not used yet"), expires(inv.expires_at)),
                };
                c.text(&meta, x + 16.0, ry + 36.0, 11.5, Weight::Regular, t.dim, Some(w - 80.0));
                let more = Rect::from_xywh(x + w - 48.0, ry + 7.0, 36.0, ROW_H - 14.0).unwrap();
                if self.invite_menu == Some(inv.id) || self.hovered(&more) {
                    c.fill_rrect(more.x(), more.y(), more.width(), more.height(), 6.0, t.hover);
                }
                for k in -1..=1 {
                    c.circle(more.x() + more.width() / 2.0 + k as f32 * 5.0, ry + ROW_H / 2.0, 1.6, t.dim);
                }
                self.regions.push((more, DashAction::InviteMenu(inv.id)));
                ry += ROW_H;
            }
        }
        y += card_h;
        if let Some((note, error)) = self.invite_note.clone() {
            let reveal = !error && self.saved.is_some();
            let nw = if reveal { w - 130.0 } else { w - 8.0 };
            let end = paragraph(c, &note, x + 4.0, y + 20.0, nw, 12.0, if error { t.red } else { t.accent });
            if reveal {
                let label = tr("Show in folder");
                let bw = c.measure(label, 13.0, Weight::Semibold) + 24.0;
                self.button(c, t, label, x + w - bw, y + 6.0, bw, Style::Secondary, true, DashAction::Reveal);
                y = (end + 8.0).max(y + 6.0 + BUTTON_H);
            } else {
                y = end + 4.0;
            }
        }
        y
    }

    /// The new-invite form
    fn draft_form(&mut self, c: &mut Canvas, t: &Theme, x: f32, y: f32, w: f32) -> f32 {
        let Some(d) = &self.draft else { return y };
        let (multi, ttl, focused) = (d.multi, d.ttl, d.focused);
        let name = d.name.value.clone();
        let (shown, caret) = d.name.display();
        let h = if multi { 16.0 + 40.0 + 12.0 + 18.0 + FIELD_H + 12.0 + 18.0 + 40.0 + 16.0 + BUTTON_H + 16.0 } else { 16.0 + 40.0 + 12.0 + 40.0 + 16.0 + BUTTON_H + 16.0 };
        c.fill_rrect(x, y, w, h, 12.0, t.surface);
        let (ix, iw) = (x + 16.0, w - 32.0);
        let mut fy = y + 16.0;
        self.segmented(c, t, ix, fy, iw, &[(multi, tr("Multi-device"), DashAction::DraftMulti(true)), (!multi, tr("One-time"), DashAction::DraftMulti(false))]);
        fy += 40.0 + 12.0;
        if multi {
            c.text(tr("Name"), ix, fy + 12.0, 12.0, Weight::Regular, t.dim, None);
            fy += 18.0;
            let r = Rect::from_xywh(ix, fy, iw, FIELD_H).unwrap();
            c.fill_rrect(ix, fy, iw, FIELD_H, 8.0, t.bg);
            if focused {
                c.stroke_rrect_w(ix + 0.75, fy + 0.75, iw - 1.5, FIELD_H - 1.5, 8.0, 1.5, t.accent);
            } else {
                c.stroke_rrect(ix + 0.5, fy + 0.5, iw - 1.0, FIELD_H - 1.0, 8.0, t.border);
            }
            let baseline = fy + FIELD_H / 2.0 + 5.0;
            if name.is_empty() {
                c.text(tr("e.g. Family"), ix + 12.0, baseline, 13.5, Weight::Regular, with_alpha(t.dim, 0.7), Some(iw - 24.0));
            } else {
                c.text(&shown, ix + 12.0, baseline, 13.5, Weight::Regular, t.text, Some(iw - 24.0));
            }
            if focused {
                let before: String = shown.chars().take(caret).collect();
                let cx = ix + 12.0 + c.measure(&before, 13.5, Weight::Regular).min(iw - 24.0);
                c.fill_rect(cx, fy + 9.0, 1.5, FIELD_H - 18.0, t.text);
            }
            self.regions.push((r, DashAction::FocusName));
            fy += FIELD_H + 12.0;
            c.text(tr("Expires"), ix, fy + 12.0, 12.0, Weight::Regular, t.dim, None);
            fy += 18.0;
            let opts = [(None, tr("No expiry")), (Some(168), tr("7 days")), (Some(720), tr("30 days"))].map(|(v, l)| (ttl == v, l, DashAction::DraftTtl(v)));
            self.segmented(c, t, ix, fy, iw, &opts);
            fy += 40.0 + 16.0;
        } else {
            c.text(tr("One device can join once within 24 hours."), ix, fy + 20.0, 12.5, Weight::Regular, t.dim, Some(iw));
            fy += 40.0 + 16.0;
        }
        let create = tr("Create");
        let cw = c.measure(create, 13.0, Weight::Semibold).max(56.0) + 40.0;
        let ready = !multi || !name.trim().is_empty();
        self.button(c, t, create, ix + iw - cw, fy, cw, Style::Primary, ready && !self.is_busy(), DashAction::CreateInvite);
        let cancel = tr("Cancel");
        let kw = c.measure(cancel, 13.0, Weight::Semibold).max(56.0) + 32.0;
        self.button(c, t, cancel, ix + iw - cw - 8.0 - kw, fy, kw, Style::Secondary, true, DashAction::CancelDraft);
        y + h
    }

    /// A row of choices: (selected, label, action) each
    fn segmented(&mut self, c: &mut Canvas, t: &Theme, x: f32, y: f32, w: f32, options: &[(bool, &str, DashAction)]) {
        c.fill_rrect(x, y, w, 40.0, 10.0, t.bg);
        let seg = (w - 8.0) / options.len() as f32;
        for (i, (selected, label, action)) in options.iter().enumerate() {
            let sx = x + 4.0 + i as f32 * seg;
            let r = Rect::from_xywh(sx, y + 4.0, seg, 32.0).unwrap();
            if *selected {
                c.fill_rrect(sx, y + 4.0, seg, 32.0, 7.0, if self.dark { t.hover } else { t.surface });
                c.stroke_rrect(sx + 0.5, y + 4.5, seg - 1.0, 31.0, 7.0, t.border);
            } else if self.hovered(&r) {
                c.fill_rrect(sx, y + 4.0, seg, 32.0, 7.0, with_alpha(t.hover, 0.6));
            }
            let weight = if *selected { Weight::Semibold } else { Weight::Regular };
            let lw = c.measure(label, 13.0, weight);
            c.text(label, sx + (seg - lw) / 2.0, y + 25.0, 13.0, weight, if *selected { t.text } else { t.dim }, None);
            self.regions.push((r, action.clone()));
        }
    }

    /// The ⋯ menu of an invite, under its button; returns its bottom edge
    fn invite_popover(&mut self, c: &mut Canvas, t: &Theme) -> Option<f32> {
        let id = self.invite_menu?;
        let area = self.invites_area?;
        let invites = self.invites();
        let row = invites.iter().skip(self.invite_scroll).take(MAX_INVITES).position(|i| i.id == id)?;
        let inv = invites.iter().find(|i| i.id == id)?.clone();
        let mut items: Vec<(String, DashAction, bool)> = Vec::new();
        if inv.name.is_some() {
            items.push((tr("Show code and QR").into(), DashAction::ShowCode(id), false));
            items.push((tr("Copy code").into(), DashAction::CopyCode(id), false));
            items.push((tr("New code").into(), DashAction::NewCode(id), false));
            for (variant, label) in CLIENTS {
                items.push((trf("Installer for {os}", &[("os", &label)]), DashAction::Download(id, variant), false));
            }
        }
        let expire = if self.revoke_armed(id) { tr("Click again to expire") } else { tr("Expire") };
        items.push((expire.into(), DashAction::Revoke(id), true));
        let w = items.iter().map(|(l, _, _)| c.measure(l, 13.0, Weight::Regular)).fold(160.0f32, f32::max) + 32.0;
        let h = items.len() as f32 * MENU_ITEM_H + 8.0;
        let x = area.x() + area.width() - 12.0 - w;
        let y = area.y() + 8.0 + (row as f32 + 1.0) * ROW_H - 6.0;
        c.fill_rrect(x - 1.0, y + 1.0, w + 2.0, h + 3.0, 11.0, with_alpha(Color::BLACK, if self.dark { 0.45 } else { 0.12 }));
        c.fill_rrect(x, y, w, h, 10.0, if self.dark { t.surface } else { t.bg });
        c.stroke_rrect(x + 0.5, y + 0.5, w - 1.0, h - 1.0, 10.0, t.border);
        // The card catches clicks between items
        self.regions.push((Rect::from_xywh(x, y, w, h).unwrap(), DashAction::InviteMenu(id)));
        for (i, (label, action, danger)) in items.into_iter().enumerate() {
            let iy = y + 4.0 + i as f32 * MENU_ITEM_H;
            let r = Rect::from_xywh(x + 4.0, iy, w - 8.0, MENU_ITEM_H).unwrap();
            if self.hovered(&r) {
                c.fill_rrect(r.x(), r.y(), r.width(), r.height(), 7.0, t.hover);
            }
            c.text(&label, x + 14.0, iy + 22.0, 13.0, Weight::Regular, if danger { t.red } else { t.text }, None);
            self.regions.push((r, action));
        }
        Some(y + h)
    }

    /// Scrolls the invite list by `rows` when (x, y) is over it; true if it moved
    pub fn scroll_invites(&mut self, x: f32, y: f32, rows: i32) -> bool {
        if !self.invites_area.is_some_and(|r| contains(&r, x, y)) {
            return false;
        }
        let total = self.invites().len();
        let next = (self.invite_scroll as i32 + rows).clamp(0, total.saturating_sub(MAX_INVITES) as i32) as usize;
        let moved = next != self.invite_scroll;
        self.invite_scroll = next;
        if moved {
            self.invite_menu = None;
        }
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
            "The router's external address ({router_ip}) is private (CGNAT), so devices on other networks can't reach this server directly. Make a device they can reach the helper node: Manage on the web, then that device's ⋯ menu. Devices on the same network can join as they are.",
            &[("router_ip", router_ip)],
        ),
        ServerNotice::ForwardPorts { tcp, udp, alt } => trf(
            "The router did not open ports automatically. For devices on other networks to connect, forward TCP {tcp} and UDP {udp} to this computer on the router, or set a domain.",
            &[("tcp", &tcp_ports(*tcp, *alt)), ("udp", udp)],
        ),
    }
}

/// `443` or `443, 24581`: the server port and the second one
fn tcp_ports(tcp: u16, alt: Option<u16>) -> String {
    match alt {
        Some(a) => format!("{tcp}, {a}"),
        None => tcp.to_string(),
    }
}

fn expires(at: i64) -> String {
    if at >= i64::MAX / 2 {
        return tr("Never expires").into();
    }
    let h = (at - unix_now()) as f64 / 3600.0;
    match h.round() as i64 {
        ..=0 => tr("Expired").into(),
        h @ 1..48 => trf("Expires in {n} h", &[("n", &h)]),
        h => trf("Expires in {n} d", &[("n", &((h + 12) / 24))]),
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
