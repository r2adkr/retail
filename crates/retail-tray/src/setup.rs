//! The installer's window, drawn like the rest of the app (tiny-skia, no
//! native widgets). Steps: welcome, then a network to join (an invite code,
//! or skip and join later from the tray), installing, and done, which shows
//! where retail's icon sits on this system. Only drawing and clicks live
//! here; `install` does the work.

use std::time::Instant;

use tiny_skia::{Color, PathBuilder, Pixmap, Rect};

use crate::draw::{Canvas, Theme, contains, shade, with_alpha};
use crate::i18n::{tr, trf};
use crate::input::TextInput;
use crate::text::{Fonts, Weight};

pub const WIDTH: f32 = 480.0;
pub const HEIGHT: f32 = 540.0;
const PAD: f32 = 32.0;
const BUTTON_H: f32 = 36.0;
const FIELD_H: f32 = 40.0;

/// What running this installer does
#[derive(Clone, Debug, PartialEq)]
pub enum Kind {
    /// The official installer on a computer without retail
    Install,
    /// The official installer over an installed retail
    Update,
    /// A server's installer, which joins its network
    Join { network: String },
    /// A server's installer on a computer in another network
    Switch { current: String, network: String },
}

#[derive(Clone, Debug, PartialEq)]
pub enum Step {
    Welcome,
    /// An invite code, or skip
    Network,
    Working,
    Done,
    Failed(String),
}

#[derive(Clone, Debug, PartialEq)]
pub enum SetupAction {
    /// Welcome's main button
    Next,
    Cancel,
    Focus,
    Join,
    Skip,
    Retry,
    Close,
    /// The window's own buttons, drawn in place of the system's frame
    Minimize,
    Quit,
}

/// The top strip a window without the system's frame is moved by
pub const DRAG_H: f32 = 52.0;

/// Which system's tray to picture on the last step
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Os {
    Windows,
    Macos,
    Linux,
}

impl Os {
    pub fn this() -> Os {
        if cfg!(windows) {
            Os::Windows
        } else if cfg!(target_os = "macos") {
            Os::Macos
        } else {
            Os::Linux
        }
    }
}

pub struct Setup {
    pub dark: bool,
    pub kind: Kind,
    pub step: Step,
    pub os: Os,
    pub version: String,
    /// Where the programs go, shown on the welcome step
    pub dir: String,
    /// The computer is in a network already: no network step
    pub joined: bool,
    pub input: TextInput,
    pub focus: bool,
    /// Under the invite field
    pub error: Option<String>,
    /// The network joined, for the last step
    pub network: Option<String>,
    pub cursor: Option<(f32, f32)>,
    started: Instant,
    regions: Vec<(Rect, SetupAction)>,
}

impl Setup {
    pub fn new(kind: Kind, version: &str, dir: &str, joined: bool) -> Self {
        Setup {
            dark: false,
            kind,
            step: Step::Welcome,
            os: Os::this(),
            version: version.to_string(),
            dir: dir.to_string(),
            joined,
            input: TextInput::new("Invite code (retail1…)", false),
            focus: false,
            error: None,
            network: None,
            cursor: None,
            started: Instant::now(),
            regions: Vec::new(),
        }
    }

    /// The step after welcome: the invite code unless one comes with the
    /// package or the computer is in a network
    pub fn after_welcome(&self) -> Step {
        match self.kind {
            Kind::Install | Kind::Update if !self.joined => Step::Network,
            _ => Step::Working,
        }
    }

    /// Animates while installing
    pub fn animating(&self) -> bool {
        self.step == Step::Working
    }

    pub fn action_at(&self, x: f32, y: f32) -> Option<SetupAction> {
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
        c.fill_rect(0.0, 0.0, WIDTH, HEIGHT, t.bg);
        if self.chrome() {
            // A hairline edge, as the tray app's popup has
            c.stroke_rrect(0.5, 0.5, WIDTH - 1.0, HEIGHT - 1.0, 8.0, t.border);
            self.window_buttons(&mut c, &t);
        }
        self.stepper(&mut c, &t);
        logo(&mut c, PAD, 64.0, 52.0, true);
        match self.step.clone() {
            Step::Welcome => self.welcome(&mut c, &t),
            Step::Network => self.network(&mut c, &t),
            Step::Working => self.working(&mut c, &t),
            Step::Done => self.done(&mut c, &t),
            Step::Failed(e) => self.failed(&mut c, &t, &e),
        }
    }

    /// Windows and Linux get no system frame, so the window draws its own
    /// buttons; macOS keeps its own over a see-through title bar
    pub fn chrome(&self) -> bool {
        self.os != Os::Macos
    }

    /// Minimize and close, top right
    fn window_buttons(&mut self, c: &mut Canvas, t: &Theme) {
        let size = 32.0;
        let y = 10.0;
        let close_x = WIDTH - 10.0 - size;
        let min_x = close_x - size - 2.0;
        let working = self.step == Step::Working;
        for (x, action) in [(min_x, SetupAction::Minimize), (close_x, SetupAction::Quit)] {
            let r = Rect::from_xywh(x, y, size, size).unwrap();
            // Closing waits until installing ends
            let enabled = !(working && action == SetupAction::Quit);
            let hover = enabled && self.hovered(&r);
            if hover {
                let bg = if action == SetupAction::Quit {
                    t.red
                } else {
                    t.hover
                };
                c.fill_rrect(x, y, size, size, 6.0, bg);
            }
            let fg = if !enabled {
                with_alpha(t.dim, 0.4)
            } else if hover && action == SetupAction::Quit {
                Color::WHITE
            } else {
                t.dim
            };
            let (cx, cy) = (x + size / 2.0, y + size / 2.0);
            if action == SetupAction::Quit {
                c.line((cx - 5.0, cy - 5.0), (cx + 5.0, cy + 5.0), 1.4, fg);
                c.line((cx + 5.0, cy - 5.0), (cx - 5.0, cy + 5.0), 1.4, fg);
            } else {
                c.line((cx - 5.5, cy), (cx + 5.5, cy), 1.4, fg);
            }
            if enabled {
                self.regions.push((r, action));
            }
        }
    }

    /// The steps across the top, the current one highlighted
    fn stepper(&self, c: &mut Canvas, t: &Theme) {
        let with_network = matches!(self.kind, Kind::Install | Kind::Update) && !self.joined;
        let mut names = vec![tr("Install")];
        if with_network {
            names.push(tr("Network"));
        }
        names.push(tr("Done"));
        let current = match self.step {
            Step::Welcome | Step::Working | Step::Failed(_) => 0,
            Step::Network => 1,
            Step::Done => names.len() - 1,
        };
        // Clear of the traffic-light buttons macOS draws at the top left
        let mut x = if self.os == Os::Macos { 84.0 } else { PAD };
        for (i, name) in names.iter().enumerate() {
            let on = i <= current;
            // The step that failed shows it, not progress
            let color = match (&self.step, on, i == current) {
                (Step::Failed(_), _, true) => t.red,
                (_, true, _) => t.accent,
                _ => t.gray,
            };
            c.circle(x + 4.0, 32.0, 4.0, color);
            let weight = if i == current {
                Weight::Semibold
            } else {
                Weight::Regular
            };
            let w = c.text(
                name,
                x + 14.0,
                36.5,
                12.0,
                weight,
                if i == current { t.text } else { t.dim },
                None,
            );
            x += 14.0 + w + 14.0;
            if i + 1 < names.len() {
                c.fill_rect(
                    x - 6.0,
                    31.5,
                    18.0,
                    1.0,
                    if i < current { t.accent } else { t.border },
                );
                x += 18.0;
            }
        }
    }

    fn title(&self, c: &mut Canvas, t: &Theme, title: &str, body: &str) -> f32 {
        c.text(
            title,
            PAD,
            152.0,
            22.0,
            Weight::Semibold,
            t.text,
            Some(WIDTH - 2.0 * PAD),
        );
        paragraph(
            c,
            body,
            PAD,
            180.0,
            WIDTH - 2.0 * PAD,
            13.5,
            20.0,
            Weight::Regular,
            t.dim,
        )
    }

    fn welcome(&mut self, c: &mut Canvas, t: &Theme) {
        let v = self.version.clone();
        let (title, body, go) = match &self.kind {
            Kind::Install => (
                tr("Install retail").to_string(),
                tr("retail connects your devices into one private network, wherever they are.")
                    .to_string(),
                tr("Install").to_string(),
            ),
            Kind::Update => (
                tr("Update retail").to_string(),
                trf(
                    "This updates retail on this computer to version {version}. Your network and settings stay.",
                    &[("version", &v)],
                ),
                tr("Update").to_string(),
            ),
            Kind::Join { network } => (
                trf("Join {network}", &[("network", network)]),
                trf(
                    "This installs retail and connects this computer to {network}.",
                    &[("network", network)],
                ),
                tr("Install and join").to_string(),
            ),
            Kind::Switch { current, network } => (
                tr("Switch networks").to_string(),
                trf(
                    "This computer is connected to {current}. Leave it and switch to {network}? You can switch back in retail's settings.",
                    &[("current", current), ("network", network)],
                ),
                tr("Switch").to_string(),
            ),
        };
        let y = self.title(c, t, &title, &body);
        // What gets installed
        let card_y = y + 18.0;
        let rows = [
            (
                tr("Background service"),
                tr("Keeps the connection and starts with the computer"),
            ),
            (
                tr("Tray app"),
                tr("Status, devices and settings, from an icon"),
            ),
            (tr("Command line"), tr("retail, for scripts and servers")),
        ];
        let card_h = 22.0 + rows.len() as f32 * 46.0;
        c.fill_rrect(PAD, card_y, WIDTH - 2.0 * PAD, card_h, 12.0, t.surface);
        for (i, (name, what)) in rows.iter().enumerate() {
            let ry = card_y + 16.0 + i as f32 * 46.0;
            c.circle(PAD + 22.0, ry + 15.0, 4.0, t.accent);
            c.text(
                name,
                PAD + 38.0,
                ry + 13.0,
                13.5,
                Weight::Semibold,
                t.text,
                Some(WIDTH - 2.0 * PAD - 54.0),
            );
            c.text(
                what,
                PAD + 38.0,
                ry + 31.0,
                12.0,
                Weight::Regular,
                t.dim,
                Some(WIDTH - 2.0 * PAD - 54.0),
            );
        }
        let foot = trf(
            "Version {version} · {dir}",
            &[("version", &v), ("dir", &self.dir)],
        );
        c.text(
            &foot,
            PAD,
            HEIGHT - 82.0,
            11.5,
            Weight::Regular,
            t.dim,
            Some(WIDTH - 2.0 * PAD),
        );
        let bw = 128.0;
        self.button(
            c,
            t,
            tr("Cancel"),
            WIDTH - PAD - 2.0 * bw - 10.0,
            HEIGHT - PAD - BUTTON_H,
            bw,
            Style::Secondary,
            true,
            SetupAction::Cancel,
        );
        self.button(
            c,
            t,
            &go,
            WIDTH - PAD - bw,
            HEIGHT - PAD - BUTTON_H,
            bw,
            Style::Primary,
            true,
            SetupAction::Next,
        );
    }

    fn network(&mut self, c: &mut Canvas, t: &Theme) {
        let y = self.title(
            c,
            t,
            tr("Join a network"),
            tr("Paste the invite code you got from the network's administrator. You can also skip this and join later from retail's icon."),
        );
        let fy = y + 22.0;
        self.field(c, t, PAD, fy, WIDTH - 2.0 * PAD);
        if let Some(e) = self.error.clone() {
            paragraph(
                c,
                &e,
                PAD + 2.0,
                fy + FIELD_H + 22.0,
                WIDTH - 2.0 * PAD,
                12.5,
                18.0,
                Weight::Regular,
                t.red,
            );
        } else {
            let hint = tr("Codes start with retail1. A server's installer joins on its own.");
            paragraph(
                c,
                hint,
                PAD + 2.0,
                fy + FIELD_H + 22.0,
                WIDTH - 2.0 * PAD,
                12.0,
                18.0,
                Weight::Regular,
                t.dim,
            );
        }
        let bw = 128.0;
        let has_code = !self.input.trimmed().is_empty();
        self.button(
            c,
            t,
            tr("Skip"),
            WIDTH - PAD - 2.0 * bw - 10.0,
            HEIGHT - PAD - BUTTON_H,
            bw,
            Style::Secondary,
            true,
            SetupAction::Skip,
        );
        self.button(
            c,
            t,
            tr("Join"),
            WIDTH - PAD - bw,
            HEIGHT - PAD - BUTTON_H,
            bw,
            Style::Primary,
            has_code,
            SetupAction::Join,
        );
    }

    fn working(&mut self, c: &mut Canvas, t: &Theme) {
        let title = match &self.kind {
            Kind::Update => tr("Updating retail…"),
            Kind::Switch { .. } => tr("Switching…"),
            _ => tr("Installing retail…"),
        };
        let hint = match self.os {
            Os::Windows => {
                tr("Allow retail to make changes when Windows asks, and keep this window open.")
            }
            Os::Macos => tr("Enter your password when macOS asks, and keep this window open."),
            Os::Linux => tr("Enter your password when asked, and keep this window open."),
        };
        let y = self.title(c, t, title, hint);
        spinner(
            c,
            WIDTH / 2.0,
            y + 90.0,
            18.0,
            t,
            self.started.elapsed().as_secs_f32(),
        );
        let note = if self.input.trimmed().is_empty()
            && matches!(self.kind, Kind::Install | Kind::Update)
        {
            tr("Copying the programs and starting the service")
        } else {
            tr("Copying the programs, starting the service and joining the network")
        };
        let w = c
            .measure(note, 12.5, Weight::Regular)
            .min(WIDTH - 2.0 * PAD);
        c.text(
            note,
            (WIDTH - w) / 2.0,
            y + 140.0,
            12.5,
            Weight::Regular,
            t.dim,
            Some(WIDTH - 2.0 * PAD),
        );
    }

    fn done(&mut self, c: &mut Canvas, t: &Theme) {
        let (title, body) = match (&self.kind, &self.network) {
            (Kind::Update, None) => (
                tr("retail is updated").to_string(),
                trf(
                    "This computer runs retail {version}.",
                    &[("version", &self.version)],
                ),
            ),
            (Kind::Switch { .. }, Some(n)) | (_, Some(n)) => (
                tr("You're connected").to_string(),
                trf(
                    "retail is installed and this computer joined {network}.",
                    &[("network", n)],
                ),
            ),
            (_, None) if self.joined => (
                tr("retail is installed").to_string(),
                tr("This computer stays in its network.").to_string(),
            ),
            (_, None) => (
                tr("retail is installed").to_string(),
                tr("Join a network whenever you're ready, from retail's icon.").to_string(),
            ),
        };
        let y = self.title(c, t, &title, &body);
        let card_y = y + 18.0;
        let card_h = 150.0;
        c.fill_rrect(PAD, card_y, WIDTH - 2.0 * PAD, card_h, 12.0, t.surface);
        picture(
            c,
            t,
            self.os,
            PAD + 16.0,
            card_y + 16.0,
            WIDTH - 2.0 * PAD - 32.0,
            74.0,
            self.dark,
        );
        let caption = match self.os {
            Os::Windows => tr(
                "retail lives in the corner of the taskbar, by the clock (it may be under ^). Click it to connect, see your devices or open settings.",
            ),
            Os::Macos => tr(
                "retail lives in the menu bar at the top right. Click it to connect, see your devices or open settings.",
            ),
            Os::Linux => tr(
                "retail lives in your desktop's tray or top bar. Click it to connect, see your devices or open settings.",
            ),
        };
        paragraph(
            c,
            caption,
            PAD + 16.0,
            card_y + 110.0,
            WIDTH - 2.0 * PAD - 32.0,
            12.0,
            17.0,
            Weight::Regular,
            t.dim,
        );
        let bw = 128.0;
        self.button(
            c,
            t,
            tr("Done"),
            WIDTH - PAD - bw,
            HEIGHT - PAD - BUTTON_H,
            bw,
            Style::Primary,
            true,
            SetupAction::Close,
        );
    }

    fn failed(&mut self, c: &mut Canvas, t: &Theme, error: &str) {
        let y = self.title(
            c,
            t,
            tr("The installation didn't finish"),
            tr("This is what went wrong. You can try again."),
        );
        let card_y = y + 18.0;
        c.fill_rrect(
            PAD,
            card_y,
            WIDTH - 2.0 * PAD,
            120.0,
            12.0,
            with_alpha(t.red, 0.10),
        );
        paragraph(
            c,
            error,
            PAD + 16.0,
            card_y + 26.0,
            WIDTH - 2.0 * PAD - 32.0,
            12.5,
            18.0,
            Weight::Regular,
            t.red,
        );
        let bw = 128.0;
        self.button(
            c,
            t,
            tr("Close"),
            WIDTH - PAD - 2.0 * bw - 10.0,
            HEIGHT - PAD - BUTTON_H,
            bw,
            Style::Secondary,
            true,
            SetupAction::Close,
        );
        self.button(
            c,
            t,
            tr("Try again"),
            WIDTH - PAD - bw,
            HEIGHT - PAD - BUTTON_H,
            bw,
            Style::Primary,
            true,
            SetupAction::Retry,
        );
    }

    fn field(&mut self, c: &mut Canvas, t: &Theme, x: f32, y: f32, w: f32) {
        let r = Rect::from_xywh(x, y, w, FIELD_H).unwrap();
        c.fill_rrect(x, y, w, FIELD_H, 8.0, t.bg);
        if self.focus {
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
        self.regions.push((r, SetupAction::Focus));
        let (shown, caret) = self.input.display();
        let (px, tx, avail) = (13.5, x + 12.0, w - 24.0);
        let baseline = y + FIELD_H / 2.0 + 5.0;
        if shown.is_empty() {
            c.text(
                tr(self.input.placeholder),
                tx,
                baseline,
                px,
                Weight::Regular,
                with_alpha(t.dim, 0.7),
                Some(avail),
            );
            if self.focus {
                c.fill_rect(tx, y + 10.0, 1.5, FIELD_H - 20.0, t.text);
            }
            return;
        }
        // Long codes slide left to keep the caret in view
        let before: String = shown.chars().take(caret).collect();
        let shift = (c.measure(&before, px, Weight::Regular) - avail + 2.0).max(0.0);
        if self.input.is_all_selected() {
            let sw = c.measure(&shown, px, Weight::Regular).min(avail);
            c.fill_rrect(
                tx - 2.0,
                y + 9.0,
                sw + 4.0,
                FIELD_H - 18.0,
                3.0,
                with_alpha(t.accent, 0.28),
            );
        }
        let (mut dropped, mut skipped) = (0, 0.0);
        for ch in shown.chars() {
            if skipped >= shift {
                break;
            }
            skipped += c.measure(ch.encode_utf8(&mut [0; 4]), px, Weight::Regular);
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
        if self.focus {
            let upto: String = visible
                .chars()
                .take(caret.saturating_sub(dropped))
                .collect();
            let cx = tx + c.measure(&upto, px, Weight::Regular);
            c.fill_rect(cx, y + 10.0, 1.5, FIELD_H - 20.0, t.text);
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
        action: SetupAction,
    ) {
        let r = Rect::from_xywh(x, y, w, BUTTON_H).unwrap();
        let hover = enabled && self.hovered(&r);
        let (bg, fg, border) = match style {
            Style::Primary => (t.accent, Color::WHITE, None),
            Style::Secondary => (t.bg, t.text, Some(t.border)),
        };
        let bg = if hover {
            shade(
                bg,
                if self.dark || style == Style::Primary {
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
        let lw = c.measure(label, 13.0, Weight::Semibold).min(w - 16.0);
        c.text(
            label,
            x + (w - lw) / 2.0,
            y + BUTTON_H / 2.0 + 4.5,
            13.0,
            Weight::Semibold,
            fg,
            Some(w - 16.0),
        );
        if enabled {
            self.regions.push((r, action));
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Style {
    Primary,
    Secondary,
}

/// Text wrapped to `w`, at spaces where it has them (otherwise anywhere, as
/// in Chinese and Japanese). Returns the baseline after the last line.
#[allow(clippy::too_many_arguments)]
fn paragraph(
    c: &mut Canvas,
    text: &str,
    x: f32,
    y: f32,
    w: f32,
    px: f32,
    line: f32,
    weight: Weight,
    color: Color,
) -> f32 {
    let mut y = y;
    for l in wrap(c, text, px, w, weight) {
        c.text(&l, x, y, px, weight, color, None);
        y += line;
    }
    y
}

fn wrap(c: &Canvas, text: &str, px: f32, w: f32, weight: Weight) -> Vec<String> {
    let mut lines = Vec::new();
    let mut cur = String::new();
    for ch in text.chars() {
        cur.push(ch);
        if c.measure(&cur, px, weight) <= w {
            continue;
        }
        // Too long: break at the last space, or before this character
        let cut = cur.rfind(' ').filter(|&i| i > 0);
        let rest = match cut {
            Some(i) => {
                let rest = cur[i + 1..].to_string();
                cur.truncate(i);
                rest
            }
            None => {
                cur.pop();
                ch.to_string()
            }
        };
        lines.push(std::mem::take(&mut cur));
        cur = rest;
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    lines
}

/// The app icon: three linked nodes, on a blue tile or bare
pub fn logo(c: &mut Canvas, x: f32, y: f32, size: f32, tile: bool) {
    let s = size / 32.0;
    let glyph = if tile {
        c.fill_rrect(
            x + 2.0 * s,
            y + 2.0 * s,
            28.0 * s,
            28.0 * s,
            8.0 * s,
            crate::draw::rgb(0x2563eb),
        );
        Color::WHITE
    } else {
        crate::draw::rgb(0x2563eb)
    };
    let nodes = [(10.0, 11.0), (22.0, 11.0), (16.0, 22.0)].map(|(nx, ny)| (x + nx * s, y + ny * s));
    for i in 0..3 {
        c.line(nodes[i], nodes[(i + 1) % 3], 2.2 * s, glyph);
    }
    for (nx, ny) in nodes {
        c.circle(nx, ny, 3.6 * s, glyph);
    }
}

/// A turning arc
fn spinner(c: &mut Canvas, cx: f32, cy: f32, r: f32, t: &Theme, secs: f32) {
    c.circle(cx, cy, r, with_alpha(t.accent, 0.15));
    c.circle(cx, cy, r - 3.5, t.bg);
    let start = secs * std::f32::consts::TAU * 0.8;
    let steps = 24;
    for i in 0..steps {
        let a0 = start + i as f32 / steps as f32 * std::f32::consts::PI * 1.2;
        let a1 = start + (i + 1) as f32 / steps as f32 * std::f32::consts::PI * 1.2;
        let rr = r - 1.75;
        c.line(
            (cx + rr * a0.cos(), cy + rr * a0.sin()),
            (cx + rr * a1.cos(), cy + rr * a1.sin()),
            3.5,
            t.accent,
        );
    }
}

/// Where the icon sits: a taskbar corner (Windows) or the right end of the
/// menu bar (macOS) or top bar (Linux), with retail's icon ringed
#[allow(clippy::too_many_arguments)]
fn picture(c: &mut Canvas, t: &Theme, os: Os, x: f32, y: f32, w: f32, h: f32, dark: bool) {
    let desk = if dark {
        crate::draw::rgb(0x2b3a55)
    } else {
        crate::draw::rgb(0xdbe6fb)
    };
    c.fill_rrect(x, y, w, h, 8.0, desk);
    let bar_h = 26.0;
    let bar = if dark {
        crate::draw::rgb(0x18181b)
    } else {
        crate::draw::rgb(0xf7f7f9)
    };
    let fg = if dark {
        crate::draw::rgb(0xd4d4d8)
    } else {
        crate::draw::rgb(0x3f3f46)
    };
    let (bar_y, top) = match os {
        Os::Windows => (y + h - bar_h, false),
        Os::Macos | Os::Linux => (y, true),
    };
    // The bar, with the desktop's rounded corners kept
    let mut pb = PathBuilder::new();
    let r = 8.0;
    if top {
        pb.move_to(x, bar_y + bar_h);
        pb.line_to(x, bar_y + r);
        pb.quad_to(x, bar_y, x + r, bar_y);
        pb.line_to(x + w - r, bar_y);
        pb.quad_to(x + w, bar_y, x + w, bar_y + r);
        pb.line_to(x + w, bar_y + bar_h);
    } else {
        pb.move_to(x, bar_y);
        pb.line_to(x + w, bar_y);
        pb.line_to(x + w, bar_y + bar_h - r);
        pb.quad_to(x + w, bar_y + bar_h, x + w - r, bar_y + bar_h);
        pb.line_to(x + r, bar_y + bar_h);
        pb.quad_to(x, bar_y + bar_h, x, bar_y + bar_h - r);
    }
    pb.close();
    c.fill_path(pb, bar);
    let mid = bar_y + bar_h / 2.0;
    // Left end: the start button and a few apps, or the menu titles
    match os {
        Os::Windows => {
            let sx = x + w / 2.0 - 54.0;
            for i in 0..5 {
                let color = if i == 0 {
                    crate::draw::rgb(0x2563eb)
                } else {
                    with_alpha(fg, 0.45)
                };
                c.fill_rrect(sx + i as f32 * 22.0, mid - 7.0, 14.0, 14.0, 3.0, color);
            }
        }
        Os::Macos => {
            c.circle(x + 16.0, mid, 5.0, fg);
            for (i, wdt) in [30.0, 24.0, 28.0].iter().enumerate() {
                c.fill_rrect(
                    x + 30.0 + i as f32 * 38.0,
                    mid - 3.0,
                    *wdt,
                    6.0,
                    3.0,
                    with_alpha(fg, 0.35),
                );
            }
        }
        Os::Linux => {
            c.fill_rrect(x + 12.0, mid - 3.0, 46.0, 6.0, 3.0, with_alpha(fg, 0.35));
            c.fill_rrect(
                x + w / 2.0 - 22.0,
                mid - 3.0,
                44.0,
                6.0,
                3.0,
                with_alpha(fg, 0.5),
            );
        }
    }
    // Right end: other icons, retail's, the clock
    let clock = "12:30";
    let cw = c.measure(clock, 11.0, Weight::Semibold);
    c.text(
        clock,
        x + w - 12.0 - cw,
        mid + 4.0,
        11.0,
        Weight::Semibold,
        fg,
        None,
    );
    let icon_x = x + w - 12.0 - cw - 30.0;
    for i in 1..3 {
        c.circle(
            icon_x - i as f32 * 22.0 + 8.0,
            mid,
            4.5,
            with_alpha(fg, 0.45),
        );
    }
    if os == Os::Windows {
        // The ^ that hides more icons
        let cx = icon_x - 66.0 + 8.0;
        c.line((cx - 4.0, mid + 2.0), (cx, mid - 2.0), 1.5, fg);
        c.line((cx, mid - 2.0), (cx + 4.0, mid + 2.0), 1.5, fg);
    }
    c.circle(icon_x + 8.0, mid, 13.0, with_alpha(t.accent, 0.22));
    c.stroke_rrect_w(icon_x - 5.0, mid - 13.0, 26.0, 26.0, 13.0, 1.5, t.accent);
    logo(c, icon_x, mid - 8.0, 16.0, true);
    // A pointer to it from the open desktop
    let (tip_y, from_y) = if top {
        (bar_y + bar_h + 6.0, bar_y + bar_h + 26.0)
    } else {
        (bar_y - 6.0, bar_y - 26.0)
    };
    c.line((icon_x + 8.0, from_y), (icon_x + 8.0, tip_y), 2.0, t.accent);
    let d = if top { -5.0 } else { 5.0 };
    c.line(
        (icon_x + 3.0, tip_y - d),
        (icon_x + 8.0, tip_y),
        2.0,
        t.accent,
    );
    c.line(
        (icon_x + 13.0, tip_y - d),
        (icon_x + 8.0, tip_y),
        2.0,
        t.accent,
    );
}

/// What the window hands back when installing ends
pub enum SetupEvent {
    Finished(Result<(), String>),
}

/// The install itself, given an invite code typed in the window (or none):
/// copies, registers, joins, and sets up the tray app
pub type Work = Box<dyn Fn(Option<String>) -> Result<(), String> + Send + Sync>;

/// Runs the installer window until it closes. `None` when no window could be
/// opened (the caller falls back to dialogs).
pub fn run_window(kind: Kind, version: &str, dir: &str, joined: bool, work: Work) -> Option<i32> {
    use winit::event_loop::EventLoop;
    let fonts = Fonts::load().ok()?;
    #[allow(unused_mut)]
    let mut builder = EventLoop::<SetupEvent>::with_user_event();
    #[cfg(target_os = "macos")]
    {
        // An installer is a regular app while it runs: in the Dock, in front
        use winit::platform::macos::{ActivationPolicy, EventLoopBuilderExtMacOS};
        builder.with_activation_policy(ActivationPolicy::Regular);
    }
    let event_loop = builder.build().ok()?;
    let mut app = window::SetupApp {
        proxy: event_loop.create_proxy(),
        setup: Setup::new(kind, version, dir, joined),
        fonts,
        canvas: None,
        work: std::sync::Arc::from(work),
        invite: None,
        mods: Default::default(),
        code: None,
        failed_to_open: false,
    };
    event_loop.run_app(&mut app).ok()?;
    if app.failed_to_open {
        return None;
    }
    Some(app.code.unwrap_or(1))
}

mod window {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use winit::application::ApplicationHandler;
    use winit::dpi::{LogicalPosition, LogicalSize};
    use winit::event::{ElementState, MouseButton, WindowEvent};
    use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoopProxy};
    use winit::keyboard::{Key, ModifiersState, NamedKey};
    use winit::window::{Theme, Window, WindowId};

    use super::{HEIGHT, Kind, Setup, SetupAction, SetupEvent, Step, WIDTH};
    use crate::i18n::tr;
    use crate::text::Fonts;

    pub struct SetupApp {
        pub proxy: EventLoopProxy<SetupEvent>,
        pub setup: Setup,
        pub fonts: Fonts,
        pub canvas: Option<crate::Canvas>,
        pub work: Arc<dyn Fn(Option<String>) -> Result<(), String> + Send + Sync>,
        /// The code being installed with, for a retry
        pub invite: Option<String>,
        pub mods: ModifiersState,
        pub code: Option<i32>,
        pub failed_to_open: bool,
    }

    impl SetupApp {
        fn redraw(&mut self) {
            let (setup, fonts) = (&mut self.setup, &self.fonts);
            if let Some(c) = &mut self.canvas {
                c.present(WIDTH, HEIGHT, |pix, scale| setup.render(fonts, pix, scale));
            }
        }

        /// Installs on another thread; the window keeps drawing meanwhile
        fn start(&mut self, invite: Option<String>) {
            self.setup.step = Step::Working;
            self.invite = invite.clone();
            let (work, proxy) = (self.work.clone(), self.proxy.clone());
            std::thread::spawn(move || {
                let r = work(invite);
                let _ = proxy.send_event(SetupEvent::Finished(r));
            });
        }

        fn act(&mut self, el: &ActiveEventLoop, action: SetupAction) {
            match action {
                SetupAction::Next => match self.setup.after_welcome() {
                    Step::Network => {
                        self.setup.step = Step::Network;
                        self.setup.focus = true;
                    }
                    _ => self.start(None),
                },
                SetupAction::Cancel => self.close(el, 1),
                SetupAction::Close => {
                    let ok = self.setup.step == Step::Done;
                    self.close(el, if ok { 0 } else { 3 });
                }
                SetupAction::Focus => self.setup.focus = true,
                SetupAction::Skip => {
                    self.setup.error = None;
                    self.setup.input.clear();
                    self.start(None);
                }
                SetupAction::Join => self.join(),
                SetupAction::Retry => self.start(self.invite.clone()),
                SetupAction::Minimize => {
                    if let Some(c) = &self.canvas {
                        c.window.set_minimized(true);
                    }
                }
                SetupAction::Quit => self.quit(el),
            }
        }

        /// A typed code is checked here first, so a mistake is fixed in place
        fn join(&mut self) {
            let code = self.setup.input.trimmed().to_string();
            if code.is_empty() {
                return;
            }
            match retail_proto::invite::Invite::decode(&code) {
                Ok(invite) => {
                    self.setup.error = None;
                    self.setup.network = invite
                        .addrs
                        .first()
                        .map(|a| crate::settings::server_label(&format!("https://{a}")));
                    self.start(Some(code));
                }
                Err(_) => {
                    self.setup.error = Some(tr("This is not a retail invite code. Paste a code that starts with retail1.").to_string());
                }
            }
        }

        /// The window's close button: not while installing, as the raised
        /// step would go on unseen
        fn quit(&mut self, el: &ActiveEventLoop) {
            if self.setup.step != Step::Working {
                let ok = self.setup.step == Step::Done;
                self.close(el, if ok { 0 } else { 1 });
            }
        }

        fn close(&mut self, el: &ActiveEventLoop, code: i32) {
            self.code = Some(code);
            el.exit();
        }
    }

    impl ApplicationHandler<SetupEvent> for SetupApp {
        fn resumed(&mut self, el: &ActiveEventLoop) {
            if self.canvas.is_some() {
                return;
            }
            // No system frame over the drawn window: Windows and Linux get
            // none at all (the window draws its own buttons), macOS a
            // see-through title bar under its own buttons
            let mut attrs = Window::default_attributes()
                .with_title("retail")
                .with_resizable(false)
                .with_decorations(!self.setup.chrome())
                .with_inner_size(LogicalSize::new(WIDTH as f64, HEIGHT as f64));
            #[cfg(target_os = "macos")]
            {
                use winit::platform::macos::WindowAttributesExtMacOS;
                attrs = attrs
                    .with_titlebar_transparent(true)
                    .with_title_hidden(true)
                    .with_fullsize_content_view(true);
            }
            if let Some(m) = el.primary_monitor() {
                let ms = m.size().to_logical::<f64>(m.scale_factor());
                let mp = m.position().to_logical::<f64>(m.scale_factor());
                attrs = attrs.with_position(LogicalPosition::new(
                    mp.x + (ms.width - WIDTH as f64) / 2.0,
                    mp.y + ((ms.height - HEIGHT as f64) / 2.5).max(0.0),
                ));
            }
            match crate::Canvas::new(el, attrs) {
                Ok(c) => {
                    #[cfg(windows)]
                    crate::round_corners(&c.window);
                    self.setup.dark = c.window.theme().is_some_and(|t| t == Theme::Dark);
                    c.window.focus_window();
                    c.window.request_redraw();
                    self.canvas = Some(c);
                }
                Err(_) => {
                    self.failed_to_open = true;
                    el.exit();
                }
            }
        }

        fn user_event(&mut self, _el: &ActiveEventLoop, event: SetupEvent) {
            let SetupEvent::Finished(r) = event;
            match r {
                Ok(()) => {
                    if let Kind::Join { network } | Kind::Switch { network, .. } = &self.setup.kind
                    {
                        self.setup.network = Some(network.clone());
                    }
                    if self.invite.is_none()
                        && matches!(self.setup.kind, Kind::Install | Kind::Update)
                    {
                        self.setup.network = None;
                    }
                    self.setup.step = Step::Done;
                }
                Err(e) => self.setup.step = Step::Failed(e),
            }
            self.redraw();
        }

        fn window_event(&mut self, el: &ActiveEventLoop, _id: WindowId, event: WindowEvent) {
            let scale = self.canvas.as_ref().map_or(1.0, |c| c.scale());
            match event {
                WindowEvent::RedrawRequested => self.redraw(),
                // Not while installing: the raised step would go on unseen
                WindowEvent::CloseRequested => self.quit(el),
                WindowEvent::ModifiersChanged(m) => self.mods = m.state(),
                WindowEvent::ThemeChanged(t) => {
                    self.setup.dark = t == Theme::Dark;
                    self.redraw();
                }
                WindowEvent::CursorMoved { position, .. } => {
                    self.setup.cursor =
                        Some(((position.x / scale) as f32, (position.y / scale) as f32));
                    self.redraw();
                }
                WindowEvent::CursorLeft { .. } => {
                    self.setup.cursor = None;
                    self.redraw();
                }
                WindowEvent::MouseInput {
                    state: ElementState::Pressed,
                    button: MouseButton::Left,
                    ..
                } => {
                    let action = self
                        .setup
                        .cursor
                        .and_then(|(x, y)| self.setup.action_at(x, y));
                    // The top strip moves a window without a frame
                    if action.is_none()
                        && self.setup.chrome()
                        && self.setup.cursor.is_some_and(|(_, y)| y < super::DRAG_H)
                        && let Some(c) = &self.canvas
                    {
                        let _ = c.window.drag_window();
                        return;
                    }
                    match action {
                        Some(SetupAction::Minimize) => self.act(el, SetupAction::Minimize),
                        _ if self.setup.step == Step::Working => return,
                        Some(a) => self.act(el, a),
                        None => self.setup.focus = false,
                    }
                    self.redraw();
                }
                WindowEvent::KeyboardInput { event, .. }
                    if event.state == ElementState::Pressed =>
                {
                    if event.logical_key == Key::Named(NamedKey::Escape)
                        && self.setup.step != Step::Network
                    {
                        self.quit(el);
                        return;
                    }
                    if self.setup.step != Step::Network {
                        if event.logical_key == Key::Named(NamedKey::Enter)
                            && self.setup.step == Step::Welcome
                        {
                            self.act(el, SetupAction::Next);
                            self.redraw();
                        }
                        return;
                    }
                    match &event.logical_key {
                        Key::Named(NamedKey::Enter) => self.join(),
                        Key::Named(NamedKey::Escape) => self.setup.focus = false,
                        _ => {
                            self.setup.focus = true;
                            let shortcut = if cfg!(target_os = "macos") {
                                self.mods.super_key()
                            } else {
                                self.mods.control_key()
                            };
                            crate::edit_input(&mut self.setup.input, &event, shortcut);
                            self.setup.error = None;
                        }
                    }
                    self.redraw();
                }
                WindowEvent::ScaleFactorChanged { .. } | WindowEvent::Resized(_) => self.redraw(),
                _ => {}
            }
        }

        fn about_to_wait(&mut self, el: &ActiveEventLoop) {
            if self.setup.animating() {
                if let Some(c) = &self.canvas {
                    c.window.request_redraw();
                }
                el.set_control_flow(ControlFlow::WaitUntil(
                    Instant::now() + Duration::from_millis(33),
                ));
            } else {
                el.set_control_flow(ControlFlow::Wait);
            }
        }
    }
}
