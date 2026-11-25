//! Tray app: a status icon with a custom-drawn popup, plus settings and server
//! windows (no native widgets, no web view), all talking to retaild over the
//! local API.
//!
//! `retail-tray --preview out.png [--settings | --server] [--dark] [--lang <en|ko|ja|zh|es>] [--state <name>]`
//! renders a window to a PNG without opening it. Popup states are `connected`,
//! `stopped`, `login`, `offline`, `many`, `exit` and `exit-menu`. Settings
//! adds `change`, and the server window takes `idle` or `running`.
//! `--setup [--os windows|macos|linux]` draws the installer: `welcome`,
//! `update`, `join`, `switch`, `network`, `network-error`, `working`, `done`,
//! `done-joined` or `failed`.
//! `--show` opens the popup at startup.

#![cfg_attr(windows, windows_subsystem = "windows")]

mod api;
mod config;
mod dashboard;
mod draw;
mod i18n;
mod icon;
mod input;
mod install;
mod settings;
mod setup;
mod sysproxy;
mod text;
mod tray;
mod ui;

use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use retail_proto::api::{BackendState, StatusResponse};
use tiny_skia::Pixmap;
use winit::application::ApplicationHandler;
use winit::dpi::{LogicalPosition, LogicalSize, PhysicalPosition, PhysicalSize};
use winit::event::{ElementState, KeyEvent, MouseButton, MouseScrollDelta, WindowEvent};
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop, EventLoopProxy};
use winit::keyboard::{Key, ModifiersState, NamedKey};
use winit::window::{Theme, Window, WindowAttributes, WindowId, WindowLevel};

use crate::api::{ActionKind, ApiEvent, Command, Origin, ServerCommand};
use crate::dashboard::{DashAction, Dashboard};
use crate::config::{Config, ThemePref};
use crate::settings::{AUTH_KEY, DEVICE, SERVER, Settings, SettingsAction};
use crate::i18n::{LangPref, tr, trf};
use crate::text::Fonts;
use crate::tray::{Anchor, Tray};
use crate::ui::{Action, Ui, View};

// A few events a second at most, so their size does not matter
#[allow(clippy::large_enum_variant)]
pub enum UserEvent {
    TrayClicked(Anchor),
    /// Started again (the app menu entry): show the popup
    Show,
    Api(ApiEvent),
}

struct Canvas {
    window: Rc<Window>,
    surface: softbuffer::Surface<Rc<Window>, Rc<Window>>,
    _context: softbuffer::Context<Rc<Window>>,
    pixmap: Option<Pixmap>,
}

impl Canvas {
    fn new(el: &ActiveEventLoop, attrs: WindowAttributes) -> Result<Self, String> {
        let window = Rc::new(el.create_window(attrs).map_err(|e| e.to_string())?);
        let context = softbuffer::Context::new(window.clone()).map_err(|e| e.to_string())?;
        let surface = softbuffer::Surface::new(&context, window.clone()).map_err(|e| e.to_string())?;
        Ok(Canvas { window, surface, _context: context, pixmap: None })
    }

    fn id(&self) -> WindowId {
        self.window.id()
    }

    fn scale(&self) -> f64 {
        self.window.scale_factor()
    }

    fn present(&mut self, width: f32, height: f32, render: impl FnOnce(&mut Pixmap, f32)) {
        let want = LogicalSize::new(width as f64, height as f64).to_physical::<u32>(self.scale());
        let inner = self.window.inner_size();
        if inner != want {
            let _ = self.window.request_inner_size(want);
        }
        let (w, h) = (inner.width.max(1), inner.height.max(1));
        let (Some(nw), Some(nh)) = (NonZeroU32::new(w), NonZeroU32::new(h)) else { return };
        if self.surface.resize(nw, nh).is_err() {
            return;
        }
        let pix = match &mut self.pixmap {
            Some(pix) if pix.width() == w && pix.height() == h => pix,
            slot => slot.insert(Pixmap::new(w, h).expect("non-zero size")),
        };
        render(pix, self.window.scale_factor() as f32);
        let Ok(mut buf) = self.surface.buffer_mut() else { return };
        for (dst, src) in buf.iter_mut().zip(pix.pixels()) {
            *dst = (src.red() as u32) << 16 | (src.green() as u32) << 8 | src.blue() as u32;
        }
        let _ = buf.present();
    }
}

struct App {
    proxy: EventLoopProxy<UserEvent>,
    fonts: Fonts,
    ui: Ui,
    settings: Settings,
    config: Config,
    popup: Option<Canvas>,
    settings_win: Option<Canvas>,
    dashboard: Dashboard,
    dashboard_win: Option<Canvas>,
    tray: Option<Tray>,
    commands: mpsc::Sender<Command>,
    fast_poll: Arc<AtomicBool>,
    dashboard_poll: Arc<AtomicBool>,
    hidden_at: Option<Instant>,
    last_anchor: Anchor,
    show_on_start: bool,
    system_dark: bool,
    mods: ModifiersState,
    /// When this process started, to tell an updated program file from ours
    started: std::time::SystemTime,
    /// Shown the new-release notice this run
    notice_pending: bool,
}

impl App {
    fn popup_visible(&self) -> bool {
        self.popup.as_ref().is_some_and(|p| p.window.is_visible().unwrap_or(false))
    }

    fn update_poll_rate(&self) {
        let windows = self.popup_visible() || self.settings_win.is_some() || self.dashboard_win.is_some();
        self.fast_poll.store(windows, Ordering::Relaxed);
        self.dashboard_poll.store(self.dashboard_win.is_some(), Ordering::Relaxed);
    }

    fn dark(&self) -> bool {
        match self.config.theme {
            ThemePref::System => self.system_dark,
            ThemePref::Light => false,
            ThemePref::Dark => true,
        }
    }

    fn apply_theme(&mut self) {
        let dark = self.dark();
        self.ui.dark = dark;
        self.settings.dark = dark;
        self.dashboard.dark = dark;
        self.settings.theme = self.config.theme;
        let theme = match self.config.theme {
            ThemePref::System => None,
            ThemePref::Light => Some(Theme::Light),
            ThemePref::Dark => Some(Theme::Dark),
        };
        for w in [&self.settings_win, &self.dashboard_win].into_iter().flatten() {
            w.window.set_theme(theme);
        }
        self.redraw_all();
    }

    fn create_popup(&mut self, el: &ActiveEventLoop) -> Result<(), String> {
        let attrs = Window::default_attributes()
            .with_title("retail")
            .with_decorations(false)
            .with_resizable(false)
            .with_visible(false)
            .with_window_level(WindowLevel::AlwaysOnTop)
            .with_inner_size(LogicalSize::new(ui::WIDTH as f64, self.ui.height() as f64));
        #[cfg(windows)]
        let attrs = {
            use winit::platform::windows::WindowAttributesExtWindows;
            attrs.with_skip_taskbar(true)
        };
        let canvas = Canvas::new(el, attrs)?;
        #[cfg(windows)]
        round_corners(&canvas.window);
        self.system_dark = canvas.window.theme().is_some_and(|t| t == Theme::Dark);
        self.popup = Some(canvas);
        self.apply_theme();
        Ok(())
    }

    fn show_popup(&mut self, anchor: Anchor) {
        let Some(p) = &self.popup else { return };
        let size = LogicalSize::new(ui::WIDTH as f64, self.ui.height() as f64).to_physical(p.scale());
        let _ = p.window.request_inner_size(size);
        p.window.set_outer_position(place(&p.window, anchor, size));
        p.window.set_visible(true);
        p.window.focus_window();
        p.window.request_redraw();
        self.update_poll_rate();
        let _ = self.commands.send(Command::Refresh);
    }

    fn hide_popup(&mut self) {
        if let Some(p) = &mut self.popup {
            p.window.set_visible(false);
            // Free the framebuffer while hidden since it is cheap to recreate
            p.pixmap = None;
        }
        self.ui.cursor = None;
        self.ui.gear = false;
        self.hidden_at = Some(Instant::now());
        self.update_poll_rate();
    }

    fn redraw_popup(&mut self) {
        if !self.popup_visible() {
            return;
        }
        let (ui, fonts) = (&mut self.ui, &self.fonts);
        let h = ui.height();
        if let Some(p) = &mut self.popup {
            p.present(ui::WIDTH, h, |pix, scale| ui.render(fonts, pix, scale));
        }
    }

    fn run_action(&mut self, el: &ActiveEventLoop, action: Action) {
        match action {
            Action::Toggle => {
                let View::Status(s) = &self.ui.view else { return };
                let on = s.state == BackendState::Running;
                if on {
                    let _ = self.commands.send(Command::Down);
                } else if let Some(server) = s.server.clone() {
                    let cmd = Command::Up { server, auth_key: None, hostname: None, invite: None, origin: Origin::Popup };
                    let _ = self.commands.send(cmd);
                }
                self.ui.pending = Some((!on, Instant::now()));
            }
            Action::Copy(text) => {
                self.ui.menu = None;
                let ok = arboard::Clipboard::new().and_then(|mut c| c.set_text(text.clone())).is_ok();
                let msg = if ok { trf("Copied {text}", &[("text", &text)]) } else { tr("Can't use the clipboard").into() };
                self.ui.toast = Some((msg, Instant::now()));
            }
            Action::OpenSettings => {
                self.ui.gear = false;
                self.hide_popup();
                self.open_settings(el);
            }
            Action::OpenServer => {
                self.ui.gear = false;
                self.hide_popup();
                self.open_dashboard(el);
            }
            Action::Quit => std::process::exit(0),
            Action::Menu(key) => {
                self.ui.gear = false;
                self.ui.menu = if self.ui.menu == Some(key) { None } else { Some(key) };
            }
            Action::Gear => {
                self.ui.menu = None;
                self.ui.gear = !self.ui.gear;
            }
            Action::Dismiss => {
                self.ui.menu = None;
                self.ui.gear = false;
            }
            Action::Update => {
                let _ = self.commands.send(Command::InstallUpdate);
            }
            Action::SetExit(key) => {
                self.ui.menu = None;
                let req = retail_proto::api::PrefsRequest { exit_node: Some(key), ..Default::default() };
                let _ = self.commands.send(Command::Prefs { req, origin: Origin::Popup });
            }
        }
    }

    fn open_settings(&mut self, el: &ActiveEventLoop) {
        if let Some(s) = &self.settings_win {
            s.window.focus_window();
            return;
        }
        self.settings.prefill();
        let theme = match self.config.theme {
            ThemePref::System => None,
            ThemePref::Light => Some(Theme::Light),
            ThemePref::Dark => Some(Theme::Dark),
        };
        let mut attrs = Window::default_attributes()
            .with_title("retail Settings")
            .with_resizable(false)
            .with_theme(theme)
            .with_inner_size(LogicalSize::new(settings::WIDTH as f64, self.settings.height() as f64));
        if let Some(m) = el.primary_monitor() {
            let ms = m.size().to_logical::<f64>(m.scale_factor());
            let mp = m.position().to_logical::<f64>(m.scale_factor());
            attrs = attrs.with_position(LogicalPosition::new(
                mp.x + (ms.width - settings::WIDTH as f64) / 2.0,
                mp.y + ((ms.height - self.settings.height() as f64) / 2.5).max(0.0),
            ));
        }
        match Canvas::new(el, attrs) {
            Ok(c) => {
                c.window.focus_window();
                c.window.request_redraw();
                self.settings_win = Some(c);
            }
            Err(e) => eprintln!("retail-tray: cannot open settings: {e}"),
        }
        self.update_poll_rate();
        let _ = self.commands.send(Command::Refresh);
    }

    fn close_settings(&mut self) {
        self.settings_win = None;
        self.settings.focus = None;
        self.settings.cursor = None;
        self.settings.changing = false;
        self.settings.adding = false;
        self.settings.server_menu = None;
        self.settings.confirm_logout = None;
        self.settings.inputs[AUTH_KEY].clear();
        self.update_poll_rate();
    }

    fn redraw_settings(&mut self) {
        let (st, fonts) = (&mut self.settings, &self.fonts);
        let h = st.height();
        if let Some(w) = &mut self.settings_win {
            w.present(settings::WIDTH, h, |pix, scale| st.render(fonts, pix, scale));
        }
    }

    fn redraw_all(&mut self) {
        self.redraw_popup();
        self.redraw_settings();
        self.redraw_dashboard();
    }

    fn open_dashboard(&mut self, el: &ActiveEventLoop) {
        if let Some(d) = &self.dashboard_win {
            d.window.focus_window();
            return;
        }
        let theme = match self.config.theme {
            ThemePref::System => None,
            ThemePref::Light => Some(Theme::Light),
            ThemePref::Dark => Some(Theme::Dark),
        };
        let mut attrs = Window::default_attributes()
            .with_title("retail Server")
            .with_resizable(false)
            .with_theme(theme)
            .with_inner_size(LogicalSize::new(dashboard::WIDTH as f64, self.dashboard.height() as f64));
        if let Some(m) = el.primary_monitor() {
            let ms = m.size().to_logical::<f64>(m.scale_factor());
            let mp = m.position().to_logical::<f64>(m.scale_factor());
            attrs = attrs.with_position(LogicalPosition::new(
                mp.x + (ms.width - dashboard::WIDTH as f64) / 2.0,
                mp.y + (ms.height / 8.0),
            ));
        }
        match Canvas::new(el, attrs) {
            Ok(c) => {
                c.window.focus_window();
                c.window.request_redraw();
                self.dashboard_win = Some(c);
            }
            Err(e) => eprintln!("retail-tray: cannot open the server window: {e}"),
        }
        self.dashboard.message = None;
        self.update_poll_rate();
        let _ = self.commands.send(Command::Server(ServerCommand::Refresh));
    }

    fn close_dashboard(&mut self) {
        self.dashboard_win = None;
        self.dashboard.cursor = None;
        self.dashboard.confirm_stop = None;
        self.dashboard.confirm_remove = None;
        // Don't keep an invite (a secret) on screen after the window closes
        self.dashboard.shown = None;
        self.dashboard.draft = None;
        self.dashboard.invite_menu = None;
        self.dashboard.invite_note = None;
        self.update_poll_rate();
    }

    fn redraw_dashboard(&mut self) {
        let (d, fonts) = (&mut self.dashboard, &self.fonts);
        if let Some(w) = &mut self.dashboard_win {
            let mut changed = false;
            w.present(dashboard::WIDTH, d.height(), |pix, scale| changed = d.render(fonts, pix, scale));
            if changed {
                w.window.request_redraw();
            }
        }
    }

    fn run_dashboard_action(&mut self, action: DashAction) {
        let d = &mut self.dashboard;
        let menu = d.invite_menu.take();
        if !matches!(action, DashAction::FocusName)
            && let Some(draft) = d.draft.as_mut()
        {
            draft.focused = false;
        }
        match action {
            DashAction::Start => {
                d.busy = Some(Instant::now());
                d.message = None;
                let _ = self.commands.send(Command::Server(ServerCommand::Start));
            }
            DashAction::Stop => {
                if d.stop_armed() {
                    d.confirm_stop = None;
                    d.busy = Some(Instant::now());
                    d.shown = None;
                    let _ = self.commands.send(Command::Server(ServerCommand::Stop));
                } else {
                    d.confirm_stop = Some(Instant::now());
                }
            }
            DashAction::OpenWeb => {
                let _ = self.commands.send(Command::Server(ServerCommand::OpenWeb));
            }
            DashAction::Remove(id) => {
                if d.remove_armed(id) {
                    d.confirm_remove = None;
                    let _ = self.commands.send(Command::Server(ServerCommand::Remove(id)));
                } else {
                    d.confirm_remove = Some((id, Instant::now()));
                }
            }
            DashAction::NewInvite => {
                d.shown = None;
                d.invite_note = None;
                d.draft = Some(crate::dashboard::Draft {
                    multi: true,
                    ttl: None,
                    name: crate::input::TextInput::new("", false),
                    focused: true,
                });
            }
            DashAction::DraftMulti(multi) => {
                if let Some(draft) = d.draft.as_mut() {
                    draft.multi = multi;
                    draft.focused = multi;
                }
            }
            DashAction::DraftTtl(ttl) => {
                if let Some(draft) = d.draft.as_mut() {
                    draft.ttl = ttl;
                }
            }
            DashAction::FocusName => {
                if let Some(draft) = d.draft.as_mut() {
                    draft.focused = true;
                }
            }
            DashAction::CancelDraft => d.draft = None,
            DashAction::CreateInvite => self.create_invite(),
            DashAction::InviteMenu(id) => d.invite_menu = (menu != Some(id)).then_some(id),
            DashAction::ShowCode(id) => {
                let _ = self.commands.send(Command::Server(ServerCommand::Code { id, copy: false }));
            }
            DashAction::CopyCode(id) => {
                let _ = self.commands.send(Command::Server(ServerCommand::Code { id, copy: true }));
            }
            DashAction::NewCode(id) => {
                if let Some(name) = d.invite_name(id) {
                    d.busy = Some(Instant::now());
                    d.creating = Some((trf("Invite '{name}'", &[("name", &name)]), false));
                    d.invite_note = Some((tr("New code made. The old code and the installers that contain it no longer work.").into(), false));
                    d.saved = None;
                    let req = retail_proto::api::InviteRequest { name: Some(name), ..Default::default() };
                    let _ = self.commands.send(Command::Server(ServerCommand::CreateInvite(req)));
                }
            }
            DashAction::Revoke(id) => {
                if d.revoke_armed(id) {
                    d.confirm_revoke = None;
                    d.shown = None;
                    let _ = self.commands.send(Command::Server(ServerCommand::Revoke(id)));
                } else {
                    // Keep the menu open to show the armed item
                    d.confirm_revoke = Some((id, Instant::now()));
                    d.invite_menu = Some(id);
                }
            }
            DashAction::Download(id, variant) => {
                d.saved = None;
                d.invite_note = Some((tr("Preparing the installer… The first one for another system is fetched from GitHub and takes a while.").into(), false));
                let dir = crate::api::downloads_dir();
                let _ = self.commands.send(Command::Server(ServerCommand::Package { id, variant: variant.to_string(), dir }));
            }
            DashAction::CopyShown => {
                if let Some(shown) = &d.shown {
                    let ok = arboard::Clipboard::new().and_then(|mut c| c.set_text(shown.code.clone())).is_ok();
                    d.invite_note = Some(if ok { (tr("Invite code copied.").into(), false) } else { (tr("Can't use the clipboard").into(), true) });
                }
            }
            DashAction::CloseShown => d.shown = None,
            DashAction::Reveal => {
                if let Some(path) = &d.saved {
                    crate::api::reveal(path);
                }
            }
        }
    }

    fn create_invite(&mut self) {
        let d = &mut self.dashboard;
        let Some(draft) = &d.draft else { return };
        let name = draft.name.trimmed().to_string();
        let req = if draft.multi {
            if name.is_empty() {
                return;
            }
            let exists = matches!(&d.status, Some(Ok(s)) if s.invites.iter().any(|i| i.name.as_deref() == Some(name.as_str())));
            if exists {
                d.invite_note = Some((tr("An invite with this name exists: its code was replaced, and the old one no longer works.").into(), false));
            }
            d.creating = Some((trf("Invite '{name}'", &[("name", &name)]), false));
            retail_proto::api::InviteRequest { name: Some(name), ttl_hours: draft.ttl, ..Default::default() }
        } else {
            d.creating = Some((tr("One-time invite").into(), true));
            retail_proto::api::InviteRequest::default()
        };
        d.busy = Some(Instant::now());
        let _ = self.commands.send(Command::Server(ServerCommand::CreateInvite(req)));
    }

    fn dashboard_key(&mut self, event: &KeyEvent) {
        let shortcut = if cfg!(target_os = "macos") { self.mods.super_key() } else { self.mods.control_key() };
        let d = &mut self.dashboard;
        if event.logical_key == Key::Named(NamedKey::Escape) {
            if d.invite_menu.take().is_none() && d.draft.take().is_none() {
                d.shown = None;
            }
            return;
        }
        let Some(draft) = d.draft.as_mut().filter(|dr| dr.focused) else { return };
        if event.logical_key == Key::Named(NamedKey::Enter) {
            self.create_invite();
            return;
        }
        edit_input(&mut draft.name, event, shortcut);
    }

    /// Host of the server this device uses, unless it is the network hosted here
    fn other_network(&self) -> Option<String> {
        let View::Status(s) = &self.ui.view else { return None };
        let server = s.server.as_deref()?;
        (!server.starts_with("https://127.0.0.1:")).then(|| server.split("://").nth(1).unwrap_or(server).to_string())
    }

    fn run_settings_action(&mut self, action: SettingsAction) {
        let st = &mut self.settings;
        match action {
            SettingsAction::Focus(i) => st.focus = Some(i),
            SettingsAction::Connect => self.connect(),
            SettingsAction::StartChange => {
                st.changing = true;
                st.adding = false;
                st.message = None;
            }
            SettingsAction::Cancel => {
                // From the form back to the list, from the list back to the account
                if st.adding && (st.logged_in() || !st.servers().is_empty()) {
                    st.adding = false;
                } else {
                    st.changing = false;
                    st.adding = false;
                }
                st.message = None;
                st.focus = None;
            }
            SettingsAction::AddServer => {
                st.adding = true;
                st.message = None;
                st.inputs[SERVER].clear();
                st.inputs[AUTH_KEY].clear();
                st.prefill();
                st.focus = Some(SERVER);
            }
            SettingsAction::SwitchServer(server) => {
                if !st.is_busy() {
                    st.busy = Some(Instant::now());
                    st.message = None;
                    let _ = self.commands.send(Command::Switch(server));
                }
            }
            SettingsAction::ServerMenu(_) => {}
            SettingsAction::ForgetServer(server) => {
                st.busy = Some(Instant::now());
                st.message = None;
                let _ = self.commands.send(Command::Forget(server));
            }
            SettingsAction::Logout => {
                if st.logout_armed() {
                    st.confirm_logout = None;
                    st.busy = Some(Instant::now());
                    st.message = None;
                    let _ = self.commands.send(Command::Logout);
                } else {
                    st.confirm_logout = Some(Instant::now());
                }
            }
            SettingsAction::Theme(pref) => {
                self.config.theme = pref;
                self.config.save();
                self.apply_theme();
            }
            SettingsAction::LangMenu => {}
            SettingsAction::Lang(pref) => {
                self.config.language = pref;
                self.config.save();
                i18n::set(pref);
                self.settings.lang = pref;
                self.redraw_all();
            }
            SettingsAction::CheckUpdate => {
                st.busy = Some(Instant::now());
                st.message = None;
                let _ = self.commands.send(Command::CheckUpdate);
            }
            SettingsAction::InstallUpdate => {
                st.message = None;
                let _ = self.commands.send(Command::InstallUpdate);
            }
            SettingsAction::AutoUpdate(on) => {
                let req = retail_proto::api::PrefsRequest { auto_update: Some(on), ..Default::default() };
                let _ = self.commands.send(Command::Prefs { req, origin: Origin::Settings });
            }
            SettingsAction::AdvertiseExit(on) => {
                let req = retail_proto::api::PrefsRequest { advertise_exit_node: Some(on), ..Default::default() };
                let _ = self.commands.send(Command::Prefs { req, origin: Origin::Settings });
            }
        }
    }

    fn connect(&mut self) {
        let st = &mut self.settings;
        if st.is_busy() {
            return;
        }
        let server = st.inputs[SERVER].trimmed().trim_end_matches('/').to_string();
        let auth_key = st.inputs[AUTH_KEY].trimmed().to_string();
        let hostname = st.inputs[DEVICE].trimmed().to_string();
        let hostname = (!hostname.is_empty()).then_some(hostname);
        if server.starts_with("retail1.") {
            st.busy = Some(Instant::now());
            st.message = None;
            st.focus = None;
            let invite = Some(server);
            let cmd = Command::Up { server: String::new(), auth_key: None, hostname, invite, origin: Origin::Settings };
            let _ = self.commands.send(cmd);
            return;
        }
        if !(server.starts_with("https://") || server.starts_with("http://")) {
            st.message = Some((tr("Paste an invite code (retail1.…) or a server address starting with https://").into(), true));
            st.focus = Some(SERVER);
            return;
        }
        if auth_key.is_empty() {
            st.message = Some((tr("Enter the auth key from the server").into(), true));
            st.focus = Some(AUTH_KEY);
            return;
        }
        st.busy = Some(Instant::now());
        st.message = None;
        st.focus = None;
        let cmd = Command::Up { server, auth_key: Some(auth_key), hostname, invite: None, origin: Origin::Settings };
        let _ = self.commands.send(cmd);
    }

    fn settings_key(&mut self, event: &KeyEvent) {
        let shortcut = if cfg!(target_os = "macos") { self.mods.super_key() } else { self.mods.control_key() };
        let form = self.settings.show_form();
        let st = &mut self.settings;
        match &event.logical_key {
            Key::Named(NamedKey::Escape) => {
                if std::mem::take(&mut st.lang_open) || st.server_menu.take().is_some() {
                    return;
                }
                if st.focus.take().is_none() {
                    st.changing = false;
                }
                return;
            }
            Key::Named(NamedKey::Tab) if form => {
                let n = 3;
                st.focus = Some(match (st.focus, self.mods.shift_key()) {
                    (None, false) => 0,
                    (None, true) => n - 1,
                    (Some(i), false) => (i + 1) % n,
                    (Some(i), true) => (i + n - 1) % n,
                });
                return;
            }
            Key::Named(NamedKey::Enter) if form => {
                self.connect();
                return;
            }
            _ => {}
        }
        let Some(i) = st.focus else { return };
        edit_input(&mut st.inputs[i], event, shortcut);
        st.message = None;
    }

    fn on_status(&mut self, result: Result<StatusResponse, String>) {
        self.ui.view = match result {
            Ok(s) => View::Status(Box::new(s)),
            Err(_) => View::Offline,
        };
        self.settings.view = self.ui.view.clone();
        if let View::Status(s) = &self.ui.view {
            let update = s.update.clone();
            let auto = s.prefs.auto_update;
            self.after_update(&update.current);
            // Tell the user about each new release once, unless it installs itself
            if update.available && !auto && !update.installing && update.latest.is_some() && update.latest != self.config.notified_update {
                self.config.notified_update = update.latest.clone();
                self.config.save();
                self.notice_pending = true;
            }
        }
        if std::mem::take(&mut self.notice_pending) && self.popup.is_some() && !self.popup_visible() {
            self.show_popup(self.last_anchor);
        }
        if self.ui.pending.is_some_and(|(target, _)| target == self.ui.is_running()) {
            self.ui.pending = None;
        }
        if let Some(tray) = &self.tray {
            let tooltip = match &self.ui.view {
                View::Status(s) => match (s.state, &s.self_node) {
                    (BackendState::Running, Some(me)) => format!("retail: connected ({})", me.ip),
                    (BackendState::Running, None) => "retail: connected".into(),
                    (BackendState::Stopped, _) => "retail: disconnected".into(),
                    (BackendState::NeedsLogin, _) => "retail: not logged in".into(),
                },
                _ => "retail: daemon not running".into(),
            };
            tray.set_state(self.ui.is_running(), &tooltip);
        }
    }

    /// The daemon updated itself and replaced this program's file: start the
    /// new one in its place
    fn after_update(&self, daemon_version: &str) {
        if !newer_version(daemon_version, env!("CARGO_PKG_VERSION")) {
            return;
        }
        let Some(dir) = std::env::current_exe().ok().and_then(|p| p.parent().map(std::path::Path::to_path_buf)) else { return };
        let me = dir.join(if cfg!(windows) { "retail-tray.exe" } else { "retail-tray" });
        let replaced = std::fs::metadata(&me).and_then(|m| m.modified()).is_ok_and(|t| t > self.started);
        if replaced && std::process::Command::new(&me).spawn().is_ok() {
            std::process::exit(0);
        }
    }

    fn on_action(&mut self, origin: Origin, kind: ActionKind, result: Result<StatusResponse, String>) {
        match (origin, result) {
            (Origin::Settings, Ok(s)) if kind == ActionKind::Update => {
                self.settings.busy = None;
                self.on_status(Ok(s));
            }
            (Origin::Settings, Ok(s)) => {
                let st = &mut self.settings;
                st.busy = None;
                st.message = Some(match kind {
                    ActionKind::Logout => (tr("Logged out. This device's keys were deleted.").into(), false),
                    ActionKind::Prefs => (tr("Saved.").into(), false),
                    ActionKind::Forget => (tr("Removed from the list.").into(), false),
                    // The update row says how it went
                    ActionKind::Update => (String::new(), false),
                    _ => (trf("Connected to {server}", &[("server", &s.server.as_deref().map_or(tr("the server").to_string(), settings::server_label))]), false),
                });
                if kind != ActionKind::Forget {
                    st.changing = false;
                }
                st.adding = false;
                st.inputs[AUTH_KEY].clear();
                self.on_status(Ok(s));
            }
            (Origin::Settings, Err(e)) => {
                self.settings.busy = None;
                self.settings.message = Some((e, true));
            }
            (Origin::Popup, Ok(s)) => self.on_status(Ok(s)),
            (Origin::Popup, Err(e)) => {
                self.ui.pending = None;
                self.ui.toast = Some((e, Instant::now()));
            }
        }
    }
}

impl ApplicationHandler<UserEvent> for App {
    fn resumed(&mut self, el: &ActiveEventLoop) {
        if self.popup.is_none()
            && let Err(e) = self.create_popup(el)
        {
            eprintln!("retail-tray: cannot create window: {e}");
            el.exit();
            return;
        }
        if self.tray.is_none() {
            match Tray::new(self.proxy.clone()) {
                Ok(t) => {
                    self.tray = Some(t);
                    if std::mem::take(&mut self.show_on_start) {
                        self.show_popup(self.last_anchor);
                    }
                }
                Err(e) => {
                    // Without a tray host, show the popup as a plain window
                    eprintln!("retail-tray: {e}");
                    self.show_popup(self.last_anchor);
                }
            }
        }
    }

    fn user_event(&mut self, _el: &ActiveEventLoop, event: UserEvent) {
        match event {
            UserEvent::Show => {
                if !self.popup_visible() {
                    self.show_popup(self.last_anchor);
                }
            }
            UserEvent::TrayClicked(anchor) => {
                self.last_anchor = anchor;
                // Clicking the icon first takes focus from the popup and hides it,
                // so don't reopen it right away
                let just_hidden = self.hidden_at.is_some_and(|t| t.elapsed() < Duration::from_millis(300));
                if self.popup_visible() {
                    self.hide_popup();
                } else if !just_hidden {
                    self.show_popup(anchor);
                }
            }
            UserEvent::Api(ApiEvent::Status(result)) => {
                self.on_status(result);
                self.redraw_all();
            }
            UserEvent::Api(ApiEvent::Action { origin, kind, result }) => {
                self.on_action(origin, kind, result);
                self.redraw_all();
            }
            UserEvent::Api(ApiEvent::Server(result)) => {
                let d = &mut self.dashboard;
                let was_busy = d.is_busy();
                d.busy = None;
                match result {
                    Ok(s) => {
                        if !s.running {
                            d.shown = None;
                            d.draft = None;
                        }
                        d.status = Some(Ok(s));
                    }
                    // A failed command keeps the last status and shows why
                    Err(e) if was_busy || matches!(d.status, Some(Ok(_))) => d.message = Some((e, true)),
                    Err(e) => d.status = Some(Err(e)),
                }
                self.dashboard.other_network = self.other_network();
                self.redraw_dashboard();
            }
            UserEvent::Api(ApiEvent::Invite(result)) => {
                let d = &mut self.dashboard;
                d.busy = None;
                match result {
                    Ok(inv) => {
                        let (title, one_time) = d.creating.take().unwrap_or_else(|| (tr("One-time invite").into(), true));
                        d.shown = Some(dashboard::Shown { title, code: inv.code, expires_at: one_time.then_some(inv.expires_at) });
                        d.draft = None;
                        d.message = None;
                    }
                    Err(e) => {
                        d.creating = None;
                        d.invite_note = Some((e, true));
                    }
                }
                self.redraw_dashboard();
            }
            UserEvent::Api(ApiEvent::Code { id, copy, result }) => {
                let d = &mut self.dashboard;
                match result {
                    Ok(code) if copy => {
                        let ok = arboard::Clipboard::new().and_then(|mut c| c.set_text(code)).is_ok();
                        d.invite_note = Some(if ok { (tr("Invite code copied.").into(), false) } else { (tr("Can't use the clipboard").into(), true) });
                    }
                    Ok(code) => {
                        let name = d.invite_name(id).unwrap_or_default();
                        d.shown = Some(dashboard::Shown { title: trf("Invite '{name}'", &[("name", &name)]), code, expires_at: None });
                        d.draft = None;
                    }
                    Err(e) => d.invite_note = Some((e, true)),
                }
                self.redraw_dashboard();
            }
            UserEvent::Api(ApiEvent::Saved(result)) => {
                let d = &mut self.dashboard;
                match result {
                    Ok(path) => {
                        let file = path.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
                        let dir = path.parent().map(|p| p.display().to_string()).unwrap_or_default();
                        d.invite_note = Some((trf("Saved {file} in {dir}. Send it to the person joining; running it is all they do.", &[("file", &file), ("dir", &dir)]), false));
                        d.saved = Some(path);
                    }
                    Err(e) => {
                        d.saved = None;
                        d.invite_note = Some((e, true));
                    }
                }
                self.redraw_dashboard();
            }
        }
    }

    fn window_event(&mut self, el: &ActiveEventLoop, id: WindowId, event: WindowEvent) {
        if let WindowEvent::ModifiersChanged(m) = &event {
            self.mods = m.state();
            return;
        }
        if let WindowEvent::ThemeChanged(theme) = event {
            self.system_dark = theme == Theme::Dark;
            self.apply_theme();
            return;
        }
        if self.dashboard_win.as_ref().is_some_and(|d| d.id() == id) {
            let scale = self.dashboard_win.as_ref().map_or(1.0, |d| d.scale());
            match event {
                WindowEvent::RedrawRequested => self.redraw_dashboard(),
                WindowEvent::CloseRequested => self.close_dashboard(),
                WindowEvent::CursorMoved { position, .. } => {
                    self.dashboard.cursor = Some(((position.x / scale) as f32, (position.y / scale) as f32));
                    self.redraw_dashboard();
                }
                WindowEvent::CursorLeft { .. } => {
                    self.dashboard.cursor = None;
                    self.redraw_dashboard();
                }
                WindowEvent::MouseInput { state: ElementState::Pressed, button: MouseButton::Left, .. } => {
                    if let Some(a) = self.dashboard.cursor.and_then(|(x, y)| self.dashboard.action_at(x, y)) {
                        self.run_dashboard_action(a);
                    }
                    self.redraw_dashboard();
                }
                WindowEvent::KeyboardInput { event, .. } if event.state == ElementState::Pressed => {
                    // Escape closes a menu, the form or the code first, then the window
                    let open = self.dashboard.invite_menu.is_some() || self.dashboard.draft.is_some() || self.dashboard.shown.is_some();
                    if event.logical_key == Key::Named(NamedKey::Escape) && !open {
                        self.close_dashboard();
                    } else {
                        self.dashboard_key(&event);
                        self.redraw_dashboard();
                    }
                }
                WindowEvent::MouseWheel { delta, .. } => {
                    let rows = match delta {
                        MouseScrollDelta::LineDelta(_, y) => -y.signum() as i32,
                        MouseScrollDelta::PixelDelta(p) => -(p.y / 40.0) as i32,
                    };
                    if let Some((x, y)) = self.dashboard.cursor
                        && rows != 0
                        && (self.dashboard.scroll_nodes(x, y, rows) || self.dashboard.scroll_invites(x, y, rows))
                    {
                        self.redraw_dashboard();
                    }
                }
                WindowEvent::ScaleFactorChanged { .. } | WindowEvent::Resized(_) => self.redraw_dashboard(),
                _ => {}
            }
            return;
        }
        let is_settings = self.settings_win.as_ref().is_some_and(|s| s.id() == id);
        let scale = if is_settings {
            self.settings_win.as_ref().map_or(1.0, |s| s.scale())
        } else {
            self.popup.as_ref().map_or(1.0, |p| p.scale())
        };

        if is_settings {
            match event {
                WindowEvent::RedrawRequested => self.redraw_settings(),
                WindowEvent::CloseRequested => self.close_settings(),
                WindowEvent::CursorMoved { position, .. } => {
                    self.settings.cursor = Some(((position.x / scale) as f32, (position.y / scale) as f32));
                    self.redraw_settings();
                }
                WindowEvent::CursorLeft { .. } => {
                    self.settings.cursor = None;
                    self.redraw_settings();
                }
                WindowEvent::MouseInput { state: ElementState::Pressed, button: MouseButton::Left, .. } => {
                    let action = self.settings.cursor.and_then(|(x, y)| self.settings.action_at(x, y));
                    // Any click closes the language list; its own button toggles it
                    let was_open = std::mem::take(&mut self.settings.lang_open);
                    let menu = self.settings.server_menu.take();
                    match action {
                        Some(SettingsAction::LangMenu) => self.settings.lang_open = !was_open,
                        Some(SettingsAction::ServerMenu(i)) => self.settings.server_menu = (menu != Some(i)).then_some(i),
                        Some(a) => self.run_settings_action(a),
                        None => self.settings.focus = None,
                    }
                    self.redraw_settings();
                }
                WindowEvent::KeyboardInput { event, .. } if event.state == ElementState::Pressed => {
                    self.settings_key(&event);
                    self.redraw_settings();
                }
                WindowEvent::MouseWheel { delta, .. } => {
                    let rows = match delta {
                        MouseScrollDelta::LineDelta(_, y) => -y.signum() as i32,
                        MouseScrollDelta::PixelDelta(p) => -(p.y / 40.0) as i32,
                    };
                    let over = self.settings.cursor.is_some_and(|(x, y)| self.settings.over_server_list(x, y));
                    if rows != 0 && over && self.settings.scroll_servers(rows) {
                        self.redraw_settings();
                    }
                }
                WindowEvent::ScaleFactorChanged { .. } | WindowEvent::Resized(_) => self.redraw_settings(),
                _ => {}
            }
            return;
        }

        match event {
            WindowEvent::RedrawRequested => self.redraw_popup(),
            WindowEvent::CloseRequested | WindowEvent::Focused(false) => {
                if self.popup_visible() {
                    self.hide_popup();
                }
            }
            WindowEvent::KeyboardInput { event, .. } if event.logical_key == Key::Named(NamedKey::Escape) => {
                self.hide_popup()
            }
            WindowEvent::CursorMoved { position, .. } => {
                self.ui.cursor = Some(((position.x / scale) as f32, (position.y / scale) as f32));
                self.redraw_popup();
            }
            WindowEvent::CursorLeft { .. } => {
                self.ui.cursor = None;
                self.redraw_popup();
            }
            WindowEvent::MouseInput { state: ElementState::Released, button: MouseButton::Left, .. } => {
                if let Some((x, y)) = self.ui.cursor
                    && let Some(action) = self.ui.action_at(x, y)
                {
                    self.run_action(el, action);
                    self.redraw_popup();
                }
            }
            WindowEvent::MouseWheel { delta, .. } => {
                let rows = match delta {
                    MouseScrollDelta::LineDelta(_, y) => -y.signum() as i32,
                    MouseScrollDelta::PixelDelta(p) => -(p.y / 40.0) as i32,
                };
                if rows != 0 && self.ui.scroll_by(rows) {
                    self.redraw_popup();
                }
            }
            WindowEvent::ScaleFactorChanged { .. } | WindowEvent::Resized(_) => self.redraw_popup(),
            _ => {}
        }
    }

    fn about_to_wait(&mut self, el: &ActiveEventLoop) {
        // Wake up to expire the toast, a stale pending toggle, or an armed
        // confirmation button
        let popup = self.ui.needs_timer().filter(|_| self.popup_visible());
        let logout = self.settings.confirm_logout.map(|t| t + Duration::from_secs(4)).filter(|_| self.settings_win.is_some());
        let dash = self.dashboard.confirm_stop.or(self.dashboard.confirm_remove.map(|(_, t)| t));
        let dash = dash.map(|t| t + Duration::from_secs(4)).filter(|_| self.dashboard_win.is_some());
        match popup.into_iter().chain(logout).chain(dash).min() {
            Some(at) => {
                if Instant::now() >= at {
                    self.redraw_all();
                }
                el.set_control_flow(ControlFlow::WaitUntil(at.max(Instant::now() + Duration::from_millis(50))));
            }
            None => el.set_control_flow(ControlFlow::Wait),
        }
    }
}

/// Positions the popup next to the tray icon, inside the icon's monitor:
/// above it for a bottom taskbar, below it for a top menu bar or panel.
fn place(window: &Window, a: Anchor, size: PhysicalSize<u32>) -> PhysicalPosition<i32> {
    let (w, h) = (size.width as f64, size.height as f64);
    let monitor = window
        .available_monitors()
        .find(|m| {
            let (p, s) = (m.position(), m.size());
            a.x >= p.x as f64 && a.x < p.x as f64 + s.width as f64 && a.y >= p.y as f64 && a.y < p.y as f64 + s.height as f64
        })
        .or_else(|| window.primary_monitor())
        .or_else(|| window.current_monitor());
    let Some(m) = monitor else {
        return PhysicalPosition::new(a.x as i32, a.y as i32);
    };
    let (mx, my, mw, mh) = (m.position().x as f64, m.position().y as f64, m.size().width as f64, m.size().height as f64);
    let margin = 10.0 * m.scale_factor();
    if a.x == 0.0 && a.y == 0.0 {
        // Position unknown (some Linux trays), so use the top-right corner
        return PhysicalPosition::new((mx + mw - w - margin) as i32, (my + 40.0 * m.scale_factor()) as i32);
    }
    let x = (a.x + a.w / 2.0 - w / 2.0).clamp(mx + margin, (mx + mw - w - margin).max(mx + margin));
    let y = if a.y > my + mh / 2.0 { a.y - h - margin } else { a.y + a.h + margin / 2.0 };
    let y = y.clamp(my, (my + mh - h).max(my));
    PhysicalPosition::new(x as i32, y as i32)
}

/// Windows 11 rounds and shadows borderless windows only on request
#[cfg(windows)]
fn round_corners(window: &Window) {
    use windows_sys::Win32::Graphics::Dwm::{DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND, DwmSetWindowAttribute};
    use winit::raw_window_handle::{HasWindowHandle, RawWindowHandle};
    if let Ok(handle) = window.window_handle()
        && let RawWindowHandle::Win32(h) = handle.as_raw()
    {
        let pref = DWMWCP_ROUND;
        // SAFETY: valid HWND owned by `window`, and the attribute takes a 4-byte enum
        unsafe {
            DwmSetWindowAttribute(
                h.hwnd.get() as _,
                DWMWA_WINDOW_CORNER_PREFERENCE as u32,
                (&pref as *const i32).cast(),
                std::mem::size_of::<i32>() as u32,
            );
        }
    }
}

/// Whether version `a` is newer than `b` (`major.minor.patch`)
fn newer_version(a: &str, b: &str) -> bool {
    let parse = |v: &str| -> Option<(u64, u64, u64)> {
        let mut it = v.split('.').map(|p| p.parse().ok());
        Some((it.next()??, it.next()??, it.next()??))
    };
    matches!((parse(a), parse(b)), (Some(x), Some(y)) if x > y)
}

/// Typing into a text field: editing keys, clipboard shortcuts, text
fn edit_input(input: &mut crate::input::TextInput, event: &KeyEvent, shortcut: bool) {
    match &event.logical_key {
        Key::Named(NamedKey::Backspace) => input.backspace(),
        Key::Named(NamedKey::Delete) => input.delete(),
        Key::Named(NamedKey::ArrowLeft) => input.left(),
        Key::Named(NamedKey::ArrowRight) => input.right(),
        Key::Named(NamedKey::Home) => input.home(),
        Key::Named(NamedKey::End) => input.end(),
        Key::Character(c) if shortcut => match c.to_lowercase().as_str() {
            "a" => input.select_all(),
            "v" => {
                if let Ok(text) = arboard::Clipboard::new().and_then(|mut c| c.get_text()) {
                    input.insert(text.trim());
                }
            }
            "c" if !input.secret => {
                let _ = arboard::Clipboard::new().and_then(|mut c| c.set_text(input.value.clone()));
            }
            _ => {}
        },
        _ => {
            if !shortcut && let Some(text) = &event.text {
                input.insert(text);
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // A client package installs itself instead of starting
    if let Some(code) = install::run(&args) {
        std::process::exit(code);
    }
    if let Some(i) = args.iter().position(|a| a == "--preview") {
        let out = args.get(i + 1).cloned().unwrap_or_else(|| "retail-tray-preview.png".into());
        let state = args.iter().position(|a| a == "--state").and_then(|i| args.get(i + 1)).map_or("connected", |s| s.as_str());
        let dark = args.iter().any(|a| a == "--dark");
        let lang = args.iter().position(|a| a == "--lang").and_then(|i| args.get(i + 1)).and_then(|l| LangPref::parse(l));
        i18n::set(lang.unwrap_or(LangPref::En));
        let result = if args.iter().any(|a| a == "--settings") {
            preview::render_settings(&out, state, dark)
        } else if args.iter().any(|a| a == "--setup") {
            let os = args.iter().position(|a| a == "--os").and_then(|i| args.get(i + 1)).map_or("this", |s| s.as_str());
            preview::render_setup(&out, state, os, dark)
        } else if args.iter().any(|a| a == "--server") {
            preview::render_dashboard(&out, state, dark)
        } else {
            preview::render(&out, state, dark)
        };
        if let Err(e) = result {
            eprintln!("preview failed: {e}");
            std::process::exit(1);
        }
        return;
    }

    let fonts = match Fonts::load() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("retail-tray: {e}");
            std::process::exit(1);
        }
    };
    let api: SocketAddr = std::env::var("RETAIL_API")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| retail_proto::LOCAL_API_ADDR.parse().expect("valid default address"));

    #[allow(unused_mut)]
    let mut builder = EventLoop::<UserEvent>::with_user_event();
    #[cfg(target_os = "macos")]
    {
        use winit::platform::macos::{ActivationPolicy, EventLoopBuilderExtMacOS};
        builder.with_activation_policy(ActivationPolicy::Accessory);
    }
    #[cfg(unix)]
    let single = match single::claim() {
        Some(l) => l,
        // Another runs: it shows its popup instead
        None => return,
    };
    let event_loop = builder.build().expect("creating the event loop");
    let proxy = event_loop.create_proxy();
    #[cfg(unix)]
    single::serve(single, proxy.clone());

    let fast_poll = Arc::new(AtomicBool::new(false));
    let dashboard_poll = Arc::new(AtomicBool::new(false));
    let api_proxy = proxy.clone();
    let commands = api::spawn(api, fast_poll.clone(), dashboard_poll.clone(), move |e| {
        let _ = api_proxy.send_event(UserEvent::Api(e));
    });

    let config = Config::load();
    i18n::set(config.language);
    let mut app = App {
        proxy,
        fonts,
        ui: Ui::new(false),
        settings: Settings::new(false, config.theme, config.language),
        config,
        popup: None,
        settings_win: None,
        dashboard: Dashboard::new(false),
        dashboard_win: None,
        tray: None,
        commands,
        fast_poll,
        dashboard_poll,
        hidden_at: None,
        last_anchor: Anchor::default(),
        show_on_start: args.iter().any(|a| a == "--show"),
        system_dark: false,
        mods: ModifiersState::empty(),
        started: std::time::SystemTime::now(),
        notice_pending: false,
    };
    if let Err(e) = event_loop.run_app(&mut app) {
        eprintln!("retail-tray: {e}");
    }
}

/// One tray app per user. Started again (the app menu entry, while it runs
/// from sign-in), it asks the running one to show its popup and exits.
#[cfg(unix)]
mod single {
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;

    use winit::event_loop::EventLoopProxy;

    use crate::UserEvent;

    fn path() -> PathBuf {
        let uid = unsafe { libc::geteuid() };
        match std::env::var_os("XDG_RUNTIME_DIR") {
            Some(d) => PathBuf::from(d).join("retail-tray.sock"),
            None => std::env::temp_dir().join(format!("retail-tray-{uid}.sock")),
        }
    }

    /// `None` when another tray app took the request to show itself.
    /// `Some(None)`: this is the only one, but others cannot reach it.
    pub fn claim() -> Option<Option<UnixListener>> {
        let p = path();
        if let Ok(mut s) = UnixStream::connect(&p) {
            let _ = s.write_all(b"show");
            return None;
        }
        // A socket left by a tray app that did not end cleanly
        let _ = std::fs::remove_file(&p);
        Some(UnixListener::bind(&p).ok())
    }

    pub fn serve(listener: Option<UnixListener>, proxy: EventLoopProxy<UserEvent>) {
        let Some(listener) = listener else { return };
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut buf = [0u8; 8];
                if stream.read(&mut buf).is_ok_and(|n| &buf[..n] == b"show") {
                    let _ = proxy.send_event(UserEvent::Show);
                }
            }
        });
    }
}

mod preview {
    use retail_proto::Key;
    use retail_proto::api::{BackendState, PeerStatus, SelfStatus, StatusResponse};
    use tiny_skia::Pixmap;

    use crate::config::ThemePref;
    use crate::settings::{AUTH_KEY, DEVICE, SERVER, Settings};
    use crate::text::Fonts;
    use crate::ui::{Ui, View};

    fn peer(name: &str, last: u8, online: bool, direct: bool, hs: Option<u64>) -> PeerStatus {
        PeerStatus {
            hostname: name.into(),
            ip: std::net::Ipv4Addr::new(100, 64, 0, last),
            node_key: Key([last; 32]),
            online,
            endpoint: direct.then(|| format!("203.0.113.{last}:41641").parse().unwrap()),
            path: None,
            candidates: vec![],
            last_handshake_secs: hs,
            exit_node: false,
            tx_bytes: 0,
            rx_bytes: 0,
            dns_name: format!("{name}.retail.internal"),
            restricted: false,
            routes: vec![],
        }
    }

    fn sample(state: &str) -> View {
        let mut peers = vec![
            PeerStatus { exit_node: true, ..peer("desktop-home", 2, true, true, Some(12)) },
            peer("nas", 3, true, true, Some(3)),
            PeerStatus { path: Some("relay".into()), ..peer("phone", 6, true, false, Some(40)) },
            peer("work-macbook", 4, true, false, None),
            peer("old-thinkpad", 5, false, false, None),
        ];
        if state == "many" {
            for i in 6..14 {
                peers.push(peer(&format!("server-{i:02}"), i, i % 3 != 0, i % 3 == 1, Some(i as u64 * 7)));
            }
        }
        let backend = match state {
            "stopped" => BackendState::Stopped,
            "login" => BackendState::NeedsLogin,
            _ => BackendState::Running,
        };
        if state == "offline" {
            return View::Offline;
        }
        View::Status(Box::new(StatusResponse {
            state: backend,
            server: (backend != BackendState::NeedsLogin).then(|| "https://vpn.example.com".into()),
            control_connected: backend == BackendState::Running,
            self_node: (backend != BackendState::NeedsLogin).then(|| SelfStatus {
                hostname: "work-laptop".into(),
                ip: std::net::Ipv4Addr::new(100, 64, 0, 1),
                node_key: Key([1; 32]),
                endpoints: vec![],
                dns_name: "work-laptop.retail.internal".into(),
            }),
            peers: if backend == BackendState::Running { peers } else { vec![] },
            last_error: None,
            prefs: retail_proto::api::Prefs {
                // `exit` routes internet traffic through desktop-home
                exit_node: matches!(state, "exit" | "exit-menu").then_some(Key([2; 32])),
                ..Default::default()
            },
            memory_peak: Some(9_437_184),
            key_expires_at: None,
            key_expired: state == "expired",
            control_via: None,
            update: retail_proto::api::UpdateStatus {
                current: env!("CARGO_PKG_VERSION").into(),
                latest: matches!(state, "update" | "updating").then(|| "0.2.0".into()),
                available: matches!(state, "update" | "updating"),
                installing: state == "updating",
                error: None,
                supported: true,
            },
            servers: if backend == BackendState::NeedsLogin {
                vec![]
            } else {
                let saved = |server: &str, last: u8, current| retail_proto::api::SavedServer {
                    server: server.into(),
                    ip: Some(std::net::Ipv4Addr::new(100, 64, 0, last)),
                    current,
                };
                vec![saved("https://vpn.example.com", 1, true), saved("https://home.example.net:8443", 7, false), saved("https://203.0.113.24", 3, false)]
            },
        }))
    }

    pub fn render(out: &str, state: &str, dark: bool) -> Result<(), String> {
        let fonts = Fonts::load()?;
        let mut ui = Ui::new(dark);
        ui.transparent_corners = true;
        ui.view = sample(state);
        if state == "exit-menu" {
            // Open the "⋯" menu of desktop-home, which offers itself as exit node
            ui.menu = Some(Key([2; 32]));
        } else if state == "gear" {
            ui.gear = true;
        } else {
            // Hover the second device row to show the hover style
            ui.cursor = Some((150.0, 72.0 + 4.0 + 64.0 + 8.0 + 36.0 + 52.0 + 20.0));
        }
        save(out, crate::ui::WIDTH, ui.height(), |pix, s| ui.render(&fonts, pix, s))
    }

    /// `--state login` shows the filled-in form with the auth key focused and
    /// a server error. `--state change` shows "Change server".
    pub fn render_settings(out: &str, state: &str, dark: bool) -> Result<(), String> {
        let fonts = Fonts::load()?;
        let mut st = Settings::new(dark, if dark { ThemePref::Dark } else { ThemePref::System }, crate::LangPref::System);
        st.view = sample(if matches!(state, "change" | "server-menu" | "many-servers" | "language") { "connected" } else { state });
        st.lang_open = state == "language";
        if state == "many-servers" {
            st.changing = true;
            st.server_scroll = 2;
            if let View::Status(s) = &mut st.view {
                for (i, host) in ["office.example.org", "lab.example.edu", "198.51.100.7", "cabin.example.net"].iter().enumerate() {
                    s.servers.push(retail_proto::api::SavedServer {
                        server: format!("https://{host}"),
                        ip: Some(std::net::Ipv4Addr::new(100, 64, 1, i as u8 + 1)),
                        current: false,
                    });
                }
            }
        }
        if state == "server-menu" {
            st.changing = true;
            st.server_menu = Some(1);
        }
        if state == "login" || state == "change" {
            st.changing = state == "change";
            st.inputs[SERVER].set("https://vpn.example.com");
            st.inputs[AUTH_KEY].set("rtl-auth-3kd92mfp1qz");
            st.inputs[DEVICE].set("work-laptop");
            st.focus = Some(AUTH_KEY);
        }
        if state == "login" {
            st.message = Some(("registration rejected (HTTP 401): invalid, used or expired auth key".into(), true));
        }
        save(out, crate::settings::WIDTH, st.height(), |pix, s| st.render(&fonts, pix, s))
    }

    /// `--state idle` (not hosting) or `running` (with devices and an invite)
    pub fn render_dashboard(out: &str, state: &str, dark: bool) -> Result<(), String> {
        use retail_proto::api::{ServerNode, ServerStatus};
        let fonts = Fonts::load()?;
        let mut d = crate::dashboard::Dashboard::new(dark);
        let node = |id: i64, name: &str, last: u8, online: bool, exit: bool| ServerNode {
            id,
            hostname: name.into(),
            os: if id == 1 { "windows".into() } else { "linux".into() },
            ip: std::net::Ipv4Addr::new(100, 64, 0, last),
            online,
            exit_node: exit,
            last_seen: (!online).then(|| {
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64 - 3 * 3600
            }),
            dns_name: format!("{name}.retail.internal"),
            tags: Vec::new(),
            advertised_routes: Vec::new(),
            approved_routes: Vec::new(),
            expires_at: None,
            expired: false,
            invite_id: None,
        };
        d.status = Some(Ok(if state == "idle" {
            ServerStatus::default()
        } else {
            ServerStatus {
                running: true,
                port: Some(443),
                public: Some("203.0.113.24:443".into()),
                lan: vec!["192.168.1.20:443".into()],
                port_mapping: Some("opened by UPnP (TCP 443, UDP 3478)".into()),
                router: Some(retail_proto::api::RouterState::Opened { method: "UPnP".into(), tcp: 443, udp: 3478 }),
                nodes: vec![
                    node(1, "work-laptop", 1, true, false),
                    node(2, "desktop-home", 2, true, true),
                    node(3, "phone", 3, false, false),
                ],
                ..Default::default()
            }
        }));
        if state == "many"
            && let Some(Ok(st)) = &mut d.status
        {
            for (i, name) in ["nas", "tablet", "work-macbook", "pi-garage", "old-thinkpad", "living-room-tv"].iter().enumerate() {
                st.nodes.push(node(4 + i as i64, name, 4 + i as u8, i % 2 == 0, false));
            }
            d.node_scroll = 2;
        }
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        if let Some(Ok(st)) = &mut d.status
            && st.running
        {
            let invite = |id: i64, name: Option<&str>, uses: u64, expires_at: i64| retail_proto::api::ServerInvite {
                id,
                reusable: name.is_some(),
                used: uses > 0,
                expires_at,
                created_at: now,
                name: name.map(str::to_string),
                uses,
            };
            st.invites = vec![invite(4, Some("Family"), 3, i64::MAX), invite(6, Some("Office"), 1, now + 20 * 24 * 3600), invite(9, None, 0, now + 20 * 3600)];
        }
        if state == "idle" {
            d.other_network = Some("vpn.example.com".into());
        } else if state == "create" {
            let mut name = crate::input::TextInput::new("", false);
            name.set("Friends");
            d.draft = Some(crate::dashboard::Draft { multi: true, ttl: Some(168), name, focused: true });
        } else if state == "invite-menu" {
            d.invite_menu = Some(4);
        } else {
            d.shown = Some(crate::dashboard::Shown {
                title: crate::i18n::trf("Invite '{name}'", &[("name", &"Family")]),
                code: "retail1.eyJhIjpbIjIwMy4wLjExMy4yNDo0NDMiLCIxOTIuMTY4LjEuMjA6NDQzIl0sInAiOiJxN2dmZDBhQmJ4MUxuT2hfR2RxVkt0Ym1zRmZ3cUkiLCJrIjoicnRsLWF1dGgtUWhLMndPbiJ9".into(),
                expires_at: None,
            });
        }
        // Lay out once to learn the height, then draw at that size
        let mut probe = Pixmap::new(1, 1).ok_or("bad size")?;
        d.render(&fonts, &mut probe, 1.0);
        save(out, crate::dashboard::WIDTH, d.height(), |pix, s| {
            d.render(&fonts, pix, s);
        })
    }

    pub fn render_setup(out: &str, state: &str, os: &str, dark: bool) -> Result<(), String> {
        use crate::setup::{Kind, Os, Setup, Step};
        let fonts = Fonts::load()?;
        let kind = match state {
            "update" => Kind::Update,
            "join" | "done-joined" => Kind::Join { network: "the retail network \"family\"".into() },
            "switch" => Kind::Switch { current: "vpn.example.com".into(), network: "the retail network \"office\"".into() },
            _ => Kind::Install,
        };
        let dir = if os == "windows" { r"C:\Program Files\retail" } else { "/usr/local/bin" };
        let mut st = Setup::new(kind, env!("CARGO_PKG_VERSION"), dir, false);
        st.dark = dark;
        st.os = match os {
            "windows" => Os::Windows,
            "macos" => Os::Macos,
            "linux" => Os::Linux,
            _ => Os::this(),
        };
        st.step = match state {
            "network" | "network-error" => Step::Network,
            "working" => Step::Working,
            "done" | "done-joined" => Step::Done,
            "failed" => Step::Failed("retaild did not start: the local API port 127.0.0.1:41112 is taken by another program".into()),
            _ => Step::Welcome,
        };
        if state == "network" {
            st.input.set("retail1qw3er5ty7ui9op0as2df4gh6jk8l");
            st.focus = true;
        }
        if state == "network-error" {
            st.input.set("hello");
            st.error = Some(crate::i18n::tr("This is not a retail invite code. Paste a code that starts with retail1.").into());
        }
        if state == "done-joined" {
            st.network = Some("the retail network \"family\"".into());
        }
        save(out, crate::setup::WIDTH, crate::setup::HEIGHT, |pix, s| st.render(&fonts, pix, s))
    }

    fn save(out: &str, w: f32, h: f32, render: impl FnOnce(&mut Pixmap, f32)) -> Result<(), String> {
        let scale = 2.0;
        let mut pix = Pixmap::new((w * scale) as u32, (h * scale) as u32).ok_or("bad size")?;
        render(&mut pix, scale);
        pix.save_png(out).map_err(|e| e.to_string())
    }
}
