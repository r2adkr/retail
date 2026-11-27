//! The status icon: Windows notification area / macOS menu bar via
//! `tray-icon`, Linux StatusNotifierItem over D-Bus via `ksni` (no GTK).
//! It only reports clicks. The popup itself is our own window.

use winit::event_loop::EventLoopProxy;

use crate::UserEvent;
use crate::icon;

/// Where the icon is on screen, in physical pixels (zero size if unknown)
#[derive(Clone, Copy, Debug, Default)]
pub struct Anchor {
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
}

#[cfg(any(windows, target_os = "macos"))]
pub struct Tray {
    icon: tray_icon::TrayIcon,
}

#[cfg(any(windows, target_os = "macos"))]
impl Tray {
    /// Must run on the main thread after the event loop has started (macOS)
    pub fn new(proxy: EventLoopProxy<UserEvent>) -> Result<Self, String> {
        use tray_icon::{MouseButtonState, TrayIconBuilder, TrayIconEvent};

        TrayIconEvent::set_event_handler(Some(move |event: TrayIconEvent| {
            if let TrayIconEvent::Click {
                rect,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                let anchor = Anchor {
                    x: rect.position.x,
                    y: rect.position.y,
                    w: rect.size.width as f64,
                    h: rect.size.height as f64,
                };
                let _ = proxy.send_event(UserEvent::TrayClicked(anchor));
            }
        }));
        #[cfg(target_os = "macos")]
        let builder = TrayIconBuilder::new().with_icon_templated(make_icon(false)?);
        #[cfg(not(target_os = "macos"))]
        let builder = TrayIconBuilder::new().with_icon(make_icon(false)?);
        let icon = builder
            .with_tooltip("retail")
            .with_menu_on_left_click(false)
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Tray { icon })
    }

    pub fn set_state(&self, connected: bool, tooltip: &str) {
        if let Ok(icon) = make_icon(connected) {
            #[cfg(target_os = "macos")]
            let _ = self.icon.set_icon_templated(Some(icon));
            #[cfg(not(target_os = "macos"))]
            let _ = self.icon.set_icon(Some(icon));
        }
        let _ = self.icon.set_tooltip(Some(tooltip));
    }
}

#[cfg(any(windows, target_os = "macos"))]
fn make_icon(connected: bool) -> Result<tray_icon::Icon, String> {
    let size = if cfg!(target_os = "macos") { 44 } else { 32 };
    tray_icon::Icon::from_rgba(
        icon::rgba(size, connected, cfg!(target_os = "macos")),
        size,
        size,
    )
    .map_err(|e| e.to_string())
}

#[cfg(target_os = "linux")]
pub struct Tray {
    handle: ksni::blocking::Handle<SniTray>,
}

#[cfg(target_os = "linux")]
pub struct SniTray {
    proxy: EventLoopProxy<UserEvent>,
    connected: bool,
    tooltip: String,
}

#[cfg(target_os = "linux")]
impl ksni::Tray for SniTray {
    fn id(&self) -> String {
        "retail".into()
    }

    fn title(&self) -> String {
        "retail".into()
    }

    fn activate(&mut self, x: i32, y: i32) {
        let anchor = Anchor {
            x: x as f64,
            y: y as f64,
            w: 0.0,
            h: 0.0,
        };
        let _ = self.proxy.send_event(UserEvent::TrayClicked(anchor));
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        [32u32, 64]
            .into_iter()
            .map(|size| {
                // StatusNotifierItem wants ARGB32 in network byte order
                let data = icon::rgba(size, self.connected, false)
                    .chunks_exact(4)
                    .flat_map(|p| [p[3], p[0], p[1], p[2]])
                    .collect();
                ksni::Icon {
                    width: size as i32,
                    height: size as i32,
                    data,
                }
            })
            .collect()
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            title: self.tooltip.clone(),
            ..Default::default()
        }
    }
}

#[cfg(target_os = "linux")]
impl Tray {
    pub fn new(proxy: EventLoopProxy<UserEvent>) -> Result<Self, String> {
        use ksni::blocking::TrayMethods;
        let handle = SniTray {
            proxy,
            connected: false,
            tooltip: "retail".into(),
        }
        .spawn()
        .map_err(|e| {
            format!("no StatusNotifier host (is a tray/appindicator extension running?): {e}")
        })?;
        Ok(Tray { handle })
    }

    pub fn set_state(&self, connected: bool, tooltip: &str) {
        let tooltip = tooltip.to_string();
        self.handle.update(move |t| {
            t.connected = connected;
            t.tooltip = tooltip;
        });
    }
}
