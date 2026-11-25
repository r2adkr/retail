//! The frame of retail's own windows (settings, server), drawn like the
//! installer's instead of the system's: on Windows and Linux no system frame
//! at all, minimize and close drawn top right and the heading strip moving
//! the window; on macOS the system's buttons on a see-through title bar,
//! with the content below them.

use tiny_skia::{Color, Pixmap, PixmapPaint, Rect, Transform};
use winit::window::{Window, WindowAttributes};

use crate::draw::{Canvas, Theme, contains, with_alpha};
use crate::text::Fonts;

/// The top strip (heading) that moves a window without a frame
pub const DRAG_H: f32 = 52.0;
const SIZE: f32 = 32.0;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Button {
    Minimize,
    Close,
}

/// Room above the content: macOS's buttons sit there
pub fn top() -> f32 {
    if cfg!(target_os = "macos") { 28.0 } else { 0.0 }
}

/// Whether this window draws its own buttons
fn drawn() -> bool {
    !cfg!(target_os = "macos")
}

pub fn attributes(attrs: WindowAttributes) -> WindowAttributes {
    #[cfg(target_os = "macos")]
    {
        use winit::platform::macos::WindowAttributesExtMacOS;
        attrs.with_titlebar_transparent(true).with_title_hidden(true).with_fullsize_content_view(true)
    }
    #[cfg(not(target_os = "macos"))]
    {
        attrs.with_decorations(false)
    }
}

/// After the window is made (Windows 11 rounds its corners)
pub fn opened(window: &Window) {
    #[cfg(windows)]
    crate::round_corners(window);
    #[cfg(not(windows))]
    let _ = window;
}

fn rects(width: f32) -> [(Rect, Button); 2] {
    let y = 10.0;
    let close_x = width - 10.0 - SIZE;
    let min_x = close_x - SIZE - 2.0;
    [
        (Rect::from_xywh(min_x, y, SIZE, SIZE).unwrap(), Button::Minimize),
        (Rect::from_xywh(close_x, y, SIZE, SIZE).unwrap(), Button::Close),
    ]
}

/// The drawn button under `pointer` (window coordinates)
pub fn button_at(width: f32, pointer: (f32, f32)) -> Option<Button> {
    if !drawn() {
        return None;
    }
    rects(width).into_iter().find(|(r, _)| contains(r, pointer.0, pointer.1)).map(|(_, b)| b)
}

/// Whether a press at `pointer` (window coordinates) that hit nothing in
/// the content should move the window
pub fn drags(pointer: (f32, f32)) -> bool {
    pointer.1 < top() + DRAG_H
}

/// Window coordinates to the content's
pub fn to_content(pointer: (f32, f32)) -> (f32, f32) {
    (pointer.0, pointer.1 - top())
}

/// The content's coordinates to the window's
pub fn to_window(pointer: (f32, f32)) -> (f32, f32) {
    (pointer.0, pointer.1 + top())
}

/// Draws the window: the content (`render`, given a pixmap of its own size
/// when it sits below the title bar) and the buttons over it
pub fn frame(
    pix: &mut Pixmap,
    fonts: &Fonts,
    scale: f32,
    width: f32,
    dark: bool,
    pointer: Option<(f32, f32)>,
    render: impl FnOnce(&mut Pixmap),
) {
    let inset = (top() * scale).round() as u32;
    if inset == 0 {
        render(pix);
    } else if let Some(mut content) = Pixmap::new(pix.width(), pix.height().saturating_sub(inset).max(1)) {
        render(&mut content);
        // The strip above takes the content's background
        let bg = content.pixel(0, 0).map(|p| p.demultiply()).map_or(Color::WHITE, |c| {
            Color::from_rgba8(c.red(), c.green(), c.blue(), 255)
        });
        pix.fill(bg);
        pix.draw_pixmap(0, inset as i32, content.as_ref(), &PixmapPaint::default(), Transform::identity(), None);
    }
    if !drawn() {
        return;
    }
    let t = Theme::new(dark);
    let mut c = Canvas { pix, fonts, scale };
    for (r, button) in rects(width) {
        let hover = pointer.is_some_and(|(x, y)| contains(&r, x, y));
        if hover {
            c.fill_rrect(r.x(), r.y(), SIZE, SIZE, 6.0, if button == Button::Close { t.red } else { t.hover });
        }
        let fg = if hover && button == Button::Close { Color::WHITE } else { with_alpha(t.dim, 1.0) };
        let (cx, cy) = (r.x() + SIZE / 2.0, r.y() + SIZE / 2.0);
        match button {
            Button::Close => {
                c.line((cx - 5.0, cy - 5.0), (cx + 5.0, cy + 5.0), 1.4, fg);
                c.line((cx + 5.0, cy - 5.0), (cx - 5.0, cy + 5.0), 1.4, fg);
            }
            Button::Minimize => c.line((cx - 5.5, cy), (cx + 5.5, cy), 1.4, fg),
        }
    }
}
