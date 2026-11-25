//! Tray icon artwork, drawn in code so there are no image assets to ship

use tiny_skia::{Color, FillRule, Paint, PathBuilder, Pixmap, Stroke, Transform};

/// Straight (non-premultiplied) RGBA pixels of a `size`×`size` icon.
///
/// `template` draws a black glyph on transparency, which macOS recolours for
/// light/dark menu bars. Otherwise it draws a coloured tile (blue when
/// connected).
pub fn rgba(size: u32, connected: bool, template: bool) -> Vec<u8> {
    draw(size, connected, template)
        .pixels()
        .iter()
        .flat_map(|p| {
            let c = p.demultiply();
            [c.red(), c.green(), c.blue(), c.alpha()]
        })
        .collect()
}

/// The app's icon (the blue tile), `size`×`size`, as PNG: for the app lists
/// (Start menu, Applications, the Linux app menu)
pub fn app_png(size: u32) -> Option<Vec<u8>> {
    draw(size, true, false).encode_png().ok()
}

fn draw(size: u32, connected: bool, template: bool) -> Pixmap {
    let mut pix = Pixmap::new(size, size).expect("non-zero icon size");
    let s = size as f32 / 32.0;
    let ts = Transform::from_scale(s, s);
    let mut paint = Paint { anti_alias: true, ..Default::default() };

    let glyph = if template {
        Color::from_rgba8(0, 0, 0, if connected { 255 } else { 110 })
    } else {
        let tile = if connected { Color::from_rgba8(0x25, 0x63, 0xeb, 255) } else { Color::from_rgba8(0x8a, 0x8a, 0x94, 255) };
        paint.set_color(tile);
        if let Some(path) = rounded_square(2.0, 2.0, 28.0, 8.0) {
            pix.fill_path(&path, &paint, FillRule::Winding, ts, None);
        }
        Color::WHITE
    };

    paint.set_color(glyph);
    let nodes = [(10.0, 11.0), (22.0, 11.0), (16.0, 22.0)];
    let mut pb = PathBuilder::new();
    pb.move_to(nodes[0].0, nodes[0].1);
    pb.line_to(nodes[1].0, nodes[1].1);
    pb.line_to(nodes[2].0, nodes[2].1);
    pb.close();
    if let Some(path) = pb.finish() {
        let stroke = Stroke { width: 2.2, ..Default::default() };
        pix.stroke_path(&path, &paint, &stroke, ts, None);
    }
    for (x, y) in nodes {
        if let Some(path) = PathBuilder::from_circle(x, y, 3.6) {
            pix.fill_path(&path, &paint, FillRule::Winding, ts, None);
        }
    }

    pix
}

fn rounded_square(x: f32, y: f32, w: f32, r: f32) -> Option<tiny_skia::Path> {
    let k = r * 0.447_715;
    let mut pb = PathBuilder::new();
    pb.move_to(x + r, y);
    pb.line_to(x + w - r, y);
    pb.cubic_to(x + w - k, y, x + w, y + k, x + w, y + r);
    pb.line_to(x + w, y + w - r);
    pb.cubic_to(x + w, y + w - k, x + w - k, y + w, x + w - r, y + w);
    pb.line_to(x + r, y + w);
    pb.cubic_to(x + k, y + w, x, y + w - k, x, y + w - r);
    pb.line_to(x, y + r);
    pb.cubic_to(x, y + k, x + k, y, x + r, y);
    pb.close();
    pb.finish()
}
