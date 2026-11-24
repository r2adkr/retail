use tiny_skia::{Color, FillRule, Paint, PathBuilder, Pixmap, Rect, Transform};

use crate::text::{Fonts, Weight};

#[derive(Clone, Copy)]
pub struct Theme {
    pub bg: Color,
    pub surface: Color,
    pub hover: Color,
    pub border: Color,
    pub text: Color,
    pub dim: Color,
    pub accent: Color,
    pub amber: Color,
    pub gray: Color,
    pub red: Color,
    pub knob: Color,
}

pub fn rgb(hex: u32) -> Color {
    Color::from_rgba8((hex >> 16) as u8, (hex >> 8) as u8, hex as u8, 255)
}

impl Theme {
    pub fn new(dark: bool) -> Self {
        if dark { Self::dark() } else { Self::light() }
    }

    pub fn light() -> Self {
        Theme {
            bg: rgb(0xffffff),
            surface: rgb(0xf4f4f6),
            hover: rgb(0xebebef),
            border: rgb(0xe6e6ea),
            text: rgb(0x16161a),
            dim: rgb(0x6e6e78),
            accent: rgb(0x2563eb),
            amber: rgb(0xe0950e),
            gray: rgb(0xb4b4bc),
            red: rgb(0xd93a3a),
            knob: rgb(0xffffff),
        }
    }

    pub fn dark() -> Self {
        Theme {
            bg: rgb(0x1d1d20),
            surface: rgb(0x27272b),
            hover: rgb(0x303036),
            border: rgb(0x34343a),
            text: rgb(0xf1f1f4),
            dim: rgb(0x9c9ca6),
            accent: rgb(0x3b82f6),
            amber: rgb(0xf0a92a),
            gray: rgb(0x5c5c66),
            red: rgb(0xf05a5a),
            knob: rgb(0xffffff),
        }
    }
}

pub fn contains(r: &Rect, x: f32, y: f32) -> bool {
    x >= r.left() && x < r.right() && y >= r.top() && y < r.bottom()
}

pub fn with_alpha(c: Color, a: f32) -> Color {
    let mut c = c;
    c.set_alpha(a);
    c
}

pub fn shade(c: Color, f: f32) -> Color {
    Color::from_rgba((c.red() * f).min(1.0), (c.green() * f).min(1.0), (c.blue() * f).min(1.0), c.alpha())
        .unwrap_or(c)
}

/// Drawing helpers in logical coordinates
pub struct Canvas<'a> {
    pub pix: &'a mut Pixmap,
    pub fonts: &'a Fonts,
    pub scale: f32,
}

impl Canvas<'_> {
    pub fn paint(color: Color) -> Paint<'static> {
        let mut p = Paint::default();
        p.set_color(color);
        p.anti_alias = true;
        p
    }

    pub fn fill_path(&mut self, pb: PathBuilder, color: Color) {
        if let Some(path) = pb.finish() {
            let ts = Transform::from_scale(self.scale, self.scale);
            self.pix.fill_path(&path, &Self::paint(color), FillRule::Winding, ts, None);
        }
    }

    pub fn fill_rect(&mut self, x: f32, y: f32, w: f32, h: f32, color: Color) {
        if let Some(r) = Rect::from_xywh(x, y, w, h) {
            let ts = Transform::from_scale(self.scale, self.scale);
            self.pix.fill_rect(r, &Self::paint(color), ts, None);
        }
    }

    pub fn rrect_path(x: f32, y: f32, w: f32, h: f32, r: f32) -> PathBuilder {
        let r = r.min(w / 2.0).min(h / 2.0);
        let k = r * 0.447_715; // r * (1 - 0.5523): control-point inset for a circular arc
        let mut pb = PathBuilder::new();
        pb.move_to(x + r, y);
        pb.line_to(x + w - r, y);
        pb.cubic_to(x + w - k, y, x + w, y + k, x + w, y + r);
        pb.line_to(x + w, y + h - r);
        pb.cubic_to(x + w, y + h - k, x + w - k, y + h, x + w - r, y + h);
        pb.line_to(x + r, y + h);
        pb.cubic_to(x + k, y + h, x, y + h - k, x, y + h - r);
        pb.line_to(x, y + r);
        pb.cubic_to(x, y + k, x + k, y, x + r, y);
        pb.close();
        pb
    }

    pub fn fill_rrect(&mut self, x: f32, y: f32, w: f32, h: f32, r: f32, color: Color) {
        self.fill_path(Self::rrect_path(x, y, w, h, r), color);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn stroke_rrect_w(&mut self, x: f32, y: f32, w: f32, h: f32, r: f32, width: f32, color: Color) {
        if let Some(path) = Self::rrect_path(x, y, w, h, r).finish() {
            let stroke = tiny_skia::Stroke { width, ..Default::default() };
            let ts = Transform::from_scale(self.scale, self.scale);
            self.pix.stroke_path(&path, &Self::paint(color), &stroke, ts, None);
        }
    }

    pub fn stroke_rrect(&mut self, x: f32, y: f32, w: f32, h: f32, r: f32, color: Color) {
        if let Some(path) = Self::rrect_path(x, y, w, h, r).finish() {
            let stroke = tiny_skia::Stroke { width: 1.0, ..Default::default() };
            let ts = Transform::from_scale(self.scale, self.scale);
            self.pix.stroke_path(&path, &Self::paint(color), &stroke, ts, None);
        }
    }

    pub fn circle(&mut self, x: f32, y: f32, r: f32, color: Color) {
        if let Some(path) = PathBuilder::from_circle(x, y, r) {
            let ts = Transform::from_scale(self.scale, self.scale);
            self.pix.fill_path(&path, &Self::paint(color), FillRule::Winding, ts, None);
        }
    }

    /// A gear: eight teeth around a ring
    pub fn gear(&mut self, cx: f32, cy: f32, r: f32, color: Color) {
        let mut pb = PathBuilder::new();
        let teeth = 8;
        let (outer, inner) = (r, r * 0.74);
        for i in 0..teeth * 4 {
            // Each tooth: up the flank, across the top, down, across the root
            let step = std::f32::consts::TAU / (teeth * 4) as f32;
            let a = i as f32 * step - step / 2.0;
            let rad = if matches!(i % 4, 1 | 2) { outer } else { inner };
            let (x, y) = (cx + rad * a.cos(), cy + rad * a.sin());
            if i == 0 { pb.move_to(x, y) } else { pb.line_to(x, y) }
        }
        pb.close();
        pb.push_circle(cx, cy, r * 0.36);
        if let Some(path) = pb.finish() {
            let ts = Transform::from_scale(self.scale, self.scale);
            self.pix.fill_path(&path, &Self::paint(color), FillRule::EvenOdd, ts, None);
        }
    }

    pub fn line(&mut self, a: (f32, f32), b: (f32, f32), width: f32, color: Color) {
        let mut pb = PathBuilder::new();
        pb.move_to(a.0, a.1);
        pb.line_to(b.0, b.1);
        if let Some(path) = pb.finish() {
            let stroke = tiny_skia::Stroke { width, ..Default::default() };
            let ts = Transform::from_scale(self.scale, self.scale);
            self.pix.stroke_path(&path, &Self::paint(color), &stroke, ts, None);
        }
    }

    pub fn hline(&mut self, x0: f32, x1: f32, y: f32, color: Color) {
        // Snap to whole device pixels so the separator stays crisp
        let s = self.scale;
        let yy = ((y * s).floor() + 0.5) / s;
        self.fill_rect(x0, yy - 0.5 / s, x1 - x0, 1.0 / s, color);
    }

    pub fn measure(&self, text: &str, px: f32, w: Weight) -> f32 {
        self.fonts.measure(text, px * self.scale, w) / self.scale
    }

    #[allow(clippy::too_many_arguments)]
    pub fn text(&mut self, text: &str, x: f32, y: f32, px: f32, w: Weight, color: Color, max_w: Option<f32>) -> f32 {
        let s = self.scale;
        self.fonts.draw(self.pix, text, x * s, y * s, px * s, w, color, max_w.map(|m| m * s)) / s
    }
}
