//! Text rendering with system fonts. ab_glyph reads glyph outlines on demand,
//! so memory stays proportional to the glyphs actually drawn (an eager
//! rasterizer would expand every glyph of a CJK font: hundreds of megabytes).
//! Fallback fonts, needed only for characters the UI font lacks (Hangul,
//! kana, Han), are opened the first time such a character shows up.

use std::cell::RefCell;
use std::collections::HashMap;

use ab_glyph::{Font, FontVec, GlyphId, PxScale, ScaleFont, point};
use tiny_skia::{Color, Pixmap, PremultipliedColorU8};

use crate::i18n::LangPref;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Weight {
    Regular,
    Semibold,
}

/// Coverage bitmap and its offset from the pen position on the baseline
struct Glyph {
    left: i32,
    top: i32,
    width: usize,
    height: usize,
    coverage: Vec<u8>,
}

pub struct Fonts {
    regular: FontVec,
    semibold: Option<FontVec>,
    fallback: &'static [(&'static str, Script)],
    /// One per `fallback` entry, opened the first time it is needed
    slots: RefCell<Vec<Slot>>,
    cache: RefCell<HashMap<(u8, GlyphId, u32), Glyph>>,
}

/// The script a fallback font is drawn for first. Han characters look
/// different in Korean, Japanese and Chinese fonts, so the interface language
/// picks among them; kana go to a Japanese font and Hangul to a Korean one.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Script {
    Ko,
    Ja,
    Zh,
    /// Covers all three (Noto Sans CJK); only Linux lists one
    #[cfg_attr(any(windows, target_os = "macos"), allow(dead_code))]
    Any,
}

enum Slot {
    Untried,
    Missing,
    Loaded(FontVec),
}

type Candidates = (&'static [&'static str], &'static [&'static str], &'static [(&'static str, Script)]);

#[cfg(windows)]
fn candidates() -> Candidates {
    (
        &["C:\\Windows\\Fonts\\segoeui.ttf", "C:\\Windows\\Fonts\\arial.ttf"],
        &["C:\\Windows\\Fonts\\seguisb.ttf", "C:\\Windows\\Fonts\\segoeuib.ttf"],
        &[
            ("C:\\Windows\\Fonts\\malgun.ttf", Script::Ko),
            ("C:\\Windows\\Fonts\\YuGothR.ttc#1", Script::Ja),
            ("C:\\Windows\\Fonts\\msyh.ttc", Script::Zh),
        ],
    )
}

#[cfg(target_os = "macos")]
fn candidates() -> Candidates {
    (
        &[
            "/System/Library/Fonts/SFNS.ttf",
            "/System/Library/Fonts/Helvetica.ttc",
            "/Library/Fonts/Arial.ttf",
        ],
        &[],
        &[
            ("/System/Library/Fonts/AppleSDGothicNeo.ttc", Script::Ko),
            ("/System/Library/Fonts/ヒラギノ角ゴシック W3.ttc", Script::Ja),
            ("/System/Library/Fonts/Hiragino Sans GB.ttc", Script::Zh),
        ],
    )
}

#[cfg(all(unix, not(target_os = "macos")))]
fn candidates() -> Candidates {
    (
        &[
            "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
            "/usr/share/fonts/noto/NotoSans-Regular.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/TTF/DejaVuSans.ttf",
            "/usr/share/fonts/dejavu/DejaVuSans.ttf",
        ],
        // Medium/SemiBold only, since a full Bold (e.g. DejaVu Sans Bold) is far
        // heavier than Segoe UI Semibold and looks clumsy. Without one, regular is used
        &[
            "/usr/share/fonts/truetype/noto/NotoSans-SemiBold.ttf",
            "/usr/share/fonts/noto/NotoSans-SemiBold.ttf",
            "/usr/share/fonts/truetype/noto/NotoSans-Medium.ttf",
            "/usr/share/fonts/noto/NotoSans-Medium.ttf",
            "/usr/share/fonts/truetype/ubuntu/Ubuntu-M.ttf",
            "/usr/share/fonts/truetype/cantarell/Cantarell-Bold.otf",
        ],
        &[
            ("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc", Script::Any),
            ("/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc", Script::Any),
            ("/usr/share/fonts/truetype/nanum/NanumGothic.ttf", Script::Ko),
        ],
    )
}

/// ab_glyph scales by the font's full height (ascent - descent), but UI sizes
/// here are em sizes, as in CSS.
fn em(font: &FontVec, px: f32) -> PxScale {
    let upem = font.units_per_em().unwrap_or(1000.0);
    PxScale::from(px * font.height_unscaled() / upem)
}

/// `path`, or `path#n` for the n-th font of a collection
fn load(path: &str) -> Option<FontVec> {
    let (path, index) = match path.rsplit_once('#') {
        Some((p, i)) => (p, i.parse().ok()?),
        None => (path, 0),
    };
    FontVec::try_from_vec_and_index(std::fs::read(path).ok()?, index).ok()
}

impl Fonts {
    pub fn load() -> Result<Self, String> {
        let (regular, semibold, fallback) = candidates();
        let regular = regular
            .iter()
            .find_map(|p| load(p))
            .ok_or_else(|| format!("no usable UI font found (tried {regular:?})"))?;
        Ok(Fonts {
            regular,
            semibold: semibold.iter().find_map(|p| load(p)),
            fallback,
            slots: RefCell::new(fallback.iter().map(|_| Slot::Untried).collect()),
            cache: RefCell::default(),
        })
    }

    /// Runs `f` with the font (and its face id) that can draw `c`
    fn with_face<R>(&self, weight: Weight, c: char, f: impl FnOnce(u8, &FontVec) -> R) -> R {
        let primary = match (weight, &self.semibold) {
            (Weight::Semibold, Some(font)) => (1, font),
            _ => (0, &self.regular),
        };
        if c.is_ascii() || primary.1.glyph_id(c).0 != 0 {
            return f(primary.0, primary.1);
        }
        let first = match c as u32 {
            0x3040..=0x30ff | 0x31f0..=0x31ff => Script::Ja,
            0x1100..=0x11ff | 0x3130..=0x318f | 0xac00..=0xd7af => Script::Ko,
            _ => match crate::i18n::current() {
                LangPref::Ja => Script::Ja,
                LangPref::Ko => Script::Ko,
                _ => Script::Zh,
            },
        };
        // Fonts for that script first, then the rest in their listed order
        let order = (0..self.fallback.len())
            .filter(|&i| self.fallback[i].1 == first)
            .chain((0..self.fallback.len()).filter(|&i| self.fallback[i].1 != first));
        for i in order {
            {
                let mut slots = self.slots.borrow_mut();
                if let Slot::Untried = slots[i] {
                    slots[i] = load(self.fallback[i].0).map_or(Slot::Missing, Slot::Loaded);
                }
            }
            let slots = self.slots.borrow();
            if let Slot::Loaded(font) = &slots[i]
                && font.glyph_id(c).0 != 0
            {
                return f(2 + i as u8, font);
            }
        }
        f(primary.0, primary.1)
    }

    fn advance(&self, weight: Weight, prev: Option<char>, c: char, px: f32) -> f32 {
        self.with_face(weight, c, |_, font| {
            let scaled = font.as_scaled(em(font, px));
            let id = font.glyph_id(c);
            let kern = prev.map_or(0.0, |p| scaled.kern(font.glyph_id(p), id));
            kern + scaled.h_advance(id)
        })
    }

    pub fn measure(&self, text: &str, px: f32, weight: Weight) -> f32 {
        let mut w = 0.0;
        let mut prev = None;
        for c in text.chars() {
            w += self.advance(weight, prev, c, px);
            prev = Some(c);
        }
        w
    }

    /// Draws `text` with its baseline at `y`, shortening it with an ellipsis to
    /// fit `max_w`. Returns the drawn width.
    #[allow(clippy::too_many_arguments)]
    pub fn draw(
        &self,
        pix: &mut Pixmap,
        text: &str,
        x: f32,
        y: f32,
        px: f32,
        weight: Weight,
        color: Color,
        max_w: Option<f32>,
    ) -> f32 {
        let fitted;
        let text = match max_w {
            Some(max) if self.measure(text, px, weight) > max => {
                let ell = self.measure("…", px, weight);
                let mut s: String = text.to_string();
                while !s.is_empty() && self.measure(&s, px, weight) + ell > max {
                    s.pop();
                }
                fitted = format!("{}…", s.trim_end());
                fitted.as_str()
            }
            _ => text,
        };
        let baseline = y.round() as i32;
        let mut pen = x;
        let mut prev = None;
        for c in text.chars() {
            self.with_face(weight, c, |face, font| {
                let scaled = font.as_scaled(em(font, px));
                let id = font.glyph_id(c);
                pen += prev.map_or(0.0, |p| scaled.kern(font.glyph_id(p), id));
                let key = (face, id, (px * 4.0).round() as u32);
                let mut cache = self.cache.borrow_mut();
                let glyph = cache.entry(key).or_insert_with(|| rasterize(font, id, px));
                blend_coverage(pix, glyph, pen.round() as i32 + glyph.left, baseline + glyph.top, color);
                pen += scaled.h_advance(id);
            });
            prev = Some(c);
        }
        pen - x
    }
}

fn rasterize(font: &FontVec, id: GlyphId, px: f32) -> Glyph {
    let glyph = id.with_scale_and_position(em(font, px), point(0.0, 0.0));
    let Some(outline) = font.outline_glyph(glyph) else {
        return Glyph { left: 0, top: 0, width: 0, height: 0, coverage: Vec::new() };
    };
    let b = outline.px_bounds();
    let (width, height) = (b.width() as usize, b.height() as usize);
    let mut coverage = vec![0u8; width * height];
    outline.draw(|gx, gy, c| {
        if let Some(v) = coverage.get_mut(gy as usize * width + gx as usize) {
            *v = (c.clamp(0.0, 1.0) * 255.0).round() as u8;
        }
    });
    Glyph { left: b.min.x as i32, top: b.min.y as i32, width, height, coverage }
}

/// Source-over blend of a coverage mask in `color` at (x, y)
fn blend_coverage(pix: &mut Pixmap, g: &Glyph, x: i32, y: i32, color: Color) {
    let (pw, ph) = (pix.width() as i32, pix.height() as i32);
    let c = color.to_color_u8();
    let pixels = pix.pixels_mut();
    for row in 0..g.height as i32 {
        let py = y + row;
        if py < 0 || py >= ph {
            continue;
        }
        for col in 0..g.width as i32 {
            let px = x + col;
            if px < 0 || px >= pw {
                continue;
            }
            let cov = g.coverage[(row as usize) * g.width + col as usize] as u32 * c.alpha() as u32 / 255;
            if cov == 0 {
                continue;
            }
            let i = (py * pw + px) as usize;
            let d = pixels[i];
            let inv = 255 - cov;
            let mix = |s: u8, d: u8| ((s as u32 * cov + d as u32 * inv + 127) / 255) as u8;
            let a = (cov + d.alpha() as u32 * inv / 255).min(255) as u8;
            let (r, g, b) = (mix(c.red(), d.red()), mix(c.green(), d.green()), mix(c.blue(), d.blue()));
            // Keep the premultiplied invariant (channel <= alpha)
            pixels[i] = PremultipliedColorU8::from_rgba(r.min(a), g.min(a), b.min(a), a).unwrap_or(d);
        }
    }
}
