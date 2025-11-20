//! Fluent 2 (Windows 11) dark design tokens and widget styles.
//!
//! Colours follow the Fluent 2 web/desktop dark theme: neutral backgrounds
//! (#1F1F1F app, #292929 card, #2E2E2E subtle hover), brand blue (#479EF5
//! foreground, #115EA3 background), 4 px control and 8 px card radii, and
//! 1 px neutral strokes.

use iced::widget::{button, container, text, text_input, toggler};
use iced::{color, Background, Border, Color, Font, Shadow, Theme, Vector};

// Neutral backgrounds
pub const BG: Color = color!(0x1f1f1f); // colorNeutralBackground2
pub const SURFACE: Color = color!(0x292929); // colorNeutralBackground1
pub const SURFACE_HOVER: Color = color!(0x3d3d3d); // colorNeutralBackground1Hover
pub const SURFACE_PRESSED: Color = color!(0x1f1f1f);
pub const SUBTLE_HOVER: Color = color!(0x383838); // colorSubtleBackgroundHover
pub const NAV_BG: Color = color!(0x1a1a1a);
pub const CONSOLE: Color = color!(0x141414); // colorNeutralBackground3
// Strokes
pub const STROKE: Color = color!(0x666666); // colorNeutralStroke1
pub const STROKE_SUBTLE: Color = color!(0x3d3d3d); // colorNeutralStroke2
// Foregrounds
pub const TEXT: Color = color!(0xffffff); // colorNeutralForeground1
pub const TEXT_2: Color = color!(0xd6d6d6); // colorNeutralForeground2
pub const MUTED: Color = color!(0xadadad); // colorNeutralForeground3
// Brand / status
pub const ACCENT: Color = color!(0x479ef5); // colorBrandForeground1
pub const BRAND_BG: Color = color!(0x115ea3); // colorBrandBackground
pub const BRAND_HOVER: Color = color!(0x0f6cbd);
pub const BRAND_PRESSED: Color = color!(0x0c3b5e);
pub const SUCCESS: Color = color!(0x54b054); // colorPaletteGreenForeground1
pub const WARNING: Color = color!(0xfaa06b); // colorPaletteDarkOrangeForeground1
pub const DANGER: Color = color!(0xdc626d); // colorPaletteRedForeground1

pub const LOGO_PNG: &[u8] = include_bytes!("../../assets/logo.png");

/// Window / taskbar icon decoded from the embedded logo.
pub fn window_icon() -> Option<iced::window::Icon> {
    let img = image::load_from_memory_with_format(LOGO_PNG, image::ImageFormat::Png).ok()?.into_rgba8();
    let (w, h) = img.dimensions();
    iced::window::icon::from_rgba(img.into_raw(), w, h).ok()
}

pub const RADIUS_CONTROL: f32 = 4.0;
pub const RADIUS_CARD: f32 = 8.0;

/// Segoe UI Variable on Windows 11; the platform default elsewhere.
pub fn ui_font() -> Font {
    if cfg!(windows) { Font::with_name("Segoe UI Variable Text") } else { Font::DEFAULT }
}

/// Cascadia Mono on Windows 11; the platform monospace elsewhere.
pub fn mono() -> Font {
    if cfg!(windows) { Font::with_name("Cascadia Mono") } else { Font::MONOSPACE }
}

/// Segoe Fluent Icons (bundled with Windows 11).
pub const ICONS: Font = Font::with_name("Segoe Fluent Icons");

pub mod icon {
    pub const KEY: char = '\u{E8D7}';
    pub const LIST: char = '\u{E8FD}';
    pub const SHIELD: char = '\u{EA18}';
    pub const PC: char = '\u{E7F8}';
    pub const SERVER: char = '\u{E968}';
    pub const LOCK: char = '\u{E72E}';
    pub const INFO: char = '\u{E946}';
}

pub fn theme() -> Theme {
    Theme::custom(
        "Fluent 2 Dark",
        iced::theme::Palette { background: BG, text: TEXT, primary: BRAND_BG, success: SUCCESS, warning: WARNING, danger: DANGER },
    )
}

fn stroke(c: Color, radius: f32) -> Border {
    Border { color: c, width: 1.0, radius: radius.into() }
}

pub fn card(_: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(SURFACE)),
        border: stroke(STROKE_SUBTLE, RADIUS_CARD),
        shadow: Shadow { color: Color { a: 0.28, ..Color::BLACK }, offset: Vector::new(0.0, 2.0), blur_radius: 4.0 },
        ..Default::default()
    }
}

pub fn console(_: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(CONSOLE)),
        border: stroke(STROKE_SUBTLE, RADIUS_CONTROL),
        text_color: Some(TEXT_2),
        ..Default::default()
    }
}

pub fn sidebar(_: &Theme) -> container::Style {
    container::Style { background: Some(Background::Color(NAV_BG)), ..Default::default() }
}

pub fn status_bar(_: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(NAV_BG)),
        border: Border { color: STROKE_SUBTLE, width: 1.0, radius: 0.0.into() },
        text_color: Some(MUTED),
        ..Default::default()
    }
}

/// Selected-item indicator pill in the navigation pane.
pub fn indicator(active: bool) -> impl Fn(&Theme) -> container::Style {
    move |_| container::Style {
        background: active.then_some(Background::Color(ACCENT)),
        border: Border { radius: 2.0.into(), ..Default::default() },
        ..Default::default()
    }
}


}