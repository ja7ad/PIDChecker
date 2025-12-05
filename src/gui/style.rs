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

pub fn badge(c: Color) -> impl Fn(&Theme) -> container::Style {
    move |_| container::Style {
        background: Some(Background::Color(Color { a: 0.16, ..c })),
        border: stroke(Color { a: 0.55, ..c }, 999.0),
        text_color: Some(c),
        ..Default::default()
    }
}

pub fn nav(active: bool) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |_, status| {
        let bg = match (active, status) {
            (_, button::Status::Pressed) => Some(SURFACE_PRESSED),
            (true, _) => Some(SUBTLE_HOVER),
            (false, button::Status::Hovered) => Some(color!(0x2e2e2e)),
            _ => None,
        };
        button::Style {
            background: bg.map(Background::Color),
            text_color: if active { TEXT } else { TEXT_2 },
            border: Border { radius: RADIUS_CONTROL.into(), ..Default::default() },
            shadow: Shadow::default(),
            snap: true,
        }
    }
}

/// Fluent "primary" (accent) button.
pub fn primary(_: &Theme, status: button::Status) -> button::Style {
    let bg = match status {
        button::Status::Hovered => BRAND_HOVER,
        button::Status::Pressed => BRAND_PRESSED,
        button::Status::Disabled => color!(0x333333),
        button::Status::Active => BRAND_BG,
    };
    button::Style {
        background: Some(Background::Color(bg)),
        text_color: if status == button::Status::Disabled { color!(0x5c5c5c) } else { TEXT },
        border: Border { radius: RADIUS_CONTROL.into(), ..Default::default() },
        shadow: Shadow::default(),
        snap: true,
    }
}

/// Fluent "secondary" (outline) button.
pub fn secondary(_: &Theme, status: button::Status) -> button::Style {
    let (bg, border) = match status {
        button::Status::Hovered => (SURFACE_HOVER, color!(0x757575)),
        button::Status::Pressed => (SURFACE_PRESSED, color!(0x6b6b6b)),
        button::Status::Disabled => (color!(0x252525), color!(0x424242)),
        button::Status::Active => (SURFACE, STROKE),
    };
    button::Style {
        background: Some(Background::Color(bg)),
        text_color: if status == button::Status::Disabled { color!(0x5c5c5c) } else { TEXT },
        border: stroke(border, RADIUS_CONTROL),
        shadow: Shadow::default(),
        snap: true,
    }
}

/// Destructive action: secondary shape with a red label.
pub fn danger(t: &Theme, status: button::Status) -> button::Style {
    let mut s = secondary(t, status);
    if status != button::Status::Disabled {
        s.text_color = DANGER;
    }
    s
}

/// Fluent text field: dark fill, subtle stroke, brand stroke when focused.
pub fn input(_: &Theme, status: text_input::Status) -> text_input::Style {
    let border = match status {
        text_input::Status::Focused { .. } => Border { color: ACCENT, width: 1.0, radius: RADIUS_CONTROL.into() },
        text_input::Status::Hovered => stroke(color!(0x757575), RADIUS_CONTROL),
        _ => stroke(STROKE_SUBTLE, RADIUS_CONTROL),
    };
    text_input::Style {
        background: Background::Color(color!(0x292929)),
        border,
        icon: MUTED,
        placeholder: color!(0x8a8a8a),
        value: TEXT,
        selection: Color { a: 0.45, ..ACCENT },
    }
}

pub fn switch(_: &Theme, status: toggler::Status) -> toggler::Style {
    let on = matches!(status, toggler::Status::Active { is_toggled: true } | toggler::Status::Hovered { is_toggled: true });
    toggler::Style {
        background: Background::Color(if on { BRAND_BG } else { Color::TRANSPARENT }),
        background_border_width: if on { 0.0 } else { 1.0 },
        background_border_color: color!(0xd1d1d1),
        foreground: Background::Color(if on { TEXT } else { color!(0xd1d1d1) }),
        foreground_border_width: 0.0,
        foreground_border_color: Color::TRANSPARENT,
        text_color: None,
        border_radius: None,
        padding_ratio: 0.2,
    }

}