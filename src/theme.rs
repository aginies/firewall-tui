//! Centralized color palette and style helpers for a cohesive, colorful look.
//!
//! The palette uses truecolor (24-bit) RGB values for a modern terminal
//! appearance. Each tab/section has its own accent color so the UI is easy to
//! scan at a glance.
//!
//! Several palettes ship with the app — a dark one (default), a light one, and
//! a set of popular community themes (Dracula, Nord, Gruvbox, Catppuccin
//! Mocha/Latte, Monokai, Solarized). The active palette is chosen at runtime
//! (cycle with `T`) and persisted to the config file. All color accessors
//! (`theme::accent()`, `theme::muted()`, …) read the *active* palette, so call
//! sites never name a specific theme.

use ratatui::style::{Color, Modifier, Style};
use std::sync::atomic::{AtomicU8, Ordering};

/// A complete color palette. The built-in themes are listed in [`THEMES`]; the
/// active one is selected at runtime via [`set_theme_by_name`] / [`next`].
pub struct Theme {
    // Accents (one per section)
    pub accent: Color,
    pub zones: Color,
    pub ports: Color,
    pub services: Color,
    pub rules: Color,
    pub forward: Color,
    // Semantic
    pub success: Color,
    pub warning: Color,
    pub danger: Color,
    pub info: Color,
    // Text
    pub text: Color,
    pub muted: Color,
    pub dim: Color,
    // Backgrounds
    pub bg_panel: Color,
    pub bg_zebra: Color,
    pub bg_selected: Color,
    pub bg_active_tab: Color,
    // Mode-banner backgrounds (runtime / permanent).
    pub banner_runtime_bg: Color,
    pub banner_permanent_bg: Color,
    /// Text drawn on top of an accent-colored pill (active tab, pending badge).
    pub on_accent: Color,
    /// True for light-background palettes (used for contrast + persistence).
    pub light: bool,
}

/// The dark palette (default).
const DARK: Theme = Theme {
    accent: Color::Rgb(56, 189, 248),     // cyan — global / header
    zones: Color::Rgb(96, 165, 250),      // blue — zones
    ports: Color::Rgb(74, 222, 128),      // green — ports
    services: Color::Rgb(192, 132, 252),  // purple — services
    rules: Color::Rgb(250, 204, 21),      // yellow — rich rules
    forward: Color::Rgb(251, 146, 60),    // orange — forwarding
    success: Color::Rgb(74, 222, 128),    // active / ok
    warning: Color::Rgb(250, 204, 21),    // permanent / caution
    danger: Color::Rgb(248, 113, 113),    // error / destructive
    info: Color::Rgb(56, 189, 248),       // informational
    text: Color::Rgb(226, 232, 240),      // primary text
    muted: Color::Rgb(148, 163, 184),     // secondary text
    dim: Color::Rgb(100, 116, 139),       // faint / placeholder
    bg_panel: Color::Rgb(15, 23, 42),     // panel / chrome background
    bg_zebra: Color::Rgb(23, 32, 48),     // alternating table row
    bg_selected: Color::Rgb(30, 58, 95),  // selected row
    bg_active_tab: Color::Rgb(8, 51, 68), // active tab pill
    banner_runtime_bg: Color::Rgb(8, 47, 66),
    banner_permanent_bg: Color::Rgb(66, 54, 10),
    on_accent: Color::Black,
    light: false,
};

/// The light palette. Text and accents are darkened for contrast on light
/// backgrounds; the selected/active surfaces are tinted pastels.
const LIGHT: Theme = Theme {
    accent: Color::Rgb(2, 132, 199),          // cyan — global / header
    zones: Color::Rgb(37, 99, 235),           // blue — zones
    ports: Color::Rgb(22, 163, 74),           // green — ports
    services: Color::Rgb(147, 51, 234),       // purple — services
    rules: Color::Rgb(202, 138, 4),           // yellow — rich rules
    forward: Color::Rgb(234, 88, 12),         // orange — forwarding
    success: Color::Rgb(22, 163, 74),         // active / ok
    warning: Color::Rgb(202, 138, 4),         // permanent / caution
    danger: Color::Rgb(220, 38, 38),          // error / destructive
    info: Color::Rgb(2, 132, 199),            // informational
    text: Color::Rgb(30, 41, 59),             // primary text
    muted: Color::Rgb(71, 85, 105),           // secondary text
    dim: Color::Rgb(148, 163, 184),           // faint / placeholder
    bg_panel: Color::Rgb(241, 245, 249),      // panel / chrome background
    bg_zebra: Color::Rgb(226, 232, 240),      // alternating table row
    bg_selected: Color::Rgb(191, 219, 254),   // selected row
    bg_active_tab: Color::Rgb(186, 230, 253), // active tab pill
    banner_runtime_bg: Color::Rgb(186, 230, 253),
    banner_permanent_bg: Color::Rgb(253, 230, 138),
    on_accent: Color::White,
    light: true,
};

/// Dracula — a dark palette with a purple tint and vivid, high-contrast accents.
const DRACULA: Theme = Theme {
    accent: Color::Rgb(139, 233, 253),   // cyan
    zones: Color::Rgb(189, 147, 249),    // purple
    ports: Color::Rgb(80, 250, 123),     // green
    services: Color::Rgb(255, 121, 198), // pink
    rules: Color::Rgb(241, 250, 140),    // yellow
    forward: Color::Rgb(255, 184, 108),  // orange
    success: Color::Rgb(80, 250, 123),
    warning: Color::Rgb(241, 250, 140),
    danger: Color::Rgb(255, 85, 85),
    info: Color::Rgb(139, 233, 253),
    text: Color::Rgb(248, 248, 242),
    muted: Color::Rgb(140, 150, 190),
    dim: Color::Rgb(98, 114, 164),
    bg_panel: Color::Rgb(40, 42, 54),
    bg_zebra: Color::Rgb(46, 49, 66),
    bg_selected: Color::Rgb(68, 71, 90),
    bg_active_tab: Color::Rgb(68, 71, 90),
    banner_runtime_bg: Color::Rgb(44, 64, 84),
    banner_permanent_bg: Color::Rgb(84, 72, 30),
    on_accent: Color::Black,
    light: false,
};

/// Nord — a cool, calm, low-saturation arctic palette.
const NORD: Theme = Theme {
    accent: Color::Rgb(136, 192, 208),   // nord8 frost
    zones: Color::Rgb(129, 161, 193),    // nord9
    ports: Color::Rgb(163, 190, 140),    // nord14 aurora green
    services: Color::Rgb(180, 142, 173), // nord15 aurora purple
    rules: Color::Rgb(235, 203, 139),    // nord13 aurora yellow
    forward: Color::Rgb(208, 135, 112),  // nord12 aurora orange
    success: Color::Rgb(163, 190, 140),
    warning: Color::Rgb(235, 203, 139),
    danger: Color::Rgb(191, 97, 106), // nord11
    info: Color::Rgb(136, 192, 208),
    text: Color::Rgb(216, 222, 233), // nord4
    muted: Color::Rgb(112, 122, 140),
    dim: Color::Rgb(76, 86, 106),        // nord3
    bg_panel: Color::Rgb(46, 52, 64),    // nord0
    bg_zebra: Color::Rgb(59, 66, 82),    // nord1
    bg_selected: Color::Rgb(67, 76, 94), // nord2
    bg_active_tab: Color::Rgb(67, 76, 94),
    banner_runtime_bg: Color::Rgb(52, 68, 90),
    banner_permanent_bg: Color::Rgb(80, 70, 45),
    on_accent: Color::Black,
    light: false,
};

/// Gruvbox — a warm, retro, low-contrast palette.
const GRUVBOX: Theme = Theme {
    accent: Color::Rgb(104, 157, 106),  // aqua
    zones: Color::Rgb(69, 133, 136),    // blue
    ports: Color::Rgb(152, 151, 26),    // green
    services: Color::Rgb(177, 98, 134), // purple
    rules: Color::Rgb(215, 153, 33),    // yellow
    forward: Color::Rgb(214, 93, 14),   // orange
    success: Color::Rgb(152, 151, 26),
    warning: Color::Rgb(215, 153, 33),
    danger: Color::Rgb(204, 36, 29), // red
    info: Color::Rgb(104, 157, 106),
    text: Color::Rgb(235, 219, 178), // fg
    muted: Color::Rgb(168, 153, 132),
    dim: Color::Rgb(102, 92, 84),        // bg3
    bg_panel: Color::Rgb(40, 40, 40),    // bg0
    bg_zebra: Color::Rgb(60, 56, 54),    // bg1
    bg_selected: Color::Rgb(80, 73, 69), // bg2
    bg_active_tab: Color::Rgb(80, 73, 69),
    banner_runtime_bg: Color::Rgb(54, 70, 72),
    banner_permanent_bg: Color::Rgb(80, 62, 30),
    on_accent: Color::Black,
    light: false,
};

/// Catppuccin Mocha — a soft, pastel dark palette.
const MOCHA: Theme = Theme {
    accent: Color::Rgb(137, 180, 250),   // blue
    zones: Color::Rgb(180, 190, 254),    // lavender
    ports: Color::Rgb(166, 227, 161),    // green
    services: Color::Rgb(203, 166, 247), // mauve
    rules: Color::Rgb(249, 226, 175),    // yellow
    forward: Color::Rgb(250, 179, 135),  // peach
    success: Color::Rgb(166, 227, 161),
    warning: Color::Rgb(249, 226, 175),
    danger: Color::Rgb(243, 139, 168), // red
    info: Color::Rgb(137, 180, 250),
    text: Color::Rgb(205, 214, 244),     // text
    muted: Color::Rgb(166, 173, 200),    // subtext
    dim: Color::Rgb(108, 112, 134),      // overlay1
    bg_panel: Color::Rgb(30, 30, 46),    // base
    bg_zebra: Color::Rgb(49, 50, 68),    // surface0
    bg_selected: Color::Rgb(69, 71, 90), // surface1
    bg_active_tab: Color::Rgb(69, 71, 90),
    banner_runtime_bg: Color::Rgb(50, 62, 90),
    banner_permanent_bg: Color::Rgb(80, 66, 40),
    on_accent: Color::Black,
    light: false,
};

/// Catppuccin Latte — the light counterpart of Mocha.
const LATTE: Theme = Theme {
    accent: Color::Rgb(30, 102, 245),   // blue
    zones: Color::Rgb(114, 135, 253),   // lavender
    ports: Color::Rgb(64, 160, 43),     // green
    services: Color::Rgb(136, 57, 239), // mauve
    rules: Color::Rgb(223, 142, 29),    // yellow
    forward: Color::Rgb(254, 100, 11),  // peach
    success: Color::Rgb(64, 160, 43),
    warning: Color::Rgb(223, 142, 29),
    danger: Color::Rgb(210, 15, 57), // red
    info: Color::Rgb(30, 102, 245),
    text: Color::Rgb(76, 79, 105),       // text
    muted: Color::Rgb(108, 111, 133),    // subtext
    dim: Color::Rgb(148, 152, 168),      // overlay2
    bg_panel: Color::Rgb(239, 241, 245), // base
    bg_zebra: Color::Rgb(220, 224, 232), // crust
    bg_selected: Color::Rgb(197, 214, 250),
    bg_active_tab: Color::Rgb(197, 214, 250),
    banner_runtime_bg: Color::Rgb(197, 214, 250),
    banner_permanent_bg: Color::Rgb(250, 224, 180),
    on_accent: Color::White,
    light: true,
};

/// Monokai — the classic Pro/Atom dark palette.
const MONOKAI: Theme = Theme {
    accent: Color::Rgb(102, 217, 239),  // blue
    zones: Color::Rgb(174, 129, 255),   // purple
    ports: Color::Rgb(166, 226, 46),    // green
    services: Color::Rgb(253, 151, 31), // orange
    rules: Color::Rgb(230, 219, 116),   // yellow
    forward: Color::Rgb(249, 38, 114),  // pink
    success: Color::Rgb(166, 226, 46),
    warning: Color::Rgb(230, 219, 116),
    danger: Color::Rgb(249, 38, 114),
    info: Color::Rgb(102, 217, 239),
    text: Color::Rgb(248, 248, 242),
    muted: Color::Rgb(117, 113, 94), // comment
    dim: Color::Rgb(70, 68, 58),
    bg_panel: Color::Rgb(39, 40, 34),
    bg_zebra: Color::Rgb(49, 50, 44),
    bg_selected: Color::Rgb(66, 68, 58),
    bg_active_tab: Color::Rgb(66, 68, 58),
    banner_runtime_bg: Color::Rgb(44, 66, 70),
    banner_permanent_bg: Color::Rgb(70, 60, 30),
    on_accent: Color::Black,
    light: false,
};

/// Solarized Dark — a contrast-balanced, color-theory-derived dark palette.
const SOLARIZED: Theme = Theme {
    accent: Color::Rgb(42, 161, 152),    // cyan
    zones: Color::Rgb(38, 139, 210),     // blue
    ports: Color::Rgb(133, 153, 0),      // green
    services: Color::Rgb(108, 113, 196), // violet
    rules: Color::Rgb(181, 137, 0),      // yellow
    forward: Color::Rgb(203, 75, 22),    // orange
    success: Color::Rgb(133, 153, 0),
    warning: Color::Rgb(181, 137, 0),
    danger: Color::Rgb(220, 50, 47), // red
    info: Color::Rgb(42, 161, 152),
    text: Color::Rgb(238, 232, 213),  // base2
    muted: Color::Rgb(131, 148, 150), // base0
    dim: Color::Rgb(88, 110, 117),    // base01
    bg_panel: Color::Rgb(7, 54, 66),  // base02
    bg_zebra: Color::Rgb(0, 43, 54),  // base03
    bg_selected: Color::Rgb(42, 58, 70),
    bg_active_tab: Color::Rgb(42, 58, 70),
    banner_runtime_bg: Color::Rgb(20, 60, 70),
    banner_permanent_bg: Color::Rgb(70, 55, 25),
    on_accent: Color::Black,
    light: false,
};

/// All built-in themes, in display order. Index 0 is the default.
pub const THEMES: [Theme; 9] = [
    DARK, LIGHT, DRACULA, NORD, GRUVBOX, MOCHA, LATTE, MONOKAI, SOLARIZED,
];

/// Human-readable names, parallel to [`THEMES`]. Used for persistence and the
/// "Theme: …" log line.
pub const THEME_NAMES: [&str; 9] = [
    "dark",
    "light",
    "dracula",
    "nord",
    "gruvbox",
    "mocha",
    "latte",
    "monokai",
    "solarized",
];

/// Which theme is active: an index into [`THEMES`] (0 = dark, the default).
static CURRENT: AtomicU8 = AtomicU8::new(0);

/// The index of the active theme (clamped to a valid range).
pub fn current_index() -> usize {
    let i = CURRENT.load(Ordering::Relaxed) as usize;
    i.min(THEMES.len() - 1)
}

/// The currently active palette.
pub fn current() -> &'static Theme {
    &THEMES[current_index()]
}

/// The name of the currently active theme (e.g. `"dracula"`).
pub fn current_name() -> &'static str {
    THEME_NAMES[current_index()]
}

/// Switch to the theme at `index` (out-of-range values are clamped).
pub fn set_theme(index: usize) {
    CURRENT.store(index.min(THEMES.len() - 1) as u8, Ordering::Relaxed);
}

/// Switch to a theme by name (case-insensitive). Returns true if a theme with
/// that name exists. Unknown names leave the current theme unchanged.
pub fn set_theme_by_name(name: &str) -> bool {
    let i = THEME_NAMES
        .iter()
        .position(|n| n.eq_ignore_ascii_case(name));
    match i {
        Some(i) => {
            CURRENT.store(i as u8, Ordering::Relaxed);
            true
        }
        None => false,
    }
}

/// Advance to the next theme (wrapping around) and return its name.
pub fn next() -> &'static str {
    let i = (current_index() + 1) % THEMES.len();
    CURRENT.store(i as u8, Ordering::Relaxed);
    THEME_NAMES[i]
}

/// True when the active palette has a light background.
pub fn is_light() -> bool {
    current().light
}

// ── Color accessors (read the active palette) ───────────────────────────────
pub fn accent() -> Color {
    current().accent
}
pub fn zones() -> Color {
    current().zones
}
pub fn ports() -> Color {
    current().ports
}
pub fn services() -> Color {
    current().services
}
pub fn rules() -> Color {
    current().rules
}
pub fn forward() -> Color {
    current().forward
}
pub fn success() -> Color {
    current().success
}
pub fn warning() -> Color {
    current().warning
}
pub fn danger() -> Color {
    current().danger
}
pub fn info() -> Color {
    current().info
}
pub fn text() -> Color {
    current().text
}
pub fn muted() -> Color {
    current().muted
}
pub fn dim() -> Color {
    current().dim
}
pub fn bg_panel() -> Color {
    current().bg_panel
}
pub fn bg_zebra() -> Color {
    current().bg_zebra
}
pub fn bg_selected() -> Color {
    current().bg_selected
}
pub fn bg_active_tab() -> Color {
    current().bg_active_tab
}
pub fn banner_runtime_bg() -> Color {
    current().banner_runtime_bg
}
pub fn banner_permanent_bg() -> Color {
    current().banner_permanent_bg
}
pub fn on_accent() -> Color {
    current().on_accent
}

// ── Style helpers (theme-agnostic) ──────────────────────────────────────────

/// Bold text in the given color.
pub fn bold(color: Color) -> Style {
    Style::default().fg(color).add_modifier(Modifier::BOLD)
}

/// Plain text in the given color.
pub fn fg(color: Color) -> Style {
    Style::default().fg(color)
}

/// A colored border style.
pub fn border(color: Color) -> Style {
    Style::default().fg(color)
}

/// The accent color associated with a tab, used to tie the tab pill, the
/// panel border, and the panel title together.
pub fn tab_color(tab: crate::types::Tab) -> Color {
    use crate::types::Tab;
    let t = current();
    match tab {
        Tab::Zones => t.zones,
        Tab::Ports => t.ports,
        Tab::Services => t.services,
        Tab::Rules => t.rules,
        Tab::Forward => t.forward,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn themes_and_names_are_parallel() {
        assert_eq!(THEMES.len(), THEME_NAMES.len());
        assert_eq!(THEME_NAMES[0], "dark");
        assert!(!THEMES[0].light);
        assert!(THEMES[1].light);
    }

    // The stateful assertions share the process-wide CURRENT atomic, so they
    // live in a single test to avoid cross-test interference under parallelism.
    #[test]
    fn theme_selection_and_cycling() {
        // Unknown names are a no-op and return false.
        assert!(!set_theme_by_name("no-such-theme"));
        // Case-insensitive match.
        assert!(set_theme_by_name("DrAcUla"));
        assert_eq!(current_name(), "dracula");
        assert!(!is_light());
        // A light theme is detected.
        assert!(set_theme_by_name("latte"));
        assert_eq!(current_name(), "latte");
        assert!(is_light());
        // next() advances forward and, after a full lap, wraps back to the start.
        set_theme(0);
        assert_eq!(next(), "light");
        for _ in 1..THEMES.len() {
            next();
        }
        assert_eq!(current_index(), 0);
        assert_eq!(current_name(), "dark");
    }
}
