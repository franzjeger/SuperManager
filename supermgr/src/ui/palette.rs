//! Make the application follow the desktop's colour scheme.
//!
//! # The problem this exists to solve
//!
//! libadwaita does not follow the GTK theme. That is a deliberate decision on
//! its part, not a configuration mistake: it ships the Adwaita stylesheet and
//! renders with it regardless of what `gtk-theme-name` says, so that GNOME
//! applications look the same everywhere. The consequence on a Plasma desktop
//! is that a libadwaita application looks like GNOME sitting in the middle of
//! Breeze, no matter which GTK theme the user has selected.
//!
//! What libadwaita *does* support is overriding its
//! [named colours](https://gnome.pages.gitlab.gnome.org/libadwaita/doc/main/named-colors.html)
//! with a CSS provider at a priority above the theme. That is the supported
//! escape hatch, and it is what this module uses.
//!
//! # Where the colours come from
//!
//! Plasma stores the active colour scheme in `kdeglobals`, in the same INI
//! form the scheme files themselves use. Reading it means the application
//! follows *the user's* scheme — Breeze, Breeze Dark, or whatever they have
//! built themselves — and their accent colour, rather than an approximation
//! of Breeze frozen into the source at the time somebody looked at it.
//!
//! That distinction matters. Hardcoding Breeze's `#3daee9` would look right
//! on the default scheme and wrong on every other, and would stop tracking
//! the accent the moment it was changed. Reading the scheme cannot drift.
//!
//! # When it does nothing
//!
//! On a desktop that is not Plasma, or with no readable `kdeglobals`, or with
//! `SUPERMGR_NO_DESKTOP_COLORS` set, [`desktop_palette`] returns `None` and
//! the application keeps stock Adwaita. Following a colour scheme that the
//! surrounding desktop does not use would be worse than not following one.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Colours
// ---------------------------------------------------------------------------

/// An 8-bit RGB colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rgb {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Rgb {
    /// Parse KDE's `r,g,b` form. A fourth component (alpha) is accepted and
    /// ignored, because some schemes carry one.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let mut parts = value.split(',').map(|p| p.trim().parse::<u8>());
        let r = parts.next()?.ok()?;
        let g = parts.next()?.ok()?;
        let b = parts.next()?.ok()?;
        // A fourth field is alpha; anything beyond that is not a colour.
        if parts.next().is_some_and(|p| p.is_err()) || parts.next().is_some() {
            return None;
        }
        Some(Self { r, g, b })
    }

    /// CSS form.
    #[must_use]
    pub fn css(self) -> String {
        format!("#{:02x}{:02x}{:02x}", self.r, self.g, self.b)
    }

    /// Perceived brightness, 0.0–1.0.
    ///
    /// Rec. 601 luma, which is what everything else uses to decide "is this
    /// scheme dark", so this agrees with the rest of the desktop.
    #[must_use]
    pub fn luma(self) -> f64 {
        (0.299 * f64::from(self.r) + 0.587 * f64::from(self.g) + 0.114 * f64::from(self.b))
            / 255.0
    }
}

// ---------------------------------------------------------------------------
// The palette
// ---------------------------------------------------------------------------

/// The parts of a KDE colour scheme this application needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Palette {
    pub window_bg: Rgb,
    pub window_fg: Rgb,
    pub view_bg: Rgb,
    pub view_fg: Rgb,
    pub header_bg: Rgb,
    pub header_fg: Rgb,
    pub accent_bg: Rgb,
    pub accent_fg: Rgb,
    pub negative: Rgb,
    pub neutral: Rgb,
    pub positive: Rgb,
}

impl Palette {
    /// Whether this is a dark scheme.
    ///
    /// Decided from the window background rather than from the scheme's
    /// name: "Breeze Dark" is one scheme out of many, and a user-built dark
    /// scheme called something else is still dark.
    #[must_use]
    pub fn is_dark(&self) -> bool {
        self.window_bg.luma() < 0.5
    }

    /// The CSS that maps this scheme onto libadwaita's named colours.
    ///
    /// Only colours are redefined. No widget is restyled, no metric is
    /// changed, no selector is written: libadwaita keeps its own spacing,
    /// its own corner radii and its own layout, and only stops being the
    /// wrong colour for the desktop it is running on.
    #[must_use]
    pub fn to_css(&self) -> String {
        let mut css = String::new();
        let mut def = |name: &str, colour: Rgb| {
            css.push_str(&format!("@define-color {name} {};\n", colour.css()));
        };

        // Surfaces.
        //
        // The mapping follows what Breeze itself does rather than what the
        // names suggest. In Dolphin the places sidebar is the *Window*
        // colour and the file list beside it is the *View* colour — lighter
        // chrome around a darker working area in the dark scheme, and the
        // reverse in the light one. libadwaita's own defaults are the other
        // way round, so taking the names at face value produces a sidebar
        // and a content pane that are the same tone with no seam between
        // them.
        def("window_bg_color", self.view_bg);
        def("window_fg_color", self.view_fg);
        def("view_bg_color", self.view_bg);
        def("view_fg_color", self.view_fg);
        def("headerbar_bg_color", self.header_bg);
        def("headerbar_fg_color", self.header_fg);
        def("headerbar_backdrop_color", self.header_bg);
        def("sidebar_bg_color", self.window_bg);
        def("sidebar_fg_color", self.window_fg);
        def("sidebar_backdrop_color", self.window_bg);
        def("secondary_sidebar_bg_color", self.window_bg);
        def("secondary_sidebar_fg_color", self.window_fg);
        // Cards sit above the working area, so they take the chrome colour
        // for the same reason the sidebar does.
        def("card_bg_color", self.window_bg);
        def("card_fg_color", self.window_fg);
        def("dialog_bg_color", self.window_bg);
        def("dialog_fg_color", self.window_fg);
        def("popover_bg_color", self.window_bg);
        def("popover_fg_color", self.window_fg);

        // Semantic colours. `_bg_` is the filled variant behind a button;
        // the bare name is the standalone one used for text, which is what
        // the status pills and the `.error` / `.success` classes pick up.
        for (prefix, colour, fg) in [
            ("accent", self.accent_bg, self.accent_fg),
            ("destructive", self.negative, self.window_bg),
            ("error", self.negative, self.window_bg),
            ("warning", self.neutral, self.window_bg),
            ("success", self.positive, self.window_bg),
        ] {
            def(&format!("{prefix}_bg_color"), colour);
            def(&format!("{prefix}_fg_color"), fg);
            def(&format!("{prefix}_color"), colour);
        }

        // Borders follow the foreground rather than being their own colour,
        // so they stay visible in both light and dark schemes without a
        // second value to keep in step.
        css.push_str("@define-color borders alpha(currentColor, 0.15);\n");
        css.push_str(SHAPE);
        css
    }
}

/// The one place this module says anything that is not a colour.
///
/// Breeze corners are 3px. libadwaita's are 12, and its primary buttons are
/// full pills, which is the single loudest thing that still reads as GNOME
/// once the palette is right — a stadium-shaped button does not appear
/// anywhere in Breeze.
///
/// Deliberately confined to radii on standard GTK elements. Restyling
/// libadwaita's widgets properly would mean re-implementing them, which is
/// how a theme ends up broken by the next libadwaita release; changing a
/// corner radius cannot break a layout.
const SHAPE: &str = "
button, entry, spinbutton, .card, .boxed-list, popover > contents,
.osd, textview, scrolledwindow.frame, .supermgr-pill {
    border-radius: 3px;
}
button.pill, button.circular {
    border-radius: 3px;
}
.supermgr-badge {
    border-radius: 2px;
}
";

// ---------------------------------------------------------------------------
// Reading kdeglobals
// ---------------------------------------------------------------------------

/// Parse the sections of a `kdeglobals` this application cares about.
///
/// Returns `None` unless the file carries a real colour scheme. A partial
/// palette is worse than none: half the application would follow Breeze and
/// the other half would stay Adwaita, which looks like a rendering fault
/// rather than a theme.
#[must_use]
pub fn parse(ini: &str) -> Option<Palette> {
    let sections = split_sections(ini);
    let get = |section: &str, key: &str| -> Option<Rgb> {
        sections.get(section)?.get(key).and_then(|v| Rgb::parse(v))
    };

    // Without these two nothing else can be positioned against anything, so
    // their absence means this file is not a colour scheme.
    let window_bg = get("Colors:Window", "BackgroundNormal")?;
    let window_fg = get("Colors:Window", "ForegroundNormal")?;

    let view_bg = get("Colors:View", "BackgroundNormal").unwrap_or(window_bg);
    let view_fg = get("Colors:View", "ForegroundNormal").unwrap_or(window_fg);

    // `Colors:Header` arrived in Plasma 5.19. Before that the titlebar took
    // the window colour, which is still the right fallback.
    let header_bg = get("Colors:Header", "BackgroundNormal").unwrap_or(window_bg);
    let header_fg = get("Colors:Header", "ForegroundNormal").unwrap_or(window_fg);

    // Plasma 6 puts the user's accent in `[General] AccentColor`, and it
    // wins: `Colors:Selection` is the scheme's own selection colour, which
    // an accent override does not rewrite.
    let accent_bg = sections
        .get("General")
        .and_then(|g| g.get("AccentColor"))
        .and_then(|v| Rgb::parse(v))
        .or_else(|| get("Colors:Selection", "BackgroundNormal"))?;
    let accent_fg = get("Colors:Selection", "ForegroundNormal")
        .unwrap_or(Rgb { r: 255, g: 255, b: 255 });

    Some(Palette {
        window_bg,
        window_fg,
        view_bg,
        view_fg,
        header_bg,
        header_fg,
        accent_bg,
        accent_fg,
        negative: get("Colors:Window", "ForegroundNegative")
            .unwrap_or(Rgb { r: 218, g: 68, b: 83 }),
        neutral: get("Colors:Window", "ForegroundNeutral")
            .unwrap_or(Rgb { r: 246, g: 116, b: 0 }),
        positive: get("Colors:Window", "ForegroundPositive")
            .unwrap_or(Rgb { r: 39, g: 174, b: 96 }),
    })
}

/// Split an INI body into `section -> key -> value`.
///
/// Deliberately tolerant: `kdeglobals` is written by several different
/// programs over the years and carries keys this does not understand. What
/// it must not do is mistake one section's key for another's.
fn split_sections(ini: &str) -> HashMap<String, HashMap<String, String>> {
    let mut sections: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut current = String::new();
    for line in ini.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            current = name.to_owned();
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            sections
                .entry(current.clone())
                .or_default()
                .insert(key.trim().to_owned(), value.trim().to_owned());
        }
    }
    sections
}

/// The colour scheme `kdeglobals` names, if it names one.
///
/// `[General] ColorScheme=BreezeDark` is a *reference*. Plasma writes the
/// resolved `[Colors:*]` sections into `kdeglobals` when a scheme is applied
/// through System Settings, but a machine whose scheme has never been
/// switched — or one set up by copying a config, or by a distribution
/// default — carries the name and nothing else. Reading only the inline
/// sections works on the first kind of machine and silently does nothing on
/// the second, which is the difference between "it follows Breeze" and "it
/// still looks like GNOME".
#[must_use]
pub fn scheme_name(ini: &str) -> Option<String> {
    split_sections(ini)
        .get("General")?
        .get("ColorScheme")
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// Candidate paths for a named scheme's `.colors` file.
///
/// The file name has the scheme's spaces removed — "Breeze Dark" lives in
/// `BreezeDark.colors` — but both spellings are tried, because a
/// hand-written scheme can be named anything its author liked.
#[must_use]
pub fn scheme_file_candidates(name: &str) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        if !xdg.is_empty() {
            dirs.push(Path::new(&xdg).join("color-schemes"));
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            dirs.push(Path::new(&home).join(".local/share/color-schemes"));
        }
    }
    for extra in std::env::var("XDG_DATA_DIRS")
        .unwrap_or_else(|_| "/usr/local/share:/usr/share".to_owned())
        .split(':')
        .filter(|d| !d.is_empty())
    {
        dirs.push(Path::new(extra).join("color-schemes"));
    }

    let squashed = name.replace(' ', "");
    let mut out = Vec::new();
    for dir in dirs {
        for stem in [squashed.as_str(), name] {
            let candidate = dir.join(format!("{stem}.colors"));
            if !out.contains(&candidate) {
                out.push(candidate);
            }
        }
    }
    out
}

/// Where `kdeglobals` lives, honouring `XDG_CONFIG_HOME`.
#[must_use]
pub fn kdeglobals_path() -> Option<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Some(Path::new(&xdg).join("kdeglobals"));
        }
    }
    std::env::var("HOME")
        .ok()
        .filter(|h| !h.is_empty())
        .map(|home| Path::new(&home).join(".config").join("kdeglobals"))
}

/// Whether this session is a Plasma one.
///
/// `XDG_CURRENT_DESKTOP` is a colon-separated list, and Plasma sets it to
/// `KDE`. Checking it is what keeps a stale `kdeglobals` on a GNOME machine
/// — left behind by one KDE application installed years ago — from
/// repainting the whole interface.
#[must_use]
pub fn is_plasma_session(current_desktop: &str) -> bool {
    current_desktop
        .split(':')
        .any(|part| part.eq_ignore_ascii_case("KDE"))
}

/// Override a palette's accent with the user's, if they have set one.
///
/// The accent lives in `kdeglobals` even when the colours come from a scheme
/// file, because Plasma 6 lets it be changed without editing the scheme. Read
/// only the scheme file and every user who picked their own accent gets
/// Breeze's blue instead.
fn apply_accent_override(mut palette: Palette, kdeglobals: &str) -> Palette {
    if let Some(accent) = split_sections(kdeglobals)
        .get("General")
        .and_then(|g| g.get("AccentColor"))
        .and_then(|v| Rgb::parse(v))
    {
        palette.accent_bg = accent;
    }
    palette
}

/// The desktop's palette, if this desktop has one worth following.
///
/// Logs why it gave up when it does, because a palette that silently does
/// nothing is indistinguishable from one that is not there — and the symptom
/// is "the application still looks like GNOME", which says nothing about the
/// cause. `RUST_LOG=supermgr=debug` prints the whole decision.
#[must_use]
pub fn desktop_palette() -> Option<Palette> {
    if std::env::var_os("SUPERMGR_NO_DESKTOP_COLORS").is_some() {
        tracing::debug!("desktop colours disabled by SUPERMGR_NO_DESKTOP_COLORS");
        return None;
    }
    let desktop = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
    if !is_plasma_session(&desktop) {
        tracing::debug!(
            xdg_current_desktop = %desktop,
            "not a Plasma session; keeping the stock stylesheet"
        );
        return None;
    }

    let Some(path) = kdeglobals_path() else {
        tracing::debug!("no HOME or XDG_CONFIG_HOME; cannot locate kdeglobals");
        return None;
    };
    let Ok(ini) = std::fs::read_to_string(&path) else {
        tracing::debug!(path = %path.display(), "kdeglobals is not readable");
        return None;
    };

    // The colours are inline when Plasma has written them there.
    if let Some(palette) = parse(&ini) {
        tracing::debug!(path = %path.display(), "colour scheme read from kdeglobals");
        return Some(palette);
    }

    // Otherwise kdeglobals only names the scheme, and the colours are in the
    // file it names.
    let Some(name) = scheme_name(&ini) else {
        tracing::debug!(
            path = %path.display(),
            "kdeglobals carries neither colours nor a scheme name"
        );
        return None;
    };
    for candidate in scheme_file_candidates(&name) {
        let Ok(scheme) = std::fs::read_to_string(&candidate) else {
            continue;
        };
        if let Some(palette) = parse(&scheme) {
            tracing::debug!(
                scheme = %name,
                path = %candidate.display(),
                "colour scheme read from its scheme file"
            );
            return Some(apply_accent_override(palette, &ini));
        }
    }
    tracing::debug!(scheme = %name, "named colour scheme could not be found on disk");
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real Breeze Dark, trimmed to the sections that matter plus a couple
    // of the ones that do not, because the parser has to skip those too.
    const BREEZE_DARK: &str = "\
[General]
ColorScheme=BreezeDark
Name=Breeze Dark
AccentColor=61,174,233

[KDE]
LookAndFeelPackage=org.kde.breezedark.desktop

[Colors:Window]
BackgroundNormal=49,54,59
ForegroundNormal=252,252,252
ForegroundNegative=218,68,83
ForegroundNeutral=246,116,0
ForegroundPositive=39,174,96

[Colors:View]
BackgroundNormal=27,30,32
ForegroundNormal=252,252,252

[Colors:Header]
BackgroundNormal=42,46,50
ForegroundNormal=252,252,252

[Colors:Selection]
BackgroundNormal=61,174,233
ForegroundNormal=255,255,255
";

    const BREEZE_LIGHT: &str = "\
[Colors:Window]
BackgroundNormal=239,240,241
ForegroundNormal=35,38,39

[Colors:View]
BackgroundNormal=252,252,252
ForegroundNormal=35,38,39

[Colors:Selection]
BackgroundNormal=61,174,233
ForegroundNormal=255,255,255
";

    #[test]
    fn a_breeze_dark_scheme_is_read_whole() {
        let p = parse(BREEZE_DARK).expect("a palette");
        assert_eq!(p.window_bg, Rgb { r: 49, g: 54, b: 59 });
        assert_eq!(p.view_bg, Rgb { r: 27, g: 30, b: 32 });
        assert_eq!(p.header_bg, Rgb { r: 42, g: 46, b: 50 });
        assert_eq!(p.accent_bg, Rgb { r: 61, g: 174, b: 233 });
        assert_eq!(p.negative, Rgb { r: 218, g: 68, b: 83 });
        assert!(p.is_dark());
    }

    #[test]
    fn dark_and_light_are_told_apart_by_the_colour_not_the_name() {
        // The light snippet carries no `ColorScheme=` at all. A scheme a user
        // built themselves usually does not say "Light" anywhere either.
        assert!(!parse(BREEZE_LIGHT).expect("a palette").is_dark());
        assert!(parse(BREEZE_DARK).expect("a palette").is_dark());
    }

    #[test]
    fn a_key_belongs_only_to_its_own_section() {
        // Every section in kdeglobals has a `BackgroundNormal`. Letting one
        // leak into another would paint the window in the tooltip's colour
        // and be very hard to explain afterwards.
        let ini = "\
[Colors:Window]
BackgroundNormal=1,1,1
ForegroundNormal=2,2,2

[Colors:Tooltip]
BackgroundNormal=3,3,3

[Colors:View]
BackgroundNormal=4,4,4

[Colors:Selection]
BackgroundNormal=5,5,5
";
        let p = parse(ini).expect("a palette");
        assert_eq!(p.window_bg, Rgb { r: 1, g: 1, b: 1 });
        assert_eq!(p.view_bg, Rgb { r: 4, g: 4, b: 4 });
        assert_eq!(p.accent_bg, Rgb { r: 5, g: 5, b: 5 });
        // The tooltip's background reached none of them.
        assert_ne!(p.header_bg, Rgb { r: 3, g: 3, b: 3 });
    }

    #[test]
    fn the_users_accent_beats_the_schemes_selection_colour() {
        // Plasma 6 lets the accent be changed without editing the scheme, so
        // `Colors:Selection` still holds Breeze's blue while `AccentColor`
        // holds what the user actually picked.
        let ini = format!("{BREEZE_DARK}\n[General]\nAccentColor=255,0,128\n");
        assert_eq!(parse(&ini).expect("a palette").accent_bg, Rgb { r: 255, g: 0, b: 128 });
    }

    #[test]
    fn a_file_that_is_not_a_colour_scheme_yields_nothing() {
        // Half a palette is worse than none: it would leave the application
        // half Breeze and half Adwaita, which reads as a rendering fault.
        assert!(parse("").is_none());
        assert!(parse("[General]\nColorScheme=BreezeDark\n").is_none());
        // Background without foreground is not enough to position anything.
        assert!(parse("[Colors:Window]\nBackgroundNormal=1,2,3\n").is_none());
    }

    #[test]
    fn a_malformed_colour_is_not_guessed_at() {
        assert_eq!(Rgb::parse("61,174,233"), Some(Rgb { r: 61, g: 174, b: 233 }));
        // Alpha is carried by some schemes and is not a fourth channel we use.
        assert_eq!(Rgb::parse("61,174,233,255"), Some(Rgb { r: 61, g: 174, b: 233 }));
        for bad in ["", "61,174", "61,174,300", "#3daee9", "61,174,233,255,1", "a,b,c"] {
            assert_eq!(Rgb::parse(bad), None, "{bad:?} was accepted");
        }
    }

    #[test]
    fn nothing_but_colours_and_corners_is_restyled() {
        // The argument for overriding named colours rather than shipping a
        // Breeze stylesheet is that it cannot break: a colour is a value,
        // not a layout. `SHAPE` is the one concession, and it is only
        // allowed to set corner radii — a radius cannot break a layout
        // either.
        //
        // Anything else (padding, min-height, background, box-shadow, a
        // libadwaita internal element) would be re-implementing widgets this
        // application does not own, which is how a theme ends up broken by
        // the next libadwaita release. So the guard is on the property, not
        // on the selector.
        let css = parse(BREEZE_DARK).expect("a palette").to_css();
        for line in css.lines().map(str::trim).filter(|l| !l.is_empty()) {
            if line.starts_with("@define-color ") {
                continue;
            }
            // A selector line, or the brace closing one.
            if line.ends_with('{') || line == "}" || line.ends_with(',') {
                continue;
            }
            let property = line.split(':').next().unwrap_or(line).trim();
            assert_eq!(
                property, "border-radius",
                "the palette sets something other than a colour or a corner: {line}"
            );
        }
    }

    #[test]
    fn the_pill_shape_is_flattened() {
        // libadwaita's `.pill` is a stadium. Nothing in Breeze is, and it is
        // the loudest remaining GNOME tell once the colours are right.
        let css = parse(BREEZE_DARK).expect("a palette").to_css();
        assert!(css.contains("button.pill"), "{css}");
    }

    #[test]
    fn every_colour_libadwaita_needs_is_defined() {
        // Any one of these left undefined falls back to Adwaita's value, and
        // one Adwaita surface in the middle of a Breeze window is more
        // jarring than all of them being Adwaita.
        let css = parse(BREEZE_DARK).expect("a palette").to_css();
        for name in [
            "window_bg_color",
            "window_fg_color",
            "view_bg_color",
            "view_fg_color",
            "headerbar_bg_color",
            "sidebar_bg_color",
            "card_bg_color",
            "dialog_bg_color",
            "popover_bg_color",
            "accent_bg_color",
            "accent_color",
            "destructive_bg_color",
            "error_color",
            "warning_color",
            "success_color",
            "borders",
        ] {
            assert!(
                css.contains(&format!("@define-color {name} ")),
                "{name} is not defined:\n{css}"
            );
        }
    }

    #[test]
    fn the_status_colours_come_from_the_scheme_not_from_adwaita() {
        // `design::Status` renders through `.success` / `.warning` /
        // `.error`, which resolve to these. If they kept Adwaita's values the
        // pills would be the one part of the window that still looked like
        // GNOME.
        let css = parse(BREEZE_DARK).expect("a palette").to_css();
        assert!(css.contains("@define-color success_color #27ae60;"), "{css}");
        assert!(css.contains("@define-color warning_color #f67400;"), "{css}");
        assert!(css.contains("@define-color error_color #da4453;"), "{css}");
        assert!(css.contains("@define-color accent_color #3daee9;"), "{css}");
    }

    #[test]
    fn a_kdeglobals_that_only_names_a_scheme_still_names_it() {
        // The case that made the whole module do nothing on a real machine:
        // Plasma writes the resolved `[Colors:*]` sections into kdeglobals
        // when a scheme is applied through System Settings, but a desktop
        // whose scheme has never been switched carries the name alone. The
        // colours are in the file it points at.
        let ini = "[General]\nColorScheme=Breeze Dark\n";
        assert!(parse(ini).is_none(), "there are no colours here to read");
        assert_eq!(scheme_name(ini).as_deref(), Some("Breeze Dark"));
    }

    #[test]
    fn a_scheme_name_is_looked_for_under_both_spellings() {
        // "Breeze Dark" lives in `BreezeDark.colors`. A scheme somebody
        // wrote themselves may well keep its spaces.
        let candidates = scheme_file_candidates("Breeze Dark");
        let names: Vec<String> = candidates
            .iter()
            .filter_map(|p| p.file_name()?.to_str().map(str::to_owned))
            .collect();
        assert!(names.iter().any(|n| n == "BreezeDark.colors"), "{names:?}");
        assert!(names.iter().any(|n| n == "Breeze Dark.colors"), "{names:?}");
        // And it looks in the system directories, not only the user's.
        assert!(
            candidates.iter().any(|p| p.starts_with("/usr/share")),
            "{candidates:?}"
        );
    }

    #[test]
    fn no_scheme_name_is_not_an_empty_scheme_name() {
        assert_eq!(scheme_name(""), None);
        assert_eq!(scheme_name("[General]\nName=x\n"), None);
        // An empty value is not a scheme to go looking for on disk.
        assert_eq!(scheme_name("[General]\nColorScheme=\n"), None);
    }

    #[test]
    fn the_accent_survives_coming_from_a_different_file() {
        // The colours come from the scheme file, but Plasma 6 keeps the
        // accent in kdeglobals — so reading only the scheme file gives every
        // user who picked their own accent Breeze's blue instead of it.
        let from_scheme = parse(BREEZE_DARK).expect("a palette");
        let merged = apply_accent_override(from_scheme, "[General]\nAccentColor=201,63,152\n");
        assert_eq!(merged.accent_bg, Rgb { r: 201, g: 63, b: 152 });
        // Everything else still comes from the scheme.
        assert_eq!(merged.window_bg, Rgb { r: 49, g: 54, b: 59 });
    }

    #[test]
    fn a_kdeglobals_with_no_accent_leaves_the_schemes_own() {
        let from_scheme = parse(BREEZE_DARK).expect("a palette");
        let merged = apply_accent_override(from_scheme, "[General]\nColorScheme=Breeze Dark\n");
        assert_eq!(merged.accent_bg, Rgb { r: 61, g: 174, b: 233 });
    }

    #[test]
    fn only_a_plasma_session_gets_repainted() {
        // A kdeglobals left behind by one KDE application on a GNOME machine
        // must not repaint everything.
        assert!(is_plasma_session("KDE"));
        assert!(is_plasma_session("kde"));
        assert!(is_plasma_session("KDE:X-Generic"));
        assert!(is_plasma_session("X-Generic:KDE"));
        assert!(!is_plasma_session("GNOME"));
        assert!(!is_plasma_session(""));
        // Not a substring match: this is a different desktop.
        assert!(!is_plasma_session("KDE-ish"));
    }
}
