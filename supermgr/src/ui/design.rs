//! The shared design language: one status vocabulary, one detail-pane
//! grammar, one set of primitives every section is built from.
//!
//! # Why this module exists
//!
//! The redesign brief names the problem precisely: *"inconsistent design
//! language between screens, dead space, generic empty states, an ambiguous
//! toolbar status, undifferentiated list rows, and inconsistent primary
//! actions."* Every one of those is what happens when each screen invents its
//! own layout. So the fix is not to restyle the screens — it is to give them
//! one vocabulary and build them all from it.
//!
//! Nothing here knows about VPN profiles or SSH hosts. It knows about
//! *statuses*, *rows*, *sections* and *empty states*, and every section
//! expresses itself in those terms.
//!
//! # System tokens, not hex
//!
//! The brief ships Breeze hex values and then says, twice, to prefer the
//! platform's own tokens where they exist:
//!
//! > prefer real Breeze widgets/Kirigami components and KDE color-scheme
//! > roles over hardcoded hex values
//!
//! That instruction applies here even though the toolkit is GTK rather than
//! Qt. Every colour below is a libadwaita style class — `.success`,
//! `.warning`, `.error`, `.accent`, `.dim-label` — which resolve against the
//! running theme and the user's accent colour. On a Plasma desktop with a
//! GTK theme following Breeze, that lands on Breeze's own palette; on GNOME
//! it lands on Adwaita's. Hardcoding `#3daee9` would look right on exactly
//! one configuration and wrong on every other, and would stop tracking the
//! user's own accent choice.
//!
//! # The dead-space fix
//!
//! The brief's detail pane is
//! `grid-template-columns: repeat(auto-fit, minmax(340px, 1fr))` — cards
//! reflow into as many columns as fit. That is the single change that stops
//! a 1900px window showing one narrow strip of content and an acre of
//! nothing. [`reflowing_columns`] is that rule.

use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;

// ---------------------------------------------------------------------------
// The status vocabulary
// ---------------------------------------------------------------------------

/// The one set of states anything in this application can be in.
///
/// The brief calls this the "unified 5-state status vocabulary" and uses it
/// for VPN tunnels, SSH hosts, Tailscale peers and provisioning runs alike.
/// Having one enum rather than a string per screen is what makes a status
/// pill mean the same thing everywhere — and what stops a sixth colour being
/// invented for the seventh screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Connected, online, reachable, succeeded.
    Connected,
    /// Deliberately not connected. Not a fault.
    Disconnected,
    /// In flight — connecting, scanning, applying.
    Connecting,
    /// Tried and failed.
    Error,
    /// Working, but not properly: partial results, stale data, warnings.
    Degraded,
    /// Never attempted, so nothing is known either way.
    Unknown,
}

impl Status {
    /// The libadwaita style class that colours this state.
    ///
    /// These follow the theme and the user's accent colour rather than
    /// naming a colour, which is what lets one build look native on both
    /// Breeze and Adwaita.
    #[must_use]
    pub fn style_class(self) -> &'static str {
        match self {
            Self::Connected => "success",
            Self::Disconnected => "dim-label",
            Self::Connecting | Self::Degraded => "warning",
            Self::Error => "error",
            Self::Unknown => "accent",
        }
    }

    /// The default label, when the caller has nothing more specific.
    ///
    /// Callers usually do have something better — "3 active", "never
    /// scanned", "handshake 4s ago" — and should pass it. This is the
    /// fallback, not the expectation.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Connected => "Connected",
            Self::Disconnected => "Disconnected",
            Self::Connecting => "Connecting…",
            Self::Error => "Error",
            Self::Degraded => "Degraded",
            Self::Unknown => "Unknown",
        }
    }

    /// Whether this state should draw attention.
    ///
    /// Used to decide whether a row deserves to be pulled to the top of a
    /// list, or whether the toolbar pill should be more than a dot. Neither
    /// "connected" nor "deliberately disconnected" is news.
    #[must_use]
    pub fn is_notable(self) -> bool {
        matches!(self, Self::Error | Self::Degraded | Self::Connecting)
    }

    /// A symbolic icon name for this state.
    #[must_use]
    pub fn icon_name(self) -> &'static str {
        match self {
            Self::Connected => "emblem-ok-symbolic",
            Self::Disconnected => "media-playback-stop-symbolic",
            Self::Connecting => "content-loading-symbolic",
            Self::Error => "dialog-error-symbolic",
            Self::Degraded => "dialog-warning-symbolic",
            Self::Unknown => "dialog-question-symbolic",
        }
    }
}

/// A status pill: a coloured dot and a short label.
///
/// The brief's toolbar problem was *"an ambiguous toolbar status"* — a
/// control that showed something was happening without saying what. A pill
/// always carries both a state and a count or phrase, so it can never be
/// ambiguous in that way.
#[must_use]
pub fn status_pill(status: Status, label: &str) -> gtk4::Box {
    let pill = gtk4::Box::new(gtk4::Orientation::Horizontal, 6);
    pill.add_css_class("supermgr-pill");
    pill.add_css_class(status.style_class());

    let dot = gtk4::Image::from_icon_name(status.icon_name());
    dot.set_pixel_size(12);
    pill.append(&dot);

    let text = gtk4::Label::new(Some(label));
    text.add_css_class("caption-heading");
    pill.append(&text);

    pill.set_tooltip_text(Some(status.label()));
    pill
}

/// A small tinted badge, for a backend name or a role.
///
/// Deliberately not colour-coded per backend. The brief gives WireGuard its
/// own teal and OpenVPN its own red, which works in a mock where every
/// colour is chosen at once; in a themed application it means six more
/// hardcoded colours competing with the status colours that carry actual
/// meaning. The badge stays neutral so the status pill is the only coloured
/// thing in a row, and therefore the thing the eye finds.
#[must_use]
pub fn badge(text: &str) -> gtk4::Label {
    let label = gtk4::Label::new(Some(text));
    label.add_css_class("supermgr-badge");
    label.add_css_class("caption");
    label.set_valign(gtk4::Align::Center);
    label
}

// ---------------------------------------------------------------------------
// The detail-pane grammar
// ---------------------------------------------------------------------------

/// A container whose children reflow into as many columns as fit.
///
/// This is the brief's `repeat(auto-fit, minmax(340px, 1fr))`, and it is the
/// single most important rule in the redesign: it is what stops a wide
/// window from showing one column of content and a screen of emptiness.
///
/// `FlowBox` rather than a `Grid` because the column count has to follow the
/// width, not be decided up front. Selection is off — these are cards, not
/// choices.
#[must_use]
pub fn reflowing_columns() -> gtk4::FlowBox {
    let flow = gtk4::FlowBox::new();
    flow.set_selection_mode(gtk4::SelectionMode::None);
    flow.set_valign(gtk4::Align::Start);
    flow.set_max_children_per_line(3);
    flow.set_min_children_per_line(1);
    flow.set_column_spacing(24);
    flow.set_row_spacing(24);
    flow.set_homogeneous(true);
    flow
}

/// Put a card into a reflowing column layout.
///
/// `FlowBox` wraps each child in a `FlowBoxChild` of its own, and that
/// wrapper does not inherit its child's visibility — so hiding a card the
/// plain way leaves an empty column sitting where it was.  Binding the two
/// means `card.set_visible(false)` removes the slot as well as the contents,
/// and the remaining cards close the gap.
pub fn add_card(flow: &gtk4::FlowBox, card: &impl IsA<gtk4::Widget>) {
    let card = card.as_ref();
    flow.append(card);
    if let Some(slot) = card.parent() {
        card.bind_property("visible", &slot, "visible")
            .sync_create()
            .build();
    }
}

/// The heading above a group of rows.
///
/// Small, uppercase, dimmed — the brief's "section caps". Its job is to be
/// findable when scanning and invisible when reading.
#[must_use]
pub fn section_caps(text: &str) -> gtk4::Label {
    let label = gtk4::Label::new(Some(&text.to_uppercase()));
    label.set_xalign(0.0);
    label.add_css_class("caption-heading");
    label.add_css_class("dim-label");
    label.set_margin_bottom(4);
    label
}

/// One card in the detail pane: a titled group of rows.
///
/// Every card in every section is this. `PreferencesGroup` gives the
/// bordered, rounded, separated-rows look for free, and gets it from the
/// theme rather than from a stylesheet here.
#[must_use]
pub fn card(title: &str) -> adw::PreferencesGroup {
    let group = adw::PreferencesGroup::new();
    if !title.is_empty() {
        group.set_title(title);
    }
    group
}

/// A label/value row — the brief's definition list.
///
/// Replaces the centred free-floating text the detail panes used to be made
/// of. A value that is an address, an ID or a fingerprint is monospaced and
/// selectable, because the only reason to look at one is to copy it.
///
/// Hands the value label back so the caller can update it, and binds the
/// row's visibility to the label's: a fact that has nothing to report hides
/// its own row rather than leaving a labelled blank behind.
#[must_use]
pub fn live_detail_row(label: &str, monospace: bool) -> (adw::ActionRow, gtk4::Label) {
    let row = adw::ActionRow::new();
    row.set_title(label);
    row.set_title_lines(1);

    let value_label = gtk4::Label::new(Some("\u{2014}"));
    value_label.set_selectable(true);
    value_label.set_xalign(1.0);
    value_label.add_css_class("dim-label");
    if monospace {
        value_label.add_css_class("monospace");
    }
    value_label.set_valign(gtk4::Align::Center);
    row.add_suffix(&value_label);

    value_label
        .bind_property("visible", &row, "visible")
        .sync_create()
        .build();
    (row, value_label)
}

/// A settings row wrapped around a switch that already exists.
///
/// The old detail panes put a bare label on the far left of a 1900px window
/// and its switch on the far right, with nothing in between and no hint of
/// what the setting did. This is an `AdwSwitchRow` in everything but
/// ownership: title and subtitle on the left, switch on the right, the whole
/// row toggles it — except the switch is one the caller already created and
/// already connected, so no handler has to move.
#[must_use]
pub fn toggle_row(switch: &gtk4::Switch, title: &str, subtitle: &str) -> adw::ActionRow {
    let row = adw::ActionRow::new();
    row.set_title(title);
    if !subtitle.is_empty() {
        row.set_subtitle(subtitle);
    }
    switch.set_valign(gtk4::Align::Center);
    row.add_suffix(switch);
    row.set_activatable_widget(Some(switch));
    // The switch is the thing callers already hold and already disable, so
    // it stays the source of truth: dimming it dims the whole row.
    switch
        .bind_property("sensitive", &row, "sensitive")
        .sync_create()
        .build();
    row
}

/// A row whose whole purpose is to be clicked, driving a button that already
/// exists.
///
/// The old panes rendered these as centred flat buttons — "Rename…",
/// "Rotate WireGuard Key…", "Export Profile…" — which read as labels rather
/// than as things that do something.  This keeps the button, because the
/// button is what the rest of the application connected its handler to, and
/// gives it a row to live in.
///
/// The button's `sensitive` and `visible` properties drive the row's, so
/// every existing `set_sensitive` / `set_visible` call keeps meaning exactly
/// what it meant.
#[must_use]
pub fn button_row(
    button: &gtk4::Button,
    title: &str,
    subtitle: &str,
    icon: &str,
) -> adw::ActionRow {
    let row = adw::ActionRow::new();
    row.set_title(title);
    if !subtitle.is_empty() {
        row.set_subtitle(subtitle);
    }
    if !icon.is_empty() {
        row.add_prefix(&gtk4::Image::from_icon_name(icon));
    }

    button.set_icon_name("go-next-symbolic");
    button.set_css_classes(&["flat"]);
    button.set_valign(gtk4::Align::Center);
    row.add_suffix(button);
    row.set_activatable_widget(Some(button));

    button
        .bind_property("sensitive", &row, "sensitive")
        .sync_create()
        .build();
    button
        .bind_property("visible", &row, "visible")
        .sync_create()
        .build();
    row
}

/// A [`button_row`] for something that destroys what it names.
#[must_use]
pub fn destructive_button_row(
    button: &gtk4::Button,
    title: &str,
    subtitle: &str,
    icon: &str,
) -> adw::ActionRow {
    let row = button_row(button, title, subtitle, icon);
    row.add_css_class("error");
    row
}

/// The header of a detail pane: title, status, and the actions that belong
/// to the whole object.
///
/// The brief's *"inconsistent primary actions"* problem was that each screen
/// put its main verb somewhere different. Here there is one place: the top
/// right of the header, first button, suggested-action styled. Everything
/// else is a row further down.
pub struct DetailHeader {
    /// The widget to pack at the top of the detail pane.
    pub widget: gtk4::Box,
    /// The object's name.
    pub title: gtk4::Label,
    /// Where the status pill goes; replace its child to update.
    pub status_slot: adw::Bin,
    /// Where secondary buttons go.
    pub actions: gtk4::Box,
}

impl DetailHeader {
    /// Build a detail header.
    #[must_use]
    pub fn new() -> Self {
        let widget = gtk4::Box::new(gtk4::Orientation::Horizontal, 12);
        widget.set_margin_bottom(18);

        let left = gtk4::Box::new(gtk4::Orientation::Vertical, 6);
        left.set_hexpand(true);
        left.set_valign(gtk4::Align::Center);

        let title = gtk4::Label::new(None);
        title.set_xalign(0.0);
        title.add_css_class("title-1");
        title.set_wrap(true);
        title.set_selectable(true);
        left.append(&title);

        let status_slot = adw::Bin::new();
        status_slot.set_halign(gtk4::Align::Start);
        left.append(&status_slot);

        widget.append(&left);

        let actions = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
        actions.set_valign(gtk4::Align::Center);
        widget.append(&actions);

        Self { widget, title, status_slot, actions }
    }
}

/// Put a status pill in a slot, replacing whatever was there.
///
/// The slot is an [`adw::Bin`] rather than a mutable pill because a pill's
/// colour comes from a style class, and swapping classes on a live widget
/// means remembering which one was on it last. Replacing the child cannot
/// leave a stale class behind.
pub fn set_pill(slot: &adw::Bin, status: Status, label: &str) {
    slot.set_child(Some(&status_pill(status, label)));
}

impl Default for DetailHeader {
    fn default() -> Self {
        Self::new()
    }
}

/// The scrollable body of a detail pane, already padded and reflowing.
///
/// Returns the scroller to pack into the pane, and the flow box to append
/// cards to. Padding is `26px` vertical and fluid horizontal, matching the
/// brief's `26px clamp(26px, 3.5vw, 56px)` closely enough that the
/// difference is not visible; GTK has no `clamp()`, so this takes the middle
/// value and lets the reflowing columns absorb the rest.
#[must_use]
pub fn detail_body() -> (gtk4::ScrolledWindow, gtk4::Box) {
    let content = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    content.set_margin_top(26);
    content.set_margin_bottom(26);
    content.set_margin_start(32);
    content.set_margin_end(32);

    let scroller = gtk4::ScrolledWindow::new();
    scroller.set_hscrollbar_policy(gtk4::PolicyType::Never);
    scroller.set_vexpand(true);
    scroller.set_child(Some(&content));

    (scroller, content)
}

// ---------------------------------------------------------------------------
// Empty states
// ---------------------------------------------------------------------------

/// An empty state that says what to do next.
///
/// The brief calls the old ones *"generic empty states"*. The difference is
/// entirely in the copy: "No profile selected" tells the operator nothing
/// they had not already worked out. Every caller of this passes a
/// description that names the next action, and usually a button that
/// performs it.
#[must_use]
pub fn empty_state(icon: &str, title: &str, description: &str) -> adw::StatusPage {
    let page = adw::StatusPage::new();
    page.set_icon_name(Some(icon));
    page.set_title(title);
    page.set_description(Some(description));
    page.set_vexpand(true);
    page
}

// ---------------------------------------------------------------------------
// Stylesheet
// ---------------------------------------------------------------------------

/// The only CSS this application ships.
///
/// Deliberately tiny, and deliberately free of colours. Everything here is
/// shape and spacing for the two widgets libadwaita has no equivalent of —
/// the status pill and the badge. Their colours come from the style classes
/// already on them, so they follow the theme.
pub const STYLESHEET: &str = "
.supermgr-pill {
    padding: 3px 10px 3px 8px;
    border-radius: 999px;
    background: alpha(currentColor, 0.12);
}
.supermgr-badge {
    padding: 1px 7px;
    border-radius: 4px;
    background: alpha(currentColor, 0.10);
    opacity: 0.85;
}
.supermgr-nav row {
    padding: 2px 0;
}
";

/// Install [`STYLESHEET`] for the default display.
///
/// # Panics
///
/// If there is no default display, which means there is no GUI to style and
/// nothing this function could usefully do instead.
pub fn install_stylesheet() {
    let provider = gtk4::CssProvider::new();
    provider.load_from_string(STYLESHEET);
    gtk4::style_context_add_provider_for_display(
        &gtk4::gdk::Display::default().expect("a display, since a window is being built"),
        &provider,
        gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    // Widget construction needs a display, which CI has not got. What is
    // worth testing here is the vocabulary itself: that the six states stay
    // distinguishable, and that nothing silently collapses two of them into
    // the same colour.

    #[test]
    fn every_status_has_a_style_class_and_a_label() {
        for status in [
            Status::Connected,
            Status::Disconnected,
            Status::Connecting,
            Status::Error,
            Status::Degraded,
            Status::Unknown,
        ] {
            assert!(!status.style_class().is_empty(), "{status:?}");
            assert!(!status.label().is_empty(), "{status:?}");
            assert!(!status.icon_name().is_empty(), "{status:?}");
        }
    }

    #[test]
    fn the_states_that_must_look_different_do() {
        // Connected, disconnected and error are the three an operator reads
        // at a glance across a list. If any two share a colour the list
        // stops being scannable, which is the problem the unified vocabulary
        // exists to fix.
        let distinct = [Status::Connected, Status::Disconnected, Status::Error];
        for (i, a) in distinct.iter().enumerate() {
            for b in &distinct[i + 1..] {
                assert_ne!(
                    a.style_class(),
                    b.style_class(),
                    "{a:?} and {b:?} render identically"
                );
            }
        }
    }

    #[test]
    fn connecting_and_degraded_share_a_colour_deliberately() {
        // Both mean "not settled yet, do not rely on this". The brief maps
        // them to the same orange. Asserted so that a later change to one of
        // them is a decision rather than a drift.
        assert_eq!(Status::Connecting.style_class(), Status::Degraded.style_class());
    }

    #[test]
    fn only_the_states_worth_interrupting_for_are_notable() {
        assert!(Status::Error.is_notable());
        assert!(Status::Degraded.is_notable());
        assert!(Status::Connecting.is_notable());
        // Neither of these is news: one is working, the other was asked to
        // stop. A list that pulls them to the top has no signal left.
        assert!(!Status::Connected.is_notable());
        assert!(!Status::Disconnected.is_notable());
        assert!(!Status::Unknown.is_notable());
    }

    #[test]
    fn the_stylesheet_names_no_colours() {
        // The whole argument for GTK-native styling is that colour comes
        // from the theme. A hex literal here would be a hardcoded Breeze
        // value that looks wrong everywhere else and stops following the
        // user's accent.
        assert!(
            !STYLESHEET.contains('#'),
            "the stylesheet hardcodes a colour:\n{STYLESHEET}"
        );
        for named in ["rgb(", "rgba(", "red", "blue", "green"] {
            assert!(
                !STYLESHEET.contains(named),
                "the stylesheet hardcodes '{named}':\n{STYLESHEET}"
            );
        }
    }
}
