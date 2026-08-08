//! Navigation helpers — the [`adw::ViewStack`] the sections live in.
//!
//! There used to be an `AdwViewSwitcher` builder here too, feeding a tab
//! strip in the header bar. The redesign replaced that with a navigation
//! sidebar ([`crate::ui::shell`]): a tab strip works for three or four
//! destinations and stops working past that, and the section list is now ten.

use libadwaita as adw;

/// Build an empty [`adw::ViewStack`] to hold the top-level sections.
///
/// Pages are added by the caller with [`adw::ViewStack::add_titled`], and
/// switched by [`crate::ui::shell`] using the child names.
pub fn build_view_stack() -> adw::ViewStack {
    adw::ViewStack::new()
}
