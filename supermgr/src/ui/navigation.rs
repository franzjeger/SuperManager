//! Navigation helpers — [`AdwViewStack`] and [`AdwViewSwitcher`] builders.

use libadwaita as adw;

/// Build an empty [`adw::ViewStack`] to hold the top-level VPN and SSH pages.
///
/// Pages are added by the caller with [`adw::ViewStack::add_titled`].
pub fn build_view_stack() -> adw::ViewStack {
    adw::ViewStack::new()
}

/// Build a wide-mode [`adw::ViewSwitcher`] linked to the given stack.
///
/// The switcher is placed in the header bar so the user can toggle between
/// the VPN and SSH sections.
pub fn build_view_switcher(stack: &adw::ViewStack) -> adw::ViewSwitcher {
    adw::ViewSwitcher::builder()
        .stack(stack)
        .policy(adw::ViewSwitcherPolicy::Wide)
        .build()
}
