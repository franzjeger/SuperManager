//! The lock screen.
//!
//! # What was here
//!
//! The page carried two primary actions side by side — "Unlock" and "Set
//! Password", both styled `suggested-action`, so both were green pills — plus
//! a confirmation field for the second one.
//!
//! The second one could not be reached. Every path that shows this page hides
//! it: the startup path hides it when a password is set, `lock_session` hides
//! it unconditionally, and when no password is set the window goes straight to
//! the application without showing the lock page at all. So "Set Password",
//! its confirmation field, its handler, and the `else if set_btn.is_visible()`
//! branch of the Enter-key handler were all dead — and each of the three call
//! sites independently repeated the same three lines to keep them that way.
//!
//! Setting a master password happens in Settings, which is where it works.
//! This page unlocks, which is all it was ever able to do, and now it says so
//! in one primary action with nothing beside it to be confused with.

use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;

use super::design;

/// Widgets composing the lock page.
#[derive(Clone)]
pub struct LockPage {
    pub container: gtk4::Widget,
    pub password_row: adw::PasswordEntryRow,
    pub unlock_btn: gtk4::Button,
    pub quit_btn: gtk4::Button,
    pub status_label: gtk4::Label,
}

/// Build the lock page.
#[must_use]
pub fn build() -> LockPage {
    let status_label = gtk4::Label::builder()
        .label(LOCKED)
        .wrap(true)
        .justify(gtk4::Justification::Center)
        .css_classes(["dim-label"])
        .build();

    let fields = design::card("");
    let password_row = adw::PasswordEntryRow::builder().title("Master password").build();
    fields.add(&password_row);

    // One primary action, in one place, as everywhere else in the
    // application. Quit is flat, because leaving is not what you came here
    // to do.
    let unlock_btn = gtk4::Button::builder()
        .label("Unlock")
        .css_classes(["suggested-action", "pill"])
        .build();
    let quit_btn = gtk4::Button::builder().label("Quit").css_classes(["flat"]).build();

    let actions = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
    actions.set_halign(gtk4::Align::Center);
    actions.append(&quit_btn);
    actions.append(&unlock_btn);

    let column = gtk4::Box::new(gtk4::Orientation::Vertical, 18);
    column.set_halign(gtk4::Align::Center);
    column.set_valign(gtk4::Align::Center);
    column.set_size_request(360, -1);
    column.append(&status_label);
    column.append(&fields);
    column.append(&actions);

    // The same `AdwStatusPage` shape every empty state in the application
    // uses, so the locked window looks like the same program as the unlocked
    // one rather than like a login screen that wandered in.
    let page = design::empty_state("system-lock-screen-symbolic", "SuperManager", "");
    page.set_child(Some(&column));

    LockPage { container: page.upcast(), password_row, unlock_btn, quit_btn, status_label }
}

/// Shown when the window opens locked.
pub const LOCKED: &str = "Enter your master password to unlock.";

/// Shown when the auto-lock timer has just locked an open session.
pub const AUTO_LOCKED: &str = "Session locked after inactivity. Enter your password.";

/// Shown after a wrong password.
pub const WRONG: &str = "Incorrect password.";

impl LockPage {
    /// Show the page, clearing whatever was typed last time.
    pub fn present(&self, reason: &str) {
        self.password_row.set_text("");
        self.status_label.set_text(reason);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_reason_the_window_locks_has_something_to_say() {
        // The page is a password field and a button in both cases. The line
        // above them is the only thing that distinguishes "you just started
        // this" from "you walked away for ten minutes", and a blank one
        // reads as a rendering fault.
        for reason in [LOCKED, AUTO_LOCKED, WRONG] {
            assert!(!reason.is_empty());
        }
    }

    #[test]
    fn the_reasons_are_told_apart() {
        // Reusing one string for all three would make the screen say the
        // same thing whether you had mistyped or merely arrived.
        assert_ne!(LOCKED, AUTO_LOCKED);
        assert_ne!(LOCKED, WRONG);
        assert_ne!(AUTO_LOCKED, WRONG);
    }
}
