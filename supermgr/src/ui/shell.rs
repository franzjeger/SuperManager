//! The application shell: a navigation sidebar, and the section it shows.
//!
//! # What changed, and why
//!
//! The window used to put its sections in an `AdwViewSwitcher` in the header
//! bar — six tabs across the top, which is a pattern that works for three or
//! four destinations and stops working past that. The brief replaces it with
//! the first of its three columns:
//!
//! > | Nav sidebar | 152 pt | column 1, `List` of destinations under a
//! > "Manage" section header |
//!
//! A sidebar list has room for names, room for a count or a status dot
//! beside each name, and room to grow. A tab strip has none of those, which
//! is why the eight sections the brief asks for would not have fitted in the
//! old chrome at all.
//!
//! # The section list is not quite the brief's
//!
//! The brief names eight: Fleet, SSH, VPN, Tailscale, Compliance,
//! Provisioning, Security, Recon. This application also has **Keys** and
//! **Console**, which are working features with their own object model and
//! their own detail panes, and which the brief does not mention — its
//! prototype was drawn from the macOS variant, where they do not exist.
//!
//! Dropping a working feature because it is absent from a mock would be a
//! silent regression, so both are kept and placed where they belong: Keys
//! beside SSH, since an SSH key is managed the same way a host is, and
//! Console at the end of the operational group. Everything else follows the
//! brief's names and order.
//!
//! Dashboard becomes **Fleet**. It is the same screen — multi-vendor device
//! monitoring — under the name the brief gives it.

use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;

use super::design;

// ---------------------------------------------------------------------------
// Sections
// ---------------------------------------------------------------------------

/// One destination in the navigation sidebar.
#[derive(Debug, Clone, Copy)]
pub struct Section {
    /// The `AdwViewStack` child name. Stable; used to switch pages.
    pub id: &'static str,
    /// What the operator sees.
    pub title: &'static str,
    /// Symbolic icon name.
    pub icon: &'static str,
    /// Whether this section has real content behind it yet.
    pub built: bool,
}

/// The sections, in the order they appear.
///
/// Two groups, as the brief has: the things you manage, and the things you
/// run against them. The split is not decoration — it is what keeps a list
/// of ten from reading as a list of ten.
pub const MANAGE: &[Section] = &[
    Section { id: "fleet",     title: "Fleet",     icon: "view-grid-symbolic",              built: true },
    Section { id: "hosts",     title: "SSH",       icon: "computer-symbolic",               built: true },
    Section { id: "keys",      title: "Keys",      icon: "dialog-password-symbolic",        built: true },
    Section { id: "vpn",       title: "VPN",       icon: "network-vpn-symbolic",            built: true },
    Section { id: "tailscale", title: "Tailscale", icon: "network-workgroup-symbolic",      built: false },
];

/// The operational group.
pub const OPERATE: &[Section] = &[
    Section { id: "provisioning", title: "Provisioning", icon: "document-edit-symbolic",     built: true },
    Section { id: "console",      title: "Console",      icon: "utilities-terminal-symbolic", built: true },
    Section { id: "compliance",   title: "Compliance",   icon: "emblem-ok-symbolic",         built: false },
    Section { id: "security",     title: "Security",     icon: "security-high-symbolic",     built: false },
    Section { id: "recon",        title: "Recon",        icon: "system-search-symbolic",     built: false },
];

/// Every section, both groups.
#[must_use]
pub fn all_sections() -> Vec<Section> {
    MANAGE.iter().chain(OPERATE.iter()).copied().collect()
}

// ---------------------------------------------------------------------------
// The shell
// ---------------------------------------------------------------------------

/// The built shell and the handles the rest of the UI needs.
pub struct Shell {
    /// The widget to put in the window.
    pub widget: adw::NavigationSplitView,
    /// Where the toolbar's trailing buttons go.
    pub header_end: gtk4::Box,
    /// Where the VPN status pill goes; replace its child to update it.
    ///
    /// The brief puts a Tailscale pill beside this one. There is no slot for
    /// it here because there is no Tailscale integration to report on yet — a
    /// permanently grey pill for a feature that does not exist is worse than
    /// no pill. It goes in when the section does.
    pub vpn_status: adw::Bin,
}

/// Build the shell around an existing section stack.
///
/// Takes the `AdwViewStack` the sections already live in rather than
/// building one, so the sections themselves are untouched by this change —
/// the chrome around them is what moves. `content` is what actually gets
/// displayed, which is the stack plus anything wrapped around it: the
/// daemon-unavailable banner has to stay above the section, not inside it.
#[must_use]
pub fn build(stack: &adw::ViewStack, content: &impl IsA<gtk4::Widget>) -> Shell {
    // --- Nav sidebar ------------------------------------------------------

    let nav = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    nav.add_css_class("supermgr-nav");
    nav.set_margin_top(6);

    let mut rows: Vec<(gtk4::ListBox, &'static [Section])> = Vec::new();
    for (heading, group) in [("Manage", MANAGE), ("Operate", OPERATE)] {
        let caps = design::section_caps(heading);
        caps.set_margin_start(18);
        caps.set_margin_top(10);
        caps.set_margin_bottom(2);
        nav.append(&caps);

        let list = gtk4::ListBox::new();
        list.add_css_class("navigation-sidebar");
        list.set_selection_mode(gtk4::SelectionMode::Single);

        for section in group {
            let row = adw::ActionRow::new();
            row.set_title(section.title);
            let icon = gtk4::Image::from_icon_name(section.icon);
            row.add_prefix(&icon);
            // A section with nothing behind it says so here rather than
            // after the operator has clicked it and found an empty page.
            if !section.built {
                let tag = design::badge("Soon");
                row.add_suffix(&tag);
            }
            list.append(&row);
        }
        nav.append(&list);
        rows.push((list, group));
    }

    // Selecting in one list clears the other, so the two behave as one.
    //
    // The row's position in its list is what identifies the section: rows
    // are appended in `group` order and never reordered, so index and
    // section stay in step. Attaching the id to the widget instead would
    // mean `set_data`, which is unsafe, and the workspace forbids that.
    for (list, group) in &rows {
        let stack = stack.clone();
        let group: &'static [Section] = group;
        let others: Vec<gtk4::ListBox> =
            rows.iter().map(|(l, _)| l.clone()).filter(|l| l != list).collect();
        list.connect_row_selected(move |_, row| {
            let Some(row) = row else { return };
            for other in &others {
                other.select_row(None::<&gtk4::ListBoxRow>);
            }
            let index = usize::try_from(row.index()).unwrap_or(usize::MAX);
            let Some(section) = group.get(index) else { return };
            if stack.child_by_name(section.id).is_some() {
                stack.set_visible_child_name(section.id);
            }
        });
    }

    // Anything else that switches the stack — the Ctrl+N shortcuts, an
    // action, a toast button — has to move the sidebar with it. The old view
    // switcher was bound to the stack and did this for free; a `ListBox` is
    // not, so without this a Ctrl+2 changes the page and leaves the sidebar
    // highlighting the section you just left.
    {
        let rows = rows.clone();
        stack.connect_visible_child_name_notify(move |stack| {
            let Some(name) = stack.visible_child_name() else { return };
            for (list, group) in &rows {
                let Some(index) = group.iter().position(|s| s.id == name) else {
                    list.select_row(None::<&gtk4::ListBoxRow>);
                    continue;
                };
                let Ok(index) = i32::try_from(index) else { continue };
                if let Some(row) = list.row_at_index(index) {
                    // Re-selecting the current row would bounce back through
                    // the handler above for no reason.
                    if !row.is_selected() {
                        list.select_row(Some(&row));
                    }
                }
            }
        });
    }

    // Every section has to resolve to a page. A nav row that does nothing
    // when clicked is worse than a crash during development, because it
    // looks like the application is merely slow.
    for section in all_sections() {
        if stack.child_by_name(section.id).is_none() {
            tracing::error!(
                section = section.id,
                "navigation section has no page in the view stack; the row will do nothing"
            );
            debug_assert!(false, "section '{}' has no page in the view stack", section.id);
        }
    }

    // Start on VPN, which is where the old window started too. By id rather
    // than by position, so reordering the group cannot silently change which
    // section the application opens on.
    if let Some((list, group)) = rows.first() {
        if let Some(index) = group.iter().position(|s| s.id == "vpn") {
            if let Some(row) = i32::try_from(index).ok().and_then(|i| list.row_at_index(i)) {
                list.select_row(Some(&row));
            }
        }
    }

    let nav_scroller = gtk4::ScrolledWindow::new();
    nav_scroller.set_hscrollbar_policy(gtk4::PolicyType::Never);
    nav_scroller.set_vexpand(true);
    nav_scroller.set_child(Some(&nav));

    // --- Sidebar chrome ---------------------------------------------------

    let sidebar_header = adw::HeaderBar::new();
    sidebar_header.set_title_widget(Some(&adw::WindowTitle::new("SuperManager", "")));

    let sidebar_view = adw::ToolbarView::new();
    sidebar_view.add_top_bar(&sidebar_header);
    sidebar_view.set_content(Some(&nav_scroller));

    let sidebar_page = adw::NavigationPage::new(&sidebar_view, "SuperManager");

    // --- Content chrome ---------------------------------------------------
    //
    // The status pill lives here rather than in the sidebar because the brief
    // puts it in the toolbar, and because it describes the state of the whole
    // application rather than of the section on screen.

    let content_header = adw::HeaderBar::new();
    content_header.set_show_title(false);

    let vpn_status = adw::Bin::new();
    content_header.pack_start(&vpn_status);

    let header_end = gtk4::Box::new(gtk4::Orientation::Horizontal, 6);
    content_header.pack_end(&header_end);

    let content_view = adw::ToolbarView::new();
    content_view.add_top_bar(&content_header);
    content_view.set_content(Some(content));

    let content_page = adw::NavigationPage::new(&content_view, "SuperManager");

    // --- Put it together --------------------------------------------------

    let split = adw::NavigationSplitView::builder().vexpand(true).build();
    // The brief's 152pt. Wide enough for "Provisioning" and a badge, narrow
    // enough that it is chrome rather than content.
    split.set_min_sidebar_width(190.0);
    split.set_max_sidebar_width(240.0);
    split.set_sidebar(Some(&sidebar_page));
    split.set_content(Some(&content_page));

    Shell { widget: split, header_end, vpn_status }
}

/// A page for a section that has no implementation yet.
///
/// The brief's prototype shows a specific message for these rather than a
/// blank pane, and names what *is* built so the operator goes somewhere
/// useful instead of concluding the application is broken.
#[must_use]
pub fn placeholder(section: Section) -> gtk4::Widget {
    let page = design::empty_state(
        section.icon,
        section.title,
        "This section is not built yet. SSH, Keys, VPN, Fleet, Provisioning \
         and Console are — pick one of those from the sidebar.",
    );
    page.upcast()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_section_id_is_unique() {
        // Ids address `AdwViewStack` children. A duplicate would make one
        // section unreachable, and the sidebar would silently show the wrong
        // page.
        let mut seen = std::collections::HashSet::new();
        for section in all_sections() {
            assert!(seen.insert(section.id), "duplicate section id: {}", section.id);
        }
    }

    #[test]
    fn the_briefs_sections_are_all_present() {
        // The eight the brief specifies. If one is dropped in a later edit,
        // this says so rather than letting it quietly disappear.
        let ids: Vec<&str> = all_sections().iter().map(|s| s.id).collect();
        for expected in [
            "fleet",
            "hosts",
            "vpn",
            "tailscale",
            "compliance",
            "provisioning",
            "security",
            "recon",
        ] {
            assert!(ids.contains(&expected), "the brief's '{expected}' section is missing");
        }
    }

    #[test]
    fn the_features_the_brief_omits_are_kept() {
        // Keys and Console exist in this application and not in the brief,
        // whose prototype came from the macOS variant. Removing them to
        // match a mock would delete working features.
        let ids: Vec<&str> = all_sections().iter().map(|s| s.id).collect();
        assert!(ids.contains(&"keys"), "SSH key management was dropped");
        assert!(ids.contains(&"console"), "the terminal was dropped");
    }

    #[test]
    fn everything_that_exists_today_is_marked_built() {
        // These six have real implementations. Marking one unbuilt would
        // put a "Soon" badge on a working screen.
        let built: Vec<&str> = all_sections()
            .iter()
            .filter(|s| s.built)
            .map(|s| s.id)
            .collect();
        for id in ["fleet", "hosts", "keys", "vpn", "provisioning", "console"] {
            assert!(built.contains(&id), "'{id}' exists but is marked unbuilt");
        }
    }

    #[test]
    fn every_built_section_has_a_page_under_the_same_id() {
        // This module addresses pages by id; `ui/mod.rs` registers them by
        // id. They are string literals in two different files, and when they
        // disagreed — "dashboard" there, "fleet" here — the result was a nav
        // row that did nothing whatsoever when clicked. No error, no empty
        // page, no clue.
        //
        // Comments are stripped before searching, because a scan that prose
        // can satisfy is satisfied by the comment explaining the scan.
        let source = include_str!("mod.rs");
        let registrations: String = source
            .lines()
            .map(|line| line.split("//").next().unwrap_or(""))
            .filter(|line| line.contains("view_stack.add_titled("))
            .collect::<Vec<_>>()
            .join("\n");

        for section in all_sections().iter().filter(|s| s.built) {
            assert!(
                registrations.contains(&format!("Some(\"{}\")", section.id)),
                "'{}' is marked built, but ui/mod.rs adds no view-stack page \
                 with that id — its sidebar row would do nothing",
                section.id
            );
        }
    }

    #[test]
    fn nothing_unbuilt_claims_to_work() {
        let unbuilt: Vec<&str> = all_sections()
            .iter()
            .filter(|s| !s.built)
            .map(|s| s.id)
            .collect();
        assert_eq!(
            unbuilt,
            vec!["tailscale", "compliance", "security", "recon"],
            "the set of unimplemented sections changed"
        );
    }
}
