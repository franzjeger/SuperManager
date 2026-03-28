//! System tray implementation via `ksni` (StatusNotifierItem).
#![allow(missing_docs)]

use std::sync::mpsc;

use supermgr_core::{vpn::profile::ProfileSummary, vpn::state::VpnState};

use crate::app::AppMsg;
use crate::dbus_client::{dbus_connect, dbus_disconnect, dbus_get_state};

// ---------------------------------------------------------------------------
// System tray
// ---------------------------------------------------------------------------

/// State stored inside the ksni tray struct.
///
/// `ksni` mutates this via `Handle::update` and calls the `ksni::Tray` trait
/// methods on it whenever it needs to re-render the icon, tooltip, or menu.
pub struct VpnTray {
    /// Current VPN state, used for icon and tooltip rendering.
    pub vpn_state: VpnState,
    /// Known VPN profiles, used for building the connect/disconnect menu.
    pub profiles: Vec<ProfileSummary>,
    /// Tokio handle used to spawn D-Bus calls from menu item callbacks.
    pub rt: tokio::runtime::Handle,
    /// Channel back to the GTK drain loop.
    pub tx: mpsc::Sender<AppMsg>,
}

impl ksni::Tray for VpnTray {
    fn id(&self) -> String {
        env!("CARGO_PKG_NAME").into()
    }

    fn icon_name(&self) -> String {
        if self.vpn_state.is_connected() {
            "network-vpn".into()
        } else {
            "network-vpn-symbolic".into()
        }
    }

    fn title(&self) -> String {
        "SuperManager".into()
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        let active_name = self.vpn_state.profile_id().and_then(|id| {
            self.profiles
                .iter()
                .find(|p| p.id == id)
                .map(|p| p.name.clone())
        });

        let description = match &self.vpn_state {
            VpnState::Connected { .. } => {
                if let Some(name) = active_name {
                    format!("Connected to {name}")
                } else {
                    "Connected".into()
                }
            }
            VpnState::Connecting { .. } => "Connecting\u{2026}".into(),
            VpnState::Disconnecting { .. } => "Disconnecting\u{2026}".into(),
            VpnState::Error { message, .. } => format!("Error: {message}"),
            VpnState::Disconnected => "Disconnected".into(),
        };

        ksni::ToolTip {
            title: "SuperManager".into(),
            description,
            ..Default::default()
        }
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        let active_id = self.vpn_state.profile_id().map(|id| id.to_string());

        let mut items: Vec<ksni::MenuItem<Self>> = self
            .profiles
            .iter()
            .map(|profile| {
                let profile_id = profile.id.to_string();
                let is_active =
                    active_id.as_deref() == Some(profile_id.as_str());

                let label = if is_active {
                    format!("\u{2713} {}", profile.name)
                } else {
                    profile.name.clone()
                };

                let rt = self.rt.clone();
                let tx = self.tx.clone();

                ksni::MenuItem::Standard(ksni::menu::StandardItem {
                    label,
                    activate: Box::new(move |_tray: &mut VpnTray| {
                        let id = profile_id.clone();
                        let tx = tx.clone();
                        if is_active {
                            rt.spawn(async move {
                                let msg = match dbus_disconnect().await {
                                    Err(e) => AppMsg::OperationFailed(e.to_string()),
                                    Ok(()) => match dbus_get_state().await {
                                        Ok(s) => AppMsg::StateUpdated(s),
                                        Err(e) => AppMsg::OperationFailed(e.to_string()),
                                    },
                                };
                                let _ = tx.send(msg);
                            });
                        } else {
                            rt.spawn(async move {
                                let msg = match dbus_connect(id).await {
                                    Err(e) => AppMsg::OperationFailed(e.to_string()),
                                    Ok(()) => match dbus_get_state().await {
                                        Ok(s) => AppMsg::StateUpdated(s),
                                        Err(e) => AppMsg::OperationFailed(e.to_string()),
                                    },
                                };
                                let _ = tx.send(msg);
                            });
                        }
                    }),
                    ..Default::default()
                })
            })
            .collect();

        items.push(ksni::MenuItem::Separator);

        {
            let tx = self.tx.clone();
            items.push(ksni::MenuItem::Standard(ksni::menu::StandardItem {
                label: "Open SuperManager".into(),
                activate: Box::new(move |_tray: &mut VpnTray| {
                    let _ = tx.send(AppMsg::ShowWindow);
                }),
                ..Default::default()
            }));
        }

        {
            let tx = self.tx.clone();
            items.push(ksni::MenuItem::Standard(ksni::menu::StandardItem {
                label: "Quit".into(),
                activate: Box::new(move |_tray: &mut VpnTray| {
                    let _ = tx.send(AppMsg::Quit);
                }),
                ..Default::default()
            }));
        }

        items
    }
}
