//! Reading a chosen config file into the add-profile form.
//!
//! WireGuard and OpenVPN configs are text files, read as they are. An Azure
//! profile is two files the Azure portal ships in one .zip —
//! `AzureVPN\azurevpnconfig.xml` (the sign-in details) and
//! `Generic\VpnSettings.xml` (the gateway's certificate and routes) — so
//! either the .zip or the first of the two, with the second found beside it.

use std::io::Read as _;
use std::path::Path;

use super::ProfileKind;
use crate::model;

/// A config file is kilobytes; anything past this is the wrong file.
const MAX_BYTES: u64 = 2 * 1024 * 1024;

pub(super) struct Loaded {
    pub text: String,
    pub text_2: String,
    /// What to show as the chosen file.
    pub label: String,
    pub suggested_name: String,
}

pub(super) fn load(kind: ProfileKind, path: &Path) -> Result<Loaded, String> {
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let size = std::fs::metadata(path)
        .map_err(|e| format!("Couldn't read {file_name}: {e}"))?
        .len();
    if size > MAX_BYTES {
        return Err(format!(
            "{file_name} is too large to be a VPN configuration."
        ));
    }
    if kind == ProfileKind::Azure {
        return load_azure(path, &file_name);
    }
    Ok(Loaded {
        text: read_text(path, &file_name)?,
        text_2: String::new(),
        label: file_name.clone(),
        suggested_name: model::name_from_file(&file_name),
    })
}

fn read_text(path: &Path, file_name: &str) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("Couldn't read {file_name}: {e}"))?;
    decode(&bytes).ok_or_else(|| format!("{file_name} isn't a text file."))
}

/// UTF-8, or the UTF-16 some Windows tools save as; without a byte-order
/// mark either way, since a parser looking for `[Interface]` or `<?xml` at
/// the start of the file would not see past one.
fn decode(bytes: &[u8]) -> Option<String> {
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        let units: Vec<u16> = rest
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16(&units).ok();
    }
    let text = std::str::from_utf8(bytes).ok()?;
    Some(text.trim_start_matches('\u{feff}').to_owned())
}

fn load_azure(path: &Path, file_name: &str) -> Result<Loaded, String> {
    let is_zip = path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("zip"));
    let (config, settings, label) = if is_zip {
        let file =
            std::fs::File::open(path).map_err(|e| format!("Couldn't read {file_name}: {e}"))?;
        let mut archive = zip::ZipArchive::new(file)
            .map_err(|e| format!("{file_name} isn't a readable .zip ({e})."))?;
        let config = zip_entry(&mut archive, "azurevpnconfig.xml")?.ok_or_else(|| {
            format!(
                "{file_name} has no azurevpnconfig.xml. Download the VPN client profile for the Azure VPN Client (OpenVPN, Entra ID authentication)."
            )
        })?;
        let settings = zip_entry(&mut archive, "vpnsettings.xml")?;
        (
            config,
            settings,
            format!("{file_name} — both profile files found"),
        )
    } else {
        if file_name.eq_ignore_ascii_case("vpnsettings.xml") {
            return Err(
                "That is VpnSettings.xml. Choose azurevpnconfig.xml, or the .zip both came in."
                    .into(),
            );
        }
        let config = read_text(path, file_name)?;
        let settings = settings_beside(path);
        (config, settings, format!("{file_name} and VpnSettings.xml"))
    };
    let settings = settings.ok_or_else(|| {
        "VpnSettings.xml, which holds the gateway's certificate, wasn't found. Choose the .zip from the Azure portal instead."
            .to_owned()
    })?;
    Ok(Loaded {
        text: config,
        text_2: settings,
        label,
        suggested_name: model::name_from_file(file_name),
    })
}

/// The first entry named `wanted`, in any folder of the archive.
fn zip_entry(
    archive: &mut zip::ZipArchive<std::fs::File>,
    wanted: &str,
) -> Result<Option<String>, String> {
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| format!("Couldn't read the .zip ({e})."))?;
        let name = entry
            .name()
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if name != wanted {
            continue;
        }
        if entry.size() > MAX_BYTES {
            return Err(format!("{wanted} in the .zip is too large."));
        }
        let mut bytes = Vec::new();
        entry
            .read_to_end(&mut bytes)
            .map_err(|e| format!("Couldn't unpack {wanted} ({e})."))?;
        return decode(&bytes)
            .map(Some)
            .ok_or_else(|| format!("{wanted} isn't a text file."));
    }
    Ok(None)
}

/// VpnSettings.xml where the portal's layout puts it relative to
/// azurevpnconfig.xml: the same folder, or `..\Generic\`.
fn settings_beside(config: &Path) -> Option<String> {
    let dir = config.parent()?;
    let candidates = [
        dir.join("VpnSettings.xml"),
        dir.parent()?.join("Generic").join("VpnSettings.xml"),
    ];
    candidates.iter().find_map(|p| {
        let bytes = std::fs::read(p).ok()?;
        decode(&bytes)
    })
}
