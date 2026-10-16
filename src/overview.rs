//! The Overview tab: a summary, the identifiers that matter most for a
//! hardware fingerprint, and a single digest over the stable ones.

use crate::report::{Item, Report, Section, Tab, tag};
use crate::util::{ADMIN, NA, sha256};

pub fn sections(r: &Report) -> Vec<Section> {
    tag(vec![glance(r), status(r), digest_section(r), identifiers(r)], Tab::Overview)
}

fn glance(r: &Report) -> Section {
    let board = format!("{} {}", r.first("motherboard", "manufacturer"), r.first("motherboard", "product"));
    let cpu = match (r.first("cpu", "cores"), r.first("cpu", "threads")) {
        (c, t) if !c.is_empty() => format!("{} · {c}C/{t}T", r.first("cpu", "name")),
        _ => r.first("cpu", "name"),
    };
    let sizes = r.all("ram", "size");
    let total_mb: u64 = sizes
        .iter()
        .filter_map(|s| {
            let (n, unit) = s.split_once(' ')?;
            Some(n.parse::<u64>().ok()? * if unit == "GB" { 1024 } else { 1 })
        })
        .sum();
    let memory = format!("{} GB · {} modules", total_mb / 1024, sizes.len());
    let disks = r.all("disks", "model");

    Section::new("glance", "AT A GLANCE").item(
        Item::new()
            .add("os", r.first("windows", "os"))
            .add("board", board.trim())
            .add("cpu", cpu)
            .add("memory", memory)
            .add("gpu", r.all("gpu", "name").join(", "))
            .add("storage", format!("{} disks · {}", disks.len(), disks.join(", ")))
            .add("displays", r.all("monitors", "name").join(", ")),
    )
}

fn status(r: &Report) -> Section {
    let changed = r
        .all("mac", "mac_status")
        .iter()
        .filter(|s| s.starts_with("changed") || s.starts_with("spoofed"))
        .count();
    let tpm = match r.first("tpm", "version") {
        v if v.is_empty() => r.first("tpm", "state"),
        v => format!("{} · {v}", r.first("tpm", "state")),
    };
    Section::new("status", "STATUS").item(
        Item::new()
            .add("privileges", if r.admin { "Administrator" } else { "Standard user" })
            .add("tpm", tpm)
            .add("secure_boot", r.first("secure_boot", "state"))
            .add("mac_addresses", if changed == 0 { "none changed".into() } else { format!("{changed} changed") }),
    )
}

fn identifiers(r: &Report) -> Section {
    let row = |name: String, value: String| Item::new().add("component", name).add("identifier", value);
    let mut rows = vec![
        row("SMBIOS UUID".into(), r.first("smbios_uuid", "uuid")),
        row("Motherboard serial".into(), r.first("motherboard", "serial")),
        row("CPU ID".into(), r.first("cpu", "id")),
    ];
    for item in r.section("disks").map(|s| s.items.as_slice()).unwrap_or_default() {
        rows.push(row(format!("Disk · {}", item.get("model").unwrap_or("?")), item.get("serial").unwrap_or(NA).into()));
    }
    for item in physical_adapters(r) {
        let mac = match item.get("factory") {
            Some(f) if f != ADMIN && f != NA => f,
            _ => item.get("mac").unwrap_or(NA),
        };
        rows.push(row(format!("MAC · {}", item.get("adapter").unwrap_or("?")), mac.into()));
    }
    for item in r.section("monitors").map(|s| s.items.as_slice()).unwrap_or_default() {
        rows.push(row(format!("Monitor · {}", item.get("name").unwrap_or("?")), item.get("serial").unwrap_or(NA).into()));
    }
    rows.push(row("TPM EK (SHA-256)".into(), r.first("tpm", "ek_sha256")));
    rows.push(row("Machine GUID".into(), r.first("software_ids", "machine_guid")));
    Section::new("identifiers", "KEY IDENTIFIERS").items(rows)
}

fn physical_adapters(r: &Report) -> impl Iterator<Item = &Item> {
    r.section("mac").map(|s| s.items.as_slice()).unwrap_or_default().iter().filter(|i| {
        let name = i.get("adapter").unwrap_or("");
        !["Virtual", "Bluetooth", "Wi-Fi Direct"].iter().any(|w| name.contains(w))
    })
}

/// Hash over identifiers that don't change with software reinstalls.
/// Returns (digest, partial) where partial means admin-only parts were missing.
pub fn digest(r: &Report) -> (String, bool) {
    let mut parts = vec![r.first("smbios_uuid", "uuid"), r.first("motherboard", "serial"), r.first("cpu", "id")];
    let mut sorted = |mut v: Vec<String>| {
        v.sort();
        parts.extend(v);
    };
    sorted(r.all("disks", "serial"));
    sorted(r.all("ram", "serial"));
    sorted(physical_adapters(r).filter_map(|i| i.get("factory")).map(str::to_string).collect());
    parts.push(r.first("tpm", "ek_sha256"));

    let partial = parts.iter().any(|p| p == ADMIN);
    let hash = sha256(parts.join("|").as_bytes());
    let short: Vec<&str> = (0..4).map(|i| &hash[i * 4..i * 4 + 4]).collect();
    (short.join("-"), partial)
}

fn digest_section(r: &Report) -> Section {
    let (digest, partial) = digest(r);
    let mut item = Item::new()
        .add("digest", digest)
        .add("based_on", "SMBIOS UUID, board, CPU, disks, RAM, factory MACs, TPM EK");
    if partial {
        item = item.add("note", "partial: run as admin to include factory MACs and the TPM EK");
    }
    Section::new("digest", "HWID DIGEST").item(item)
}
