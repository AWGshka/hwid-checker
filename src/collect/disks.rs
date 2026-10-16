//! Physical disks: model/serial via IOCTL_STORAGE_QUERY_PROPERTY (no admin
//! needed), partition-table ID via IOCTL_DISK_GET_DRIVE_LAYOUT_EX (admin).

use windows::Win32::Foundation::GENERIC_READ;

use crate::report::{Item, Section};
use crate::util::{self, cstr_at, err_value, guid_from_bytes, guid_string, u32_at};

const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D_1400;
const IOCTL_DISK_GET_DRIVE_LAYOUT_EX: u32 = 0x0007_0050;

const BUS_TYPES: [&str; 20] = [
    "Unknown", "SCSI", "ATAPI", "ATA", "1394", "SSA", "Fibre", "USB", "RAID", "iSCSI", "SAS", "SATA", "SD",
    "MMC", "Virtual", "FileBackedVirtual", "Spaces", "NVMe", "SCM", "UFS",
];

pub fn section() -> Section {
    let mut s = Section::new("disks", "DISKS");
    for n in 0..32 {
        let path = format!(r"\\.\PhysicalDrive{n}");
        let Ok(h) = util::open_device(&path, 0) else { continue };
        let Some((model, serial, bus)) = descriptor(&h) else { continue };
        s = s.item(
            Item::new()
                .add("model", model)
                .add("serial", serial)
                .add("bus", bus)
                .add("disk_id", disk_id(&path))
        );
    }
    s
}

/// Parses STORAGE_DEVICE_DESCRIPTOR into (model, serial, bus type).
fn descriptor(h: &util::Handle) -> Option<(String, String, String)> {
    // STORAGE_PROPERTY_QUERY { StorageDeviceProperty, PropertyStandardQuery, [0] }
    let query = [0u8; 12];
    let d = util::ioctl(h, IOCTL_STORAGE_QUERY_PROPERTY, &query, 4096).ok()?;
    let at = |off| cstr_at(&d, u32_at(&d, off).unwrap_or(0) as usize);
    let model = [at(12), at(16)].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" ");
    let bus = u32_at(&d, 28).and_then(|b| BUS_TYPES.get(b as usize)).copied().unwrap_or("Unknown");
    Some((model, at(24), bus.to_string()))
}

/// GPT disk GUID or MBR disk signature.
fn disk_id(path: &str) -> String {
    let layout = util::open_device(path, GENERIC_READ.0)
        .and_then(|h| util::ioctl(&h, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, &[], 64 * 1024));
    let d = match layout {
        Ok(d) => d,
        Err(e) => return err_value(&e),
    };
    match u32_at(&d, 0) {
        Some(0) => u32_at(&d, 8).map(|sig| format!("MBR {sig:08X}")).unwrap_or_default(),
        Some(1) => d.get(8..24).and_then(guid_from_bytes).map(|g| format!("GPT {}", guid_string(&g))).unwrap_or_default(),
        _ => "RAW".into(),
    }
}
