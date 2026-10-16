//! Raw SMBIOS table via GetSystemFirmwareTable('RSMB'): BIOS, system UUID,
//! motherboard, chassis, CPU socket data and memory modules.
//! Field offsets follow the DMTF SMBIOS reference specification (DSP0134).

use windows::Win32::System::SystemInformation::{FIRMWARE_TABLE_PROVIDER, GetSystemFirmwareTable};

use crate::report::{Item, Section};
use crate::util::{u16_at, u32_at};

pub struct Structure {
    kind: u8,
    data: Vec<u8>,
    strings: Vec<String>,
}

impl Structure {
    fn str(&self, off: usize) -> String {
        match self.data.get(off) {
            Some(&i) if i > 0 => self.strings.get(i as usize - 1).map(|s| s.trim().to_string()).unwrap_or_default(),
            _ => String::new(),
        }
    }
}

pub struct Smbios {
    major: u8,
    minor: u8,
    structs: Vec<Structure>,
}

impl Smbios {
    fn of(&self, kind: u8) -> impl Iterator<Item = &Structure> {
        self.structs.iter().filter(move |s| s.kind == kind)
    }
}

pub fn read() -> Option<Smbios> {
    let provider = FIRMWARE_TABLE_PROVIDER(u32::from_be_bytes(*b"RSMB"));
    let size = unsafe { GetSystemFirmwareTable(provider, 0, None) };
    if size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let got = unsafe { GetSystemFirmwareTable(provider, 0, Some(&mut buf)) };
    if got == 0 || got > size {
        return None;
    }
    parse(&buf)
}

/// `buf` is a RawSMBIOSData: 8-byte header followed by the structure table.
fn parse(buf: &[u8]) -> Option<Smbios> {
    let (major, minor) = (*buf.get(1)?, *buf.get(2)?);
    let len = u32_at(buf, 4)? as usize;
    let table = buf.get(8..8 + len)?;

    let mut structs = Vec::new();
    let mut i = 0;
    while i + 4 <= table.len() {
        let (kind, formatted_len) = (table[i], table[i + 1] as usize);
        if formatted_len < 4 || i + formatted_len > table.len() {
            break;
        }
        // Unformatted section: null-terminated strings, ended by a double null.
        let start = i + formatted_len;
        let mut end = start;
        while end + 1 < table.len() && !(table[end] == 0 && table[end + 1] == 0) {
            end += 1;
        }
        let strings = table[start..end].split(|&b| b == 0).map(|s| String::from_utf8_lossy(s).into_owned()).collect();
        structs.push(Structure { kind, data: table[i..start].to_vec(), strings });
        i = end + 2;
        if kind == 127 {
            break;
        }
    }
    Some(Smbios { major, minor, structs })
}

fn section(
    sm: Option<&Smbios>,
    key: &'static str,
    title: &'static str,
    kind: u8,
    f: impl Fn(&Smbios, &Structure) -> Option<Item>,
) -> Section {
    let s = Section::new(key, title);
    match sm {
        Some(sm) => s.items(sm.of(kind).filter_map(|st| f(sm, st))),
        None => s.note("SMBIOS table unavailable"),
    }
}

pub fn bios(sm: Option<&Smbios>) -> Section {
    section(sm, "bios", "BIOS", 0, |_, b| {
        Some(Item::new().add("vendor", b.str(0x04)).add("version", b.str(0x05)).add("date", b.str(0x08)))
    })
}

pub fn uuid(sm: Option<&Smbios>) -> Section {
    section(sm, "smbios_uuid", "SMBIOS UUID", 1, |sm, s| Some(Item::new().add("uuid", format_uuid(sm, s))))
}

pub fn system(sm: Option<&Smbios>) -> Section {
    section(sm, "system", "SYSTEM", 1, |_, s| {
        Some(
            Item::new()
                .add("product", s.str(0x05))
                .add("manufacturer", s.str(0x04))
                .add("serial", s.str(0x07))
                .add("sku", s.str(0x19))
                .add("family", s.str(0x1A)),
        )
    })
}

pub fn baseboard(sm: Option<&Smbios>) -> Section {
    section(sm, "motherboard", "MOTHERBOARD", 2, |_, b| {
        Some(
            Item::new()
                .add("manufacturer", b.str(0x04))
                .add("product", b.str(0x05))
                .add("version", b.str(0x06))
                .add("serial", b.str(0x07))
                .add("asset_tag", b.str(0x08)),
        )
    })
}

pub fn chassis(sm: Option<&Smbios>) -> Section {
    section(sm, "chassis", "CHASSIS", 3, |_, c| {
        Some(
            Item::new()
                .add("manufacturer", c.str(0x04))
                .add("serial", c.str(0x07))
                .add("asset_tag", c.str(0x08)),
        )
    })
}

pub fn memory(sm: Option<&Smbios>) -> Section {
    section(sm, "ram", "RAM", 17, |_, m| {
        let size_mb = match u16_at(&m.data, 0x0C)? {
            0 => return None, // empty slot
            0xFFFF => None,
            0x7FFF => u32_at(&m.data, 0x1C).map(|v| (v & 0x7FFF_FFFF) as u64),
            v if v & 0x8000 != 0 => Some((v & 0x7FFF) as u64 / 1024),
            v => Some(v as u64),
        };
        let size = match size_mb {
            Some(mb) if mb >= 1024 && mb % 1024 == 0 => format!("{} GB", mb / 1024),
            Some(mb) => format!("{mb} MB"),
            None => String::new(),
        };
        let speed = u16_at(&m.data, 0x15).filter(|&s| s != 0 && s != 0xFFFF).map(|s| format!("{s} MT/s"));
        let slot = [m.str(0x11), m.str(0x10)].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" / ");
        Some(
            Item::new()
                .add("slot", slot)
                .add("manufacturer", m.str(0x17))
                .add("part", m.str(0x1A))
                .add("serial", m.str(0x18))
                .add("size", size)
                .add("speed", speed.unwrap_or_default()),
        )
    })
}

/// Serial number of the first processor structure (often an OEM placeholder).
pub fn cpu_serial(sm: Option<&Smbios>) -> String {
    sm.and_then(|sm| sm.of(4).next()).map(|p| p.str(0x20)).unwrap_or_default()
}

fn format_uuid(sm: &Smbios, s: &Structure) -> String {
    let Some(b) = s.data.get(0x08..0x18) else { return String::new() };
    if b.iter().all(|&x| x == 0) {
        return "not present".into();
    }
    if b.iter().all(|&x| x == 0xFF) {
        return "not set".into();
    }
    // Since SMBIOS 2.6 the first three fields are little-endian.
    let le = (sm.major, sm.minor) >= (2, 6);
    let (d1, d2, d3) = if le {
        (
            u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            u16::from_le_bytes([b[4], b[5]]),
            u16::from_le_bytes([b[6], b[7]]),
        )
    } else {
        (
            u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
            u16::from_be_bytes([b[4], b[5]]),
            u16::from_be_bytes([b[6], b[7]]),
        )
    };
    format!("{d1:08X}-{d2:04X}-{d3:04X}-{:02X}{:02X}-{}", b[8], b[9], crate::util::hex(&b[10..16]))
}
