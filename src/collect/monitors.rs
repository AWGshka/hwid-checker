//! Connected monitors: EDID read through SetupAPI (manufacturer, model, serial,
//! manufacture date).

use windows::Win32::Devices::DeviceAndDriverInstallation::{
    DICS_FLAG_GLOBAL, DIGCF_PRESENT, DIREG_DEV, GUID_DEVCLASS_MONITOR, SP_DEVINFO_DATA, SetupDiDestroyDeviceInfoList,
    SetupDiEnumDeviceInfo, SetupDiGetClassDevsW, SetupDiOpenDevRegKey,
};
use windows::Win32::System::Registry::{KEY_READ, RegCloseKey, RegQueryValueExW};
use windows::core::{PCWSTR, w};

use crate::report::{Item, Section};
use crate::util::u32_at;

pub fn section() -> Section {
    let s = Section::new("monitors", "MONITORS");
    let Ok(devs) = (unsafe { SetupDiGetClassDevsW(Some(&GUID_DEVCLASS_MONITOR), PCWSTR::null(), None, DIGCF_PRESENT) })
    else {
        return s.note("device enumeration failed");
    };

    let mut items = Vec::new();
    for i in 0.. {
        let mut dev = SP_DEVINFO_DATA { cbSize: size_of::<SP_DEVINFO_DATA>() as u32, ..Default::default() };
        if unsafe { SetupDiEnumDeviceInfo(devs, i, &mut dev) }.is_err() {
            break;
        }
        if let Some(item) = read_edid(devs, &dev).as_deref().and_then(parse_edid) {
            items.push(item);
        }
    }
    unsafe {
        let _ = SetupDiDestroyDeviceInfoList(devs);
    }
    s.items(items).note("no monitors with EDID found")
}

fn read_edid(
    devs: windows::Win32::Devices::DeviceAndDriverInstallation::HDEVINFO,
    dev: &SP_DEVINFO_DATA,
) -> Option<Vec<u8>> {
    unsafe {
        let key = SetupDiOpenDevRegKey(devs, dev, DICS_FLAG_GLOBAL.0, 0, DIREG_DEV, KEY_READ.0).ok()?;
        let mut buf = vec![0u8; 1024];
        let mut len = buf.len() as u32;
        let r = RegQueryValueExW(key, w!("EDID"), None, None, Some(buf.as_mut_ptr()), Some(&mut len));
        let _ = RegCloseKey(key);
        r.ok().ok()?;
        buf.truncate(len as usize);
        Some(buf)
    }
}

/// EDID 1.x base block: vendor/product at 8..12, serial at 12, date at 16,
/// four 18-byte descriptors from 54 (0xFC = name, 0xFF = serial string).
fn parse_edid(e: &[u8]) -> Option<Item> {
    if e.len() < 128 || e[..8] != [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00] {
        return None;
    }
    let v = u16::from_be_bytes([e[8], e[9]]);
    let vendor: String = [(v >> 10) & 0x1F, (v >> 5) & 0x1F, v & 0x1F].iter().map(|&c| (b'A' + c as u8 - 1) as char).collect();
    let product = u16::from_le_bytes([e[10], e[11]]);
    let numeric_serial = u32_at(e, 12).unwrap_or(0);

    let (mut name, mut serial) = (String::new(), String::new());
    for off in [54, 72, 90, 108] {
        let d = &e[off..off + 18];
        if d[..3] != [0, 0, 0] {
            continue;
        }
        let text = String::from_utf8_lossy(&d[5..]).split('\n').next().unwrap_or("").trim().to_string();
        match d[3] {
            0xFC => name = text,
            0xFF => serial = text,
            _ => {}
        }
    }
    if serial.is_empty() && numeric_serial != 0 {
        serial = numeric_serial.to_string();
    }
    let date = match (e[16], e[17] as u32 + 1990) {
        (0xFF, year) => format!("model year {year}"),
        (0, year) => year.to_string(),
        (week, year) => format!("week {week}/{year}"),
    };
    let id = format!("{vendor}{product:04X}");
    Some(
        Item::new()
            .add("name", if name.is_empty() { id.clone() } else { name })
            .add("serial", serial)
            .add("id", id)
            .add("made", date),
    )
}
