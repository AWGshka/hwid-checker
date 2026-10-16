//! Volumes (including hidden EFI/recovery ones): label, mount point, serial, GUID.

use windows::Win32::Storage::FileSystem::{
    FindFirstVolumeW, FindNextVolumeW, FindVolumeClose, GetVolumeInformationW, GetVolumePathNamesForVolumeNameW,
};
use windows::core::PCWSTR;

use crate::report::{Item, Section};
use crate::util::{NA, from_wide, wide};

struct Volume {
    label: String,
    mount: String,
    serial: String,
    fs: String,
    guid: String,
}

pub fn section() -> Section {
    let s = Section::new("volumes", "VOLUMES");
    let mut name = [0u16; 260];
    let Ok(find) = (unsafe { FindFirstVolumeW(&mut name) }) else {
        return s.note("volume enumeration failed");
    };
    let mut vols = Vec::new();
    loop {
        vols.push(volume(&from_wide(&name)));
        if unsafe { FindNextVolumeW(find, &mut name) }.is_err() {
            break;
        }
    }
    unsafe {
        let _ = FindVolumeClose(find);
    }
    // Lettered volumes first, alphabetically.
    vols.sort_by(|a, b| (a.mount.is_empty(), &a.mount).cmp(&(b.mount.is_empty(), &b.mount)));

    s.items(vols.into_iter().map(|v| {
        Item::new()
            .add("label", if v.label.is_empty() { "(no label)".into() } else { v.label })
            .add("mount", v.mount)
            .add("serial", v.serial)
            .add("fs", v.fs)
            .add("guid", v.guid)
    }))
}

fn volume(guid_path: &str) -> Volume {
    let w = wide(guid_path);
    let guid = guid_path.find('{').map(|i| guid_path[i..].trim_end_matches('\\').to_uppercase()).unwrap_or_default();

    let mut paths = [0u16; 1024];
    let mut len = 0u32;
    let mount = match unsafe { GetVolumePathNamesForVolumeNameW(PCWSTR(w.as_ptr()), Some(&mut paths), &mut len) } {
        Ok(()) => from_wide(&paths), // first entry of the multi-string
        Err(_) => String::new(),
    };

    let (mut label, mut fs, mut serial) = ([0u16; 261], [0u16; 261], 0u32);
    let ok = unsafe {
        GetVolumeInformationW(PCWSTR(w.as_ptr()), Some(&mut label), Some(&mut serial), None, None, Some(&mut fs))
    }
    .is_ok();

    Volume {
        label: if ok { from_wide(&label) } else { String::new() },
        mount,
        serial: if ok { format!("{:04X}-{:04X}", serial >> 16, serial & 0xFFFF) } else { NA.into() },
        fs: if ok { from_wide(&fs) } else { String::new() },
        guid,
    }
}
