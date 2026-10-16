//! Connected USB devices and their serial numbers. A device's serial is the
//! last part of its instance ID (USB\VID_xxxx&PID_xxxx\<serial>); devices
//! without one get a Windows-generated ID containing '&' instead.

use windows::Win32::Devices::DeviceAndDriverInstallation::{
    DIGCF_ALLCLASSES, DIGCF_PRESENT, HDEVINFO, SETUP_DI_REGISTRY_PROPERTY, SP_DEVINFO_DATA, SPDRP_DEVICEDESC,
    SPDRP_FRIENDLYNAME, SPDRP_SERVICE, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo, SetupDiGetClassDevsW,
    SetupDiGetDeviceInstanceIdW, SetupDiGetDevicePropertyW, SetupDiGetDeviceRegistryPropertyW,
};
use windows::Win32::Devices::Properties::{DEVPKEY_Device_BusReportedDeviceDesc, DEVPROPTYPE};
use windows::core::w;

use crate::report::{Item, Section};
use crate::util::{from_wide, from_wide_bytes};

pub fn section() -> Section {
    let s = Section::new("usb", "USB DEVICES");
    let Ok(devs) =
        (unsafe { SetupDiGetClassDevsW(None, w!("USB"), None, DIGCF_PRESENT | DIGCF_ALLCLASSES) })
    else {
        return s.note("device enumeration failed");
    };

    let mut rows: Vec<(bool, Item)> = Vec::new();
    for i in 0.. {
        let mut dev = SP_DEVINFO_DATA { cbSize: size_of::<SP_DEVINFO_DATA>() as u32, ..Default::default() };
        if unsafe { SetupDiEnumDeviceInfo(devs, i, &mut dev) }.is_err() {
            break;
        }
        let Some(id) = instance_id(devs, &dev) else { continue };
        let parts: Vec<&str> = id.splitn(3, '\\').collect();
        let [_, hw, tail] = parts[..] else { continue };
        // Skip root hubs and per-interface children of composite devices.
        if !hw.starts_with("VID_") || hw.contains("&MI_") {
            continue;
        }
        let service = registry_property(devs, &dev, SPDRP_SERVICE).unwrap_or_default().to_ascii_lowercase();
        if service.starts_with("usbhub") {
            continue;
        }
        let vid = hw.get(4..8).unwrap_or("????");
        let pid = hw.find("PID_").and_then(|p| hw.get(p + 4..p + 8)).unwrap_or("????");
        let serial = if tail.contains('&') { String::new() } else { tail.to_string() };
        let name = bus_description(devs, &dev)
            .or_else(|| registry_property(devs, &dev, SPDRP_FRIENDLYNAME))
            .or_else(|| registry_property(devs, &dev, SPDRP_DEVICEDESC))
            .unwrap_or_default();
        rows.push((
            !serial.is_empty(),
            Item::new().add("device", name).add("vid_pid", format!("{vid}:{pid}")).add("serial", serial),
        ));
    }
    unsafe {
        let _ = SetupDiDestroyDeviceInfoList(devs);
    }
    // Devices with serials first.
    rows.sort_by_key(|(has_serial, item)| (!has_serial, item.get("device").unwrap_or("").to_lowercase()));
    s.items(rows.into_iter().map(|(_, i)| i)).note("no USB devices")
}

fn instance_id(devs: HDEVINFO, dev: &SP_DEVINFO_DATA) -> Option<String> {
    let mut buf = [0u16; 512];
    unsafe { SetupDiGetDeviceInstanceIdW(devs, dev, Some(&mut buf), None) }.ok()?;
    Some(from_wide(&buf))
}

fn registry_property(devs: HDEVINFO, dev: &SP_DEVINFO_DATA, prop: SETUP_DI_REGISTRY_PROPERTY) -> Option<String> {
    let mut buf = [0u8; 1024];
    unsafe { SetupDiGetDeviceRegistryPropertyW(devs, dev, prop, None, Some(&mut buf), None) }.ok()?;
    Some(from_wide_bytes(&buf)).filter(|s| !s.is_empty())
}

/// The product string the device itself reports (e.g. "USB Receiver"),
/// which is more specific than the driver's generic description.
fn bus_description(devs: HDEVINFO, dev: &SP_DEVINFO_DATA) -> Option<String> {
    let mut buf = [0u8; 1024];
    let mut ty = DEVPROPTYPE::default();
    unsafe {
        SetupDiGetDevicePropertyW(devs, dev, &DEVPKEY_Device_BusReportedDeviceDesc, &mut ty, Some(&mut buf), None, 0)
    }
    .ok()?;
    Some(from_wide_bytes(&buf).trim().to_string()).filter(|s| !s.is_empty())
}
