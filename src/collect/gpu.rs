//! GPUs via DXGI. A per-board GPU serial isn't exposed by Windows (only by
//! vendor SDKs such as NVAPI), so this shows the PCI hardware ID instead.

use windows::Win32::Graphics::Dxgi::{CreateDXGIFactory1, DXGI_ADAPTER_FLAG_SOFTWARE, IDXGIFactory1};

use crate::report::{Item, Section};
use crate::util::from_wide;

pub fn section() -> Section {
    let s = Section::new("gpu", "GPU");
    let Ok(factory) = (unsafe { CreateDXGIFactory1::<IDXGIFactory1>() }) else {
        return s.note("DXGI unavailable");
    };
    let mut items = Vec::new();
    for i in 0.. {
        let Ok(adapter) = (unsafe { factory.EnumAdapters1(i) }) else { break };
        let Ok(d) = (unsafe { adapter.GetDesc1() }) else { continue };
        if d.Flags & DXGI_ADAPTER_FLAG_SOFTWARE.0 as u32 != 0 {
            continue;
        }
        items.push(
            Item::new()
                .add("name", from_wide(&d.Description))
                .add(
                    "id",
                    format!(
                        "VEN_{:04X}&DEV_{:04X}&SUBSYS_{:08X}&REV_{:02X}",
                        d.VendorId, d.DeviceId, d.SubSysId, d.Revision
                    ),
                )
                .add("vram", format!("{} MB", d.DedicatedVideoMemory / (1024 * 1024))),
        );
    }
    s.items(items)
}
