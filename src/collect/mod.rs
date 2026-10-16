//! Data collectors: each module reads one kind of hardware or software
//! identifier straight from Windows APIs and returns report sections.

mod cpu;
mod disks;
mod firmware;
mod gpu;
mod monitors;
mod net;
mod smbios;
mod system;
mod tpm;
mod usb;
mod volumes;

use crate::report::{self, Report, Tab};

/// Runs every collector and groups the sections into tabs.
pub fn collect(admin: bool) -> Report {
    let sm = smbios::read();
    let sm = sm.as_ref();
    let adapters = net::adapters();
    let tabs = [
        (
            Tab::System,
            vec![system::windows(), system::software_ids(), net::interface_guids_section(&adapters)],
        ),
        (
            Tab::Hardware,
            vec![
                cpu::section(sm),
                smbios::baseboard(sm),
                smbios::bios(sm),
                smbios::uuid(sm),
                smbios::system(sm),
                smbios::chassis(sm),
                smbios::memory(sm),
            ],
        ),
        (Tab::Storage, vec![disks::section(), volumes::section()]),
        (
            Tab::Network,
            vec![net::mac_section(&adapters), net::gateway_section(&adapters), net::bluetooth_section()],
        ),
        (Tab::Devices, vec![gpu::section(), monitors::section(), usb::section()]),
        (Tab::Security, vec![tpm::section(), firmware::secure_boot(admin)]),
    ];
    let sections = tabs.into_iter().flat_map(|(tab, secs)| report::tag(secs, tab)).collect();
    Report { admin, sections }
}
