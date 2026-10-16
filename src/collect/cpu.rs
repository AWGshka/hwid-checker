//! CPU identity straight from the CPUID instruction.

use windows::Win32::System::SystemInformation::{
    GetLogicalProcessorInformation, RelationProcessorCore, SYSTEM_LOGICAL_PROCESSOR_INFORMATION,
};

use crate::report::{Item, Section};
use super::smbios::{self, Smbios};

pub fn section(sm: Option<&Smbios>) -> Section {
    let (vendor, brand, id) = cpuid();
    let (cores, threads) = topology();
    Section::new("cpu", "CPU").item(
        Item::new()
            .add("name", brand)
            .add("id", id)
            .add("vendor", vendor)
            .add("cores", cores.to_string())
            .add("threads", threads.to_string())
            .add("serial", smbios::cpu_serial(sm)),
    )
}

/// (physical cores, logical processors)
fn topology() -> (u32, u32) {
    let mut len = 0u32;
    unsafe {
        let _ = GetLogicalProcessorInformation(None, &mut len);
        let n = len as usize / size_of::<SYSTEM_LOGICAL_PROCESSOR_INFORMATION>();
        let mut buf = vec![SYSTEM_LOGICAL_PROCESSOR_INFORMATION::default(); n];
        if GetLogicalProcessorInformation(Some(buf.as_mut_ptr()), &mut len).is_err() {
            return (0, 0);
        }
        buf.iter()
            .filter(|i| i.Relationship == RelationProcessorCore)
            .fold((0, 0), |(c, t), i| (c + 1, t + i.ProcessorMask.count_ones()))
    }
}

/// Returns (vendor, brand string, ProcessorId). ProcessorId is leaf 1 EDX:EAX,
/// the same value WMI reports as Win32_Processor.ProcessorId.
#[cfg(target_arch = "x86_64")]
#[allow(unused_unsafe)]
fn cpuid() -> (String, String, String) {
    use std::arch::x86_64::__cpuid;
    let text = |bytes: Vec<u8>| String::from_utf8_lossy(&bytes).trim_matches(['\0', ' ']).to_string();
    unsafe {
        let l0 = __cpuid(0);
        let vendor = [l0.ebx, l0.edx, l0.ecx].iter().flat_map(|r| r.to_le_bytes()).collect();

        let mut brand = Vec::new();
        if __cpuid(0x8000_0000).eax >= 0x8000_0004 {
            for leaf in 0x8000_0002..=0x8000_0004u32 {
                let r = __cpuid(leaf);
                for reg in [r.eax, r.ebx, r.ecx, r.edx] {
                    brand.extend(reg.to_le_bytes());
                }
            }
        }

        let l1 = __cpuid(1);
        (text(vendor), text(brand), format!("{:08X}{:08X}", l1.edx, l1.eax))
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn cpuid() -> (String, String, String) {
    use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;
    const KEY: &str = r"HARDWARE\DESCRIPTION\System\CentralProcessor\0";
    let get = |name| crate::util::reg_string(HKEY_LOCAL_MACHINE, KEY, name).unwrap_or_default();
    (get("VendorIdentifier"), get("ProcessorNameString"), String::new())
}
