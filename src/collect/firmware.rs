//! Firmware type and Secure Boot. As admin, Secure Boot is read from the UEFI
//! variables themselves; otherwise from the registry copy Windows keeps.

use windows::Win32::Security::SE_SYSTEM_ENVIRONMENT_NAME;
use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;
use windows::Win32::System::SystemInformation::{FIRMWARE_TYPE, FirmwareTypeBios, FirmwareTypeUefi, GetFirmwareType};
use windows::Win32::System::WindowsProgramming::GetFirmwareEnvironmentVariableW;
use windows::core::{PCWSTR, w};

use crate::report::{Item, Section};
use crate::util;

pub fn secure_boot(admin: bool) -> Section {
    let s = Section::new("secure_boot", "SECURE BOOT");
    let mut fw = FIRMWARE_TYPE::default();
    unsafe {
        let _ = GetFirmwareType(&mut fw);
    }
    if fw == FirmwareTypeBios {
        return s.item(Item::new().add("state", "Unsupported").add("firmware", "Legacy BIOS"));
    }
    let firmware = if fw == FirmwareTypeUefi { "UEFI" } else { "Unknown" };

    if admin
        && util::enable_privilege(SE_SYSTEM_ENVIRONMENT_NAME)
        && let Some(enabled) = efi_byte(w!("SecureBoot"))
    {
        let setup = efi_byte(w!("SetupMode")).map(|m| if m == 1 { "yes" } else { "no" }).unwrap_or_default();
        return s.item(
            Item::new()
                .add("state", on_off(enabled == 1))
                .add("setup_mode", setup)
                .add("firmware", firmware)
                .add("source", "UEFI variable"),
        );
    }

    let reg = util::reg_dword(
        HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
        "UEFISecureBootEnabled",
    );
    s.item(
        Item::new()
            .add("state", reg.map(|v| on_off(v == 1)).unwrap_or(util::NA))
            .add("firmware", firmware)
            .add("source", "registry"),
    )
}

fn on_off(b: bool) -> &'static str {
    if b { "On" } else { "Off" }
}

/// Reads a 1-byte variable from the EFI global namespace.
fn efi_byte(name: PCWSTR) -> Option<u8> {
    let mut b = 0u8;
    let n = unsafe {
        GetFirmwareEnvironmentVariableW(name, w!("{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}"), Some(&mut b as *mut u8 as _), 1)
    };
    (n == 1).then_some(b)
}
