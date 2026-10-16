//! Windows installation details and the software-side identifiers Windows
//! generates (registry GUIDs, SIDs, DHCPv6 DUID, hardware IDs).

use std::ffi::c_void;

use windows::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE as HKLM;
use windows::Win32::System::SystemInformation::{ComputerNamePhysicalDnsHostname, GetComputerNameExW};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::PWSTR;

use crate::report::{Item, Section};
use crate::util::{Handle, from_wide, reg_binary, reg_dword, reg_string, utc_datetime};

const NT: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

fn get(key: &str, name: &str) -> String {
    reg_string(HKLM, key, name).unwrap_or_default()
}

pub fn windows() -> Section {
    let build: u32 = get(NT, "CurrentBuild").parse().unwrap_or(0);
    // ProductName still says "Windows 10" on Windows 11.
    let mut product = get(NT, "ProductName");
    if build >= 22000 {
        product = product.replacen("Windows 10", "Windows 11", 1);
    }
    let ubr = reg_dword(HKLM, NT, "UBR").map(|u| format!(".{u}")).unwrap_or_default();
    let os = format!("{product} {} (build {build}{ubr})", get(NT, "DisplayVersion"));
    let installed = reg_dword(HKLM, NT, "InstallDate").map(|t| utc_datetime(t as i64)).unwrap_or_default();

    Section::new("windows", "WINDOWS").item(
        Item::new()
            .add("computer_name", computer_name())
            .add("os", os)
            .add("installed", installed)
            .add("registered_owner", get(NT, "RegisteredOwner"))
            .add("product_id", get(NT, "ProductId")),
    )
}

pub fn software_ids() -> Section {
    let (user_sid, machine_sid) = sids();
    let duid = reg_binary(HKLM, r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters", "Dhcpv6DUID")
        .map(|b| b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join("-"))
        .unwrap_or_default();

    Section::new("software_ids", "SOFTWARE IDENTIFIERS").item(
        Item::new()
            .add("machine_guid", get(r"SOFTWARE\Microsoft\Cryptography", "MachineGuid"))
            .add("hw_profile_guid", get(r"SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001", "HwProfileGuid"))
            .add("hardware_config", get(r"SYSTEM\HardwareConfig", "LastConfig"))
            .add("computer_hardware_id", get(r"SYSTEM\CurrentControlSet\Control\SystemInformation", "ComputerHardwareId"))
            .add("sus_client_id", get(r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate", "SusClientId"))
            .add("sqm_machine_id", get(r"SOFTWARE\Microsoft\SQMClient", "MachineId"))
            .add("dhcpv6_duid", duid)
            .add("machine_sid", machine_sid)
            .add("user_sid", user_sid),
    )
}

fn computer_name() -> String {
    let mut buf = [0u16; 256];
    let mut len = buf.len() as u32;
    match unsafe { GetComputerNameExW(ComputerNamePhysicalDnsHostname, Some(PWSTR(buf.as_mut_ptr())), &mut len) } {
        Ok(()) => from_wide(&buf),
        Err(_) => std::env::var("COMPUTERNAME").unwrap_or_default(),
    }
}

/// Current user's SID, and the machine SID it is issued under (local and
/// Microsoft accounts are S-1-5-21-<machine>-<RID>).
fn sids() -> (String, String) {
    let user = unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return Default::default();
        }
        let token = Handle(token);
        let mut len = 0u32;
        let _ = GetTokenInformation(token.0, TokenUser, None, 0, &mut len);
        let mut buf = vec![0u64; len as usize / 8 + 1];
        if GetTokenInformation(token.0, TokenUser, Some(buf.as_mut_ptr() as *mut c_void), len, &mut len).is_err() {
            return Default::default();
        }
        let tu = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut s = PWSTR::null();
        if ConvertSidToStringSidW(tu.User.Sid, &mut s).is_err() {
            return Default::default();
        }
        let out = s.to_string().unwrap_or_default();
        let _ = LocalFree(Some(HLOCAL(s.0 as *mut c_void)));
        out
    };
    let machine = match user.strip_prefix("S-1-5-21-") {
        Some(_) => user.rsplit_once('-').map(|(m, _)| m.to_string()).unwrap_or_default(),
        None => String::new(),
    };
    (user, machine)
}
