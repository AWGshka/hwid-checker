//! Small helpers shared by the collectors: wide strings, registry reads,
//! device handles and IOCTLs, privilege checks.

use std::ffi::c_void;

use windows::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_SUCCESS, GetLastError, HANDLE,
};
use windows::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_QUERY, TokenElevation,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::Security::Cryptography::{BCRYPT_SHA256_ALG_HANDLE, BCryptHash};
use windows::Win32::System::Registry::{
    HKEY, KEY_READ, REG_ROUTINE_FLAGS, RRF_RT_REG_BINARY, RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RegCloseKey,
    RegEnumKeyExW, RegGetValueW, RegOpenKeyExW,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::{Error, GUID, PCWSTR, PWSTR};

pub const NA: &str = "N/A";
pub const ADMIN: &str = "requires admin";

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

pub fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// UTF-16LE bytes (as returned by registry/NCrypt) to a String.
pub fn from_wide_bytes(bytes: &[u8]) -> String {
    let w: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
    from_wide(&w)
}

/// Null-terminated ASCII string at `offset` inside `buf` (offset 0 means "absent").
pub fn cstr_at(buf: &[u8], offset: usize) -> String {
    if offset == 0 || offset >= buf.len() {
        return String::new();
    }
    let s = &buf[offset..];
    let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    String::from_utf8_lossy(&s[..end]).trim().to_string()
}

pub fn u16_at(buf: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(buf.get(off..off + 2)?.try_into().ok()?))
}

pub fn u32_at(buf: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(buf.get(off..off + 4)?.try_into().ok()?))
}

pub fn guid_from_bytes(b: &[u8]) -> Option<GUID> {
    let b: &[u8; 16] = b.get(..16)?.try_into().ok()?;
    Some(GUID::from_values(
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        u16::from_le_bytes([b[4], b[5]]),
        u16::from_le_bytes([b[6], b[7]]),
        [b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]],
    ))
}

pub fn guid_string(g: &GUID) -> String {
    let d = g.data4;
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        g.data1, g.data2, g.data3, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
    )
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

pub fn mac_string(mac: &[u8]) -> String {
    mac.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

pub fn is_access_denied(e: &Error) -> bool {
    e.code() == ERROR_ACCESS_DENIED.to_hresult()
}

/// "requires admin" for access-denied errors, "N/A" for anything else.
pub fn err_value(e: &Error) -> String {
    if is_access_denied(e) { ADMIN } else { NA }.to_string()
}

// ---------------------------------------------------------------------------
// Registry

fn reg_raw(key: HKEY, subkey: &str, name: &str, flags: REG_ROUTINE_FLAGS) -> Option<Vec<u8>> {
    let (sub, val) = (wide(subkey), wide(name));
    let mut size = 0u32;
    unsafe {
        RegGetValueW(key, PCWSTR(sub.as_ptr()), PCWSTR(val.as_ptr()), flags, None, None, Some(&mut size))
            .ok()
            .ok()?;
        let mut buf = vec![0u8; size as usize];
        RegGetValueW(
            key,
            PCWSTR(sub.as_ptr()),
            PCWSTR(val.as_ptr()),
            flags,
            None,
            Some(buf.as_mut_ptr() as *mut c_void),
            Some(&mut size),
        )
        .ok()
        .ok()?;
        buf.truncate(size as usize);
        Some(buf)
    }
}

pub fn reg_string(key: HKEY, subkey: &str, name: &str) -> Option<String> {
    let raw = reg_raw(key, subkey, name, RRF_RT_REG_SZ)?;
    Some(from_wide_bytes(&raw).trim().to_string()).filter(|s| !s.is_empty())
}

pub fn reg_dword(key: HKEY, subkey: &str, name: &str) -> Option<u32> {
    u32_at(&reg_raw(key, subkey, name, RRF_RT_REG_DWORD)?, 0)
}

pub fn reg_binary(key: HKEY, subkey: &str, name: &str) -> Option<Vec<u8>> {
    reg_raw(key, subkey, name, RRF_RT_REG_BINARY).filter(|b| !b.is_empty())
}

pub fn reg_subkeys(root: HKEY, path: &str) -> Vec<String> {
    let p = wide(path);
    let mut key = HKEY::default();
    if unsafe { RegOpenKeyExW(root, PCWSTR(p.as_ptr()), Some(0), KEY_READ, &mut key) }.is_err() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for i in 0.. {
        let mut name = [0u16; 256];
        let mut len = name.len() as u32;
        let r = unsafe { RegEnumKeyExW(key, i, Some(PWSTR(name.as_mut_ptr())), &mut len, None, None, None, None) };
        if r.is_err() {
            break;
        }
        out.push(from_wide(&name[..len as usize]));
    }
    unsafe {
        let _ = RegCloseKey(key);
    }
    out
}

// ---------------------------------------------------------------------------
// Hashing and time

pub fn sha256(data: &[u8]) -> String {
    let mut out = [0u8; 32];
    let status = unsafe { BCryptHash(BCRYPT_SHA256_ALG_HANDLE, None, data, &mut out) };
    if status.is_ok() { hex(&out) } else { NA.into() }
}

/// Unix timestamp to (year, month, day, hour, minute, second), UTC.
/// Civil-from-days algorithm by H. Hinnant.
fn civil(ts: i64) -> (i64, i64, i64, i64, i64, i64) {
    let (days, secs) = (ts.div_euclid(86_400), ts.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + (month <= 2) as i64;
    (year, month, day, secs / 3600, secs % 3600 / 60, secs % 60)
}

pub fn utc_datetime(ts: i64) -> String {
    let (y, mo, d, h, mi, _) = civil(ts);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02} UTC")
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Current UTC time as `YYYYMMDD-HHMMSS`, for file names.
pub fn timestamp_compact() -> String {
    let (y, mo, d, h, mi, s) = civil(unix_now());
    format!("{y:04}{mo:02}{d:02}-{h:02}{mi:02}{s:02}")
}

// ---------------------------------------------------------------------------
// Devices

pub struct Handle(pub HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Opens a device path such as `\\.\PhysicalDrive0`. `access` 0 is enough for
/// most query IOCTLs and works without admin.
pub fn open_device(path: &str, access: u32) -> windows::core::Result<Handle> {
    let w = wide(path);
    let h = unsafe {
        CreateFileW(
            PCWSTR(w.as_ptr()),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )?
    };
    Ok(Handle(h))
}

pub fn ioctl(h: &Handle, code: u32, input: &[u8], out_len: usize) -> windows::core::Result<Vec<u8>> {
    let mut out = vec![0u8; out_len];
    let mut returned = 0u32;
    let input_ptr = (!input.is_empty()).then_some(input.as_ptr() as *const c_void);
    unsafe {
        DeviceIoControl(
            h.0,
            code,
            input_ptr,
            input.len() as u32,
            Some(out.as_mut_ptr() as *mut c_void),
            out_len as u32,
            Some(&mut returned),
            None,
        )?;
    }
    out.truncate(returned as usize);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Process token

pub fn is_admin() -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let token = Handle(token);
        let mut elevation = TOKEN_ELEVATION::default();
        let mut len = 0u32;
        GetTokenInformation(
            token.0,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut c_void),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
        .is_ok()
            && elevation.TokenIsElevated != 0
    }
}

pub fn enable_privilege(name: PCWSTR) -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let token = Handle(token);
        let mut tp = TOKEN_PRIVILEGES { PrivilegeCount: 1, ..Default::default() };
        if LookupPrivilegeValueW(PCWSTR::null(), name, &mut tp.Privileges[0].Luid).is_err() {
            return false;
        }
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        // AdjustTokenPrivileges "succeeds" even when the privilege isn't held; check last error.
        AdjustTokenPrivileges(token.0, false, Some(&tp), 0, None, None).is_ok() && GetLastError() == ERROR_SUCCESS
    }
}
