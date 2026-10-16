//! TPM presence/version via TPM Base Services, plus manufacturer and a SHA-256
//! of the endorsement key (EK) public part via the Platform Crypto Provider.
//! The EK is burned into the TPM, so its hash is one of the most stable IDs.

use std::ffi::c_void;

use windows::Win32::Security::Cryptography::{
    MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_HANDLE, NCRYPT_PROV_HANDLE, NCryptFreeObject, NCryptGetProperty,
    NCryptOpenStorageProvider,
};
use windows::Win32::Security::OBJECT_SECURITY_INFORMATION;
use windows::Win32::System::TpmBaseServices::{TPM_DEVICE_INFO, Tbsi_GetDeviceInfo};
use windows::core::{PCWSTR, w};

use crate::report::{Item, Section};
use crate::util::{NA, err_value, from_wide_bytes, sha256};

pub fn section() -> Section {
    let s = Section::new("tpm", "TPM");
    let mut info = TPM_DEVICE_INFO::default();
    let r = unsafe { Tbsi_GetDeviceInfo(size_of::<TPM_DEVICE_INFO>() as u32, &mut info as *mut _ as *mut c_void) };
    if r != 0 {
        return s.item(Item::new().add("state", "Off / not present"));
    }
    let version = match info.tpmVersion {
        1 => "1.2".to_string(),
        2 => "2.0".to_string(),
        v => format!("unknown ({v})"),
    };
    let (manufacturer, ek) = pcp_info();
    s.item(
        Item::new()
            .add("state", "On")
            .add("version", version)
            .add("manufacturer", manufacturer)
            .add("ek_sha256", ek),
    )
}

fn pcp_info() -> (String, String) {
    unsafe {
        let mut prov = NCRYPT_PROV_HANDLE::default();
        if NCryptOpenStorageProvider(&mut prov, MS_PLATFORM_CRYPTO_PROVIDER, 0).is_err() {
            return (NA.into(), NA.into());
        }
        let h = NCRYPT_HANDLE(prov.0);
        // Returned as a UTF-16 string, e.g. "AMD", "INTC", "IFX".
        let manufacturer = property(h, w!("PCP_TPM_MANUFACTURER_ID"))
            .ok()
            .map(|b| from_wide_bytes(&b))
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| NA.into());
        let ek = match property(h, w!("PCP_EKPUB")) {
            Ok(blob) => sha256(&blob),
            Err(e) => err_value(&e),
        };
        let _ = NCryptFreeObject(h);
        (manufacturer, ek)
    }
}

unsafe fn property(h: NCRYPT_HANDLE, name: PCWSTR) -> windows::core::Result<Vec<u8>> {
    let mut size = 0u32;
    unsafe {
        NCryptGetProperty(h, name, None, &mut size, OBJECT_SECURITY_INFORMATION(0))?;
        let mut buf = vec![0u8; size as usize];
        NCryptGetProperty(h, name, Some(&mut buf), &mut size, OBJECT_SECURITY_INFORMATION(0))?;
        buf.truncate(size as usize);
        Ok(buf)
    }
}
