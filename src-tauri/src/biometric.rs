use std::ptr;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use windows::core::HSTRING;
use windows::Security::Credentials::UI::{
    UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
};
use zeroize::Zeroizing;

const DPAPI_ENTROPY: &[u8] = b"VaultPass-WindowsHello-DPAPI-v1";
const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

const MB_YESNO: u32 = 0x0000_0004;
const MB_ICONQUESTION: u32 = 0x0000_0020;
const MB_DEFBUTTON2: u32 = 0x0000_0100;
const MB_SETFOREGROUND: u32 = 0x0001_0000;
const MB_TOPMOST: u32 = 0x0004_0000;
const IDYES: i32 = 6;

#[repr(C)]
struct DataBlob {
    cb_data: u32,
    pb_data: *mut u8,
}

#[link(name = "crypt32")]
extern "system" {
    fn CryptProtectData(
        p_data_in: *const DataBlob,
        sz_data_descr: *const u16,
        p_optional_entropy: *const DataBlob,
        pv_reserved: *mut core::ffi::c_void,
        p_prompt_struct: *const core::ffi::c_void,
        dw_flags: u32,
        p_data_out: *mut DataBlob,
    ) -> i32;

    fn CryptUnprotectData(
        p_data_in: *const DataBlob,
        ppsz_data_descr: *mut *mut u16,
        p_optional_entropy: *const DataBlob,
        pv_reserved: *mut core::ffi::c_void,
        p_prompt_struct: *const core::ffi::c_void,
        dw_flags: u32,
        p_data_out: *mut DataBlob,
    ) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn LocalFree(h_mem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
}

#[link(name = "user32")]
extern "system" {
    fn MessageBoxW(
        h_wnd: *mut core::ffi::c_void,
        lp_text: *const u16,
        lp_caption: *const u16,
        u_type: u32,
    ) -> i32;
}

pub fn dpapi_protect_key(key: &[u8; 32]) -> Result<String, String> {
    let in_blob = DataBlob {
        cb_data: key.len() as u32,
        pb_data: key.as_ptr() as *mut u8,
    };
    let entropy_blob = DataBlob {
        cb_data: DPAPI_ENTROPY.len() as u32,
        pb_data: DPAPI_ENTROPY.as_ptr() as *mut u8,
    };
    let mut out_blob = DataBlob {
        cb_data: 0,
        pb_data: ptr::null_mut(),
    };

    let ok = unsafe {
        CryptProtectData(
            &in_blob,
            ptr::null(),
            &entropy_blob,
            ptr::null_mut(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
    };

    if ok == 0 || out_blob.pb_data.is_null() {
        return Err("Gagal mengenkripsi kunci dengan Windows DPAPI.".to_string());
    }

    let encrypted =
        unsafe { std::slice::from_raw_parts(out_blob.pb_data, out_blob.cb_data as usize).to_vec() };
    unsafe {
        LocalFree(out_blob.pb_data as *mut core::ffi::c_void);
    }

    Ok(B64.encode(encrypted))
}

pub fn dpapi_unprotect_key(encoded_b64: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let mut encrypted = B64
        .decode(encoded_b64)
        .map_err(|_| "Data kunci biometrik DPAPI tidak valid.".to_string())?;

    let in_blob = DataBlob {
        cb_data: encrypted.len() as u32,
        pb_data: encrypted.as_mut_ptr(),
    };
    let entropy_blob = DataBlob {
        cb_data: DPAPI_ENTROPY.len() as u32,
        pb_data: DPAPI_ENTROPY.as_ptr() as *mut u8,
    };
    let mut out_blob = DataBlob {
        cb_data: 0,
        pb_data: ptr::null_mut(),
    };

    let ok = unsafe {
        CryptUnprotectData(
            &in_blob,
            ptr::null_mut(),
            &entropy_blob,
            ptr::null_mut(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
    };

    if ok == 0 || out_blob.pb_data.is_null() {
        return Err(
            "Gagal mendekripsi kunci biometrik dari Windows DPAPI. Silakan buka dengan Master Password."
                .to_string(),
        );
    }

    let slice =
        unsafe { std::slice::from_raw_parts_mut(out_blob.pb_data, out_blob.cb_data as usize) };
    if slice.len() != 32 {
        for b in slice.iter_mut() {
            *b = 0;
        }
        unsafe {
            LocalFree(out_blob.pb_data as *mut core::ffi::c_void);
        }
        return Err("Ukuran kunci biometrik tidak valid.".to_string());
    }

    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(slice);

    for b in slice.iter_mut() {
        *b = 0;
    }
    unsafe {
        LocalFree(out_blob.pb_data as *mut core::ffi::c_void);
    }

    Ok(key)
}

pub fn is_windows_hello_available() -> bool {
    std::thread::spawn(|| {
        let op = UserConsentVerifier::CheckAvailabilityAsync().ok()?;
        let avail = op.join().ok()?;
        Some(avail == UserConsentVerifierAvailability::Available)
    })
    .join()
    .ok()
    .flatten()
    .unwrap_or(false)
}

fn prompt_native_consent_dialog(prompt_message: &str) -> Result<(), String> {
    let text = format!(
        "{prompt_message}\n\n\
         (Windows Hello Sidik Jari belum terdeteksi di perangkat ini, menggunakan dialog konfirmasi keamanan Windows DPAPI).\n\n\
         Klik 'Yes' untuk mengizinkan akses, atau 'No' untuk menolak."
    );
    let mut text_utf16: Vec<u16> = text.encode_utf16().collect();
    text_utf16.push(0);

    let mut caption_utf16: Vec<u16> = "VaultPass — Konfirmasi Keamanan".encode_utf16().collect();
    caption_utf16.push(0);

    let response = unsafe {
        MessageBoxW(
            ptr::null_mut(),
            text_utf16.as_ptr(),
            caption_utf16.as_ptr(),
            MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2 | MB_SETFOREGROUND | MB_TOPMOST,
        )
    };

    if response == IDYES {
        Ok(())
    } else {
        Err("Akses ditolak atau dibatalkan oleh pengguna.".to_string())
    }
}

pub fn request_windows_hello_verification(prompt_message: &str) -> Result<(), String> {
    let msg = prompt_message.to_string();
    let hello_result =
        std::thread::spawn(move || -> Result<UserConsentVerificationResult, String> {
            let hmsg = HSTRING::from(msg.as_str());
            let op = UserConsentVerifier::RequestVerificationAsync(&hmsg)
                .map_err(|e| format!("Gagal memanggil dialog Windows Hello: {e}"))?;
            op.join()
                .map_err(|e| format!("Gagal menunggu hasil verifikasi Windows Hello: {e}"))
        })
        .join()
        .map_err(|_| "Thread verifikasi Windows Hello gagal.".to_string());

    match hello_result {
        Ok(Ok(UserConsentVerificationResult::Verified)) => Ok(()),
        Ok(Ok(UserConsentVerificationResult::Canceled)) => {
            Err("Verifikasi Sidik Jari / Windows Hello dibatalkan.".to_string())
        }
        Ok(Ok(UserConsentVerificationResult::RetriesExhausted)) => {
            Err("Percobaan verifikasi Windows Hello habis.".to_string())
        }
        // Fallback to native top-most Windows Security Consent Dialog if fingerprint/Hello
        // hardware is not enrolled or unpackaged WinRT prompt is unavailable
        Ok(Ok(UserConsentVerificationResult::DeviceNotPresent))
        | Ok(Ok(UserConsentVerificationResult::NotConfiguredForUser))
        | Ok(Ok(_))
        | Ok(Err(_))
        | Err(_) => prompt_native_consent_dialog(prompt_message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpapi_protect_and_unprotect_roundtrip() {
        let original = [0x5Au8; 32];
        let protected = dpapi_protect_key(&original).unwrap();
        let unprotected = dpapi_unprotect_key(&protected).unwrap();
        assert_eq!(&*unprotected, &original);
    }
}
