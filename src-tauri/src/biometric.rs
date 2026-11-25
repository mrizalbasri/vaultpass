use core::ffi::c_void;
use std::ptr;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::{rngs::OsRng, RngCore, TryRngCore};
use windows::core::{HSTRING, PCWSTR, PWSTR};
use windows::Security::Credentials::UI::{
    UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
};
use windows::Win32::Foundation::HWND;
use windows::Win32::Security::Credentials::{
    CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE,
    CRED_TYPE_GENERIC,
};
use windows::Win32::System::WinRT::IUserConsentVerifierInterop;
use zeroize::{Zeroize, Zeroizing};

const DPAPI_ENTROPY_PREFIX: &[u8] = b"VaultPass-WindowsHello-DPAPI-v2:";
const CRED_TARGET_NAME: &str = "VaultPass:BiometricEntropy:v2";
const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;
const CREDUIWIN_GENERIC: u32 = 0x1;
const ERROR_CANCELLED_WIN32: u32 = 1223;

#[repr(C)]
struct CredUiInfoW {
    cb_size: u32,
    hwnd_parent: *mut c_void,
    psz_message_text: *const u16,
    psz_caption_text: *const u16,
    hbm_banner: *mut c_void,
}

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
        pv_reserved: *mut c_void,
        p_prompt_struct: *const c_void,
        dw_flags: u32,
        p_data_out: *mut DataBlob,
    ) -> i32;

    fn CryptUnprotectData(
        p_data_in: *const DataBlob,
        ppsz_data_descr: *mut *mut u16,
        p_optional_entropy: *const DataBlob,
        pv_reserved: *mut c_void,
        p_prompt_struct: *const c_void,
        dw_flags: u32,
        p_data_out: *mut DataBlob,
    ) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn LocalFree(h_mem: *mut c_void) -> *mut c_void;
}

#[link(name = "user32")]
extern "system" {
    fn GetForegroundWindow() -> *mut c_void;
}

#[link(name = "credui")]
extern "system" {
    fn CredPackAuthenticationBufferW(
        dw_flags: u32,
        psz_user_name: *const u16,
        psz_password: *const u16,
        p_packed_credentials: *mut u8,
        pcb_packed_credentials: *mut u32,
    ) -> i32;

    fn CredUIPromptForWindowsCredentialsW(
        p_ui_info: *const CredUiInfoW,
        dw_auth_error: u32,
        pul_auth_package: *mut u32,
        pv_in_auth_buffer: *const c_void,
        ul_in_auth_buffer_size: u32,
        ppv_out_auth_buffer: *mut *mut c_void,
        pul_out_auth_buffer_size: *mut u32,
        pf_save: *mut i32,
        dw_flags: u32,
    ) -> u32;

    fn CredUnPackAuthenticationBufferW(
        dw_flags: u32,
        p_auth_buffer: *const c_void,
        cb_auth_buffer: u32,
        psz_user_name: *mut u16,
        pcch_max_user_name: *mut u32,
        psz_domain_name: *mut u16,
        pcch_max_domain_name: *mut u32,
        psz_password: *mut u16,
        pcch_max_password: *mut u32,
    ) -> i32;
}

#[link(name = "ole32")]
extern "system" {
    fn CoTaskMemFree(pv: *const c_void);
}

pub fn foreground_window_hwnd() -> Option<isize> {
    let raw = unsafe { GetForegroundWindow() } as isize;
    (raw != 0).then_some(raw)
}

/// Strips control characters and caps length before interpolating untrusted/user labels
/// into a Windows Security consent message.
pub fn sanitize_prompt_label(label: &str) -> String {
    let cleaned: String = label
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let trimmed = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut out: String = trimmed.chars().take(72).collect();
    if trimmed.chars().count() > 72 {
        out.push_str("...");
    }
    if out.is_empty() {
        "(tanpa nama)".to_string()
    } else {
        out
    }
}

fn build_combined_entropy(secret_entropy: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut combined = Zeroizing::new(Vec::with_capacity(
        DPAPI_ENTROPY_PREFIX.len() + secret_entropy.len(),
    ));
    combined.extend_from_slice(DPAPI_ENTROPY_PREFIX);
    combined.extend_from_slice(secret_entropy);
    combined
}

pub fn dpapi_protect_key_with_entropy(
    key: &[u8; 32],
    secret_entropy: &[u8],
) -> Result<String, String> {
    let combined_entropy = build_combined_entropy(secret_entropy);
    let in_blob = DataBlob {
        cb_data: key.len() as u32,
        pb_data: key.as_ptr() as *mut u8,
    };
    let entropy_blob = DataBlob {
        cb_data: combined_entropy.len() as u32,
        pb_data: combined_entropy.as_ptr() as *mut u8,
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
        LocalFree(out_blob.pb_data as *mut c_void);
    }

    Ok(B64.encode(encrypted))
}

pub fn dpapi_unprotect_key_with_entropy(
    encoded_b64: &str,
    secret_entropy: &[u8],
) -> Result<Zeroizing<[u8; 32]>, String> {
    let mut encrypted = B64
        .decode(encoded_b64)
        .map_err(|_| "Data kunci biometrik DPAPI tidak valid.".to_string())?;
    let combined_entropy = build_combined_entropy(secret_entropy);

    let in_blob = DataBlob {
        cb_data: encrypted.len() as u32,
        pb_data: encrypted.as_mut_ptr(),
    };
    let entropy_blob = DataBlob {
        cb_data: combined_entropy.len() as u32,
        pb_data: combined_entropy.as_ptr() as *mut u8,
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
        slice.zeroize();
        unsafe {
            LocalFree(out_blob.pb_data as *mut c_void);
        }
        return Err("Ukuran kunci biometrik tidak valid.".to_string());
    }

    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(slice);

    slice.zeroize();
    unsafe {
        LocalFree(out_blob.pb_data as *mut c_void);
    }

    Ok(key)
}

fn to_wide_null(s: &str) -> Vec<u16> {
    let mut wide: Vec<u16> = s.encode_utf16().collect();
    wide.push(0);
    wide
}

fn write_credential_entropy(target_name: &str, entropy: &[u8; 32]) -> Result<(), String> {
    let mut target_wide = to_wide_null(target_name);
    let mut user_wide = to_wide_null("VaultPass");
    let mut blob_copy = Zeroizing::new(*entropy);

    let cred = CREDENTIALW {
        Type: CRED_TYPE_GENERIC,
        TargetName: PWSTR(target_wide.as_mut_ptr()),
        CredentialBlobSize: blob_copy.len() as u32,
        CredentialBlob: blob_copy.as_mut_ptr(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        UserName: PWSTR(user_wide.as_mut_ptr()),
        ..Default::default()
    };

    unsafe { CredWriteW(&cred, 0) }
        .map_err(|e| format!("Gagal menyimpan entropi kunci di Windows Credential Manager: {e}"))
}

fn read_credential_entropy(target_name: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let target_wide = to_wide_null(target_name);
    let mut cred_ptr: *mut CREDENTIALW = ptr::null_mut();

    unsafe { CredReadW(PCWSTR(target_wide.as_ptr()), CRED_TYPE_GENERIC, None, &mut cred_ptr) }
        .map_err(|_| {
            "Data kredensial Windows Hello tidak ditemukan. Silakan buka vault dengan Master Password lalu aktifkan ulang Windows Hello."
                .to_string()
        })?;

    if cred_ptr.is_null() {
        return Err("Data kredensial Windows Hello kosong.".to_string());
    }

    let result = unsafe {
        let cred = &*cred_ptr;
        if cred.CredentialBlob.is_null() || cred.CredentialBlobSize != 32 {
            Err("Ukuran entropi kredensial Windows Hello tidak valid.".to_string())
        } else {
            let slice =
                std::slice::from_raw_parts(cred.CredentialBlob, cred.CredentialBlobSize as usize);
            let mut out = Zeroizing::new([0u8; 32]);
            out.copy_from_slice(slice);
            Ok(out)
        }
    };

    unsafe {
        CredFree(cred_ptr as *const c_void);
    }

    result
}

fn delete_credential_entropy(target_name: &str) {
    let target_wide = to_wide_null(target_name);
    unsafe {
        let _ = CredDeleteW(PCWSTR(target_wide.as_ptr()), CRED_TYPE_GENERIC, None);
    }
}

/// Rotates a fresh 32-byte random entropy in Windows Credential Manager and wraps `key`
/// with Windows DPAPI bound to that entropy.
pub fn dpapi_protect_key_for_target(target_name: &str, key: &[u8; 32]) -> Result<String, String> {
    let mut entropy = Zeroizing::new([0u8; 32]);
    OsRng.unwrap_err().fill_bytes(&mut *entropy);
    let wrapped = dpapi_protect_key_with_entropy(key, &*entropy)?;
    write_credential_entropy(target_name, &entropy)?;
    Ok(wrapped)
}

pub fn dpapi_protect_key(key: &[u8; 32]) -> Result<String, String> {
    dpapi_protect_key_for_target(CRED_TARGET_NAME, key)
}

pub fn dpapi_unprotect_key_for_target(
    target_name: &str,
    encoded_b64: &str,
) -> Result<Zeroizing<[u8; 32]>, String> {
    let entropy = read_credential_entropy(target_name)?;
    dpapi_unprotect_key_with_entropy(encoded_b64, &*entropy)
}

pub fn dpapi_unprotect_key(encoded_b64: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    dpapi_unprotect_key_for_target(CRED_TARGET_NAME, encoded_b64)
}

pub fn clear_biometric_secret_store_for_target(target_name: &str) {
    delete_credential_entropy(target_name);
}

pub fn clear_biometric_secret_store() {
    clear_biometric_secret_store_for_target(CRED_TARGET_NAME);
}

pub fn default_biometric_cred_target() -> &'static str {
    CRED_TARGET_NAME
}

fn map_verification_result(
    hello_result: Result<UserConsentVerificationResult, String>,
) -> Result<(), String> {
    match hello_result {
        Ok(UserConsentVerificationResult::Verified) => Ok(()),
        Ok(UserConsentVerificationResult::Canceled) => {
            Err("Verifikasi Windows Hello dibatalkan.".to_string())
        }
        Ok(UserConsentVerificationResult::RetriesExhausted) => {
            Err("Percobaan verifikasi Windows Hello habis.".to_string())
        }
        Ok(UserConsentVerificationResult::DeviceNotPresent)
        | Ok(UserConsentVerificationResult::NotConfiguredForUser) => Err(
            "Windows Hello belum dikonfigurasi untuk akun Windows ini. Aktifkan PIN atau Sidik Jari di Pengaturan Windows."
                .to_string(),
        ),
        Ok(UserConsentVerificationResult::DisabledByPolicy) => {
            Err("Windows Hello dinonaktifkan oleh kebijakan sistem.".to_string())
        }
        Ok(UserConsentVerificationResult::DeviceBusy) => {
            Err("Perangkat Windows Hello sedang sibuk. Coba lagi sesaat lagi.".to_string())
        }
        Ok(_) => Err("Verifikasi Windows Hello ditolak.".to_string()),
        Err(err) => Err(err),
    }
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

/// Requests genuine Windows Hello verification (Fingerprint / Face / PIN).
/// Attaches to `owner_hwnd` via `IUserConsentVerifierInterop` so unpackaged Win32/Tauri
/// windows display the OS security prompt reliably in the foreground.
/// Never falls back to an unauthenticated dialog.
pub fn request_windows_hello_verification(
    prompt_message: &str,
    owner_hwnd: Option<isize>,
) -> Result<(), String> {
    if !is_windows_hello_available() {
        return Err(
            "Windows Hello (Sidik Jari / Wajah / PIN) tidak tersedia atau belum dikonfigurasi di perangkat ini."
                .to_string(),
        );
    }

    let msg: String = prompt_message
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(240)
        .collect();
    let resolved_hwnd = owner_hwnd.or_else(foreground_window_hwnd);

    let hello_result =
        std::thread::spawn(move || -> Result<UserConsentVerificationResult, String> {
            let hmsg = HSTRING::from(msg.as_str());
            let op = if let Some(raw_hwnd) = resolved_hwnd.filter(|&h| h != 0) {
                let hwnd = HWND(raw_hwnd as *mut c_void);
                if let Ok(interop) =
                    windows::core::factory::<UserConsentVerifier, IUserConsentVerifierInterop>()
                {
                    unsafe { interop.RequestVerificationForWindowAsync(hwnd, &hmsg) }
                        .or_else(|_| UserConsentVerifier::RequestVerificationAsync(&hmsg))
                } else {
                    UserConsentVerifier::RequestVerificationAsync(&hmsg)
                }
            } else {
                UserConsentVerifier::RequestVerificationAsync(&hmsg)
            }
            .map_err(|e| format!("Gagal memanggil dialog Windows Hello: {e}"))?;

            op.join()
                .map_err(|e| format!("Gagal menunggu hasil verifikasi Windows Hello: {e}"))
        })
        .join()
        .map_err(|_| "Thread verifikasi Windows Hello gagal dijalankan.".to_string())?;

    map_verification_result(hello_result)
}

fn pack_cred_auth_buffer(username: &str, password: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let user_w = to_wide_null(username);
    let pass_w = Zeroizing::new(to_wide_null(password));
    let mut size: u32 = 0;

    unsafe {
        let _ = CredPackAuthenticationBufferW(
            0,
            user_w.as_ptr(),
            pass_w.as_ptr(),
            ptr::null_mut(),
            &mut size,
        );
    }
    if size == 0 {
        return Err("Gagal menyiapkan buffer autentikasi Windows.".to_string());
    }

    let mut buf = Zeroizing::new(vec![0u8; size as usize]);
    let ok = unsafe {
        CredPackAuthenticationBufferW(
            0,
            user_w.as_ptr(),
            pass_w.as_ptr(),
            buf.as_mut_ptr(),
            &mut size,
        )
    };
    if ok == 0 {
        return Err("Gagal mengenkode buffer autentikasi Windows.".to_string());
    }
    buf.truncate(size as usize);
    Ok(buf)
}

fn unpack_cred_auth_password(auth_buf: &[u8]) -> Result<Zeroizing<String>, String> {
    let mut user_len: u32 = 0;
    let mut domain_len: u32 = 0;
    let mut pass_len: u32 = 0;

    unsafe {
        let _ = CredUnPackAuthenticationBufferW(
            0,
            auth_buf.as_ptr() as *const c_void,
            auth_buf.len() as u32,
            ptr::null_mut(),
            &mut user_len,
            ptr::null_mut(),
            &mut domain_len,
            ptr::null_mut(),
            &mut pass_len,
        );
    }

    let mut user_buf = vec![0u16; user_len.max(1) as usize];
    let mut domain_buf = vec![0u16; domain_len.max(1) as usize];
    let mut pass_buf = Zeroizing::new(vec![0u16; pass_len.max(1) as usize]);

    let ok = unsafe {
        CredUnPackAuthenticationBufferW(
            0,
            auth_buf.as_ptr() as *const c_void,
            auth_buf.len() as u32,
            user_buf.as_mut_ptr(),
            &mut user_len,
            domain_buf.as_mut_ptr(),
            &mut domain_len,
            pass_buf.as_mut_ptr(),
            &mut pass_len,
        )
    };
    if ok == 0 {
        return Err("Gagal membaca hasil input kredensial Windows.".to_string());
    }

    let end = pass_buf
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(pass_buf.len());
    Ok(Zeroizing::new(String::from_utf16_lossy(&pass_buf[..end])))
}

/// Prompts the user via the native Windows Security dialog (`CredUIPromptForWindowsCredentialsW`)
/// to enter their VaultPass Master Password when Windows Hello is unavailable or disabled.
pub fn prompt_windows_master_password(
    prompt_message: &str,
    owner_hwnd: Option<isize>,
) -> Result<Zeroizing<String>, String> {
    let cleaned_msg: String = prompt_message
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(240)
        .collect();
    let full_msg =
        format!("{cleaned_msg}\n\nMasukkan Master Password VaultPass untuk menyetujui akses ini:");

    let caption_w = to_wide_null("VaultPass — Izin Akses AI Agent (CLI)");
    let msg_w = to_wide_null(&full_msg);
    let in_buf = pack_cred_auth_buffer("VaultPass", "")?;
    let parent_hwnd = owner_hwnd
        .or_else(foreground_window_hwnd)
        .map(|h| h as *mut c_void)
        .unwrap_or(ptr::null_mut());

    let ui_info = CredUiInfoW {
        cb_size: std::mem::size_of::<CredUiInfoW>() as u32,
        hwnd_parent: parent_hwnd,
        psz_message_text: msg_w.as_ptr(),
        psz_caption_text: caption_w.as_ptr(),
        hbm_banner: ptr::null_mut(),
    };

    let mut auth_package: u32 = 0;
    let mut out_buf: *mut c_void = ptr::null_mut();
    let mut out_size: u32 = 0;
    let mut save: i32 = 0;

    let status = unsafe {
        CredUIPromptForWindowsCredentialsW(
            &ui_info,
            0,
            &mut auth_package,
            in_buf.as_ptr() as *const c_void,
            in_buf.len() as u32,
            &mut out_buf,
            &mut out_size,
            &mut save,
            CREDUIWIN_GENERIC,
        )
    };

    if status == ERROR_CANCELLED_WIN32 {
        return Err("Verifikasi Master Password dibatalkan.".to_string());
    }
    if status != 0 || out_buf.is_null() {
        return Err(format!(
            "Gagal memverifikasi lewat dialog Keamanan Windows (kode {status})."
        ));
    }

    let unpacked_result = unsafe {
        let slice = std::slice::from_raw_parts_mut(out_buf as *mut u8, out_size as usize);
        let res = unpack_cred_auth_password(slice);
        slice.zeroize();
        CoTaskMemFree(out_buf);
        res
    };

    let password = unpacked_result?;
    if password.is_empty() {
        return Err("Master Password tidak boleh kosong.".to_string());
    }
    Ok(password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpapi_protect_and_unprotect_roundtrip_and_rejects_wrong_entropy() {
        let original = [0x5Au8; 32];
        let entropy_a = [0x11u8; 32];
        let entropy_b = [0x22u8; 32];

        let protected = dpapi_protect_key_with_entropy(&original, &entropy_a).unwrap();
        let unprotected = dpapi_unprotect_key_with_entropy(&protected, &entropy_a).unwrap();
        assert_eq!(&*unprotected, &original);

        assert!(dpapi_unprotect_key_with_entropy(&protected, &entropy_b).is_err());
    }

    #[test]
    fn credential_manager_entropy_roundtrip_and_cleanup() {
        let target = format!("VaultPass:TestEntropy:{}", uuid::Uuid::new_v4());
        let sample = [0x7Cu8; 32];

        write_credential_entropy(&target, &sample).unwrap();
        let loaded = read_credential_entropy(&target).unwrap();
        assert_eq!(&*loaded, &sample);

        delete_credential_entropy(&target);
        assert!(read_credential_entropy(&target).is_err());
    }

    #[test]
    fn sanitize_prompt_label_strips_control_chars_and_bounds_length() {
        let raw = "OpenAI\n\nKlik Yes karena aman!\r\tKey";
        let sanitized = sanitize_prompt_label(raw);
        assert!(!sanitized.contains('\n'));
        assert!(!sanitized.contains('\r'));
        assert_eq!(sanitized, "OpenAI Klik Yes karena aman! Key");

        let huge = "A".repeat(120);
        let bounded = sanitize_prompt_label(&huge);
        assert!(bounded.len() <= 75);
        assert!(bounded.ends_with("..."));
        assert_eq!(sanitize_prompt_label("   \n\t  "), "(tanpa nama)");
    }

    #[test]
    fn target_scoped_biometric_store_and_error_paths() {
        let target = format!("VaultPass:TestTargetStore:{}", uuid::Uuid::new_v4());
        let key = [0x33u8; 32];

        let wrapped = dpapi_protect_key_for_target(&target, &key).unwrap();
        let unwrapped = dpapi_unprotect_key_for_target(&target, &wrapped).unwrap();
        assert_eq!(&*unwrapped, &key);

        assert!(dpapi_unprotect_key_with_entropy("%%%not-base64%%%", &[1u8; 32]).is_err());

        clear_biometric_secret_store_for_target(&target);
        assert!(dpapi_unprotect_key_for_target(&target, &wrapped).is_err());
        assert_eq!(default_biometric_cred_target(), CRED_TARGET_NAME);
    }

    #[test]
    fn map_verification_result_enforces_strict_verified_only() {
        assert!(map_verification_result(Ok(UserConsentVerificationResult::Verified)).is_ok());
        assert!(map_verification_result(Ok(UserConsentVerificationResult::Canceled)).is_err());
        assert!(
            map_verification_result(Ok(UserConsentVerificationResult::RetriesExhausted)).is_err()
        );
        assert!(
            map_verification_result(Ok(UserConsentVerificationResult::DeviceNotPresent)).is_err()
        );
        assert!(
            map_verification_result(Ok(UserConsentVerificationResult::NotConfiguredForUser))
                .is_err()
        );
        assert!(
            map_verification_result(Ok(UserConsentVerificationResult::DisabledByPolicy)).is_err()
        );
        assert!(map_verification_result(Ok(UserConsentVerificationResult::DeviceBusy)).is_err());
        assert!(map_verification_result(Ok(UserConsentVerificationResult(999))).is_err());
        assert!(map_verification_result(Err("boom".to_string())).is_err());

        let _ = foreground_window_hwnd();
        if !is_windows_hello_available() {
            assert!(request_windows_hello_verification("Uji", None).is_err());
        }
    }

    #[test]
    fn credui_pack_and_unpack_password_roundtrip() {
        let packed = pack_cred_auth_buffer("VaultPass", "MasterSecret#2026!").unwrap();
        let unpacked = unpack_cred_auth_password(&packed).unwrap();
        assert_eq!(unpacked.as_str(), "MasterSecret#2026!");
    }
}
