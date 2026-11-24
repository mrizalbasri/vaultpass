use core::ffi::c_void;
use std::ptr;
use std::thread;
use std::time::Duration;

use zeroize::Zeroize;

const CF_UNICODETEXT: u32 = 13;
const GMEM_MOVEABLE: u32 = 0x0002;
const GMEM_ZEROINIT: u32 = 0x0040;

#[link(name = "user32")]
extern "system" {
    fn OpenClipboard(h_wnd_new_owner: *mut c_void) -> i32;
    fn CloseClipboard() -> i32;
    fn EmptyClipboard() -> i32;
    fn SetClipboardData(u_format: u32, h_mem: *mut c_void) -> *mut c_void;
    fn GetClipboardData(u_format: u32) -> *mut c_void;
    fn RegisterClipboardFormatW(lpsz_format: *const u16) -> u32;
}

#[link(name = "kernel32")]
extern "system" {
    fn GlobalAlloc(u_flags: u32, dw_bytes: usize) -> *mut c_void;
    fn GlobalLock(h_mem: *mut c_void) -> *mut c_void;
    fn GlobalUnlock(h_mem: *mut c_void) -> i32;
    fn GlobalFree(h_mem: *mut c_void) -> *mut c_void;
    fn GlobalSize(h_mem: *mut c_void) -> usize;
}

struct ClipboardGuard;

impl ClipboardGuard {
    fn open() -> Result<Self, String> {
        for attempt in 0..6 {
            let opened = unsafe { OpenClipboard(ptr::null_mut()) };
            if opened != 0 {
                return Ok(Self);
            }
            if attempt < 5 {
                thread::sleep(Duration::from_millis(15));
            }
        }
        Err("Gagal membuka clipboard Windows (sedang digunakan aplikasi lain).".to_string())
    }
}

impl Drop for ClipboardGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseClipboard();
        }
    }
}

fn register_format(name: &str) -> u32 {
    let mut wide: Vec<u16> = name.encode_utf16().collect();
    wide.push(0);
    unsafe { RegisterClipboardFormatW(wide.as_ptr()) }
}

unsafe fn set_raw_clipboard_bytes(format: u32, bytes: &[u8]) -> Result<(), String> {
    if format == 0 {
        return Ok(());
    }
    let alloc_len = bytes.len().max(1);
    let hmem = unsafe { GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, alloc_len) };
    if hmem.is_null() {
        return Err("Gagal mengalokasikan memori clipboard.".to_string());
    }

    let dst = unsafe { GlobalLock(hmem) } as *mut u8;
    if dst.is_null() {
        unsafe {
            let _ = GlobalFree(hmem);
        }
        return Err("Gagal mengunci memori clipboard.".to_string());
    }

    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len());
        let _ = GlobalUnlock(hmem);
    }

    let placed = unsafe { SetClipboardData(format, hmem) };
    if placed.is_null() {
        // OS only takes ownership of hmem when SetClipboardData succeeds.
        unsafe {
            let _ = GlobalFree(hmem);
        }
        return Err("Gagal menulis data ke clipboard Windows.".to_string());
    }

    Ok(())
}

/// Copies UTF-16 text to the Windows clipboard. When `exclude_from_history` is true,
/// sets Windows Clipboard History (`Win+V`), Cloud Clipboard Sync, and monitor-exclusion
/// formats in the same clipboard transaction so secrets are never persisted in history.
pub fn set_clipboard_text(text: &str, exclude_from_history: bool) -> Result<(), String> {
    let _guard = ClipboardGuard::open()?;

    if unsafe { EmptyClipboard() } == 0 {
        return Err("Gagal mengosongkan clipboard sebelum menyalin.".to_string());
    }

    let mut utf16: Vec<u16> = text.encode_utf16().collect();
    utf16.push(0);
    let byte_slice =
        unsafe { std::slice::from_raw_parts(utf16.as_ptr() as *const u8, utf16.len() * 2) };

    unsafe {
        set_raw_clipboard_bytes(CF_UNICODETEXT, byte_slice)?;
    }

    // Volatile-zero temporary UTF-16 buffer containing sensitive text.
    utf16.zeroize();

    if exclude_from_history {
        let zero_dword = 0u32.to_le_bytes();
        let fmt_monitor = register_format("ExcludeClipboardContentFromMonitorProcessing");
        let fmt_history = register_format("CanIncludeInClipboardHistory");
        let fmt_cloud = register_format("CanUploadToCloudClipboard");

        unsafe {
            let _ = set_raw_clipboard_bytes(fmt_monitor, &zero_dword);
            let _ = set_raw_clipboard_bytes(fmt_history, &zero_dword);
            let _ = set_raw_clipboard_bytes(fmt_cloud, &zero_dword);
        }
    }

    Ok(())
}

/// Atomically checks whether the current clipboard text still equals `expected`
/// and clears it inside a single clipboard lock without allocating a new String copy.
pub fn clear_clipboard_if_matches(expected: &str) {
    let Ok(_guard) = ClipboardGuard::open() else {
        return;
    };

    let handle = unsafe { GetClipboardData(CF_UNICODETEXT) };
    if handle.is_null() {
        return;
    }

    let matches = unsafe {
        let byte_cap = GlobalSize(handle);
        let ptr = GlobalLock(handle) as *const u16;
        if ptr.is_null() || byte_cap < 2 {
            false
        } else {
            let max_units = byte_cap / 2;
            let raw = std::slice::from_raw_parts(ptr, max_units);
            let nul_pos = raw.iter().position(|&c| c == 0).unwrap_or(max_units);
            let equal = raw[..nul_pos].iter().copied().eq(expected.encode_utf16());
            let _ = GlobalUnlock(handle);
            equal
        }
    };

    if matches {
        unsafe {
            let _ = EmptyClipboard();
        }
    }
}
