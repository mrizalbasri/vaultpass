pub mod biometric;
pub mod clipboard;
pub mod crypto;
pub mod vault;

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::{Manager, State, WebviewWindow};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::biometric::{
    clear_biometric_secret_store, dpapi_protect_key, dpapi_unprotect_key,
    is_windows_hello_available, request_windows_hello_verification,
};
use crate::clipboard::{clear_clipboard_if_matches, set_clipboard_text};
use crate::crypto::{
    derive_key, generate_password as generate_random_password, KdfParams, PasswordGenOptions,
};
use crate::vault::{
    normalize_hint, now_iso, open_vault_with_key, open_vault_with_password, read_envelope,
    refresh_backup_after_rekey, sanitize_imported_env_var_name, save_unlocked_vault,
    summarize_entries, validate_env_var_name, write_envelope_atomic, UnlockedVault, VaultEntry,
    VaultEntryInput, VaultEntrySummary, VaultPayload,
};

pub const BIOMETRIC_CONFIG_VERSION: u32 = 2;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig {
    pub vault_path: PathBuf,
    #[serde(default)]
    pub biometric_version: u32,
    #[serde(default)]
    pub biometric_key_dpapi_b64: Option<String>,
    #[serde(default)]
    pub biometric_vault_path: Option<PathBuf>,
}

impl AppConfig {
    pub fn is_biometric_enabled_for(&self, path: &Path) -> bool {
        self.biometric_version == BIOMETRIC_CONFIG_VERSION
            && self.biometric_key_dpapi_b64.is_some()
            && self.biometric_vault_path.as_deref() == Some(path)
            && path.exists()
    }
}

pub fn default_app_data_dir() -> PathBuf {
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        if !local_app_data.trim().is_empty() {
            return PathBuf::from(local_app_data).join("com.rizal.vaultpass");
        }
    }
    if let Ok(user_profile) = std::env::var("USERPROFILE") {
        if !user_profile.trim().is_empty() {
            return PathBuf::from(user_profile)
                .join("AppData")
                .join("Local")
                .join("com.rizal.vaultpass");
        }
    }
    std::env::temp_dir().join("com.rizal.vaultpass")
}

pub fn resolve_cli_executable_path() -> String {
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(exe_dir) = current_exe.parent() {
            let sibling = exe_dir.join("vaultpass-cli.exe");
            if sibling.exists() {
                return sibling.to_string_lossy().to_string();
            }
            // In `tauri dev`, `current_exe` is in `target/debug/` while the user may have
            // built `target/release/vaultpass-cli.exe` (or vice versa).
            if let Some(target_dir) = exe_dir.parent() {
                for profile in ["release", "debug"] {
                    let candidate = target_dir.join(profile).join("vaultpass-cli.exe");
                    if candidate.exists() {
                        return candidate.to_string_lossy().to_string();
                    }
                }
            }
        }
    }
    "vaultpass-cli.exe".to_string()
}

pub fn load_or_init_config() -> Result<(PathBuf, AppConfig), String> {
    let app_data_dir = default_app_data_dir();
    let config_path = app_data_dir.join("config.json");

    if config_path.exists() {
        if let Ok(bytes) = fs::read(&config_path) {
            if let Ok(cfg) = serde_json::from_slice::<AppConfig>(&bytes) {
                if !cfg.vault_path.as_os_str().is_empty() {
                    return Ok((config_path, cfg));
                }
            }
        }
    }

    let vault_path = app_data_dir.join("vault.vpass");

    Ok((
        config_path,
        AppConfig {
            vault_path,
            biometric_version: 0,
            biometric_key_dpapi_b64: None,
            biometric_vault_path: None,
        },
    ))
}

struct AppState {
    config_path: PathBuf,
    config: Mutex<AppConfig>,
    unlocked: Mutex<Option<UnlockedVault>>,
    clipboard_generation: Arc<AtomicU64>,
}

impl AppState {
    fn current_config(&self) -> Result<AppConfig, String> {
        self.config
            .lock()
            .map(|c| c.clone())
            .map_err(|_| "Gagal membaca konfigurasi aplikasi.".to_string())
    }

    fn current_vault_path(&self) -> Result<PathBuf, String> {
        Ok(self.current_config()?.vault_path)
    }

    fn save_config(&self, next_cfg: AppConfig) -> Result<(), String> {
        if let Some(parent) = self.config_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Gagal membuat folder konfigurasi: {e}"))?;
        }
        let bytes = serde_json::to_vec_pretty(&next_cfg)
            .map_err(|e| format!("Gagal serialisasi konfigurasi: {e}"))?;
        fs::write(&self.config_path, bytes)
            .map_err(|e| format!("Gagal menyimpan konfigurasi: {e}"))?;

        let mut guard = self
            .config
            .lock()
            .map_err(|_| "Gagal memperbarui state konfigurasi.".to_string())?;
        *guard = next_cfg;
        Ok(())
    }
}

fn window_hwnd_isize(window: &WebviewWindow) -> Option<isize> {
    window.hwnd().ok().map(|h| h.0 as isize)
}

fn copy_with_optional_auto_clear(
    secret_text: Zeroizing<String>,
    is_sensitive: bool,
    clear_seconds: u32,
    clipboard_generation: &Arc<AtomicU64>,
) -> Result<u32, String> {
    set_clipboard_text(secret_text.as_str(), is_sensitive)?;

    if !is_sensitive || clear_seconds == 0 {
        return Ok(0);
    }

    let gen = clipboard_generation.fetch_add(1, Ordering::SeqCst) + 1;
    let gen_counter = Arc::clone(clipboard_generation);

    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(u64::from(clear_seconds)));
        if gen_counter.load(Ordering::SeqCst) != gen {
            return;
        }
        clear_clipboard_if_matches(secret_text.as_str());
    });

    Ok(clear_seconds)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultStatus {
    exists: bool,
    unlocked: bool,
    vault_path: String,
    cli_path: String,
    entry_count: usize,
    auto_lock_minutes: u32,
    clipboard_clear_seconds: u32,
    windows_hello_available: bool,
    biometric_enabled: bool,
    password_hint: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UpsertEntryResponse {
    saved_id: String,
    entries: Vec<VaultEntrySummary>,
}

#[tauri::command]
fn vault_status(state: State<'_, AppState>) -> Result<VaultStatus, String> {
    let cfg = state.current_config()?;
    let vault_path = &cfg.vault_path;
    let windows_hello_available = is_windows_hello_available();
    let guard = state
        .unlocked
        .lock()
        .map_err(|_| "State vault mengalami lock poisoning.".to_string())?;

    let (unlocked, entry_count, auto_lock_minutes, clipboard_clear_seconds, password_hint) =
        if let Some(ref v) = *guard {
            (
                true,
                v.payload.entries.len(),
                v.payload.settings.auto_lock_minutes,
                v.payload.settings.clipboard_clear_seconds,
                v.password_hint.clone(),
            )
        } else {
            let disk_hint = if vault_path.exists() {
                read_envelope(vault_path)
                    .ok()
                    .and_then(|env| normalize_hint(env.password_hint))
            } else {
                None
            };
            (false, 0, 5, 20, disk_hint)
        };

    Ok(VaultStatus {
        exists: vault_path.exists(),
        unlocked,
        vault_path: vault_path.to_string_lossy().to_string(),
        cli_path: resolve_cli_executable_path(),
        entry_count,
        auto_lock_minutes,
        clipboard_clear_seconds,
        windows_hello_available,
        biometric_enabled: windows_hello_available && cfg.is_biometric_enabled_for(vault_path),
        password_hint,
    })
}

#[tauri::command]
fn create_vault(
    master_password: String,
    password_hint: Option<String>,
    state: State<'_, AppState>,
) -> Result<VaultStatus, String> {
    let cfg = state.current_config()?;
    let vault_path = cfg.vault_path.clone();
    let master_password = Zeroizing::new(master_password);
    if master_password.chars().count() < 10 {
        return Err("Master password minimal 10 karakter.".to_string());
    }
    if vault_path.exists() {
        return Err("File vault sudah ada di lokasi tersebut.".to_string());
    }

    let kdf = KdfParams::new_random();
    let key = derive_key(&master_password, &kdf)?;
    let unlocked_vault = UnlockedVault {
        key,
        kdf,
        payload: VaultPayload::default(),
        password_hint: normalize_hint(password_hint),
    };

    save_unlocked_vault(&vault_path, &unlocked_vault)?;
    if !state.config_path.exists() {
        state.save_config(cfg)?;
    }

    let mut guard = state
        .unlocked
        .lock()
        .map_err(|_| "State vault terkunci internal.".to_string())?;
    *guard = Some(unlocked_vault);

    drop(guard);
    vault_status(state)
}

#[tauri::command]
fn update_password_hint(
    password_hint: Option<String>,
    state: State<'_, AppState>,
) -> Result<VaultStatus, String> {
    let vault_path = state.current_vault_path()?;
    {
        let mut guard = state
            .unlocked
            .lock()
            .map_err(|_| "State vault terkunci internal.".to_string())?;
        let vault = guard
            .as_mut()
            .ok_or_else(|| "Vault sedang terkunci.".to_string())?;
        vault.password_hint = normalize_hint(password_hint);
        save_unlocked_vault(&vault_path, vault)?;
    }
    vault_status(state)
}

#[tauri::command]
fn unlock_vault(
    master_password: String,
    state: State<'_, AppState>,
) -> Result<Vec<VaultEntrySummary>, String> {
    let vault_path = state.current_vault_path()?;
    let master_password = Zeroizing::new(master_password);
    if !vault_path.exists() {
        return Err("Vault belum dibuat.".to_string());
    }

    let unlocked_vault = open_vault_with_password(&vault_path, &master_password)?;
    let summaries = summarize_entries(&unlocked_vault.payload.entries);

    let mut guard = state
        .unlocked
        .lock()
        .map_err(|_| "State vault terkunci internal.".to_string())?;
    *guard = Some(unlocked_vault);

    Ok(summaries)
}

#[tauri::command]
fn unlock_vault_biometric(
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> Result<Vec<VaultEntrySummary>, String> {
    let cfg = state.current_config()?;
    let vault_path = cfg.vault_path.clone();
    if !cfg.is_biometric_enabled_for(&vault_path) {
        return Err("Windows Hello belum diaktifkan untuk vault ini.".to_string());
    }

    let dpapi_b64 = cfg
        .biometric_key_dpapi_b64
        .ok_or_else(|| "Data kunci biometrik tidak ditemukan.".to_string())?;

    request_windows_hello_verification(
        "Buka VaultPass dengan Windows Hello",
        window_hwnd_isize(&window),
    )?;
    let key = dpapi_unprotect_key(&dpapi_b64)?;
    let unlocked_vault = open_vault_with_key(&vault_path, key)?;
    let summaries = summarize_entries(&unlocked_vault.payload.entries);

    let mut guard = state
        .unlocked
        .lock()
        .map_err(|_| "State vault terkunci internal.".to_string())?;
    *guard = Some(unlocked_vault);

    Ok(summaries)
}

#[tauri::command]
fn enable_biometric_unlock(
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> Result<VaultStatus, String> {
    if !is_windows_hello_available() {
        return Err(
            "Windows Hello belum aktif di perangkat ini. Aktifkan PIN atau Sidik Jari Windows Hello di Pengaturan Windows terlebih dahulu."
                .to_string(),
        );
    }

    let key_copy: Zeroizing<[u8; 32]> = {
        let guard = state
            .unlocked
            .lock()
            .map_err(|_| "State vault terkunci internal.".to_string())?;
        let vault = guard.as_ref().ok_or_else(|| {
            "Buka vault terlebih dahulu sebelum mengaktifkan Windows Hello.".to_string()
        })?;
        vault.key.clone()
    };

    request_windows_hello_verification(
        "Aktifkan Windows Hello & akses AI Agent CLI untuk VaultPass",
        window_hwnd_isize(&window),
    )?;

    let dpapi_b64 = dpapi_protect_key(&key_copy)?;
    let mut cfg = state.current_config()?;
    cfg.biometric_version = BIOMETRIC_CONFIG_VERSION;
    cfg.biometric_key_dpapi_b64 = Some(dpapi_b64);
    cfg.biometric_vault_path = Some(cfg.vault_path.clone());
    state.save_config(cfg)?;

    vault_status(state)
}

#[tauri::command]
fn disable_biometric_unlock(state: State<'_, AppState>) -> Result<VaultStatus, String> {
    clear_biometric_secret_store();
    let mut cfg = state.current_config()?;
    cfg.biometric_version = 0;
    cfg.biometric_key_dpapi_b64 = None;
    cfg.biometric_vault_path = None;
    state.save_config(cfg)?;
    vault_status(state)
}

#[tauri::command]
fn lock_vault(state: State<'_, AppState>) -> Result<(), String> {
    let mut guard = state
        .unlocked
        .lock()
        .map_err(|_| "State vault terkunci internal.".to_string())?;
    *guard = None;
    Ok(())
}

#[tauri::command]
fn list_entries(state: State<'_, AppState>) -> Result<Vec<VaultEntrySummary>, String> {
    let guard = state
        .unlocked
        .lock()
        .map_err(|_| "State vault terkunci internal.".to_string())?;
    let vault = guard
        .as_ref()
        .ok_or_else(|| "Vault sedang terkunci.".to_string())?;
    Ok(summarize_entries(&vault.payload.entries))
}

#[tauri::command]
fn reveal_entry_secret(id: String, state: State<'_, AppState>) -> Result<String, String> {
    let guard = state
        .unlocked
        .lock()
        .map_err(|_| "State vault terkunci internal.".to_string())?;
    let vault = guard
        .as_ref()
        .ok_or_else(|| "Vault sedang terkunci.".to_string())?;
    let entry = vault
        .payload
        .entries
        .iter()
        .find(|item| item.id == id)
        .ok_or_else(|| "Item tidak ditemukan di dalam vault.".to_string())?;
    Ok(entry.password.clone())
}

#[tauri::command]
fn copy_entry_secret(id: String, state: State<'_, AppState>) -> Result<u32, String> {
    let (secret, clear_seconds) = {
        let guard = state
            .unlocked
            .lock()
            .map_err(|_| "State vault terkunci internal.".to_string())?;
        let vault = guard
            .as_ref()
            .ok_or_else(|| "Vault sedang terkunci.".to_string())?;
        let entry = vault
            .payload
            .entries
            .iter()
            .find(|item| item.id == id)
            .ok_or_else(|| "Item tidak ditemukan di dalam vault.".to_string())?;
        (
            Zeroizing::new(entry.password.clone()),
            vault.payload.settings.clipboard_clear_seconds,
        )
    };

    copy_with_optional_auto_clear(secret, true, clear_seconds, &state.clipboard_generation)
}

#[tauri::command]
fn upsert_entry(
    entry: VaultEntryInput,
    state: State<'_, AppState>,
) -> Result<UpsertEntryResponse, String> {
    if entry.title.trim().is_empty() {
        return Err("Nama layanan/akun wajib diisi.".to_string());
    }
    if entry.password.is_empty() {
        return Err("Password atau Key wajib diisi.".to_string());
    }
    let validated_env = validate_env_var_name(&entry.env_var_name)?;

    let vault_path = state.current_vault_path()?;
    let mut guard = state
        .unlocked
        .lock()
        .map_err(|_| "State vault terkunci internal.".to_string())?;
    let vault = guard
        .as_mut()
        .ok_or_else(|| "Vault sedang terkunci.".to_string())?;

    let now = now_iso();
    let saved_id = if let Some(ref existing_id) = entry.id {
        if let Some(pos) = vault
            .payload
            .entries
            .iter()
            .position(|item| &item.id == existing_id)
        {
            let created_at = vault.payload.entries[pos].created_at.clone();
            let updated = VaultEntry {
                id: existing_id.clone(),
                title: entry.title.trim().to_string(),
                username: entry.username.trim().to_string(),
                password: entry.password,
                url: entry.url.trim().to_string(),
                category: entry.category,
                env_var_name: validated_env,
                notes: entry.notes,
                favorite: entry.favorite,
                created_at,
                updated_at: now,
            };
            vault.payload.entries[pos] = updated;
            existing_id.clone()
        } else {
            return Err("Akun yang ingin diperbarui tidak ditemukan.".to_string());
        }
    } else {
        let new_id = Uuid::new_v4().to_string();
        let created = VaultEntry {
            id: new_id.clone(),
            title: entry.title.trim().to_string(),
            username: entry.username.trim().to_string(),
            password: entry.password,
            url: entry.url.trim().to_string(),
            category: entry.category,
            env_var_name: validated_env,
            notes: entry.notes,
            favorite: entry.favorite,
            created_at: now.clone(),
            updated_at: now,
        };
        vault.payload.entries.insert(0, created);
        new_id
    };

    save_unlocked_vault(&vault_path, vault)?;
    let entries = summarize_entries(&vault.payload.entries);
    Ok(UpsertEntryResponse { saved_id, entries })
}

#[tauri::command]
fn delete_entry(id: String, state: State<'_, AppState>) -> Result<Vec<VaultEntrySummary>, String> {
    let vault_path = state.current_vault_path()?;
    let mut guard = state
        .unlocked
        .lock()
        .map_err(|_| "State vault terkunci internal.".to_string())?;
    let vault = guard
        .as_mut()
        .ok_or_else(|| "Vault sedang terkunci.".to_string())?;

    let before = vault.payload.entries.len();
    vault.payload.entries.retain(|item| item.id != id);
    if vault.payload.entries.len() == before {
        return Err("Akun tidak ditemukan.".to_string());
    }

    save_unlocked_vault(&vault_path, vault)?;
    Ok(summarize_entries(&vault.payload.entries))
}

#[tauri::command]
fn toggle_favorite(
    id: String,
    state: State<'_, AppState>,
) -> Result<Vec<VaultEntrySummary>, String> {
    let vault_path = state.current_vault_path()?;
    let mut guard = state
        .unlocked
        .lock()
        .map_err(|_| "State vault terkunci internal.".to_string())?;
    let vault = guard
        .as_mut()
        .ok_or_else(|| "Vault sedang terkunci.".to_string())?;

    let target = vault
        .payload
        .entries
        .iter_mut()
        .find(|item| item.id == id)
        .ok_or_else(|| "Akun tidak ditemukan.".to_string())?;

    target.favorite = !target.favorite;
    target.updated_at = now_iso();

    save_unlocked_vault(&vault_path, vault)?;
    Ok(summarize_entries(&vault.payload.entries))
}

#[tauri::command]
fn change_master_password(
    current_password: String,
    new_password: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut cfg = state.current_config()?;
    let vault_path = cfg.vault_path.clone();
    let current_password = Zeroizing::new(current_password);
    let new_password = Zeroizing::new(new_password);

    if new_password.chars().count() < 10 {
        return Err("Master password baru minimal 10 karakter.".to_string());
    }

    let _verified = open_vault_with_password(&vault_path, &current_password)
        .map_err(|_| "Master password saat ini salah.".to_string())?;

    let new_key = {
        let mut guard = state
            .unlocked
            .lock()
            .map_err(|_| "State vault terkunci internal.".to_string())?;
        let vault = guard
            .as_mut()
            .ok_or_else(|| "Vault sedang terkunci.".to_string())?;

        let new_kdf = KdfParams::new_random();
        let derived_key = derive_key(&new_password, &new_kdf)?;
        vault.kdf = new_kdf;
        vault.key = derived_key.clone();

        save_unlocked_vault(&vault_path, vault)?;
        refresh_backup_after_rekey(&vault_path, vault)?;
        derived_key
    };

    if cfg.is_biometric_enabled_for(&vault_path) {
        match dpapi_protect_key(&new_key) {
            Ok(dpapi_b64) => {
                cfg.biometric_version = BIOMETRIC_CONFIG_VERSION;
                cfg.biometric_key_dpapi_b64 = Some(dpapi_b64);
                state.save_config(cfg)?;
            }
            Err(_) => {
                clear_biometric_secret_store();
                cfg.biometric_version = 0;
                cfg.biometric_key_dpapi_b64 = None;
                cfg.biometric_vault_path = None;
                let _ = state.save_config(cfg);
            }
        }
    }

    Ok(())
}

#[tauri::command]
fn update_settings(
    auto_lock_minutes: u32,
    clipboard_clear_seconds: u32,
    state: State<'_, AppState>,
) -> Result<VaultStatus, String> {
    if auto_lock_minutes > 1_440 {
        return Err("Batas auto-lock maksimal 1440 menit (24 jam).".to_string());
    }
    if clipboard_clear_seconds > 600 {
        return Err("Batas pembersihan clipboard maksimal 600 detik.".to_string());
    }

    let vault_path = state.current_vault_path()?;
    {
        let mut guard = state
            .unlocked
            .lock()
            .map_err(|_| "State vault terkunci internal.".to_string())?;
        let vault = guard
            .as_mut()
            .ok_or_else(|| "Vault sedang terkunci.".to_string())?;

        vault.payload.settings.auto_lock_minutes = auto_lock_minutes;
        vault.payload.settings.clipboard_clear_seconds = clipboard_clear_seconds;
        save_unlocked_vault(&vault_path, vault)?;
    }

    vault_status(state)
}

#[tauri::command]
fn generate_password(options: PasswordGenOptions) -> Result<String, String> {
    generate_random_password(&options)
}

#[tauri::command]
fn copy_secret(
    text: String,
    is_sensitive: bool,
    state: State<'_, AppState>,
) -> Result<u32, String> {
    let text = Zeroizing::new(text);

    let clear_seconds = {
        let guard = state
            .unlocked
            .lock()
            .map_err(|_| "State vault terkunci internal.".to_string())?;
        let vault = guard
            .as_ref()
            .ok_or_else(|| "Vault sedang terkunci.".to_string())?;
        vault.payload.settings.clipboard_clear_seconds
    };

    copy_with_optional_auto_clear(
        text,
        is_sensitive,
        clear_seconds,
        &state.clipboard_generation,
    )
}

#[tauri::command]
fn export_encrypted_backup(state: State<'_, AppState>) -> Result<Option<String>, String> {
    let vault_path = state.current_vault_path()?;
    {
        let guard = state
            .unlocked
            .lock()
            .map_err(|_| "State vault terkunci internal.".to_string())?;
        if guard.is_none() {
            return Err("Vault sedang terkunci.".to_string());
        }
    }

    let envelope = read_envelope(&vault_path)?;
    let default_name = format!(
        "vaultpass-backup-{}.vpass",
        chrono::Local::now().format("%Y%m%d-%H%M")
    );

    let picked = rfd::FileDialog::new()
        .add_filter("VaultPass Encrypted Backup", &["vpass"])
        .set_file_name(&default_name)
        .save_file();

    let Some(dest_path) = picked else {
        return Ok(None);
    };

    write_envelope_atomic(&dest_path, &envelope)?;
    Ok(Some(dest_path.to_string_lossy().to_string()))
}

#[tauri::command]
fn import_encrypted_backup(
    backup_password: String,
    state: State<'_, AppState>,
) -> Result<usize, String> {
    let vault_path = state.current_vault_path()?;
    let backup_password = Zeroizing::new(backup_password);

    let picked = rfd::FileDialog::new()
        .add_filter("VaultPass Encrypted Backup", &["vpass"])
        .pick_file();

    let Some(src_path) = picked else {
        return Ok(0);
    };

    let imported = open_vault_with_password(&src_path, &backup_password)?;

    let mut guard = state
        .unlocked
        .lock()
        .map_err(|_| "State vault terkunci internal.".to_string())?;
    let vault = guard
        .as_mut()
        .ok_or_else(|| "Vault sedang terkunci.".to_string())?;

    let existing_ids: HashSet<String> = vault
        .payload
        .entries
        .iter()
        .map(|item| item.id.clone())
        .collect();

    let mut added = 0usize;
    for entry in &imported.payload.entries {
        if !existing_ids.contains(&entry.id)
            && !entry.title.trim().is_empty()
            && !entry.password.is_empty()
        {
            let mut sanitized = entry.clone();
            sanitized.title = sanitized.title.trim().to_string();
            sanitized.username = sanitized.username.trim().to_string();
            sanitized.url = sanitized.url.trim().to_string();
            sanitized.env_var_name = sanitize_imported_env_var_name(&sanitized.env_var_name);
            vault.payload.entries.push(sanitized);
            added += 1;
        }
    }

    if added > 0 {
        save_unlocked_vault(&vault_path, vault)?;
    }

    Ok(added)
}

#[tauri::command]
fn pick_vault_save_location(state: State<'_, AppState>) -> Result<Option<VaultStatus>, String> {
    let mut cfg = state.current_config()?;
    let old_path = cfg.vault_path.clone();
    let was_bio = cfg.is_biometric_enabled_for(&old_path);

    let default_dir = old_path
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(default_app_data_dir);
    let default_name = old_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("vault.vpass");

    let mut dialog = rfd::FileDialog::new()
        .add_filter("VaultPass Encrypted Vault (.vpass)", &["vpass"])
        .set_file_name(default_name);
    if default_dir.exists() {
        dialog = dialog.set_directory(&default_dir);
    }

    let Some(mut dest_path) = dialog.save_file() else {
        return Ok(None);
    };

    if dest_path.extension().is_none() {
        dest_path.set_extension("vpass");
    }

    let moved_existing = old_path.exists() && old_path != dest_path;
    if moved_existing {
        let envelope = read_envelope(&old_path)?;
        write_envelope_atomic(&dest_path, &envelope)?;
    }

    cfg.vault_path = dest_path.clone();
    if was_bio {
        cfg.biometric_vault_path = Some(dest_path);
    }
    state.save_config(cfg)?;

    if moved_existing {
        let _ = fs::remove_file(&old_path);
        let _ = fs::remove_file(old_path.with_extension("vpass.bak"));
        let _ = fs::remove_file(old_path.with_extension("vpass.tmp"));
    }

    Ok(Some(vault_status(state)?))
}

#[tauri::command]
fn pick_existing_vault_file(state: State<'_, AppState>) -> Result<Option<VaultStatus>, String> {
    let mut cfg = state.current_config()?;
    let old_path = cfg.vault_path.clone();
    let default_dir = old_path
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(default_app_data_dir);

    let mut dialog =
        rfd::FileDialog::new().add_filter("VaultPass Encrypted Vault (.vpass)", &["vpass"]);
    if default_dir.exists() {
        dialog = dialog.set_directory(&default_dir);
    }

    let Some(picked_path) = dialog.pick_file() else {
        return Ok(None);
    };

    {
        let mut guard = state
            .unlocked
            .lock()
            .map_err(|_| "State vault terkunci internal.".to_string())?;
        *guard = None;
    }

    cfg.vault_path = picked_path;
    state.save_config(cfg)?;
    Ok(Some(vault_status(state)?))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let (config_path, cfg) = load_or_init_config()?;

            app.manage(AppState {
                config_path,
                config: Mutex::new(cfg),
                unlocked: Mutex::new(None),
                clipboard_generation: Arc::new(AtomicU64::new(0)),
            });

            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            vault_status,
            create_vault,
            update_password_hint,
            unlock_vault,
            unlock_vault_biometric,
            enable_biometric_unlock,
            disable_biometric_unlock,
            lock_vault,
            list_entries,
            reveal_entry_secret,
            copy_entry_secret,
            upsert_entry,
            delete_entry,
            toggle_favorite,
            change_master_password,
            update_settings,
            generate_password,
            copy_secret,
            export_encrypted_backup,
            import_encrypted_backup,
            pick_vault_save_location,
            pick_existing_vault_file,
        ])
        .run(tauri::generate_context!())
        .expect("error while running VaultPass application");
}
