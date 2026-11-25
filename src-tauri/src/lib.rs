pub mod biometric;
pub mod clipboard;
pub mod crypto;
pub mod vault;

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tauri::{Manager, State, WebviewWindow};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::biometric::{
    clear_biometric_secret_store_for_target, default_biometric_cred_target,
    dpapi_protect_key_for_target, dpapi_unprotect_key_for_target, is_windows_hello_available,
    request_windows_hello_verification,
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

pub fn load_or_init_config_in(app_data_dir: &Path) -> Result<(PathBuf, AppConfig), String> {
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

pub fn load_or_init_config() -> Result<(PathBuf, AppConfig), String> {
    load_or_init_config_in(&default_app_data_dir())
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
    unlock_cooldown_seconds: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UpsertEntryResponse {
    saved_id: String,
    entries: Vec<VaultEntrySummary>,
}

fn cooldown_duration_for_failures(failures: u32) -> Option<Duration> {
    match failures {
        0..=2 => None,
        3..=4 => Some(Duration::from_secs(3)),
        5..=6 => Some(Duration::from_secs(10)),
        7..=9 => Some(Duration::from_secs(30)),
        _ => Some(Duration::from_secs(60)),
    }
}

#[derive(Debug, Default)]
struct PasswordAttemptGuard {
    failed_attempts: u32,
    cooldown_until: Option<Instant>,
}

impl PasswordAttemptGuard {
    fn remaining_cooldown_secs(&self, now: Instant) -> u64 {
        match self.cooldown_until {
            Some(until) if until > now => {
                let ms = until.duration_since(now).as_millis();
                ms.div_ceil(1_000).max(1) as u64
            }
            _ => 0,
        }
    }

    fn check_allowed(&self, now: Instant) -> Result<(), String> {
        let rem = self.remaining_cooldown_secs(now);
        if rem > 0 {
            Err(format!(
                "Terlalu banyak percobaan gagal. Coba lagi dalam {rem} detik."
            ))
        } else {
            Ok(())
        }
    }

    fn record_failure(&mut self, now: Instant) -> Option<u64> {
        self.failed_attempts = self.failed_attempts.saturating_add(1);
        if let Some(dur) = cooldown_duration_for_failures(self.failed_attempts) {
            self.cooldown_until = Some(now + dur);
            Some(dur.as_secs())
        } else {
            None
        }
    }

    fn reset(&mut self) {
        self.failed_attempts = 0;
        self.cooldown_until = None;
    }
}

struct AppState {
    config_path: PathBuf,
    config: Mutex<AppConfig>,
    unlocked: Mutex<Option<UnlockedVault>>,
    clipboard_generation: Arc<AtomicU64>,
    cred_target_name: String,
    kdf_override: Option<KdfParams>,
    auth_guard: Mutex<PasswordAttemptGuard>,
}

impl AppState {
    fn new(config_path: PathBuf, cfg: AppConfig) -> Self {
        Self {
            config_path,
            config: Mutex::new(cfg),
            unlocked: Mutex::new(None),
            clipboard_generation: Arc::new(AtomicU64::new(0)),
            cred_target_name: default_biometric_cred_target().to_string(),
            kdf_override: None,
            auth_guard: Mutex::new(PasswordAttemptGuard::default()),
        }
    }

    fn current_cooldown_secs(&self) -> u64 {
        self.auth_guard
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remaining_cooldown_secs(Instant::now())
    }

    fn check_password_attempt_allowed(&self) -> Result<(), String> {
        self.auth_guard
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .check_allowed(Instant::now())
    }

    fn record_password_failure(&self, base_err: String) -> String {
        let wait_secs = self
            .auth_guard
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record_failure(Instant::now());
        if let Some(secs) = wait_secs {
            format!("{base_err} Terlalu banyak percobaan gagal — tunggu {secs} detik.")
        } else {
            base_err
        }
    }

    fn reset_password_attempts(&self) {
        self.auth_guard
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .reset();
    }

    fn fresh_kdf(&self) -> KdfParams {
        self.kdf_override
            .clone()
            .unwrap_or_else(KdfParams::new_random)
    }

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

    fn status(&self, windows_hello_available: bool) -> Result<VaultStatus, String> {
        let cfg = self.current_config()?;
        let vault_path = &cfg.vault_path;
        let guard = self
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
            unlock_cooldown_seconds: self.current_cooldown_secs(),
        })
    }

    fn create_vault(
        &self,
        master_password: String,
        password_hint: Option<String>,
        windows_hello_available: bool,
    ) -> Result<VaultStatus, String> {
        let cfg = self.current_config()?;
        let vault_path = cfg.vault_path.clone();
        let master_password = Zeroizing::new(master_password);
        if master_password.chars().count() < 10 {
            return Err("Master password minimal 10 karakter.".to_string());
        }
        if vault_path.exists() {
            return Err("File vault sudah ada di lokasi tersebut.".to_string());
        }

        let kdf = self.fresh_kdf();
        let key = derive_key(&master_password, &kdf)?;
        let unlocked_vault = UnlockedVault {
            key,
            kdf,
            payload: VaultPayload::default(),
            password_hint: normalize_hint(password_hint),
        };

        save_unlocked_vault(&vault_path, &unlocked_vault)?;
        if !self.config_path.exists() {
            self.save_config(cfg)?;
        }

        let mut guard = self
            .unlocked
            .lock()
            .map_err(|_| "State vault terkunci internal.".to_string())?;
        *guard = Some(unlocked_vault);
        drop(guard);

        self.status(windows_hello_available)
    }

    fn update_password_hint(
        &self,
        password_hint: Option<String>,
        windows_hello_available: bool,
    ) -> Result<VaultStatus, String> {
        let vault_path = self.current_vault_path()?;
        {
            let mut guard = self
                .unlocked
                .lock()
                .map_err(|_| "State vault terkunci internal.".to_string())?;
            let vault = guard
                .as_mut()
                .ok_or_else(|| "Vault sedang terkunci.".to_string())?;
            vault.password_hint = normalize_hint(password_hint);
            save_unlocked_vault(&vault_path, vault)?;
        }
        self.status(windows_hello_available)
    }

    fn unlock_with_password(
        &self,
        master_password: String,
    ) -> Result<Vec<VaultEntrySummary>, String> {
        let vault_path = self.current_vault_path()?;
        let master_password = Zeroizing::new(master_password);
        if !vault_path.exists() {
            return Err("Vault belum dibuat.".to_string());
        }
        self.check_password_attempt_allowed()?;

        let unlocked_vault = open_vault_with_password(&vault_path, &master_password)
            .map_err(|e| self.record_password_failure(e))?;
        self.reset_password_attempts();
        let summaries = summarize_entries(&unlocked_vault.payload.entries);

        let mut guard = self
            .unlocked
            .lock()
            .map_err(|_| "State vault terkunci internal.".to_string())?;
        *guard = Some(unlocked_vault);

        Ok(summaries)
    }

    fn prepare_biometric_unlock(&self) -> Result<(PathBuf, String), String> {
        let cfg = self.current_config()?;
        let vault_path = cfg.vault_path.clone();
        if !cfg.is_biometric_enabled_for(&vault_path) {
            return Err("Windows Hello belum diaktifkan untuk vault ini.".to_string());
        }
        let dpapi_b64 = cfg
            .biometric_key_dpapi_b64
            .ok_or_else(|| "Data kunci biometrik tidak ditemukan.".to_string())?;
        Ok((vault_path, dpapi_b64))
    }

    fn finish_biometric_unlock(
        &self,
        vault_path: &Path,
        dpapi_b64: &str,
    ) -> Result<Vec<VaultEntrySummary>, String> {
        let key = dpapi_unprotect_key_for_target(&self.cred_target_name, dpapi_b64)?;
        let unlocked_vault = open_vault_with_key(vault_path, key)?;
        self.reset_password_attempts();
        let summaries = summarize_entries(&unlocked_vault.payload.entries);

        let mut guard = self
            .unlocked
            .lock()
            .map_err(|_| "State vault terkunci internal.".to_string())?;
        *guard = Some(unlocked_vault);

        Ok(summaries)
    }

    fn extract_unlocked_key_for_biometric(
        &self,
        windows_hello_available: bool,
    ) -> Result<Zeroizing<[u8; 32]>, String> {
        if !windows_hello_available {
            return Err(
                "Windows Hello belum aktif di perangkat ini. Aktifkan PIN atau Sidik Jari Windows Hello di Pengaturan Windows terlebih dahulu."
                    .to_string(),
            );
        }
        let guard = self
            .unlocked
            .lock()
            .map_err(|_| "State vault terkunci internal.".to_string())?;
        let vault = guard.as_ref().ok_or_else(|| {
            "Buka vault terlebih dahulu sebelum mengaktifkan Windows Hello.".to_string()
        })?;
        Ok(vault.key.clone())
    }

    fn persist_biometric_key(
        &self,
        key: &[u8; 32],
        windows_hello_available: bool,
    ) -> Result<VaultStatus, String> {
        let dpapi_b64 = dpapi_protect_key_for_target(&self.cred_target_name, key)?;
        let mut cfg = self.current_config()?;
        cfg.biometric_version = BIOMETRIC_CONFIG_VERSION;
        cfg.biometric_key_dpapi_b64 = Some(dpapi_b64);
        cfg.biometric_vault_path = Some(cfg.vault_path.clone());
        self.save_config(cfg)?;
        self.status(windows_hello_available)
    }

    fn disable_biometric(&self, windows_hello_available: bool) -> Result<VaultStatus, String> {
        clear_biometric_secret_store_for_target(&self.cred_target_name);
        let mut cfg = self.current_config()?;
        cfg.biometric_version = 0;
        cfg.biometric_key_dpapi_b64 = None;
        cfg.biometric_vault_path = None;
        self.save_config(cfg)?;
        self.status(windows_hello_available)
    }

    fn lock(&self) -> Result<(), String> {
        let mut guard = self
            .unlocked
            .lock()
            .map_err(|_| "State vault terkunci internal.".to_string())?;
        *guard = None;
        Ok(())
    }

    fn list_entries(&self) -> Result<Vec<VaultEntrySummary>, String> {
        let guard = self
            .unlocked
            .lock()
            .map_err(|_| "State vault terkunci internal.".to_string())?;
        let vault = guard
            .as_ref()
            .ok_or_else(|| "Vault sedang terkunci.".to_string())?;
        Ok(summarize_entries(&vault.payload.entries))
    }

    fn reveal_secret(&self, id: &str) -> Result<String, String> {
        let guard = self
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

    fn copy_entry_secret(&self, id: &str) -> Result<u32, String> {
        let (secret, clear_seconds) = {
            let guard = self
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

        copy_with_optional_auto_clear(secret, true, clear_seconds, &self.clipboard_generation)
    }

    fn copy_text(&self, text: String, is_sensitive: bool) -> Result<u32, String> {
        let text = Zeroizing::new(text);
        let clear_seconds = {
            let guard = self
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
            &self.clipboard_generation,
        )
    }

    fn upsert_entry(&self, entry: VaultEntryInput) -> Result<UpsertEntryResponse, String> {
        if entry.title.trim().is_empty() {
            return Err("Nama layanan/akun wajib diisi.".to_string());
        }
        if entry.password.is_empty() {
            return Err("Password atau Key wajib diisi.".to_string());
        }
        let validated_env = validate_env_var_name(&entry.env_var_name)?;

        let vault_path = self.current_vault_path()?;
        let mut guard = self
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
                vault.payload.entries[pos] = VaultEntry {
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

    fn delete_entry(&self, id: &str) -> Result<Vec<VaultEntrySummary>, String> {
        let vault_path = self.current_vault_path()?;
        let mut guard = self
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

    fn toggle_favorite(&self, id: &str) -> Result<Vec<VaultEntrySummary>, String> {
        let vault_path = self.current_vault_path()?;
        let mut guard = self
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

    fn change_master_password(
        &self,
        current_password: String,
        new_password: String,
    ) -> Result<(), String> {
        let mut cfg = self.current_config()?;
        let vault_path = cfg.vault_path.clone();
        let current_password = Zeroizing::new(current_password);
        let new_password = Zeroizing::new(new_password);

        if new_password.chars().count() < 10 {
            return Err("Master password baru minimal 10 karakter.".to_string());
        }
        self.check_password_attempt_allowed()?;

        let _verified = open_vault_with_password(&vault_path, &current_password).map_err(|_| {
            self.record_password_failure("Master password saat ini salah.".to_string())
        })?;
        self.reset_password_attempts();

        let new_key = {
            let mut guard = self
                .unlocked
                .lock()
                .map_err(|_| "State vault terkunci internal.".to_string())?;
            let vault = guard
                .as_mut()
                .ok_or_else(|| "Vault sedang terkunci.".to_string())?;

            let new_kdf = self.fresh_kdf();
            let derived_key = derive_key(&new_password, &new_kdf)?;
            vault.kdf = new_kdf;
            vault.key = derived_key.clone();

            save_unlocked_vault(&vault_path, vault)?;
            refresh_backup_after_rekey(&vault_path, vault)?;
            derived_key
        };

        if cfg.is_biometric_enabled_for(&vault_path) {
            match dpapi_protect_key_for_target(&self.cred_target_name, &new_key) {
                Ok(dpapi_b64) => {
                    cfg.biometric_version = BIOMETRIC_CONFIG_VERSION;
                    cfg.biometric_key_dpapi_b64 = Some(dpapi_b64);
                    self.save_config(cfg)?;
                }
                Err(_) => {
                    clear_biometric_secret_store_for_target(&self.cred_target_name);
                    cfg.biometric_version = 0;
                    cfg.biometric_key_dpapi_b64 = None;
                    cfg.biometric_vault_path = None;
                    let _ = self.save_config(cfg);
                }
            }
        }

        Ok(())
    }

    fn update_settings(
        &self,
        auto_lock_minutes: u32,
        clipboard_clear_seconds: u32,
        windows_hello_available: bool,
    ) -> Result<VaultStatus, String> {
        if auto_lock_minutes > 1_440 {
            return Err("Batas auto-lock maksimal 1440 menit (24 jam).".to_string());
        }
        if clipboard_clear_seconds > 600 {
            return Err("Batas pembersihan clipboard maksimal 600 detik.".to_string());
        }

        let vault_path = self.current_vault_path()?;
        {
            let mut guard = self
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

        self.status(windows_hello_available)
    }

    fn ensure_unlocked(&self) -> Result<(), String> {
        let guard = self
            .unlocked
            .lock()
            .map_err(|_| "State vault terkunci internal.".to_string())?;
        if guard.is_none() {
            return Err("Vault sedang terkunci.".to_string());
        }
        Ok(())
    }

    fn export_backup_to_path(&self, dest_path: &Path) -> Result<String, String> {
        self.ensure_unlocked()?;
        let vault_path = self.current_vault_path()?;
        let envelope = read_envelope(&vault_path)?;
        write_envelope_atomic(dest_path, &envelope)?;
        Ok(dest_path.to_string_lossy().to_string())
    }

    fn import_backup_from_path(
        &self,
        src_path: &Path,
        backup_password: String,
    ) -> Result<usize, String> {
        let vault_path = self.current_vault_path()?;
        let backup_password = Zeroizing::new(backup_password);
        let imported = open_vault_with_password(src_path, &backup_password)?;

        let mut guard = self
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

    fn relocate_vault_to(
        &self,
        mut dest_path: PathBuf,
        windows_hello_available: bool,
    ) -> Result<VaultStatus, String> {
        let mut cfg = self.current_config()?;
        let old_path = cfg.vault_path.clone();
        let was_bio = cfg.is_biometric_enabled_for(&old_path);

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
        self.save_config(cfg)?;

        if moved_existing {
            let _ = fs::remove_file(&old_path);
            let _ = fs::remove_file(old_path.with_extension("vpass.bak"));
            let _ = fs::remove_file(old_path.with_extension("vpass.tmp"));
        }

        self.status(windows_hello_available)
    }

    fn switch_existing_vault(
        &self,
        picked_path: PathBuf,
        windows_hello_available: bool,
    ) -> Result<VaultStatus, String> {
        let mut cfg = self.current_config()?;
        self.lock()?;
        self.reset_password_attempts();
        cfg.vault_path = picked_path;
        self.save_config(cfg)?;
        self.status(windows_hello_available)
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

#[tauri::command]
fn vault_status(state: State<'_, AppState>) -> Result<VaultStatus, String> {
    state.status(is_windows_hello_available())
}

#[tauri::command]
fn create_vault(
    master_password: String,
    password_hint: Option<String>,
    state: State<'_, AppState>,
) -> Result<VaultStatus, String> {
    state.create_vault(master_password, password_hint, is_windows_hello_available())
}

#[tauri::command]
fn update_password_hint(
    password_hint: Option<String>,
    state: State<'_, AppState>,
) -> Result<VaultStatus, String> {
    state.update_password_hint(password_hint, is_windows_hello_available())
}

#[tauri::command]
fn unlock_vault(
    master_password: String,
    state: State<'_, AppState>,
) -> Result<Vec<VaultEntrySummary>, String> {
    state.unlock_with_password(master_password)
}

#[tauri::command]
fn unlock_vault_biometric(
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> Result<Vec<VaultEntrySummary>, String> {
    let (vault_path, dpapi_b64) = state.prepare_biometric_unlock()?;
    request_windows_hello_verification(
        "Buka VaultPass dengan Windows Hello",
        window_hwnd_isize(&window),
    )?;
    state.finish_biometric_unlock(&vault_path, &dpapi_b64)
}

#[tauri::command]
fn enable_biometric_unlock(
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> Result<VaultStatus, String> {
    let hello_avail = is_windows_hello_available();
    let key_copy = state.extract_unlocked_key_for_biometric(hello_avail)?;
    request_windows_hello_verification(
        "Aktifkan Windows Hello & akses AI Agent CLI untuk VaultPass",
        window_hwnd_isize(&window),
    )?;
    state.persist_biometric_key(&key_copy, hello_avail)
}

#[tauri::command]
fn disable_biometric_unlock(state: State<'_, AppState>) -> Result<VaultStatus, String> {
    state.disable_biometric(is_windows_hello_available())
}

#[tauri::command]
fn lock_vault(state: State<'_, AppState>) -> Result<(), String> {
    state.lock()
}

#[tauri::command]
fn list_entries(state: State<'_, AppState>) -> Result<Vec<VaultEntrySummary>, String> {
    state.list_entries()
}

#[tauri::command]
fn reveal_entry_secret(id: String, state: State<'_, AppState>) -> Result<String, String> {
    state.reveal_secret(&id)
}

#[tauri::command]
fn copy_entry_secret(id: String, state: State<'_, AppState>) -> Result<u32, String> {
    state.copy_entry_secret(&id)
}

#[tauri::command]
fn upsert_entry(
    entry: VaultEntryInput,
    state: State<'_, AppState>,
) -> Result<UpsertEntryResponse, String> {
    state.upsert_entry(entry)
}

#[tauri::command]
fn delete_entry(id: String, state: State<'_, AppState>) -> Result<Vec<VaultEntrySummary>, String> {
    state.delete_entry(&id)
}

#[tauri::command]
fn toggle_favorite(
    id: String,
    state: State<'_, AppState>,
) -> Result<Vec<VaultEntrySummary>, String> {
    state.toggle_favorite(&id)
}

#[tauri::command]
fn change_master_password(
    current_password: String,
    new_password: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state.change_master_password(current_password, new_password)
}

#[tauri::command]
fn update_settings(
    auto_lock_minutes: u32,
    clipboard_clear_seconds: u32,
    state: State<'_, AppState>,
) -> Result<VaultStatus, String> {
    state.update_settings(
        auto_lock_minutes,
        clipboard_clear_seconds,
        is_windows_hello_available(),
    )
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
    state.copy_text(text, is_sensitive)
}

#[tauri::command]
fn export_encrypted_backup(state: State<'_, AppState>) -> Result<Option<String>, String> {
    state.ensure_unlocked()?;
    let default_name = format!(
        "vaultpass-backup-{}.vpass",
        chrono::Local::now().format("%Y%m%d-%H%M")
    );
    let picked = rfd::FileDialog::new()
        .add_filter("VaultPass Encrypted Backup", &["vpass"])
        .set_file_name(&default_name)
        .save_file();

    match picked {
        Some(dest_path) => state.export_backup_to_path(&dest_path).map(Some),
        None => Ok(None),
    }
}

#[tauri::command]
fn import_encrypted_backup(
    backup_password: String,
    state: State<'_, AppState>,
) -> Result<usize, String> {
    state.ensure_unlocked()?;
    let picked = rfd::FileDialog::new()
        .add_filter("VaultPass Encrypted Backup", &["vpass"])
        .pick_file();

    match picked {
        Some(src_path) => state.import_backup_from_path(&src_path, backup_password),
        None => Ok(0),
    }
}

#[tauri::command]
fn pick_vault_save_location(state: State<'_, AppState>) -> Result<Option<VaultStatus>, String> {
    let old_path = state.current_vault_path()?;
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

    match dialog.save_file() {
        Some(dest_path) => state
            .relocate_vault_to(dest_path, is_windows_hello_available())
            .map(Some),
        None => Ok(None),
    }
}

#[tauri::command]
fn pick_existing_vault_file(state: State<'_, AppState>) -> Result<Option<VaultStatus>, String> {
    let old_path = state.current_vault_path()?;
    let default_dir = old_path
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(default_app_data_dir);

    let mut dialog =
        rfd::FileDialog::new().add_filter("VaultPass Encrypted Vault (.vpass)", &["vpass"]);
    if default_dir.exists() {
        dialog = dialog.set_directory(&default_dir);
    }

    match dialog.pick_file() {
        Some(picked_path) => state
            .switch_existing_vault(picked_path, is_windows_hello_available())
            .map(Some),
        None => Ok(None),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let (config_path, cfg) = load_or_init_config()?;
            app.manage(AppState::new(config_path, cfg));

            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_zoom(1.0);
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine};

    fn make_test_state() -> (PathBuf, AppState) {
        let dir = std::env::temp_dir().join(format!("vaultpass-state-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let (config_path, cfg) = load_or_init_config_in(&dir).unwrap();
        let mut state = AppState::new(config_path, cfg);
        state.cred_target_name = format!("VaultPass:TestStateCred:{}", Uuid::new_v4());
        // Use fast 8 MiB / 1-iteration KDF in unit tests while staying within production bounds.
        state.kdf_override = Some(KdfParams {
            algorithm: "argon2id".to_string(),
            memory_kib: 8_192,
            iterations: 1,
            parallelism: 1,
            salt_b64: B64.encode([0x42u8; 16]),
        });
        (dir, state)
    }

    #[test]
    fn app_state_vault_lifecycle_crud_settings_and_lock() {
        let (dir, state) = make_test_state();

        let initial = state.status(false).unwrap();
        assert!(!initial.exists);
        assert!(!initial.unlocked);
        assert!(!initial.cli_path.is_empty());
        assert!(default_app_data_dir().ends_with("com.rizal.vaultpass"));

        assert!(state
            .create_vault("short".to_string(), None, false)
            .is_err());
        assert!(state
            .unlock_with_password("ten-chars!!".to_string())
            .is_err());

        let created = state
            .create_vault(
                "correct-master-123".to_string(),
                Some("  hewan peliharaan  ".to_string()),
                false,
            )
            .unwrap();
        assert!(created.exists);
        assert!(created.unlocked);
        assert_eq!(created.password_hint.as_deref(), Some("hewan peliharaan"));

        // Creating again when vault file already exists must fail.
        assert!(state
            .create_vault("correct-master-123".to_string(), None, false)
            .is_err());

        let hint_updated = state
            .update_password_hint(Some("petunjuk baru".to_string()), false)
            .unwrap();
        assert_eq!(hint_updated.password_hint.as_deref(), Some("petunjuk baru"));

        assert!(state
            .upsert_entry(VaultEntryInput {
                id: None,
                title: "   ".to_string(),
                username: "".to_string(),
                password: "secret".to_string(),
                url: "".to_string(),
                category: "Login".to_string(),
                env_var_name: "".to_string(),
                notes: "".to_string(),
                favorite: false,
            })
            .is_err());

        assert!(state
            .upsert_entry(VaultEntryInput {
                id: None,
                title: "Valid".to_string(),
                username: "".to_string(),
                password: "".to_string(),
                url: "".to_string(),
                category: "Login".to_string(),
                env_var_name: "".to_string(),
                notes: "".to_string(),
                favorite: false,
            })
            .is_err());

        let added = state
            .upsert_entry(VaultEntryInput {
                id: None,
                title: "OpenAI Prod".to_string(),
                username: "proj_1".to_string(),
                password: "sk-super-secret-value-999".to_string(),
                url: "https://api.openai.com".to_string(),
                category: "API Key".to_string(),
                env_var_name: "openai_api_key".to_string(),
                notes: "catatan".to_string(),
                favorite: false,
            })
            .unwrap();
        assert_eq!(added.entries.len(), 1);
        assert_eq!(added.entries[0].env_var_name, "OPENAI_API_KEY");

        let revealed = state.reveal_secret(&added.saved_id).unwrap();
        assert_eq!(revealed, "sk-super-secret-value-999");
        assert!(state.reveal_secret("missing-id").is_err());

        let updated = state
            .upsert_entry(VaultEntryInput {
                id: Some(added.saved_id.clone()),
                title: "OpenAI Production".to_string(),
                username: "proj_1".to_string(),
                password: "sk-rotated-value-888".to_string(),
                url: "https://api.openai.com".to_string(),
                category: "API Key".to_string(),
                env_var_name: "OPENAI_API_KEY".to_string(),
                notes: "updated".to_string(),
                favorite: false,
            })
            .unwrap();
        assert_eq!(updated.entries[0].title, "OpenAI Production");
        assert_eq!(
            state.reveal_secret(&added.saved_id).unwrap(),
            "sk-rotated-value-888"
        );

        let toggled = state.toggle_favorite(&added.saved_id).unwrap();
        assert!(toggled[0].favorite);
        assert!(state.toggle_favorite("missing-id").is_err());

        assert!(state.update_settings(2_000, 20, false).is_err());
        assert!(state.update_settings(5, 999, false).is_err());
        let next_settings = state.update_settings(15, 0, false).unwrap();
        assert_eq!(next_settings.auto_lock_minutes, 15);
        assert_eq!(next_settings.clipboard_clear_seconds, 0);

        {
            let _serial = crate::clipboard::CLIPBOARD_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            assert_eq!(state.copy_entry_secret(&added.saved_id).unwrap(), 0);
            assert_eq!(
                state.copy_text("public-user".to_string(), false).unwrap(),
                0
            );
            clear_clipboard_if_matches("public-user");
        }

        state.lock().unwrap();
        let locked_status = state.status(false).unwrap();
        assert!(!locked_status.unlocked);
        assert_eq!(
            locked_status.password_hint.as_deref(),
            Some("petunjuk baru")
        );
        assert!(state.list_entries().is_err());
        assert!(state.reveal_secret(&added.saved_id).is_err());

        let unlocked_list = state
            .unlock_with_password("correct-master-123".to_string())
            .unwrap();
        assert_eq!(unlocked_list.len(), 1);

        assert!(state.delete_entry("missing-id").is_err());
        let remaining = state.delete_entry(&added.saved_id).unwrap();
        assert!(remaining.is_empty());

        let reloaded = load_or_init_config_in(&dir).unwrap().1;
        assert_eq!(reloaded.vault_path, dir.join("vault.vpass"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn biometric_rotation_backup_import_and_relocation() {
        let (dir_a, state_a) = make_test_state();
        let (dir_b, state_b) = make_test_state();

        state_a
            .create_vault("alpha-password-123".to_string(), None, true)
            .unwrap();
        let item = state_a
            .upsert_entry(VaultEntryInput {
                id: None,
                title: "Stripe Key".to_string(),
                username: "acct_1".to_string(),
                password: "rk_live_example_12345".to_string(),
                url: "".to_string(),
                category: "API Key".to_string(),
                env_var_name: "STRIPE_API_KEY".to_string(),
                notes: "".to_string(),
                favorite: true,
            })
            .unwrap();

        // Biometric enrollment + unlock + master-password rotation re-wrapping biometric key.
        assert!(state_a.extract_unlocked_key_for_biometric(false).is_err());
        let key_copy = state_a.extract_unlocked_key_for_biometric(true).unwrap();
        let bio_status = state_a.persist_biometric_key(&key_copy, true).unwrap();
        assert!(bio_status.biometric_enabled);

        state_a.lock().unwrap();
        let (vpath, dpapi_blob) = state_a.prepare_biometric_unlock().unwrap();
        let bio_entries = state_a
            .finish_biometric_unlock(&vpath, &dpapi_blob)
            .unwrap();
        assert_eq!(bio_entries.len(), 1);

        assert!(state_a
            .change_master_password("alpha-password-123".to_string(), "short".to_string())
            .is_err());
        assert!(state_a
            .change_master_password("wrong-pw".to_string(), "bravo-password-456".to_string())
            .is_err());
        state_a
            .change_master_password(
                "alpha-password-123".to_string(),
                "bravo-password-456".to_string(),
            )
            .unwrap();

        // Biometric key must still unlock vault after master-password rotation.
        state_a.lock().unwrap();
        let (vpath2, dpapi_blob2) = state_a.prepare_biometric_unlock().unwrap();
        assert_eq!(
            state_a
                .finish_biometric_unlock(&vpath2, &dpapi_blob2)
                .unwrap()
                .len(),
            1
        );

        // Export encrypted backup from A, then import into B.
        let backup_file = dir_a.join("exported-backup.vpass");
        state_a.export_backup_to_path(&backup_file).unwrap();

        state_b
            .create_vault("charlie-password-789".to_string(), None, false)
            .unwrap();
        let imported_count = state_b
            .import_backup_from_path(&backup_file, "bravo-password-456".to_string())
            .unwrap();
        assert_eq!(imported_count, 1);
        assert_eq!(
            state_b.reveal_secret(&item.saved_id).unwrap(),
            "rk_live_example_12345"
        );

        // Relocate vault A to a new path without extension and ensure old files are cleaned up.
        let old_vault = state_a.current_vault_path().unwrap();
        let moved_target = dir_a.join("moved").join("custom_vault");
        let relocated = state_a.relocate_vault_to(moved_target, true).unwrap();
        assert!(relocated.vault_path.ends_with("custom_vault.vpass"));
        assert!(relocated.biometric_enabled);
        assert!(!old_vault.exists());
        assert!(!old_vault.with_extension("vpass.bak").exists());

        // Switching to another existing vault locks the current session.
        let switched = state_a
            .switch_existing_vault(state_b.current_vault_path().unwrap(), true)
            .unwrap();
        assert!(!switched.unlocked);

        let disabled = state_a.disable_biometric(true).unwrap();
        assert!(!disabled.biometric_enabled);
        assert!(state_a.prepare_biometric_unlock().is_err());

        clear_biometric_secret_store_for_target(&state_b.cred_target_name);
        let _ = fs::remove_dir_all(&dir_a);
        let _ = fs::remove_dir_all(&dir_b);
    }

    #[test]
    fn locked_guards_auto_clear_timer_and_default_kdf_paths() {
        let (dir, mut state) = make_test_state();

        // Exercise default random KDF generator path.
        state.kdf_override = None;
        assert_eq!(state.fresh_kdf().algorithm, "argon2id");
        state.kdf_override = Some(KdfParams {
            algorithm: "argon2id".to_string(),
            memory_kib: 8_192,
            iterations: 1,
            parallelism: 1,
            salt_b64: B64.encode([0x55u8; 16]),
        });

        let _ = load_or_init_config().unwrap();

        // All state-mutating/reading operations must reject when vault is locked.
        assert!(state.ensure_unlocked().is_err());
        assert!(state
            .update_password_hint(Some("x".to_string()), false)
            .is_err());
        assert!(state.copy_entry_secret("any").is_err());
        assert!(state.copy_text("any".to_string(), true).is_err());
        assert!(state.delete_entry("any").is_err());
        assert!(state.toggle_favorite("any").is_err());
        assert!(state.update_settings(5, 20, false).is_err());
        assert!(state.export_backup_to_path(&dir.join("out.vpass")).is_err());

        state
            .create_vault("delta-password-123".to_string(), None, false)
            .unwrap();

        // Updating a non-existent entry ID must fail cleanly.
        assert!(state
            .upsert_entry(VaultEntryInput {
                id: Some("does-not-exist".to_string()),
                title: "Ghost".to_string(),
                username: "".to_string(),
                password: "pw".to_string(),
                url: "".to_string(),
                category: "Login".to_string(),
                env_var_name: "".to_string(),
                notes: "".to_string(),
                favorite: false,
            })
            .is_err());

        // Exercise auto-clear timer thread (both superseded generation and active clear).
        state.update_settings(5, 1, false).unwrap();
        {
            let _serial = crate::clipboard::CLIPBOARD_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            assert_eq!(
                state.copy_text("first-secret".to_string(), true).unwrap(),
                1
            );
            assert_eq!(
                state.copy_text("second-secret".to_string(), true).unwrap(),
                1
            );
            std::thread::sleep(Duration::from_millis(1_200));
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn master_password_cooldown_escalates_blocks_and_resets() {
        let now = Instant::now();
        let mut guard = PasswordAttemptGuard::default();
        assert_eq!(guard.remaining_cooldown_secs(now), 0);
        assert!(guard.check_allowed(now).is_ok());

        let expected = [
            None,
            None,
            Some(3),
            Some(3),
            Some(10),
            Some(10),
            Some(30),
            Some(30),
            Some(30),
            Some(60),
        ];
        for (idx, exp) in expected.into_iter().enumerate() {
            assert_eq!(guard.record_failure(now), exp, "failure {}", idx + 1);
        }
        assert_eq!(guard.remaining_cooldown_secs(now), 60);
        assert!(guard
            .check_allowed(now)
            .unwrap_err()
            .contains("Coba lagi dalam 60 detik"));
        assert!(guard.check_allowed(now + Duration::from_secs(60)).is_ok());

        guard.reset();
        assert_eq!(guard.failed_attempts, 0);
        assert_eq!(guard.remaining_cooldown_secs(now), 0);

        let (dir, state) = make_test_state();
        state
            .create_vault("correct-master-123".to_string(), None, false)
            .unwrap();
        state.lock().unwrap();

        let err1 = state
            .unlock_with_password("wrong-pass-1".to_string())
            .unwrap_err();
        assert!(!err1.contains("tunggu"));
        let err2 = state
            .unlock_with_password("wrong-pass-2".to_string())
            .unwrap_err();
        assert!(!err2.contains("tunggu"));
        let err3 = state
            .unlock_with_password("wrong-pass-3".to_string())
            .unwrap_err();
        assert!(err3.contains("tunggu 3 detik"));
        assert!(state.status(false).unwrap().unlock_cooldown_seconds >= 1);

        let blocked = state
            .unlock_with_password("correct-master-123".to_string())
            .unwrap_err();
        assert!(blocked.contains("Coba lagi dalam"));

        state.auth_guard.lock().unwrap().cooldown_until =
            Some(Instant::now() - Duration::from_millis(5));
        assert_eq!(
            state
                .unlock_with_password("correct-master-123".to_string())
                .unwrap()
                .len(),
            0
        );
        assert_eq!(state.status(false).unwrap().unlock_cooldown_seconds, 0);

        for _ in 0..2 {
            let e = state
                .change_master_password("wrong-current".to_string(), "next-master-456".to_string())
                .unwrap_err();
            assert!(!e.contains("tunggu"));
        }
        let change_cooldown = state
            .change_master_password("wrong-current".to_string(), "next-master-456".to_string())
            .unwrap_err();
        assert!(change_cooldown.contains("tunggu 3 detik"));

        let change_blocked = state
            .change_master_password(
                "correct-master-123".to_string(),
                "next-master-456".to_string(),
            )
            .unwrap_err();
        assert!(change_blocked.contains("Coba lagi dalam"));

        let switched = state
            .switch_existing_vault(dir.join("vault.vpass"), false)
            .unwrap();
        assert_eq!(switched.unlock_cooldown_seconds, 0);

        let _ = fs::remove_dir_all(&dir);
    }
}
