use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{
    decrypt_envelope, decrypt_envelope_with_key, encrypt_with_key, KdfParams, VaultEnvelope,
};

const MAX_HINT_CHARS: usize = 200;
const MAX_ENV_VAR_LEN: usize = 128;

const BLOCKED_ENV_VAR_NAMES: &[&str] = &[
    "PATH",
    "PATHEXT",
    "COMSPEC",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "HOMEDRIVE",
    "HOMEPATH",
    "HOME",
    "SHELL",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "NODE_OPTIONS",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONHOME",
    "PERL5OPT",
    "RUBYOPT",
    "JAVA_TOOL_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "DOTNET_STARTUP_HOOKS",
    "COR_PROFILER",
    "CORECLR_PROFILER",
    "RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTC_WRAPPER",
];

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct VaultEntry {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub category: String,
    #[serde(default)]
    pub env_var_name: String,
    pub notes: String,
    pub favorite: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// Metadata-only entry representation sent over IPC to WebView so plaintext passwords
/// and API keys are not held in JavaScript's non-zeroizable heap for every item.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultEntrySummary {
    pub id: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub category: String,
    pub env_var_name: String,
    pub notes: String,
    pub favorite: bool,
    pub password_length: usize,
    pub strength_score: u8,
    pub reused_count: usize,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultEntryInput {
    pub id: Option<String>,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub category: String,
    #[serde(default)]
    pub env_var_name: String,
    pub notes: String,
    pub favorite: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct VaultSettings {
    pub auto_lock_minutes: u32,
    pub clipboard_clear_seconds: u32,
}

impl Default for VaultSettings {
    fn default() -> Self {
        Self {
            auto_lock_minutes: 5,
            clipboard_clear_seconds: 20,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct VaultPayload {
    pub entries: Vec<VaultEntry>,
    pub settings: VaultSettings,
}

pub struct UnlockedVault {
    pub key: Zeroizing<[u8; 32]>,
    pub kdf: KdfParams,
    pub payload: VaultPayload,
    pub password_hint: Option<String>,
}

pub fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

pub fn normalize_hint(hint: Option<String>) -> Option<String> {
    hint.map(|h| {
        h.chars()
            .filter(|c| !c.is_control())
            .collect::<String>()
            .trim()
            .chars()
            .take(MAX_HINT_CHARS)
            .collect::<String>()
    })
    .filter(|h| !h.is_empty())
}

/// Validates and normalizes an environment variable identifier (allowing empty string when unset).
pub fn validate_env_var_name(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.len() > MAX_ENV_VAR_LEN {
        return Err(format!(
            "Nama environment variable maksimal {MAX_ENV_VAR_LEN} karakter."
        ));
    }

    let normalized = trimmed.to_ascii_uppercase();
    let mut chars = normalized.chars();
    let Some(first) = chars.next() else {
        return Ok(String::new());
    };

    if !(first.is_ascii_uppercase() || first == '_')
        || !chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        return Err(
            "Nama environment variable hanya boleh berisi huruf A-Z, angka 0-9, dan underscore (_), serta tidak boleh diawali angka."
                .to_string(),
        );
    }

    if BLOCKED_ENV_VAR_NAMES.contains(&normalized.as_str()) {
        return Err(format!(
            "Nama environment variable '{normalized}' dicadangkan oleh sistem dan tidak boleh ditimpa."
        ));
    }

    Ok(normalized)
}

/// Best-effort sanitizer for legacy or imported entries so invalid env names do not poison imports.
pub fn sanitize_imported_env_var_name(raw: &str) -> String {
    validate_env_var_name(raw).unwrap_or_default()
}

pub fn evaluate_password_strength_score(password: &str) -> u8 {
    if password.is_empty() {
        return 0;
    }

    let char_len = password.chars().count();
    let mut points: u8 = 0;
    if char_len >= 8 {
        points += 1;
    }
    if char_len >= 12 {
        points += 1;
    }
    if char_len >= 16 {
        points += 1;
    }

    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        points += 1;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        points += 1;
    }
    if password.chars().any(|c| !c.is_ascii_alphanumeric()) {
        points += 1;
    }

    if char_len < 8 {
        points = points.min(1);
    }

    let mut iter = password.chars();
    if let Some(first) = iter.next() {
        if char_len > 1 && iter.all(|c| c == first) {
            points = 0;
        }
    }

    match points {
        0..=1 => 1,
        2..=3 => 2,
        4 => 3,
        _ => 4,
    }
}

pub fn summarize_entries(entries: &[VaultEntry]) -> Vec<VaultEntrySummary> {
    entries
        .iter()
        .map(|entry| {
            // Count reuse directly against in-memory VaultEntry slices to avoid cloning
            // secrets into a non-zeroized temporary HashMap.
            let reused_count = entries
                .iter()
                .filter(|other| other.password == entry.password)
                .count();
            VaultEntrySummary {
                id: entry.id.clone(),
                title: entry.title.clone(),
                username: entry.username.clone(),
                url: entry.url.clone(),
                category: entry.category.clone(),
                env_var_name: entry.env_var_name.clone(),
                notes: entry.notes.clone(),
                favorite: entry.favorite,
                password_length: entry.password.chars().count(),
                strength_score: evaluate_password_strength_score(&entry.password),
                reused_count,
                created_at: entry.created_at.clone(),
                updated_at: entry.updated_at.clone(),
            }
        })
        .collect()
}

pub fn read_envelope(path: &Path) -> Result<VaultEnvelope, String> {
    let bytes = fs::read(path).map_err(|e| format!("Gagal membaca file vault: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("Format file vault rusak: {e}"))
}

fn write_bytes_synced(path: &Path, data: &[u8]) -> Result<(), String> {
    let mut file =
        File::create(path).map_err(|e| format!("Gagal membuat file sementara vault: {e}"))?;
    file.write_all(data)
        .map_err(|e| format!("Gagal menulis data vault: {e}"))?;
    file.sync_all()
        .map_err(|e| format!("Gagal sinkronisasi disk vault: {e}"))
}

pub fn write_envelope_atomic(path: &Path, envelope: &VaultEnvelope) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Gagal membuat direktori penyimpanan vault: {e}"))?;
    }

    let serialized = serde_json::to_vec_pretty(envelope)
        .map_err(|e| format!("Gagal serialisasi envelope vault: {e}"))?;

    let tmp_path = path.with_extension("vpass.tmp");
    let bak_path = path.with_extension("vpass.bak");

    write_bytes_synced(&tmp_path, &serialized)?;

    if path.exists() {
        fs::copy(path, &bak_path)
            .map_err(|e| format!("Gagal membuat salinan backup sebelum menyimpan: {e}"))?;
    }

    fs::rename(&tmp_path, path).map_err(|e| format!("Gagal memindahkan file vault baru: {e}"))?;

    Ok(())
}

pub fn save_unlocked_vault(path: &Path, unlocked: &UnlockedVault) -> Result<(), String> {
    let plaintext = Zeroizing::new(
        serde_json::to_vec(&unlocked.payload)
            .map_err(|e| format!("Gagal serialisasi data vault: {e}"))?,
    );
    let mut envelope = encrypt_with_key(&plaintext, &unlocked.key, unlocked.kdf.clone())?;
    envelope.password_hint = normalize_hint(unlocked.password_hint.clone());
    write_envelope_atomic(path, &envelope)
}

/// Overwrites `.vpass.bak` with a freshly encrypted envelope (using a distinct random nonce)
/// after master-password rotation so the old password can no longer decrypt `.vpass.bak`.
pub fn refresh_backup_after_rekey(path: &Path, unlocked: &UnlockedVault) -> Result<(), String> {
    let bak_path = path.with_extension("vpass.bak");
    let bak_tmp_path = path.with_extension("vpass.bak.tmp");

    let plaintext = Zeroizing::new(
        serde_json::to_vec(&unlocked.payload)
            .map_err(|e| format!("Gagal serialisasi data backup vault: {e}"))?,
    );
    let mut fresh_backup_envelope =
        encrypt_with_key(&plaintext, &unlocked.key, unlocked.kdf.clone())?;
    fresh_backup_envelope.password_hint = normalize_hint(unlocked.password_hint.clone());

    let serialized = serde_json::to_vec_pretty(&fresh_backup_envelope)
        .map_err(|e| format!("Gagal serialisasi backup vault: {e}"))?;

    write_bytes_synced(&bak_tmp_path, &serialized)?;
    fs::rename(&bak_tmp_path, &bak_path)
        .map_err(|e| format!("Gagal memperbarui file backup vault (.vpass.bak): {e}"))?;
    Ok(())
}

pub fn open_vault_with_password(
    path: &Path,
    master_password: &str,
) -> Result<UnlockedVault, String> {
    let envelope = read_envelope(path)?;
    let (key, plaintext) = decrypt_envelope(&envelope, master_password)?;
    let payload: VaultPayload = serde_json::from_slice(&plaintext)
        .map_err(|e| format!("Data di dalam vault tidak valid: {e}"))?;

    Ok(UnlockedVault {
        key,
        kdf: envelope.kdf,
        payload,
        password_hint: normalize_hint(envelope.password_hint),
    })
}

pub fn open_vault_with_key(path: &Path, key: Zeroizing<[u8; 32]>) -> Result<UnlockedVault, String> {
    let envelope = read_envelope(path)?;
    let plaintext = decrypt_envelope_with_key(&envelope, &key)?;
    let payload: VaultPayload = serde_json::from_slice(&plaintext)
        .map_err(|e| format!("Data di dalam vault tidak valid: {e}"))?;

    Ok(UnlockedVault {
        key,
        kdf: envelope.kdf,
        payload,
        password_hint: normalize_hint(envelope.password_hint),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::derive_key;
    use base64::{engine::general_purpose::STANDARD as B64, Engine};

    #[test]
    fn atomic_save_and_reopen_creates_backup_without_leaving_tmp() {
        let dir = std::env::temp_dir().join(format!("vaultpass-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let vault_path = dir.join("vault.vpass");

        let kdf = KdfParams {
            algorithm: "argon2id".to_string(),
            memory_kib: 8192,
            iterations: 1,
            parallelism: 1,
            salt_b64: B64.encode([11u8; 16]),
        };
        let key = derive_key("test-master-pw", &kdf).unwrap();
        let mut unlocked = UnlockedVault {
            key,
            kdf,
            payload: VaultPayload::default(),
            password_hint: Some("Kucing pertama".to_string()),
        };

        save_unlocked_vault(&vault_path, &unlocked).unwrap();
        assert!(vault_path.exists());
        assert!(!vault_path.with_extension("vpass.tmp").exists());

        unlocked.payload.entries.push(VaultEntry {
            id: "1".to_string(),
            title: "OpenAI API".to_string(),
            username: "rizal".to_string(),
            password: "sk-live-123".to_string(),
            url: "https://platform.openai.com".to_string(),
            category: "API Key".to_string(),
            env_var_name: "OPENAI_API_KEY".to_string(),
            notes: "".to_string(),
            favorite: true,
            created_at: now_iso(),
            updated_at: now_iso(),
        });
        save_unlocked_vault(&vault_path, &unlocked).unwrap();

        assert!(vault_path.with_extension("vpass.bak").exists());
        assert!(!vault_path.with_extension("vpass.tmp").exists());

        let reopened = open_vault_with_password(&vault_path, "test-master-pw").unwrap();
        assert_eq!(reopened.payload.entries.len(), 1);
        assert_eq!(reopened.payload.entries[0].title, "OpenAI API");
        assert_eq!(reopened.payload.entries[0].env_var_name, "OPENAI_API_KEY");
        assert_eq!(reopened.password_hint.as_deref(), Some("Kucing pertama"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rekey_refresh_invalidates_old_password_on_backup_file() {
        let dir = std::env::temp_dir().join(format!("vaultpass-rekey-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let vault_path = dir.join("vault.vpass");
        let bak_path = vault_path.with_extension("vpass.bak");

        let old_kdf = KdfParams {
            algorithm: "argon2id".to_string(),
            memory_kib: 8192,
            iterations: 1,
            parallelism: 1,
            salt_b64: B64.encode([21u8; 16]),
        };
        let old_key = derive_key("old-master-password", &old_kdf).unwrap();
        let mut unlocked = UnlockedVault {
            key: old_key,
            kdf: old_kdf,
            payload: VaultPayload::default(),
            password_hint: None,
        };
        unlocked.payload.entries.push(VaultEntry {
            id: "1".to_string(),
            title: "Secret".to_string(),
            username: "u".to_string(),
            password: "pw".to_string(),
            url: "".to_string(),
            category: "Login".to_string(),
            env_var_name: "".to_string(),
            notes: "".to_string(),
            favorite: false,
            created_at: now_iso(),
            updated_at: now_iso(),
        });
        save_unlocked_vault(&vault_path, &unlocked).unwrap();

        let new_kdf = KdfParams {
            algorithm: "argon2id".to_string(),
            memory_kib: 8192,
            iterations: 1,
            parallelism: 1,
            salt_b64: B64.encode([22u8; 16]),
        };
        unlocked.key = derive_key("new-master-password", &new_kdf).unwrap();
        unlocked.kdf = new_kdf;
        save_unlocked_vault(&vault_path, &unlocked).unwrap();
        refresh_backup_after_rekey(&vault_path, &unlocked).unwrap();

        assert!(open_vault_with_password(&vault_path, "old-master-password").is_err());
        assert!(open_vault_with_password(&bak_path, "old-master-password").is_err());
        assert!(open_vault_with_password(&vault_path, "new-master-password").is_ok());
        assert!(open_vault_with_password(&bak_path, "new-master-password").is_ok());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn env_var_validation_rejects_injection_and_reserved_names() {
        assert_eq!(validate_env_var_name("").unwrap(), "");
        assert_eq!(
            validate_env_var_name(" openai_api_key ").unwrap(),
            "OPENAI_API_KEY"
        );
        assert!(validate_env_var_name("1INVALID").is_err());
        assert!(validate_env_var_name("OPENAI_KEY; calc.exe").is_err());
        assert!(validate_env_var_name("$(whoami)").is_err());
        assert!(validate_env_var_name("PATH").is_err());
        assert!(validate_env_var_name("node_options").is_err());
    }

    #[test]
    fn summarize_entries_computes_reuse_and_strength_without_exposing_secret() {
        let entries = vec![
            VaultEntry {
                id: "a".to_string(),
                title: "One".to_string(),
                username: "".to_string(),
                password: "reused-weak".to_string(),
                url: "".to_string(),
                category: "Login".to_string(),
                env_var_name: "".to_string(),
                notes: "".to_string(),
                favorite: false,
                created_at: now_iso(),
                updated_at: now_iso(),
            },
            VaultEntry {
                id: "b".to_string(),
                title: "Two".to_string(),
                username: "".to_string(),
                password: "reused-weak".to_string(),
                url: "".to_string(),
                category: "Login".to_string(),
                env_var_name: "".to_string(),
                notes: "".to_string(),
                favorite: false,
                created_at: now_iso(),
                updated_at: now_iso(),
            },
            VaultEntry {
                id: "c".to_string(),
                title: "Strong".to_string(),
                username: "".to_string(),
                password: "Tr0ub4dor&3-VeryLongPassword!".to_string(),
                url: "".to_string(),
                category: "API Key".to_string(),
                env_var_name: "STRONG_KEY".to_string(),
                notes: "".to_string(),
                favorite: true,
                created_at: now_iso(),
                updated_at: now_iso(),
            },
        ];

        let summaries = summarize_entries(&entries);
        assert_eq!(summaries.len(), 3);
        assert_eq!(summaries[0].reused_count, 2);
        assert_eq!(summaries[1].reused_count, 2);
        assert_eq!(summaries[2].reused_count, 1);
        assert_eq!(summaries[2].strength_score, 4);
    }

    #[test]
    fn strength_hint_key_open_and_sanitizer_edge_cases() {
        assert_eq!(evaluate_password_strength_score(""), 0);
        assert_eq!(evaluate_password_strength_score("Ab1!"), 1);
        assert_eq!(evaluate_password_strength_score("aaaaaaaaaaaa"), 1);
        assert_eq!(evaluate_password_strength_score("Abcd1234"), 2);
        assert_eq!(evaluate_password_strength_score("Abcd12345678"), 3);

        assert_eq!(normalize_hint(Some("   \n\t  ".to_string())), None);
        let long_hint = format!("petunjuk\n{}", "x".repeat(250));
        let normalized = normalize_hint(Some(long_hint)).unwrap();
        assert!(!normalized.contains('\n'));
        assert_eq!(normalized.chars().count(), MAX_HINT_CHARS);

        assert!(validate_env_var_name(&"A".repeat(MAX_ENV_VAR_LEN + 1)).is_err());
        assert_eq!(sanitize_imported_env_var_name("valid_key"), "VALID_KEY");
        assert_eq!(sanitize_imported_env_var_name("PATH"), "");

        let dir = std::env::temp_dir().join(format!("vaultpass-keyopen-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let vault_path = dir.join("vault.vpass");

        let kdf = KdfParams {
            algorithm: "argon2id".to_string(),
            memory_kib: 8192,
            iterations: 1,
            parallelism: 1,
            salt_b64: B64.encode([31u8; 16]),
        };
        let key = derive_key("key-open-pw", &kdf).unwrap();
        let unlocked = UnlockedVault {
            key: key.clone(),
            kdf,
            payload: VaultPayload::default(),
            password_hint: Some("ingat ini".to_string()),
        };
        save_unlocked_vault(&vault_path, &unlocked).unwrap();

        let reopened_by_key = open_vault_with_key(&vault_path, key).unwrap();
        assert_eq!(reopened_by_key.password_hint.as_deref(), Some("ingat ini"));

        let _ = fs::remove_dir_all(&dir);
    }
}
