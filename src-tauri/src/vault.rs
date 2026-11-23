use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{
    decrypt_envelope, decrypt_envelope_with_key, encrypt_with_key, KdfParams, VaultEnvelope,
};

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
    hint.map(|h| h.trim().to_string()).filter(|h| !h.is_empty())
}

pub fn read_envelope(path: &Path) -> Result<VaultEnvelope, String> {
    let bytes = fs::read(path).map_err(|e| format!("Gagal membaca file vault: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("Format file vault rusak: {e}"))
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

    {
        let mut tmp_file = File::create(&tmp_path)
            .map_err(|e| format!("Gagal membuat file sementara vault: {e}"))?;
        tmp_file
            .write_all(&serialized)
            .map_err(|e| format!("Gagal menulis data vault: {e}"))?;
        tmp_file
            .sync_all()
            .map_err(|e| format!("Gagal sinkronisasi disk vault: {e}"))?;
    }

    if path.exists() {
        fs::copy(path, &bak_path)
            .map_err(|e| format!("Gagal membuat salinan backup sebelum menyimpan: {e}"))?;
    }

    fs::rename(&tmp_path, path)
        .map_err(|e| format!("Gagal memindahkan file vault baru: {e}"))?;

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

pub fn open_vault_with_key(
    path: &Path,
    key: Zeroizing<[u8; 32]>,
) -> Result<UnlockedVault, String> {
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
        assert_eq!(
            reopened.password_hint.as_deref(),
            Some("Kucing pertama")
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
