use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::{rngs::OsRng, Rng, RngCore, TryRngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const VAULT_MAGIC: &str = "VAULTPASS";
pub const VAULT_VERSION: u32 = 1;
pub const DEFAULT_MEMORY_KIB: u32 = 65_536; // 64 MiB
pub const DEFAULT_ITERATIONS: u32 = 3;
pub const DEFAULT_PARALLELISM: u32 = 4;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KdfParams {
    pub algorithm: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt_b64: String,
}

impl KdfParams {
    pub fn new_random() -> Self {
        let mut salt = [0u8; 16];
        OsRng.unwrap_err().fill_bytes(&mut salt);
        Self {
            algorithm: "argon2id".to_string(),
            memory_kib: DEFAULT_MEMORY_KIB,
            iterations: DEFAULT_ITERATIONS,
            parallelism: DEFAULT_PARALLELISM,
            salt_b64: B64.encode(salt),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultEnvelope {
    pub magic: String,
    pub version: u32,
    pub kdf: KdfParams,
    pub cipher: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_hint: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordGenOptions {
    pub length: usize,
    pub uppercase: bool,
    pub lowercase: bool,
    pub numbers: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

fn build_aad(magic: &str, version: u32, kdf: &KdfParams, cipher: &str) -> Vec<u8> {
    format!(
        "{}|v{}|{}|m={},t={},p={}|{}|{}",
        magic,
        version,
        kdf.algorithm,
        kdf.memory_kib,
        kdf.iterations,
        kdf.parallelism,
        kdf.salt_b64,
        cipher
    )
    .into_bytes()
}

pub fn derive_key(master_password: &str, kdf: &KdfParams) -> Result<Zeroizing<[u8; 32]>, String> {
    if kdf.algorithm != "argon2id" {
        return Err("Algoritma KDF tidak didukung.".to_string());
    }

    let salt = B64
        .decode(&kdf.salt_b64)
        .map_err(|_| "Salt pada file vault tidak valid.".to_string())?;
    if salt.len() < 16 {
        return Err("Panjang salt pada file vault tidak memenuhi standar keamanan.".to_string());
    }

    let params = Params::new(kdf.memory_kib, kdf.iterations, kdf.parallelism, Some(32))
        .map_err(|e| format!("Parameter Argon2id tidak valid: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(master_password.as_bytes(), &salt, &mut *key)
        .map_err(|e| format!("Gagal melakukan derivasi kunci: {e}"))?;

    Ok(key)
}

pub fn encrypt_with_key(
    plaintext: &[u8],
    key: &[u8; 32],
    kdf: KdfParams,
) -> Result<VaultEnvelope, String> {
    let cipher_name = "aes-256-gcm".to_string();
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("Gagal menginisialisasi cipher AES-256-GCM: {e}"))?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.unwrap_err().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);
    let aad = build_aad(VAULT_MAGIC, VAULT_VERSION, &kdf, &cipher_name);

    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| "Gagal mengenkripsi payload vault.".to_string())?;

    Ok(VaultEnvelope {
        magic: VAULT_MAGIC.to_string(),
        version: VAULT_VERSION,
        kdf,
        cipher: cipher_name,
        nonce_b64: B64.encode(nonce_bytes),
        ciphertext_b64: B64.encode(ciphertext),
        password_hint: None,
    })
}

pub fn decrypt_envelope_with_key(
    envelope: &VaultEnvelope,
    key: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, String> {
    if envelope.magic != VAULT_MAGIC || envelope.version != VAULT_VERSION {
        return Err("Format file vault tidak dikenali atau versi tidak didukung.".to_string());
    }
    if envelope.cipher != "aes-256-gcm" {
        return Err("Cipher vault tidak didukung.".to_string());
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("Gagal menginisialisasi cipher: {e}"))?;

    let nonce_bytes = B64
        .decode(&envelope.nonce_b64)
        .map_err(|_| "Nonce pada file vault tidak valid.".to_string())?;
    if nonce_bytes.len() != 12 {
        return Err("Panjang nonce tidak valid.".to_string());
    }
    let nonce = Nonce::try_from(nonce_bytes.as_slice())
        .map_err(|_| "Panjang nonce tidak valid.".to_string())?;

    let ciphertext = B64
        .decode(&envelope.ciphertext_b64)
        .map_err(|_| "Ciphertext pada file vault tidak valid.".to_string())?;

    let aad = build_aad(
        &envelope.magic,
        envelope.version,
        &envelope.kdf,
        &envelope.cipher,
    );

    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| {
            "Master password salah atau file vault telah rusak/dimodifikasi.".to_string()
        })?;

    Ok(Zeroizing::new(plaintext))
}

/// Derived key plus the decrypted vault bytes, both wiped from memory on drop.
pub type DecryptedVault = (Zeroizing<[u8; 32]>, Zeroizing<Vec<u8>>);

pub fn decrypt_envelope(
    envelope: &VaultEnvelope,
    master_password: &str,
) -> Result<DecryptedVault, String> {
    if envelope.magic != VAULT_MAGIC || envelope.version != VAULT_VERSION {
        return Err("Format file vault tidak dikenali atau versi tidak didukung.".to_string());
    }
    let key = derive_key(master_password, &envelope.kdf)?;
    let plaintext = decrypt_envelope_with_key(envelope, &key)?;
    Ok((key, plaintext))
}

pub fn generate_password(options: &PasswordGenOptions) -> Result<String, String> {
    if !(8..=128).contains(&options.length) {
        return Err("Panjang password harus antara 8 hingga 128 karakter.".to_string());
    }

    let filter_ambiguous = |chars: &str| -> Vec<char> {
        chars
            .chars()
            .filter(|c| !options.exclude_ambiguous || !"0OIl1".contains(*c))
            .collect()
    };

    let mut pools: Vec<Vec<char>> = Vec::new();
    if options.uppercase {
        pools.push(filter_ambiguous("ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
    }
    if options.lowercase {
        pools.push(filter_ambiguous("abcdefghijklmnopqrstuvwxyz"));
    }
    if options.numbers {
        pools.push(filter_ambiguous("0123456789"));
    }
    if options.symbols {
        pools.push("!@#$%^&*()-_=+[]{}|;:,.<>?".chars().collect());
    }

    if pools.is_empty() {
        return Err("Pilih minimal satu jenis karakter.".to_string());
    }
    if options.length < pools.len() {
        return Err(
            "Panjang password terlalu pendek untuk kombinasi karakter yang dipilih.".to_string(),
        );
    }

    let combined: Vec<char> = pools.iter().flatten().copied().collect();
    let mut chars: Vec<char> = Vec::with_capacity(options.length);
    // Draw directly from the OS CSPRNG; unwrap_err panics only if the OS RNG fails.
    let mut rng = OsRng.unwrap_err();

    for pool in &pools {
        let idx = rng.random_range(0..pool.len());
        chars.push(pool[idx]);
    }

    while chars.len() < options.length {
        let idx = rng.random_range(0..combined.len());
        chars.push(combined[idx]);
    }

    for i in (1..chars.len()).rev() {
        let j = rng.random_range(0..=i);
        chars.swap(i, j);
    }

    Ok(chars.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip_succeeds() {
        let kdf = KdfParams {
            algorithm: "argon2id".to_string(),
            memory_kib: 8192,
            iterations: 1,
            parallelism: 1,
            salt_b64: B64.encode([42u8; 16]),
        };
        let key = derive_key("super-secret-master", &kdf).unwrap();
        let envelope = encrypt_with_key(b"hello-vault-data", &key, kdf).unwrap();

        let (_derived, plaintext) = decrypt_envelope(&envelope, "super-secret-master").unwrap();
        assert_eq!(&*plaintext, b"hello-vault-data");
    }

    #[test]
    fn wrong_password_fails_authentication() {
        let kdf = KdfParams {
            algorithm: "argon2id".to_string(),
            memory_kib: 8192,
            iterations: 1,
            parallelism: 1,
            salt_b64: B64.encode([7u8; 16]),
        };
        let key = derive_key("correct-password", &kdf).unwrap();
        let envelope = encrypt_with_key(b"secret", &key, kdf).unwrap();

        let result = decrypt_envelope(&envelope, "wrong-password");
        assert!(result.is_err());
    }

    #[test]
    fn tampered_header_aad_fails_authentication() {
        let kdf = KdfParams {
            algorithm: "argon2id".to_string(),
            memory_kib: 8192,
            iterations: 1,
            parallelism: 1,
            salt_b64: B64.encode([9u8; 16]),
        };
        let key = derive_key("master-12345", &kdf).unwrap();
        let mut envelope = encrypt_with_key(b"secret", &key, kdf).unwrap();

        envelope.kdf.iterations = 10;
        let result = decrypt_envelope(&envelope, "master-12345");
        assert!(result.is_err());
    }

    // --- Compatibility guards -------------------------------------------------
    // These pin the on-disk format. They were generated with argon2 0.5 and
    // aes-gcm 0.10. If a dependency upgrade makes them fail, existing user
    // vaults would no longer open, so do NOT just update the constants.
    const COMPAT_PASSWORD: &str = "kompatibel-123";
    const COMPAT_KEY_B64: &str = "kP8/pEx+Pet39QwIouvZbX53btwmydhK0p5wMS/ki0k=";
    const COMPAT_ENVELOPE_JSON: &str = r#"{"magic":"VAULTPASS","version":1,"kdf":{"algorithm":"argon2id","memoryKib":8192,"iterations":2,"parallelism":1,"saltB64":"BQUFBQUFBQUFBQUFBQUFBQ=="},"cipher":"aes-256-gcm","nonceB64":"ZEKVNcrRILrrmf7m","ciphertextB64":"gkAHE2FhO5/iS4KrYs4d2TkL1elo34UjOMvQsKBIS8RkaxCkz+/WL2QHC1TsajM/VFP9sbO7cC83oy+EsPzA22WN842e+MpMoxzmUS67dbux3jspFrIFgjazRhPLRTcv8tweXe03bpwVfGO8XREw9K2b5kcZ2Oxf6MiP5KCdF83NcQu3Lrr4VofBF9sSzNcj8Em9pJosg0SJ7Feth/WiP15c+I3PYBiOjfIM/5uW735uOlstp6YWVUmEOO5BEXFUmsCijKNoYkmEemPZ4B4qnhn6oeBWM4WRwz6WFRm9Opuzux9OTTEfJFiVXPwJSeqJ4tR5IEcgnJUB8XcHgaDIu4r+Z0cvBO3YI+p0T4r9F79B2z5V9hLGxG+aQmw3up0bjvnOcSZfiP0QIMpD1vzXeNZ4aMVu9ZN6Eo40L2Ri3JqiMo4j0Nz6hdofG2UjhTJS5Whh4yykUx9RaRqv4EYr/sid67hct7TQjG2zP5Xr/mqG22N24O/5"}"#;

    #[test]
    fn argon2id_derivation_matches_known_answer() {
        let envelope: VaultEnvelope = serde_json::from_str(COMPAT_ENVELOPE_JSON).unwrap();
        let key = derive_key(COMPAT_PASSWORD, &envelope.kdf).unwrap();
        assert_eq!(B64.encode(*key), COMPAT_KEY_B64);
    }

    #[test]
    fn vault_written_by_previous_versions_still_decrypts() {
        let envelope: VaultEnvelope = serde_json::from_str(COMPAT_ENVELOPE_JSON).unwrap();
        let (_key, plaintext) = decrypt_envelope(&envelope, COMPAT_PASSWORD).unwrap();
        let text = std::str::from_utf8(&plaintext).unwrap();
        assert!(text.contains("\"title\":\"OpenAI\""));
        assert!(text.contains("\"password\":\"sk-demo-0000\""));
    }

    #[test]
    fn fixture_rejects_wrong_password_and_tampered_ciphertext() {
        let envelope: VaultEnvelope = serde_json::from_str(COMPAT_ENVELOPE_JSON).unwrap();
        assert!(decrypt_envelope(&envelope, "salah-123").is_err());

        let mut tampered = envelope.clone();
        let mut bytes = B64.decode(&tampered.ciphertext_b64).unwrap();
        bytes[0] ^= 0x01;
        tampered.ciphertext_b64 = B64.encode(bytes);
        assert!(decrypt_envelope(&tampered, COMPAT_PASSWORD).is_err());
    }

    #[test]
    fn generator_respects_length_and_excludes_ambiguous() {
        let opts = PasswordGenOptions {
            length: 24,
            uppercase: true,
            lowercase: true,
            numbers: true,
            symbols: true,
            exclude_ambiguous: true,
        };
        let pw = generate_password(&opts).unwrap();
        assert_eq!(pw.len(), 24);
        for ch in ['0', 'O', 'I', 'l', '1'] {
            assert!(!pw.contains(ch));
        }
    }
}
