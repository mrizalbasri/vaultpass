use std::env;
use std::path::Path;
use std::process::{Command, ExitCode};

use serde::Serialize;
use vaultpass_lib::biometric::{
    dpapi_unprotect_key, foreground_window_hwnd, is_windows_hello_available,
    prompt_windows_master_password, request_windows_hello_verification, sanitize_prompt_label,
};
use vaultpass_lib::vault::{
    open_vault_with_key, open_vault_with_password, validate_env_var_name, UnlockedVault, VaultEntry,
};
use vaultpass_lib::{load_or_init_config, AppConfig};
use zeroize::Zeroizing;

const API_KEY_CATEGORY: &str = "API Key";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CliStatus {
    vault_path: String,
    exists: bool,
    cli_ready: bool,
    auth_mode: &'static str,
    biometric_enabled: bool,
    windows_hello_available: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CliAccountSummary<'a> {
    id: &'a str,
    title: &'a str,
    username: &'a str,
    url: &'a str,
    category: &'a str,
    env_var_name: &'a str,
    favorite: bool,
}

fn print_usage() {
    eprintln!(
        "VaultPass CLI (AI Agent & API Key Integration — khusus kategori 'API Key')\n\
         Penggunaan:\n  \
           vaultpass-cli status\n  \
           vaultpass-cli list [--query <kata-kunci>]\n  \
           vaultpass-cli get <nama-atau-id-persis> --field <key|password|username|url|env|notes|json>\n  \
           vaultpass-cli run --key <nama-atau-id-persis> [--env <NAMA_ENV>] -- <perintah> [argumen...]\n\n\
         Otentikasi Persetujuan:\n  \
           - Jika Windows Hello aktif: verifikasi sidik jari / wajah / PIN Windows Hello.\n  \
           - Jika Windows Hello belum aktif: otomatis memunculkan dialog Windows Security untuk Master Password.\n\n\
         Contoh untuk AI Agent (Validasi / Pakai API Key tanpa bocor di log chat):\n  \
           vaultpass-cli run --key \"OpenAI\" --env OPENAI_API_KEY -- python test_api.py\n  \
           vaultpass-cli get \"OpenAI\" --field key"
    );
}

fn default_env_name(title: &str, custom_env: &str) -> Result<String, String> {
    if !custom_env.trim().is_empty() {
        return validate_env_var_name(custom_env);
    }

    let mut sanitized = String::new();
    for ch in title.chars() {
        if ch.is_ascii_alphanumeric() {
            sanitized.push(ch.to_ascii_uppercase());
        } else if !sanitized.ends_with('_') {
            sanitized.push('_');
        }
    }
    let trimmed = sanitized.trim_matches('_');
    if trimmed.is_empty() {
        return validate_env_var_name("VAULTPASS_API_KEY");
    }

    let prefixed = if trimmed
        .chars()
        .next()
        .is_some_and(|first| first.is_ascii_digit())
    {
        format!("KEY_{trimmed}")
    } else {
        trimmed.to_string()
    };

    let candidate = if prefixed.ends_with("_KEY")
        || prefixed.ends_with("_TOKEN")
        || prefixed.ends_with("_SECRET")
    {
        prefixed
    } else {
        format!("{prefixed}_API_KEY")
    };

    validate_env_var_name(&candidate)
}

/// Resolves a single `API Key` entry using exact matching on `id`, `title`, or `env_var_name`.
/// Rejects non-`API Key` categories and refuses ambiguous duplicate titles.
fn find_exact_api_key_entry<'a>(
    entries: &'a [VaultEntry],
    target: &str,
) -> Result<&'a VaultEntry, String> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return Err("Nama atau ID API Key tidak boleh kosong.".to_string());
    }

    if let Some(by_id) = entries
        .iter()
        .find(|item| item.category == API_KEY_CATEGORY && item.id == trimmed)
    {
        return Ok(by_id);
    }

    let target_lower = trimmed.to_lowercase();
    let matches: Vec<&VaultEntry> = entries
        .iter()
        .filter(|item| {
            item.category == API_KEY_CATEGORY
                && (item.title.to_lowercase() == target_lower
                    || (!item.env_var_name.is_empty()
                        && item.env_var_name.to_lowercase() == target_lower))
        })
        .collect();

    let safe_label = sanitize_prompt_label(trimmed);
    match matches.as_slice() {
        [single] => Ok(*single),
        [] => Err(format!(
            "API Key '{safe_label}' tidak ditemukan. Hanya item berkategori 'API Key' dengan nama, env variable, atau ID yang cocok persis yang dapat diakses melalui CLI."
        )),
        many => {
            let ids: Vec<&str> = many.iter().map(|m| m.id.as_str()).collect();
            Err(format!(
                "Terdapat {} item 'API Key' dengan nama/env serupa ('{safe_label}'). Gunakan ID spesifik: {}",
                many.len(),
                ids.join(", ")
            ))
        }
    }
}

fn unlock_vault_for_cli(
    vault_path: &Path,
    cfg: &AppConfig,
    bio_enabled: bool,
    prompt_message: &str,
) -> Result<UnlockedVault, String> {
    if !vault_path.exists() {
        return Err(
            "File vault belum ditemukan. Buka aplikasi VaultPass terlebih dahulu untuk membuat vault."
                .to_string(),
        );
    }

    let owner_hwnd = foreground_window_hwnd();
    if bio_enabled {
        request_windows_hello_verification(prompt_message, owner_hwnd)?;
        let dpapi_b64 = cfg
            .biometric_key_dpapi_b64
            .as_ref()
            .ok_or_else(|| "Kunci biometrik tidak ditemukan.".to_string())?;
        let key = dpapi_unprotect_key(dpapi_b64)?;
        open_vault_with_key(vault_path, key)
    } else {
        let master_password = prompt_windows_master_password(prompt_message, owner_hwnd)?;
        open_vault_with_password(vault_path, &master_password)
    }
}

fn run_cli() -> Result<u8, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        print_usage();
        return Ok(0);
    }

    let (_config_path, cfg) = load_or_init_config()?;
    let vault_path = &cfg.vault_path;
    let hello_available = is_windows_hello_available();
    let bio_enabled = hello_available && cfg.is_biometric_enabled_for(vault_path);

    match args[0].as_str() {
        "status" => {
            let exists = vault_path.exists();
            let status = CliStatus {
                vault_path: vault_path.to_string_lossy().to_string(),
                exists,
                cli_ready: exists,
                auth_mode: if bio_enabled {
                    "windows-hello"
                } else {
                    "windows-security-password"
                },
                biometric_enabled: bio_enabled,
                windows_hello_available: hello_available,
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&status).map_err(|e| e.to_string())?
            );
            Ok(0)
        }
        "list" => {
            let query = args
                .windows(2)
                .find(|w| w[0] == "--query" || w[0] == "-q")
                .map(|w| w[1].to_lowercase());

            let unlocked = unlock_vault_for_cli(
                vault_path,
                &cfg,
                bio_enabled,
                "AI Agent (VaultPass CLI) meminta izin melihat daftar item kategori API Key",
            )?;

            let list: Vec<CliAccountSummary<'_>> = unlocked
                .payload
                .entries
                .iter()
                .filter(|item| item.category == API_KEY_CATEGORY)
                .filter(|item| {
                    if let Some(ref q) = query {
                        item.title.to_lowercase().contains(q)
                            || item.username.to_lowercase().contains(q)
                            || item.url.to_lowercase().contains(q)
                            || item.env_var_name.to_lowercase().contains(q)
                    } else {
                        true
                    }
                })
                .map(|item| CliAccountSummary {
                    id: &item.id,
                    title: &item.title,
                    username: &item.username,
                    url: &item.url,
                    category: &item.category,
                    env_var_name: &item.env_var_name,
                    favorite: item.favorite,
                })
                .collect();

            println!(
                "{}",
                serde_json::to_string_pretty(&list).map_err(|e| e.to_string())?
            );
            Ok(0)
        }
        "get" => {
            if args.len() < 2 {
                return Err(
                    "Gunakan: vaultpass-cli get <nama-atau-id> --field <key|password|username|url|env|notes|json>"
                        .to_string(),
                );
            }

            let target = &args[1];
            let field = args
                .windows(2)
                .find(|w| w[0] == "--field" || w[0] == "-f")
                .map(|w| w[1].as_str())
                .ok_or_else(|| {
                    "Argumen '--field' wajib disertakan (pilihan: key, password, username, url, env, notes, json)."
                        .to_string()
                })?;

            if !matches!(
                field,
                "password" | "key" | "username" | "url" | "notes" | "env" | "json"
            ) {
                return Err(format!(
                    "Field '{field}' tidak dikenali. Gunakan: key, password, username, url, env, notes, atau json."
                ));
            }

            let safe_target = sanitize_prompt_label(target);
            let unlocked = unlock_vault_for_cli(
                vault_path,
                &cfg,
                bio_enabled,
                &format!(
                    "AI Agent (VaultPass CLI) meminta membaca field '{field}' dari API Key '{safe_target}'"
                ),
            )?;
            let entry = find_exact_api_key_entry(&unlocked.payload.entries, target)?;

            match field {
                "password" | "key" => println!("{}", entry.password),
                "username" => println!("{}", entry.username),
                "url" => println!("{}", entry.url),
                "notes" => println!("{}", entry.notes),
                "env" => {
                    let env_name = default_env_name(&entry.title, &entry.env_var_name)?;
                    println!("{}={}", env_name, entry.password);
                }
                "json" => println!(
                    "{}",
                    serde_json::to_string_pretty(entry).map_err(|e| e.to_string())?
                ),
                _ => unreachable!(),
            }
            Ok(0)
        }
        "run" => {
            let sep_pos = args.iter().position(|a| a == "--").ok_or_else(|| {
                "Pisahkan perintah yang ingin dijalankan dengan '--', contoh: vaultpass-cli run --key OpenAI -- python app.py"
                    .to_string()
            })?;

            let cli_flags = &args[1..sep_pos];
            let cmd_parts = &args[sep_pos + 1..];
            if cmd_parts.is_empty() {
                return Err("Perintah setelah '--' tidak boleh kosong.".to_string());
            }

            let target = cli_flags
                .windows(2)
                .find(|w| w[0] == "--key" || w[0] == "-k")
                .map(|w| w[1].clone())
                .ok_or_else(|| {
                    "Gunakan: vaultpass-cli run --key <nama-atau-id> [--env <NAMA_ENV>] -- <perintah>"
                        .to_string()
                })?;

            let custom_env = cli_flags
                .windows(2)
                .find(|w| w[0] == "--env" || w[0] == "-e")
                .map(|w| validate_env_var_name(&w[1]))
                .transpose()?
                .filter(|v| !v.is_empty());

            let safe_cmd = sanitize_prompt_label(&cmd_parts[0]);
            let safe_target = sanitize_prompt_label(&target);
            let (env_var, secret_value) = {
                let unlocked = unlock_vault_for_cli(
                    vault_path,
                    &cfg,
                    bio_enabled,
                    &format!(
                        "AI Agent ingin menjalankan '{safe_cmd}' dengan menyuntikkan API Key '{safe_target}'"
                    ),
                )?;
                let entry = find_exact_api_key_entry(&unlocked.payload.entries, &target)?;

                let resolved_env = match custom_env {
                    Some(explicit) => explicit,
                    None => default_env_name(&entry.title, &entry.env_var_name)?,
                };
                let secret = Zeroizing::new(entry.password.clone());
                // `unlocked` drops at the end of this block, wiping the master key and all
                // other vault entries from RAM before the child process is spawned.
                (resolved_env, secret)
            };

            let status = Command::new(&cmd_parts[0])
                .args(&cmd_parts[1..])
                .env(&env_var, secret_value.as_str())
                .status()
                .map_err(|e| format!("Gagal menjalankan perintah '{}': {e}", cmd_parts[0]))?;

            drop(secret_value);
            let code = status
                .code()
                .and_then(|c| u8::try_from(c).ok())
                .unwrap_or(if status.success() { 0 } else { 1 });
            Ok(code)
        }
        other => Err(format!(
            "Perintah '{}' tidak dikenali. Jalankan 'vaultpass-cli --help'.",
            sanitize_prompt_label(other)
        )),
    }
}

fn main() -> ExitCode {
    match run_cli() {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("Error: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(id: &str, title: &str, category: &str, env_var: &str) -> VaultEntry {
        VaultEntry {
            id: id.to_string(),
            title: title.to_string(),
            username: "user".to_string(),
            password: format!("secret-{id}"),
            url: "".to_string(),
            category: category.to_string(),
            env_var_name: env_var.to_string(),
            notes: "".to_string(),
            favorite: false,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn cli_lookup_isolates_api_keys_and_requires_exact_match() {
        let entries = vec![
            sample_entry("1", "GitHub Personal", "Login", ""),
            sample_entry("2", "BCA Prioritas", "Finance", ""),
            sample_entry("3", "GitHub Deploy Token", "API Key", "GITHUB_TOKEN"),
        ];

        assert!(find_exact_api_key_entry(&entries, "GitHub Personal").is_err());
        assert!(find_exact_api_key_entry(&entries, "BCA Prioritas").is_err());
        assert!(find_exact_api_key_entry(&entries, "GitHub").is_err());

        let by_title = find_exact_api_key_entry(&entries, "github deploy token").unwrap();
        assert_eq!(by_title.id, "3");

        let by_env = find_exact_api_key_entry(&entries, "GITHUB_TOKEN").unwrap();
        assert_eq!(by_env.id, "3");

        let by_id = find_exact_api_key_entry(&entries, "3").unwrap();
        assert_eq!(by_id.title, "GitHub Deploy Token");
    }

    #[test]
    fn cli_lookup_rejects_ambiguous_duplicate_api_key_titles() {
        let entries = vec![
            sample_entry("id-a", "OpenAI", "API Key", "OPENAI_API_KEY"),
            sample_entry("id-b", "OpenAI", "API Key", "OPENAI_STAGING_KEY"),
        ];

        let err = find_exact_api_key_entry(&entries, "OpenAI").unwrap_err();
        assert!(err.contains("id-a"));
        assert!(err.contains("id-b"));
        assert_eq!(
            find_exact_api_key_entry(&entries, "id-b").unwrap().id,
            "id-b"
        );
    }

    #[test]
    fn default_env_name_normalizes_and_rejects_reserved_vars() {
        assert_eq!(
            default_env_name("OpenAI Prod", "").unwrap(),
            "OPENAI_PROD_API_KEY"
        );
        assert_eq!(
            default_env_name("123 Service", "").unwrap(),
            "KEY_123_SERVICE_API_KEY"
        );
        assert!(default_env_name("OpenAI", "PATH").is_err());
        assert!(default_env_name("OpenAI", "BAD;CMD").is_err());
    }
}
