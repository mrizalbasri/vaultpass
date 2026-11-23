use std::env;
use std::process::{self, Command};

use serde::Serialize;
use vaultpass_lib::biometric::{
    dpapi_unprotect_key, is_windows_hello_available, request_windows_hello_verification,
};
use vaultpass_lib::load_or_init_config;
use vaultpass_lib::vault::open_vault_with_key;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CliStatus {
    vault_path: String,
    exists: bool,
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
        "VaultPass CLI (AI Agent & Secret Key Integration)\n\
         Penggunaan:\n  \
           vaultpass-cli status\n  \
           vaultpass-cli list [--query <kata-kunci>]\n  \
           vaultpass-cli get <nama-akun-atau-id> [--field password|username|url|env|notes|json]\n  \
           vaultpass-cli run --key <nama-akun-atau-id> [--env <NAMA_ENV>] -- <perintah> [argumen...]\n\n\
         Contoh untuk AI Agent (Validasi / Pakai API Key tanpa bocor di log chat):\n  \
           vaultpass-cli get \"OpenAI\" --field password\n  \
           vaultpass-cli run --key \"OpenAI\" --env OPENAI_API_KEY -- python test_api.py"
    );
}

fn default_env_name(title: &str, custom_env: &str) -> String {
    if !custom_env.trim().is_empty() {
        return custom_env.trim().to_string();
    }
    let sanitized: String = title
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = sanitized.trim_matches('_');
    if trimmed.is_empty() {
        "VAULTPASS_SECRET".to_string()
    } else {
        format!("{trimmed}_KEY")
    }
}

fn run_cli() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        print_usage();
        return Ok(());
    }

    let (_config_path, cfg) = load_or_init_config()?;
    let vault_path = &cfg.vault_path;
    let bio_enabled = cfg.is_biometric_enabled_for(vault_path);

    match args[0].as_str() {
        "status" => {
            let status = CliStatus {
                vault_path: vault_path.to_string_lossy().to_string(),
                exists: vault_path.exists(),
                biometric_enabled: bio_enabled,
                windows_hello_available: is_windows_hello_available(),
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&status).map_err(|e| e.to_string())?
            );
            Ok(())
        }
        "list" => {
            if !bio_enabled {
                return Err(
                    "Akses Windows Hello & AI Agent belum diaktifkan. Buka aplikasi VaultPass -> Pengaturan & Backup -> Aktifkan Windows Hello."
                        .to_string(),
                );
            }
            let query = args
                .windows(2)
                .find(|w| w[0] == "--query" || w[0] == "-q")
                .map(|w| w[1].to_lowercase());

            request_windows_hello_verification(
                "AI Agent (VaultPass CLI) meminta izin melihat daftar akun/key di VaultPass",
            )?;

            let dpapi_b64 = cfg
                .biometric_key_dpapi_b64
                .as_ref()
                .ok_or_else(|| "Kunci biometrik tidak ditemukan.".to_string())?;
            let key = dpapi_unprotect_key(dpapi_b64)?;
            let unlocked = open_vault_with_key(vault_path, key)?;

            let list: Vec<CliAccountSummary<'_>> = unlocked
                .payload
                .entries
                .iter()
                .filter(|item| {
                    if let Some(ref q) = query {
                        item.title.to_lowercase().contains(q)
                            || item.username.to_lowercase().contains(q)
                            || item.url.to_lowercase().contains(q)
                            || item.category.to_lowercase().contains(q)
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
            Ok(())
        }
        "get" => {
            if args.len() < 2 {
                return Err("Masukkan nama akun/key atau ID: vaultpass-cli get <nama-akun>".to_string());
            }
            if !bio_enabled {
                return Err(
                    "Akses Windows Hello & AI Agent belum diaktifkan. Buka aplikasi VaultPass -> Pengaturan & Backup -> Aktifkan Windows Hello."
                        .to_string(),
                );
            }

            let target = &args[1];
            let field = args
                .windows(2)
                .find(|w| w[0] == "--field" || w[0] == "-f")
                .map(|w| w[1].as_str())
                .unwrap_or("json");

            request_windows_hello_verification(&format!(
                "AI Agent (VaultPass CLI) meminta membaca key/kredensial: {}",
                target
            ))?;

            let dpapi_b64 = cfg
                .biometric_key_dpapi_b64
                .as_ref()
                .ok_or_else(|| "Kunci biometrik tidak ditemukan.".to_string())?;
            let key = dpapi_unprotect_key(dpapi_b64)?;
            let unlocked = open_vault_with_key(vault_path, key)?;

            let target_lower = target.to_lowercase();
            let entry = unlocked
                .payload
                .entries
                .iter()
                .find(|item| {
                    item.id == *target
                        || item.title.to_lowercase() == target_lower
                        || (!item.env_var_name.is_empty()
                            && item.env_var_name.to_lowercase() == target_lower)
                })
                .or_else(|| {
                    unlocked
                        .payload
                        .entries
                        .iter()
                        .find(|item| item.title.to_lowercase().contains(&target_lower))
                })
                .ok_or_else(|| format!("Akun atau Key '{target}' tidak ditemukan di dalam vault."))?;

            match field {
                "password" | "key" => println!("{}", entry.password),
                "username" => println!("{}", entry.username),
                "url" => println!("{}", entry.url),
                "notes" => println!("{}", entry.notes),
                "env" => {
                    let env_name = default_env_name(&entry.title, &entry.env_var_name);
                    println!("{}={}", env_name, entry.password);
                }
                "json" => println!(
                    "{}",
                    serde_json::to_string_pretty(entry).map_err(|e| e.to_string())?
                ),
                other => {
                    return Err(format!(
                        "Field '{other}' tidak dikenali. Gunakan: password, key, username, url, env, notes, atau json."
                    ));
                }
            }
            Ok(())
        }
        "run" => {
            if !bio_enabled {
                return Err(
                    "Akses Windows Hello & AI Agent belum diaktifkan. Buka aplikasi VaultPass -> Pengaturan & Backup -> Aktifkan Windows Hello."
                        .to_string(),
                );
            }

            let target = args
                .windows(2)
                .find(|w| w[0] == "--key" || w[0] == "-k")
                .map(|w| w[1].clone())
                .ok_or_else(|| {
                    "Gunakan: vaultpass-cli run --key <nama-key> [--env <NAMA_ENV>] -- <perintah>"
                        .to_string()
                })?;

            let custom_env = args
                .windows(2)
                .find(|w| w[0] == "--env" || w[0] == "-e")
                .map(|w| w[1].clone());

            let sep_pos = args.iter().position(|a| a == "--").ok_or_else(|| {
                "Pisahkan perintah yang ingin dijalankan dengan '--', contoh: vaultpass-cli run --key OpenAI -- python app.py"
                    .to_string()
            })?;

            let cmd_parts = &args[sep_pos + 1..];
            if cmd_parts.is_empty() {
                return Err("Perintah setelah '--' tidak boleh kosong.".to_string());
            }

            request_windows_hello_verification(&format!(
                "AI Agent ingin menjalankan '{}' menggunakan Secret Key '{}' dari VaultPass",
                cmd_parts[0], target
            ))?;

            let dpapi_b64 = cfg
                .biometric_key_dpapi_b64
                .as_ref()
                .ok_or_else(|| "Kunci biometrik tidak ditemukan.".to_string())?;
            let key = dpapi_unprotect_key(dpapi_b64)?;
            let unlocked = open_vault_with_key(vault_path, key)?;

            let target_lower = target.to_lowercase();
            let entry = unlocked
                .payload
                .entries
                .iter()
                .find(|item| {
                    item.id == target
                        || item.title.to_lowercase() == target_lower
                        || (!item.env_var_name.is_empty()
                            && item.env_var_name.to_lowercase() == target_lower)
                })
                .or_else(|| {
                    unlocked
                        .payload
                        .entries
                        .iter()
                        .find(|item| item.title.to_lowercase().contains(&target_lower))
                })
                .ok_or_else(|| format!("Key '{target}' tidak ditemukan di dalam vault."))?;

            let env_var = custom_env
                .unwrap_or_else(|| default_env_name(&entry.title, &entry.env_var_name));

            let status = Command::new(&cmd_parts[0])
                .args(&cmd_parts[1..])
                .env(&env_var, &entry.password)
                .status()
                .map_err(|e| format!("Gagal menjalankan perintah '{}': {e}", cmd_parts[0]))?;

            process::exit(status.code().unwrap_or(1));
        }
        other => Err(format!(
            "Perintah '{other}' tidak dikenali. Jalankan 'vaultpass-cli --help'."
        )),
    }
}

fn main() {
    if let Err(err) = run_cli() {
        eprintln!("Error: {err}");
        process::exit(1);
    }
}
