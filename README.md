# VaultPass — Personal Desktop Password Manager

Aplikasi desktop password manager offline pribadi yang dibangun dengan **Tauri v2**, **Rust**, **React**, dan **TypeScript**.

## Arsitektur Keamanan
- **Key Derivation:** Argon2id (`m = 64 MiB`, `t = 3`, `p = 4`, 16-byte random salt).
- **Enkripsi Vault:** AES-256-GCM (*Authenticated Encryption with Associated Data*) dengan 12-byte random nonce baru di setiap penyimpanan.
- **Perlindungan Memori:** `zeroize` untuk menghapus kunci dan payload dari RAM saat vault dikunci.
- **Atomic Save & Auto-Backup:** Menulis ke `.vpass.tmp`, sinkronisasi ke disk, membuat salinan `.vpass.bak`, baru mengganti file `vault.vpass` secara atomik.
- **Keamanan Harian:** Auto-lock saat idle, pembersihan clipboard otomatis, generator password berbasis OS CSPRNG, serta export/import backup terenkripsi (`.vpass`).

## Menjalankan di Mode Development
```bash
npm install
npm run tauri dev
```

## Build Installer / Executable
```bash
npm run tauri build
```
