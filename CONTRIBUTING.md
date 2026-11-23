# Berkontribusi ke VaultPass

Terima kasih sudah tertarik! VaultPass masih berstatus pre-release, jadi masukan, laporan bug, dan pull request sangat membantu.

Untuk **kerentanan keamanan**, jangan buka issue publik. Ikuti [SECURITY.md](SECURITY.md).

## Prasyarat

- Windows 10/11 dengan [WebView2](https://developer.microsoft.com/microsoft-edge/webview2/)
- [Node.js](https://nodejs.org) 22 atau lebih baru
- [Rust](https://rustup.rs) stable
- Prasyarat Tauri v2 untuk Windows (Microsoft C++ Build Tools)

> Backend memakai Windows DPAPI dan Windows Hello, jadi aplikasi dan tes Rust saat ini hanya berjalan di Windows.

## Menjalankan di lokal

```bash
git clone https://github.com/mrizalbasri/vaultpass.git
cd vaultpass
npm install
npm run tauri dev
```

## Sebelum membuka pull request

Jalankan semua pemeriksaan ini. CI menjalankan hal yang sama dan semuanya harus hijau.

```bash
# Frontend
npm run build

# Backend (jalankan dari folder src-tauri)
cd src-tauri
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --lib
```

Gunakan `cargo fmt` untuk merapikan format secara otomatis.

## Alur kerja

1. Fork repo ini lalu buat branch dari `main`, misalnya `feat/nama-fitur` atau `fix/nama-bug`.
2. Buat perubahan yang kecil dan fokus. Satu PR sebaiknya mengerjakan satu hal.
3. Tambahkan tes bila mengubah logika di `crypto.rs`, `vault.rs`, atau `biometric.rs`.
4. Buka pull request ke `main` dan isi template PR.

## Format commit

Proyek ini memakai [Conventional Commits](https://www.conventionalcommits.org/):

```text
feat(ui): tambah indikator sesi
fix(vault): tolak file backup yang rusak
docs: perbarui README
chore(deps): naikkan versi argon2
```

## Panduan penting

- **Jangan pernah** menyertakan file `.vpass`, master password, API key, atau token di commit, issue, atau screenshot.
- Perubahan di kode kriptografi dan penanganan vault akan ditinjau lebih ketat. Jelaskan alasan dan dampaknya di deskripsi PR.
- Ikuti gaya kode yang ada. Frontend memakai design token di `src/index.css`, bukan warna yang ditulis langsung di komponen.
- Teks antarmuka memakai Bahasa Indonesia.

## Melapor bug atau mengusulkan fitur

Buka [issue baru](https://github.com/mrizalbasri/vaultpass/issues/new/choose) dan pilih templat yang sesuai. Cantumkan langkah mengulang, perilaku yang diharapkan, dan versi Windows kamu.

Dengan berkontribusi, kamu setuju kontribusimu dilisensikan di bawah [MIT](LICENSE) dan mengikuti [Kode Etik](CODE_OF_CONDUCT.md).
