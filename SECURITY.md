# Kebijakan Keamanan

VaultPass menyimpan data sensitif, jadi laporan keamanan sangat kami hargai.

## Versi yang didukung

Proyek ini masih pre-release. Perbaikan keamanan hanya diberikan untuk versi terbaru di branch `main`.

## Cara melapor kerentanan

**Jangan membuka issue atau pull request publik** untuk kerentanan.

Gunakan fitur pelaporan privat GitHub:

1. Buka tab **Security** di repo ini.
2. Pilih **Report a vulnerability**.
3. Jelaskan temuanmu.

Sertakan, jika memungkinkan:

- Deskripsi masalah dan dampaknya
- Langkah untuk mengulang atau contoh kode
- Versi atau commit yang terdampak
- Saran perbaikan (opsional)

**Jangan melampirkan** file vault asli, master password, atau API key milikmu. Buat vault uji baru untuk membuktikan masalahnya.

Saya akan berusaha menanggapi laporan dalam beberapa hari dan memberi kabar perkembangannya. Ini proyek pribadi, jadi waktu respons bisa bervariasi.

## Cakupan

Yang termasuk cakupan:

- Kriptografi dan derivasi kunci (`src-tauri/src/crypto.rs`)
- Penyimpanan, pemuatan, backup, dan impor vault (`src-tauri/src/vault.rs`)
- Integrasi Windows Hello dan DPAPI (`src-tauri/src/biometric.rs`)
- CLI untuk AI Agent (`vaultpass-cli`)
- Kebocoran rahasia lewat clipboard, log, atau UI

Di luar cakupan:

- Serangan yang membutuhkan malware atau eksekusi kode berbahaya di dalam sesi akun pengguna Windows yang sama (ketika Windows Hello aktif pada aplikasi Win32 *unpackaged*, DPAPI dan Credential Manager memiliki batas kepercayaan yang sama dengan akun pengguna Windows tersebut; `vaultpass-cli` menjaga agar secret tidak terekspos di log chat/terminal dan memerlukan persetujuan interaktif, bukan menggantikan sandbox OS)
- Kehilangan master password. Master password tidak disimpan dan tidak bisa dipulihkan
- Kerentanan di dependensi pihak ketiga yang belum ada perbaikannya. Laporkan ke proyek aslinya

## Model keamanan singkat

Detail teknis ada di bagian "Cara kerja keamanan" pada [README](README.md). Aplikasi ini belum diaudit oleh pihak ketiga. Pertimbangkan hal itu sebelum menyimpan data yang sangat penting.
