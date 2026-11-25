import type { EntryCategory } from "../types";

export interface ServicePreset {
  label: string;
  title: string;
  url?: string;
  envVarName?: string;
  usernamePlaceholder?: string;
  urlPlaceholder?: string;
  notesPlaceholder?: string;
}

export interface CategoryFormConfig {
  shortLabel: string;
  modalHeadingNew: string;
  subtitle: string;
  submitLabel: string;
  accentPillActive: string;
  accentDot: string;
  titleLabel: string;
  titlePlaceholder: string;
  usernameLabel: string;
  usernamePlaceholder: string;
  usernameMono?: boolean;
  secretLabel: string;
  secretPlaceholder: string;
  showEnvVar: boolean;
  showUrl: boolean;
  urlLabel: string;
  urlPlaceholder: string;
  notesLabel: string;
  notesPlaceholder: string;
  detailUsernameLabel: string;
  detailSecretLabel: string;
  detailCopySecretLabel: string;
  detailUrlLabel: string;
  presets: ServicePreset[];
}

export const CATEGORY_FORM_CONFIG: Record<EntryCategory, CategoryFormConfig> = {
  Login: {
    shortLabel: "Login",
    modalHeadingNew: "Tambah Akun Login",
    subtitle: "Form khusus akun website & aplikasi (Google, GitHub, Microsoft, dll.)",
    submitLabel: "Simpan Akun Login",
    accentPillActive: "border-honey/50 bg-honey/15 text-honey",
    accentDot: "bg-honey",
    titleLabel: "Nama Layanan / Aplikasi *",
    titlePlaceholder: "Contoh: Google, GitHub, Microsoft, Apple",
    usernameLabel: "Email / Username",
    usernamePlaceholder: "nama@gmail.com atau username akun",
    secretLabel: "Password Akun *",
    secretPlaceholder: "Masukkan atau generate password kuat...",
    showEnvVar: false,
    showUrl: true,
    urlLabel: "URL Halaman Login (Opsional)",
    urlPlaceholder: "https://accounts.google.com",
    notesLabel: "Email Pemulihan / Kode Backup 2FA (Opsional)",
    notesPlaceholder: "Email/HP pemulihan, 8-digit kode backup 2FA, atau catatan keamanan...",
    detailUsernameLabel: "Email / Username",
    detailSecretLabel: "Password",
    detailCopySecretLabel: "Salin Password",
    detailUrlLabel: "Website Login",
    presets: [
      {
        label: "Google",
        title: "Google",
        url: "https://accounts.google.com",
        usernamePlaceholder: "nama@gmail.com",
        notesPlaceholder: "Email pemulihan, nomor HP, atau kode backup 2FA Google...",
      },
      {
        label: "GitHub",
        title: "GitHub",
        url: "https://github.com/login",
        usernamePlaceholder: "username atau email GitHub",
        notesPlaceholder: "Recovery codes 2FA GitHub atau catatan SSH...",
      },
      {
        label: "Microsoft",
        title: "Microsoft",
        url: "https://login.live.com",
        usernamePlaceholder: "nama@outlook.com / email Microsoft",
      },
      {
        label: "Apple ID",
        title: "Apple ID",
        url: "https://appleid.apple.com",
        usernamePlaceholder: "email Apple ID",
      },
    ],
  },
  "API Key": {
    shortLabel: "API Key",
    modalHeadingNew: "Simpan API Key / Secret Token",
    subtitle: "Form khusus developer token & API key yang terintegrasi dengan AI Agent CLI",
    submitLabel: "Simpan API Key",
    accentPillActive: "border-sky/50 bg-sky/15 text-sky",
    accentDot: "bg-sky",
    titleLabel: "Nama Provider / Key *",
    titlePlaceholder: "Contoh: OpenAI Production, Google Gemini, Stripe",
    usernameLabel: "Account / Project / Org ID (Opsional)",
    usernamePlaceholder: "proj_... / org-... / email console",
    usernameMono: true,
    secretLabel: "Secret Key / API Token (Sekali-Tampil) *",
    secretPlaceholder: "sk-... / AIza... / ghp_... / secret token",
    showEnvVar: true,
    showUrl: true,
    urlLabel: "Base URL / Endpoint / Console (Opsional)",
    urlPlaceholder: "https://api.openai.com/v1",
    notesLabel: "Scope, Expired & Catatan AI Agent (Opsional)",
    notesPlaceholder: "Scope izin key, batas kuota, tanggal kedaluwarsa, atau instruksi penggunaan...",
    detailUsernameLabel: "Account / Project ID",
    detailSecretLabel: "Secret / API Key (tersimpan permanen)",
    detailCopySecretLabel: "Salin Key",
    detailUrlLabel: "API Endpoint / Console",
    presets: [
      {
        label: "OpenAI",
        title: "OpenAI",
        envVarName: "OPENAI_API_KEY",
        url: "https://platform.openai.com/api-keys",
      },
      {
        label: "Google Gemini",
        title: "Google Gemini",
        envVarName: "GEMINI_API_KEY",
        url: "https://aistudio.google.com/apikey",
      },
      {
        label: "Anthropic",
        title: "Anthropic",
        envVarName: "ANTHROPIC_API_KEY",
        url: "https://console.anthropic.com/settings/keys",
      },
      {
        label: "GitHub PAT",
        title: "GitHub PAT",
        envVarName: "GITHUB_TOKEN",
        url: "https://github.com/settings/tokens",
      },
      {
        label: "Stripe",
        title: "Stripe",
        envVarName: "STRIPE_SECRET_KEY",
        url: "https://dashboard.stripe.com/apikeys",
      },
      {
        label: "Supabase",
        title: "Supabase",
        envVarName: "SUPABASE_SERVICE_ROLE_KEY",
        url: "https://supabase.com/dashboard",
      },
    ],
  },
  Finance: {
    shortLabel: "Finance",
    modalHeadingNew: "Tambah Rekening / E-Wallet",
    subtitle: "Form khusus perbankan, mobile banking, e-wallet, kartu, & PIN transaksi",
    submitLabel: "Simpan Data Finansial",
    accentPillActive: "border-sage/50 bg-sage/15 text-sage",
    accentDot: "bg-sage",
    titleLabel: "Nama Bank / E-Wallet / Layanan *",
    titlePlaceholder: "Contoh: BCA Mobile, Livin' Mandiri, GoPay, Bibit",
    usernameLabel: "Nomor Rekening / No. Kartu / User ID",
    usernamePlaceholder: "Contoh: 1234567890 atau User ID M-Banking",
    usernameMono: true,
    secretLabel: "PIN / Password Transaksi *",
    secretPlaceholder: "Masukkan PIN 6 digit atau password akses...",
    showEnvVar: false,
    showUrl: false,
    urlLabel: "URL Internet Banking (Opsional)",
    urlPlaceholder: "https://klikbca.com",
    notesLabel: "Cabang, Kode Akses / M-PIN & Catatan (Opsional)",
    notesPlaceholder: "Cabang pembuka, masa berlaku kartu (MM/YY), kode akses, atau catatan limit...",
    detailUsernameLabel: "Nomor Rekening / User ID",
    detailSecretLabel: "PIN / Password Transaksi",
    detailCopySecretLabel: "Salin PIN / Password",
    detailUrlLabel: "Portal Perbankan",
    presets: [
      { label: "BCA", title: "BCA", usernamePlaceholder: "No. Rekening / Kode Akses BCA" },
      { label: "Mandiri", title: "Livin' Mandiri", usernamePlaceholder: "No. Rekening / User ID" },
      { label: "BRI", title: "BRImo", usernamePlaceholder: "No. Rekening / Username BRImo" },
      { label: "BNI", title: "wondr by BNI", usernamePlaceholder: "No. Rekening / User ID" },
      { label: "GoPay", title: "GoPay", usernamePlaceholder: "Nomor HP terdaftar (08...)" },
    ],
  },
  Work: {
    shortLabel: "Work",
    modalHeadingNew: "Tambah Akun Kerja / Kantor",
    subtitle: "Form khusus sistem kantor, portal SSO, server internal, & VPN kerja",
    submitLabel: "Simpan Akun Kerja",
    accentPillActive: "border-[#b6a4e8]/50 bg-[#b6a4e8]/15 text-[#b6a4e8]",
    accentDot: "bg-[#b6a4e8]",
    titleLabel: "Aplikasi / Sistem Kerja *",
    titlePlaceholder: "Contoh: Slack Kantor, Jira, VPN Kantor, GitLab Internal",
    usernameLabel: "Email Kerja / ID Karyawan",
    usernamePlaceholder: "nama@perusahaan.com atau NIK karyawan",
    secretLabel: "Password / Passcode Kerja *",
    secretPlaceholder: "Masukkan password SSO atau passcode...",
    showEnvVar: false,
    showUrl: true,
    urlLabel: "Portal SSO / Host / Alamat Server (Opsional)",
    urlPlaceholder: "https://sso.perusahaan.com atau host VPN",
    notesLabel: "Divisi, Kebijakan Rotasi & Catatan Akses (Opsional)",
    notesPlaceholder: "Tim/divisi, jadwal ganti password 90 hari, port VPN, atau instruksi IT...",
    detailUsernameLabel: "Email Kerja / ID Karyawan",
    detailSecretLabel: "Password / Passcode",
    detailCopySecretLabel: "Salin Password",
    detailUrlLabel: "Portal SSO / Host",
    presets: [
      { label: "Workspace", title: "Google Workspace Kantor", url: "https://mail.google.com" },
      { label: "Slack", title: "Slack Kantor", url: "https://slack.com/signin" },
      { label: "Jira", title: "Jira / Atlassian", url: "https://id.atlassian.com" },
      { label: "VPN Kantor", title: "VPN Kantor", urlPlaceholder: "vpn.perusahaan.com:443" },
    ],
  },
  Personal: {
    shortLabel: "Personal",
    modalHeadingNew: "Tambah Item Pribadi / Wi-Fi",
    subtitle: "Form khusus jaringan Wi-Fi rumah, layanan publik, & akses pribadi",
    submitLabel: "Simpan Item Pribadi",
    accentPillActive: "border-coral/50 bg-coral/15 text-coral",
    accentDot: "bg-coral",
    titleLabel: "Nama Akun / Perangkat / Layanan *",
    titlePlaceholder: "Contoh: Wi-Fi Rumah, IndiHome, BPJS, Kunci Router",
    usernameLabel: "ID / SSID Wi-Fi / Nomor Pelanggan",
    usernamePlaceholder: "Nama SSID Wi-Fi atau nomor identitas/pelanggan",
    secretLabel: "Password / Kode Rahasia *",
    secretPlaceholder: "Password Wi-Fi, PIN perangkat, atau kode akses...",
    showEnvVar: false,
    showUrl: false,
    urlLabel: "URL Layanan / Router (Opsional)",
    urlPlaceholder: "http://192.168.1.1",
    notesLabel: "Catatan Pribadi (Opsional)",
    notesPlaceholder: "Lokasi perangkat, nomor pelanggan tambahan, atau info keluarga...",
    detailUsernameLabel: "ID / SSID / Nomor",
    detailSecretLabel: "Password / Kode Rahasia",
    detailCopySecretLabel: "Salin Password",
    detailUrlLabel: "Tautan Layanan",
    presets: [
      {
        label: "Wi-Fi Rumah",
        title: "Wi-Fi Rumah",
        usernamePlaceholder: "Nama Wi-Fi (SSID)",
      },
      {
        label: "Router Admin",
        title: "Router Admin",
        url: "http://192.168.1.1",
        usernamePlaceholder: "admin",
      },
      {
        label: "BPJS / Publik",
        title: "Mobile JKN (BPJS)",
        usernamePlaceholder: "NIK / Nomor Kartu BPJS",
      },
    ],
  },
  Social: {
    shortLabel: "Social",
    modalHeadingNew: "Tambah Akun Media Sosial",
    subtitle: "Form khusus akun sosial media, komunitas, & informasi pemulihan handle",
    submitLabel: "Simpan Akun Sosial",
    accentPillActive: "border-[#e89fc4]/50 bg-[#e89fc4]/15 text-[#e89fc4]",
    accentDot: "bg-[#e89fc4]",
    titleLabel: "Nama Platform Sosial *",
    titlePlaceholder: "Contoh: Instagram, X / Twitter, Discord, TikTok, LinkedIn",
    usernameLabel: "Username / @Handle / Email",
    usernamePlaceholder: "@username atau email/no. HP terdaftar",
    secretLabel: "Password *",
    secretPlaceholder: "Masukkan atau generate password...",
    showEnvVar: false,
    showUrl: true,
    urlLabel: "Link Profil / Login (Opsional)",
    urlPlaceholder: "https://instagram.com/username",
    notesLabel: "No. HP Pemulihan & Backup Code 2FA (Opsional)",
    notesPlaceholder: "Nomor HP tertaut, email cadangan, atau backup code 2FA...",
    detailUsernameLabel: "Username / @Handle",
    detailSecretLabel: "Password",
    detailCopySecretLabel: "Salin Password",
    detailUrlLabel: "Profil / Platform",
    presets: [
      { label: "Instagram", title: "Instagram", url: "https://www.instagram.com" },
      { label: "X / Twitter", title: "X (Twitter)", url: "https://x.com" },
      { label: "Discord", title: "Discord", url: "https://discord.com/login" },
      { label: "TikTok", title: "TikTok", url: "https://www.tiktok.com" },
      { label: "LinkedIn", title: "LinkedIn", url: "https://www.linkedin.com" },
    ],
  },
  Other: {
    shortLabel: "Other (Default)",
    modalHeadingNew: "Tambah Item Baru (Default)",
    subtitle: "Form standar umum untuk menyimpan kredensial atau secret bebas lainnya",
    submitLabel: "Simpan Item",
    accentPillActive: "border-cream/40 bg-ink-700 text-cream",
    accentDot: "bg-mute",
    titleLabel: "Judul Item *",
    titlePlaceholder: "Contoh: Lisensi Software, Server Backup, Brankas Digital",
    usernameLabel: "Username / Identitas (Opsional)",
    usernamePlaceholder: "Username, email, atau kode identitas",
    secretLabel: "Password / Secret *",
    secretPlaceholder: "Masukkan password, lisensi, atau secret...",
    showEnvVar: false,
    showUrl: true,
    urlLabel: "URL / Tautan (Opsional)",
    urlPlaceholder: "https://...",
    notesLabel: "Catatan (Opsional)",
    notesPlaceholder: "Catatan tambahan untuk item ini...",
    detailUsernameLabel: "Username / Identitas",
    detailSecretLabel: "Password / Secret",
    detailCopySecretLabel: "Salin Secret",
    detailUrlLabel: "URL / Tautan",
    presets: [],
  },
};

export function resolveDynamicLoginHints(title: string): {
  usernameLabel?: string;
  usernamePlaceholder?: string;
  secretLabel?: string;
  suggestedUrl?: string;
  notesPlaceholder?: string;
} {
  const normalized = title.trim().toLowerCase();
  if (normalized === "google" || normalized === "gmail" || normalized.startsWith("google ")) {
    return {
      usernameLabel: "Alamat Email Google (Gmail)",
      usernamePlaceholder: "nama@gmail.com",
      secretLabel: "Password Akun Google *",
      suggestedUrl: "https://accounts.google.com",
      notesPlaceholder: "Email pemulihan, nomor HP pemulihan, atau 8-digit kode backup 2FA Google...",
    };
  }
  if (normalized === "github") {
    return {
      usernameLabel: "Username / Email GitHub",
      usernamePlaceholder: "username atau email GitHub",
      secretLabel: "Password Akun GitHub *",
      suggestedUrl: "https://github.com/login",
      notesPlaceholder: "Recovery codes 2FA GitHub atau catatan keamanan...",
    };
  }
  if (normalized === "microsoft" || normalized === "outlook") {
    return {
      usernameLabel: "Email Akun Microsoft",
      usernamePlaceholder: "nama@outlook.com / email Microsoft",
      secretLabel: "Password Akun Microsoft *",
      suggestedUrl: "https://login.live.com",
    };
  }
  if (normalized === "apple" || normalized === "apple id" || normalized === "icloud") {
    return {
      usernameLabel: "Email Apple ID",
      usernamePlaceholder: "nama@icloud.com / email Apple ID",
      secretLabel: "Password Apple ID *",
      suggestedUrl: "https://appleid.apple.com",
    };
  }
  return {};
}
