import { useEffect, useState } from "react";
import {
  Bot,
  Download,
  Fingerprint,
  FolderOpen,
  FolderPlus,
  KeyRound,
  Lightbulb,
  Shield,
  Upload,
  X,
} from "lucide-react";
import { vaultApi } from "../api";
import type { VaultStatus } from "../types";
import { useEscapeKey } from "../utils/useEscapeKey";

interface SettingsModalProps {
  open: boolean;
  status: VaultStatus;
  onClose: () => void;
  onStatusChange: (nextStatus: VaultStatus) => void;
  onEntriesImported: () => Promise<void>;
}

export function SettingsModal({
  open,
  status,
  onClose,
  onStatusChange,
  onEntriesImported,
}: SettingsModalProps) {
  const [autoLockMinutes, setAutoLockMinutes] = useState(status.autoLockMinutes);
  const [clipboardClearSeconds, setClipboardClearSeconds] = useState(
    status.clipboardClearSeconds
  );
  const [passwordHintInput, setPasswordHintInput] = useState(status.passwordHint ?? "");

  const [currentPw, setCurrentPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [confirmPw, setConfirmPw] = useState("");
  const [backupPw, setBackupPw] = useState("");

  const [message, setMessage] = useState<{ type: "ok" | "err"; text: string } | null>(
    null
  );
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (open) {
      setAutoLockMinutes(status.autoLockMinutes);
      setClipboardClearSeconds(status.clipboardClearSeconds);
      setPasswordHintInput(status.passwordHint ?? "");
      setMessage(null);
      setCurrentPw("");
      setNewPw("");
      setConfirmPw("");
      setBackupPw("");
    }
  }, [open, status]);

  useEscapeKey(open, onClose);

  if (!open) return null;

  async function handleSaveHint(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMessage(null);
    try {
      const updated = await vaultApi.updatePasswordHint(passwordHintInput);
      onStatusChange(updated);
      setMessage({
        type: "ok",
        text: updated.passwordHint
          ? "Pengingat Master Password berhasil disimpan."
          : "Pengingat Master Password dihapus.",
      });
    } catch (err) {
      setMessage({
        type: "err",
        text: typeof err === "string" ? err : "Gagal menyimpan pengingat.",
      });
    } finally {
      setBusy(false);
    }
  }

  async function handleToggleBiometric() {
    setBusy(true);
    setMessage(null);
    try {
      if (status.biometricEnabled) {
        const next = await vaultApi.disableBiometricUnlock();
        onStatusChange(next);
        setMessage({
          type: "ok",
          text: "Windows Hello & akses AI Agent CLI dinonaktifkan.",
        });
      } else {
        const next = await vaultApi.enableBiometricUnlock();
        onStatusChange(next);
        setMessage({
          type: "ok",
          text: "Windows Hello (Sidik Jari / PIN) & AI Agent CLI berhasil diaktifkan!",
        });
      }
    } catch (err) {
      setMessage({
        type: "err",
        text: typeof err === "string" ? err : "Gagal mengubah pengaturan Windows Hello.",
      });
    } finally {
      setBusy(false);
    }
  }

  async function handleSaveTimers(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMessage(null);
    try {
      const updated = await vaultApi.updateSettings(
        autoLockMinutes,
        clipboardClearSeconds
      );
      onStatusChange(updated);
      setMessage({ type: "ok", text: "Pengaturan keamanan disimpan." });
    } catch (err) {
      setMessage({
        type: "err",
        text: typeof err === "string" ? err : "Gagal menyimpan pengaturan.",
      });
    } finally {
      setBusy(false);
    }
  }

  async function handleChangeMasterPassword(e: React.FormEvent) {
    e.preventDefault();
    setMessage(null);
    if (newPw.length < 10) {
      setMessage({ type: "err", text: "Master password baru minimal 10 karakter." });
      return;
    }
    if (newPw !== confirmPw) {
      setMessage({ type: "err", text: "Konfirmasi password baru tidak cocok." });
      return;
    }
    setBusy(true);
    try {
      await vaultApi.changeMasterPassword(currentPw, newPw);
      setCurrentPw("");
      setNewPw("");
      setConfirmPw("");
      setMessage({
        type: "ok",
        text: "Master password berhasil diganti & vault dienkripsi ulang.",
      });
    } catch (err) {
      setMessage({
        type: "err",
        text: typeof err === "string" ? err : "Gagal mengganti master password.",
      });
    } finally {
      setBusy(false);
    }
  }

  async function handleExportBackup() {
    setBusy(true);
    setMessage(null);
    try {
      const savedPath = await vaultApi.exportEncryptedBackup();
      if (savedPath) {
        setMessage({
          type: "ok",
          text: `Backup terenkripsi disimpan ke: ${savedPath}`,
        });
      }
    } catch (err) {
      setMessage({
        type: "err",
        text: typeof err === "string" ? err : "Gagal mengekspor backup.",
      });
    } finally {
      setBusy(false);
    }
  }

  async function handleImportBackup(e: React.FormEvent) {
    e.preventDefault();
    if (!backupPw) {
      setMessage({
        type: "err",
        text: "Masukkan master password dari file backup yang ingin diimpor.",
      });
      return;
    }
    setBusy(true);
    setMessage(null);
    try {
      const count = await vaultApi.importEncryptedBackup(backupPw);
      if (count > 0) {
        await onEntriesImported();
        setBackupPw("");
        setMessage({
          type: "ok",
          text: `Berhasil mengimpor ${count} akun dari backup terenkripsi.`,
        });
      } else {
        setMessage({
          type: "ok",
          text: "Tidak ada akun baru untuk diimpor (atau dialog dibatalkan).",
        });
      }
    } catch (err) {
      setMessage({
        type: "err",
        text: typeof err === "string" ? err : "Gagal mengimpor backup.",
      });
    } finally {
      setBusy(false);
    }
  }

  async function handleMoveVaultLocation() {
    setBusy(true);
    setMessage(null);
    try {
      const next = await vaultApi.pickVaultSaveLocation();
      if (next) {
        onStatusChange(next);
        setMessage({
          type: "ok",
          text: `Lokasi penyimpanan vault berhasil dipindahkan ke: ${next.vaultPath}`,
        });
      }
    } catch (err) {
      setMessage({
        type: "err",
        text: typeof err === "string" ? err : "Gagal memindahkan lokasi vault.",
      });
    } finally {
      setBusy(false);
    }
  }

  async function handleSwitchExistingVault() {
    setBusy(true);
    setMessage(null);
    try {
      const next = await vaultApi.pickExistingVaultFile();
      if (next) {
        onStatusChange(next);
        onClose();
      }
    } catch (err) {
      setMessage({
        type: "err",
        text: typeof err === "string" ? err : "Gagal mengganti file vault.",
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/70 p-4 backdrop-blur-xs animate-fade-in">
      <div className="max-h-[90vh] w-full max-w-xl overflow-x-hidden overflow-y-auto overscroll-none rounded-2xl border border-ink-700 bg-ink-900 p-6 shadow-pop animate-pop-in">
        <div className="mb-5 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-honey" />
            <h2 className="font-display text-lg font-semibold text-cream">
              Pengaturan & Keamanan
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-1.5 text-mute hover:bg-ink-700 hover:text-cream"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {message && (
          <div
            className={`mb-4 rounded-xl border px-3.5 py-2.5 text-xs ${
              message.type === "ok"
                ? "border-sage/30 bg-sage/10 text-sage"
                : "border-coral/30 bg-coral/10 text-coral"
            }`}
          >
            {message.text}
          </div>
        )}

        <div className="space-y-6">
          {/* Windows Hello Biometrics & AI Agent CLI Access */}
          <div className="rounded-xl border border-sage/25 bg-sage/5 p-4">
            <div className="mb-2 flex items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <Fingerprint className="h-4 w-4 text-sage" />
                <h3 className="text-xs font-semibold tracking-wider text-sage uppercase">
                  Sidik Jari (Windows Hello) & Akses AI Agent
                </h3>
              </div>
              <span
                className={`rounded-full px-2 py-0.5 text-[10px] font-medium ${
                  status.biometricEnabled
                    ? "bg-sage/20 text-sage"
                    : "bg-ink-700 text-mute"
                }`}
              >
                {status.biometricEnabled ? "Aktif" : "Nonaktif"}
              </span>
            </div>
            <p className="mb-3 text-xs text-cream-soft/90">
              <code>vaultpass-cli</code> hanya mengizinkan akses ke item berkategori{" "}
              <strong>API Key</strong> dengan pencocokan nama/ID persis. Jika{" "}
              <strong>Windows Hello</strong> diaktifkan, persetujuan cukup memakai Sidik Jari/PIN;
              jika belum aktif, CLI otomatis memunculkan dialog{" "}
              <strong>Windows Security (Master Password)</strong> tanpa mengetik password di chat.
            </p>
            {!status.windowsHelloAvailable && !status.biometricEnabled && (
              <p className="mb-3 rounded-lg border border-sky/25 bg-sky/10 px-3 py-2 text-xs text-sky">
                Windows Hello belum aktif di Windows kamu — <code>vaultpass-cli</code> tetap langsung
                bisa dipakai menggunakan dialog Master Password Windows Security. Aktifkan PIN/Sidik
                Jari di Pengaturan Windows jika ingin buka 1-sentuh.
              </p>
            )}
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                disabled={busy || (!status.windowsHelloAvailable && !status.biometricEnabled)}
                onClick={() => void handleToggleBiometric()}
                className={`inline-flex items-center gap-2 rounded-xl px-3.5 py-2 text-xs font-medium transition disabled:cursor-not-allowed disabled:opacity-50 ${
                  status.biometricEnabled
                    ? "border border-coral/40 bg-coral/10 text-coral hover:bg-coral/20"
                    : "bg-honey text-ink-950 hover:bg-[#f2c466]"
                }`}
              >
                <Fingerprint className="h-4 w-4" />
                {status.biometricEnabled
                  ? "Nonaktifkan Windows Hello & AI CLI"
                  : "Aktifkan Sidik Jari / Windows Hello & AI CLI"}
              </button>
            </div>

            <div className="mt-3 rounded-lg border border-ink-700 bg-ink-950/90 p-3">
              <div className="mb-1 flex items-center gap-1.5 text-[11px] font-medium text-cream-soft">
                <Bot className="h-3.5 w-3.5 text-honey" />
                Perintah CLI untuk AI Agent (Khusus Kategori API Key):
              </div>
              <pre className="overflow-x-auto font-mono text-[11px] leading-relaxed text-mute">
                {`vaultpass-cli.exe run --key 'OpenAI' --env 'OPENAI_API_KEY' -- python script.py\nvaultpass-cli.exe get 'OpenAI' --field key`}
              </pre>
            </div>
          </div>

          {/* Master Password Login Hint */}
          <form
            onSubmit={handleSaveHint}
            className="rounded-xl border border-ink-700 bg-ink-950/60 p-4"
          >
            <div className="mb-2 flex items-center gap-1.5">
              <Lightbulb className="h-4 w-4 text-honey" />
              <h3 className="text-xs font-semibold tracking-wider text-mute uppercase">
                Pengingat / Petunjuk Saat Login
              </h3>
            </div>
            <p className="mb-2.5 text-xs text-mute">
              Ditampilkan di layar login saat kamu klik <em>&ldquo;Lihat Pengingat&rdquo;</em> untuk
              membantu mengingat Master Password tanpa membocorkannya.
            </p>
            <div className="flex flex-col gap-2 sm:flex-row">
              <input
                type="text"
                value={passwordHintInput}
                onChange={(e) => setPasswordHintInput(e.target.value)}
                placeholder="Contoh: Nama kucing pertama + angka favorit..."
                className="flex-1 rounded-xl border border-ink-600 bg-ink-950 px-3 py-2 text-xs text-cream placeholder:text-faint outline-none focus:border-honey/70"
              />
              <button
                type="submit"
                disabled={busy}
                className="rounded-xl bg-ink-700 px-3.5 py-2 text-xs font-medium text-cream hover:bg-ink-600 disabled:opacity-50"
              >
                Simpan Pengingat
              </button>
            </div>
          </form>

          {/* Active Vault File Location */}
          <div className="rounded-xl border border-ink-700 bg-ink-950/60 p-4">
            <h3 className="mb-1.5 text-xs font-semibold tracking-wider text-mute uppercase">
              Lokasi Penyimpanan File Vault (.vpass)
            </h3>
            <p className="mb-2 text-xs text-mute">
              Kamu bebas mengatur tempat file vault utama disimpan (misal di folder khusus di
              Drive D, flashdisk, atau folder Google Drive/OneDrive).
            </p>
            <div className="rounded-lg border border-ink-700 bg-ink-850 px-3 py-2 font-mono text-xs break-all text-cream">
              {status.vaultPath}
            </div>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <button
                type="button"
                disabled={busy}
                onClick={() => void handleMoveVaultLocation()}
                className="inline-flex items-center gap-1.5 rounded-xl bg-honey px-3.5 py-2 text-xs font-semibold text-ink-950 hover:bg-[#f8c65a] disabled:opacity-50"
              >
                <FolderPlus className="h-3.5 w-3.5" />
                Pindahkan Lokasi Vault...
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={() => void handleSwitchExistingVault()}
                className="inline-flex items-center gap-1.5 rounded-xl border border-ink-600 bg-ink-850 px-3.5 py-2 text-xs font-medium text-cream hover:bg-ink-700 disabled:opacity-50"
              >
                <FolderOpen className="h-3.5 w-3.5 text-honey" />
                Buka File .vpass Lain...
              </button>
            </div>
          </div>

          {/* Auto-lock & clipboard timers */}
          <form
            onSubmit={handleSaveTimers}
            className="rounded-xl border border-ink-700 bg-ink-950/60 p-4"
          >
            <h3 className="mb-3 text-xs font-semibold tracking-wider text-mute uppercase">
              Otomatisasi Keamanan
            </h3>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div>
                <label className="mb-1 block text-xs text-cream-soft">
                  Auto-Lock Saat Idle
                </label>
                <select
                  value={autoLockMinutes}
                  onChange={(e) => setAutoLockMinutes(Number(e.target.value))}
                  className="w-full rounded-xl border border-ink-600 bg-ink-950 px-3 py-2 text-xs text-cream outline-none focus:border-honey/70"
                >
                  <option value={1}>1 Menit</option>
                  <option value={3}>3 Menit</option>
                  <option value={5}>5 Menit</option>
                  <option value={15}>15 Menit</option>
                  <option value={30}>30 Menit</option>
                  <option value={0}>Nonaktif</option>
                </select>
              </div>
              <div>
                <label className="mb-1 block text-xs text-cream-soft">
                  Hapus Clipboard Setelah Copy
                </label>
                <select
                  value={clipboardClearSeconds}
                  onChange={(e) => setClipboardClearSeconds(Number(e.target.value))}
                  className="w-full rounded-xl border border-ink-600 bg-ink-950 px-3 py-2 text-xs text-cream outline-none focus:border-honey/70"
                >
                  <option value={10}>10 Detik</option>
                  <option value={20}>20 Detik</option>
                  <option value={30}>30 Detik</option>
                  <option value={60}>60 Detik</option>
                  <option value={0}>Jangan Hapus</option>
                </select>
              </div>
            </div>
            <div className="mt-3 flex justify-end">
              <button
                type="submit"
                disabled={busy}
                className="rounded-xl bg-ink-700 px-3.5 py-1.5 text-xs font-medium text-cream hover:bg-ink-600 disabled:opacity-50"
              >
                Simpan Pengaturan
              </button>
            </div>
          </form>

          {/* Encrypted Backup & Restore */}
          <div className="rounded-xl border border-ink-700 bg-ink-950/60 p-4">
            <h3 className="mb-2 text-xs font-semibold tracking-wider text-mute uppercase">
              Backup & Restore Terenkripsi (.vpass)
            </h3>
            <p className="mb-3 text-xs text-mute">
              Buat salinan cadangan terpisah (tetap terenkripsi Argon2id + AES-256-GCM) atau
              gabungkan akun dari file backup lama.
            </p>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                disabled={busy}
                onClick={() => void handleExportBackup()}
                className="inline-flex items-center gap-1.5 rounded-xl bg-ink-700 px-3.5 py-2 text-xs font-medium text-cream hover:bg-ink-600 disabled:opacity-50"
              >
                <Download className="h-3.5 w-3.5" />
                Export Salinan Backup (.vpass)
              </button>
            </div>

            <form
              onSubmit={handleImportBackup}
              className="mt-3 flex flex-col gap-2 border-t border-ink-700/80 pt-3 sm:flex-row"
            >
              <input
                type="password"
                value={backupPw}
                onChange={(e) => setBackupPw(e.target.value)}
                placeholder="Master password file backup..."
                className="flex-1 rounded-xl border border-ink-600 bg-ink-950 px-3 py-1.5 text-xs text-cream placeholder:text-faint outline-none focus:border-honey/70"
              />
              <button
                type="submit"
                disabled={busy}
                className="inline-flex items-center justify-center gap-1.5 rounded-xl border border-ink-600 bg-ink-850 px-3.5 py-1.5 text-xs font-medium text-cream hover:bg-ink-700 disabled:opacity-50"
              >
                <Upload className="h-3.5 w-3.5" />
                Import & Gabung
              </button>
            </form>
          </div>

          {/* Change Master Password */}
          <form
            onSubmit={handleChangeMasterPassword}
            className="rounded-xl border border-ink-700 bg-ink-950/60 p-4"
          >
            <div className="mb-3 flex items-center gap-1.5">
              <KeyRound className="h-3.5 w-3.5 text-mute" />
              <h3 className="text-xs font-semibold tracking-wider text-mute uppercase">
                Ganti Master Password
              </h3>
            </div>
            <div className="space-y-2.5">
              <input
                type="password"
                value={currentPw}
                onChange={(e) => setCurrentPw(e.target.value)}
                placeholder="Master password saat ini"
                className="w-full rounded-xl border border-ink-600 bg-ink-950 px-3 py-2 text-xs text-cream placeholder:text-faint outline-none focus:border-honey/70"
              />
              <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
                <input
                  type="password"
                  value={newPw}
                  onChange={(e) => setNewPw(e.target.value)}
                  placeholder="Master password baru (min 10)"
                  className="w-full rounded-xl border border-ink-600 bg-ink-950 px-3 py-2 text-xs text-cream placeholder:text-faint outline-none focus:border-honey/70"
                />
                <input
                  type="password"
                  value={confirmPw}
                  onChange={(e) => setConfirmPw(e.target.value)}
                  placeholder="Konfirmasi password baru"
                  className="w-full rounded-xl border border-ink-600 bg-ink-950 px-3 py-2 text-xs text-cream placeholder:text-faint outline-none focus:border-honey/70"
                />
              </div>
              <div className="flex justify-end">
                <button
                  type="submit"
                  disabled={busy}
                  className="rounded-xl border border-honey/40 bg-honey/10 px-3.5 py-1.5 text-xs font-medium text-cream hover:bg-honey/20 disabled:opacity-50"
                >
                  Perbarui Master Password
                </button>
              </div>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}
