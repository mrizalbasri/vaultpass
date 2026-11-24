import { useEffect, useState } from "react";
import { Eye, EyeOff, Star, Terminal, Wand2, X } from "lucide-react";
import { vaultApi } from "../api";
import {
  ENTRY_CATEGORIES,
  type EntryCategory,
  type VaultEntry,
  type VaultEntryInput,
} from "../types";
import { evaluatePasswordStrength } from "../utils/passwordStrength";
import { useEscapeKey } from "../utils/useEscapeKey";

interface EntryFormModalProps {
  open: boolean;
  initialEntry: VaultEntry | null;
  defaultCategory?: EntryCategory;
  onClose: () => void;
  onSave: (input: VaultEntryInput) => Promise<void>;
}

const ENV_VAR_PATTERN = /^[A-Z_][A-Z0-9_]*$/;

function suggestEnvVarName(title: string): string {
  const cleaned = title
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
  if (!cleaned) return "";
  const prefixed = /^[0-9]/.test(cleaned) ? `KEY_${cleaned}` : cleaned;
  if (
    prefixed.endsWith("_KEY") ||
    prefixed.endsWith("_TOKEN") ||
    prefixed.endsWith("_SECRET")
  ) {
    return prefixed;
  }
  return `${prefixed}_API_KEY`;
}

export function EntryFormModal({
  open,
  initialEntry,
  defaultCategory = "Login",
  onClose,
  onSave,
}: EntryFormModalProps) {
  const [title, setTitle] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [url, setUrl] = useState("");
  const [category, setCategory] = useState<EntryCategory>(defaultCategory);
  const [envVarName, setEnvVarName] = useState("");
  const [notes, setNotes] = useState("");
  const [favorite, setFavorite] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [loadingSecret, setLoadingSecret] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) {
      setPassword("");
      setShowPassword(false);
      setLoadingSecret(false);
      return;
    }

    let cancelled = false;
    setShowPassword(false);
    setError(null);

    if (initialEntry) {
      setTitle(initialEntry.title);
      setUsername(initialEntry.username);
      setPassword("");
      setUrl(initialEntry.url);
      setCategory(initialEntry.category);
      setEnvVarName(initialEntry.envVarName || "");
      setNotes(initialEntry.notes);
      setFavorite(initialEntry.favorite);
      setLoadingSecret(true);
      void vaultApi
        .revealEntrySecret(initialEntry.id)
        .then((secret) => {
          if (!cancelled) {
            setPassword(secret);
          }
        })
        .catch((err) => {
          if (!cancelled) {
            setError(
              typeof err === "string" ? err : "Gagal memuat password/secret item."
            );
          }
        })
        .finally(() => {
          if (!cancelled) {
            setLoadingSecret(false);
          }
        });
    } else {
      setTitle("");
      setUsername("");
      setPassword("");
      setUrl("");
      setCategory(defaultCategory);
      setEnvVarName("");
      setNotes("");
      setFavorite(false);
      setLoadingSecret(false);
    }

    return () => {
      cancelled = true;
    };
  }, [open, initialEntry, defaultCategory]);

  useEscapeKey(open, onClose);

  if (!open) return null;

  const isApiKey = category === "API Key";
  const strength = evaluatePasswordStrength(password);

  async function handleQuickGenerate() {
    try {
      const pw = await vaultApi.generatePassword({
        length: 24,
        uppercase: true,
        lowercase: true,
        numbers: true,
        symbols: !isApiKey,
        excludeAmbiguous: true,
      });
      setPassword(pw);
      setShowPassword(true);
    } catch {
      // Ignore transient error
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (!title.trim()) {
      setError("Judul akun / nama key wajib diisi (contoh: OpenAI, GitHub, BCA).");
      return;
    }
    if (!password) {
      setError(isApiKey ? "Secret / API Key tidak boleh kosong." : "Password tidak boleh kosong.");
      return;
    }

    const finalEnvVar =
      envVarName.trim() || (isApiKey ? suggestEnvVarName(title) : "");
    if (finalEnvVar && !ENV_VAR_PATTERN.test(finalEnvVar)) {
      setError(
        "Nama Env Variable hanya boleh berisi huruf A-Z, angka 0-9, dan underscore (_), serta tidak boleh diawali angka."
      );
      return;
    }

    setSaving(true);
    try {
      await onSave({
        id: initialEntry?.id,
        title: title.trim(),
        username: username.trim(),
        password,
        url: url.trim(),
        category,
        envVarName: finalEnvVar,
        notes: notes.trim(),
        favorite,
      });
      onClose();
    } catch (err) {
      setError(typeof err === "string" ? err : "Gagal menyimpan data.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/70 p-4 backdrop-blur-xs animate-fade-in">
      <div className="max-h-[90vh] w-full max-w-lg overflow-y-auto rounded-2xl border border-ink-700 bg-ink-900 p-6 shadow-pop animate-pop-in">
        <div className="mb-5 flex items-center justify-between">
          <h2 className="font-display text-lg font-semibold text-cream">
            {initialEntry
              ? "Edit Akun / Secret Key"
              : isApiKey
                ? "Simpan API Key / Secret Token"
                : "Tambah Akun Baru"}
          </h2>
          <div className="flex items-center gap-1.5">
            <button
              type="button"
              onClick={() => setFavorite((prev) => !prev)}
              className={`rounded-lg p-1.5 transition ${
                favorite
                  ? "bg-honey/15 text-honey"
                  : "text-mute hover:bg-ink-700 hover:text-cream"
              }`}
              title="Tandai Favorit"
            >
              <Star className={`h-4 w-4 ${favorite ? "fill-honey" : ""}`} />
            </button>
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg p-1.5 text-mute hover:bg-ink-700 hover:text-cream"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <div className="sm:col-span-2">
              <label className="mb-1 block text-xs font-medium text-cream-soft">
                {isApiKey ? "Nama Layanan / Key *" : "Nama Layanan / Akun *"}
              </label>
              <input
                type="text"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                autoFocus
                placeholder={
                  isApiKey
                    ? "Contoh: OpenAI Production, GitHub PAT, Stripe"
                    : "Contoh: Google, GitHub, BCA"
                }
                className="w-full rounded-xl border border-ink-600/80 bg-ink-950 px-3.5 py-2 text-sm text-cream placeholder:text-faint outline-none focus:border-honey/70 focus:ring-4 focus:ring-honey/10"
              />
            </div>

            <div>
              <label className="mb-1 block text-xs font-medium text-cream-soft">
                Kategori
              </label>
              <select
                value={category}
                onChange={(e) => setCategory(e.target.value as EntryCategory)}
                className="w-full rounded-xl border border-ink-600/80 bg-ink-950 px-3 py-2 text-sm text-cream outline-none focus:border-honey/70 focus:ring-4 focus:ring-honey/10"
              >
                {ENTRY_CATEGORIES.map((cat) => (
                  <option key={cat} value={cat}>
                    {cat}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label className="mb-1 block text-xs font-medium text-cream-soft">
                {isApiKey ? "Account / Project ID (Opsional)" : "Email / Username"}
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder={
                  isApiKey ? "proj_... atau email akun" : "nama@email.com atau username"
                }
                className="w-full rounded-xl border border-ink-600/80 bg-ink-950 px-3.5 py-2 text-sm text-cream placeholder:text-faint outline-none focus:border-honey/70 focus:ring-4 focus:ring-honey/10"
              />
            </div>

            <div>
              <label className="mb-1 flex items-center gap-1 text-xs font-medium text-cream-soft">
                <Terminal className="h-3.5 w-3.5 text-sky" />
                Nama Env Variable (AI Agent)
              </label>
              <input
                type="text"
                value={envVarName}
                onChange={(e) =>
                  setEnvVarName(e.target.value.toUpperCase().replace(/[^A-Z0-9_]/g, ""))
                }
                placeholder={suggestEnvVarName(title) || "OPENAI_API_KEY"}
                className="w-full rounded-xl border border-ink-600/80 bg-ink-950 px-3.5 py-2 font-mono text-xs text-sky placeholder:text-faint outline-none focus:border-honey/70 focus:ring-4 focus:ring-honey/10"
              />
            </div>
          </div>

          <div>
            <div className="mb-1 flex items-center justify-between">
              <label className="text-xs font-medium text-cream-soft">
                {isApiKey
                  ? "Secret / API Key (Tempel Key Sekali-Tampil di Sini) *"
                  : "Password *"}
              </label>
              <button
                type="button"
                onClick={() => void handleQuickGenerate()}
                className="inline-flex items-center gap-1 text-xs font-medium text-honey hover:text-cream"
              >
                <Wand2 className="h-3.5 w-3.5" />
                Generate Kuat
              </button>
            </div>
            <div className="relative">
              <input
                type={showPassword ? "text" : "password"}
                value={password}
                disabled={loadingSecret}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={
                  loadingSecret
                    ? "Memuat secret dari vault..."
                    : isApiKey
                      ? "sk-... / ghp_... / secret token"
                      : "Masukkan atau generate password..."
                }
                className="w-full rounded-xl border border-ink-600/80 bg-ink-950 py-2 pr-10 pl-3.5 font-mono text-sm text-cream placeholder:text-faint outline-none focus:border-honey/70 focus:ring-4 focus:ring-honey/10 disabled:opacity-60"
              />
              <button
                type="button"
                onClick={() => setShowPassword((prev) => !prev)}
                className="absolute top-1/2 right-2.5 -translate-y-1/2 rounded-md p-1 text-mute hover:bg-ink-700 hover:text-cream"
              >
                {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>

            {password.length > 0 && (
              <div className="mt-2">
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-faint">{password.length} karakter</span>
                  <span className={strength.colorClass}>{strength.label}</span>
                </div>
                <div className="mt-1 grid grid-cols-4 gap-1">
                  {[1, 2, 3, 4].map((step) => (
                    <div
                      key={step}
                      className={`h-1 rounded-full ${
                        strength.score >= step ? strength.barClass : "bg-ink-700"
                      }`}
                    />
                  ))}
                </div>
              </div>
            )}
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-cream-soft">
              URL Website / Endpoint (Opsional)
            </label>
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://..."
              className="w-full rounded-xl border border-ink-600/80 bg-ink-950 px-3.5 py-2 text-sm text-cream placeholder:text-faint outline-none focus:border-honey/70 focus:ring-4 focus:ring-honey/10"
            />
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-cream-soft">
              Catatan (Opsional)
            </label>
            <textarea
              rows={3}
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder={
                isApiKey
                  ? "Scope key, tanggal expired, atau catatan penggunaan AI Agent..."
                  : "Catatan pemulihan, PIN tambahan, atau info keamanan lainnya..."
              }
              className="w-full resize-none rounded-xl border border-ink-600/80 bg-ink-950 px-3.5 py-2 text-sm text-cream placeholder:text-faint outline-none focus:border-honey/70 focus:ring-4 focus:ring-honey/10"
            />
          </div>

          {error && (
            <div className="rounded-xl border border-coral/30 bg-coral/10 px-3.5 py-2 text-xs text-coral">
              {error}
            </div>
          )}

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="rounded-xl border border-ink-600 px-4 py-2 text-xs font-medium text-cream-soft hover:bg-ink-700"
            >
              Batal
            </button>
            <button
              type="submit"
              disabled={saving || loadingSecret}
              className="rounded-xl bg-cream px-4 py-2 text-xs font-medium text-ink-950 hover:bg-[#fff5d2] disabled:opacity-60"
            >
              {saving
                ? "Menyimpan..."
                : initialEntry
                  ? "Simpan Perubahan"
                  : isApiKey
                    ? "Simpan API Key"
                    : "Simpan Akun"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
