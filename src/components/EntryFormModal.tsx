import { useEffect, useRef, useState, type ReactNode } from "react";
import {
  AtSign,
  Briefcase,
  Eye,
  EyeOff,
  Globe,
  Hash,
  Landmark,
  Layers,
  Sparkles,
  Star,
  Terminal,
  User,
  Wand2,
  X,
} from "lucide-react";
import { vaultApi } from "../api";
import {
  ENTRY_CATEGORIES,
  type EntryCategory,
  type VaultEntry,
  type VaultEntryInput,
} from "../types";
import {
  CATEGORY_FORM_CONFIG,
  resolveDynamicLoginHints,
  type ServicePreset,
} from "../utils/categoryConfig";
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

const CATEGORY_ICON: Record<EntryCategory, ReactNode> = {
  Login: <Globe className="h-3.5 w-3.5" />,
  "API Key": <Terminal className="h-3.5 w-3.5" />,
  Finance: <Landmark className="h-3.5 w-3.5" />,
  Work: <Briefcase className="h-3.5 w-3.5" />,
  Personal: <User className="h-3.5 w-3.5" />,
  Social: <AtSign className="h-3.5 w-3.5" />,
  Other: <Layers className="h-3.5 w-3.5" />,
};

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

const inputClass =
  "w-full rounded-xl border border-ink-600/80 bg-ink-950 px-3.5 py-2 text-sm text-cream placeholder:text-faint outline-none transition focus:border-honey/70 focus:ring-4 focus:ring-honey/10";

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
  const [autoFilledUrl, setAutoFilledUrl] = useState<string>("");

  const usernameInputRef = useRef<HTMLInputElement>(null);
  const secretInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!open) {
      setPassword("");
      setShowPassword(false);
      setLoadingSecret(false);
      setAutoFilledUrl("");
      return;
    }

    let cancelled = false;
    setShowPassword(false);
    setError(null);
    setAutoFilledUrl("");

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

  const cfg = CATEGORY_FORM_CONFIG[category];
  const isApiKey = category === "API Key";
  const isFinance = category === "Finance";
  const loginHints = category === "Login" ? resolveDynamicLoginHints(title) : {};
  const matchedPreset = cfg.presets.find(
    (p) => p.title.toLowerCase() === title.trim().toLowerCase()
  );

  const effectiveUsernameLabel = loginHints.usernameLabel ?? cfg.usernameLabel;
  const effectiveUsernamePlaceholder =
    loginHints.usernamePlaceholder ??
    matchedPreset?.usernamePlaceholder ??
    cfg.usernamePlaceholder;
  const effectiveSecretLabel = loginHints.secretLabel ?? cfg.secretLabel;
  const effectiveUrlPlaceholder =
    loginHints.suggestedUrl ??
    matchedPreset?.urlPlaceholder ??
    cfg.urlPlaceholder;
  const effectiveNotesPlaceholder =
    loginHints.notesPlaceholder ??
    matchedPreset?.notesPlaceholder ??
    cfg.notesPlaceholder;

  // Keep existing URL visible when editing even if the category hides URL by default.
  const shouldShowUrl = cfg.showUrl || Boolean(initialEntry?.url);
  const strength = evaluatePasswordStrength(password, category);
  const previewEnvVar = envVarName.trim() || suggestEnvVarName(title) || "OPENAI_API_KEY";

  function handleSelectCategory(nextCategory: EntryCategory) {
    setCategory(nextCategory);
    setError(null);
    if (!initialEntry && autoFilledUrl && url === autoFilledUrl) {
      setUrl("");
      setAutoFilledUrl("");
    }
  }

  function handleApplyPreset(preset: ServicePreset) {
    setTitle(preset.title);
    setError(null);
    if (preset.envVarName) {
      setEnvVarName(preset.envVarName);
    }
    if (preset.url && (!url.trim() || url === autoFilledUrl)) {
      setUrl(preset.url);
      setAutoFilledUrl(preset.url);
    }
    if (isApiKey) {
      secretInputRef.current?.focus();
    } else {
      usernameInputRef.current?.focus();
    }
  }

  function handleTitleChange(nextTitle: string) {
    setTitle(nextTitle);
    if (!initialEntry && category === "Login") {
      const hints = resolveDynamicLoginHints(nextTitle);
      if (hints.suggestedUrl && (!url.trim() || url === autoFilledUrl)) {
        setUrl(hints.suggestedUrl);
        setAutoFilledUrl(hints.suggestedUrl);
      }
    }
  }

  async function handleQuickGenerate(mode: "password" | "token" | "pin6") {
    try {
      const pw =
        mode === "pin6"
          ? await vaultApi.generatePassword({
              length: 6,
              uppercase: false,
              lowercase: false,
              numbers: true,
              symbols: false,
              excludeAmbiguous: false,
            })
          : await vaultApi.generatePassword({
              length: mode === "token" ? 32 : 24,
              uppercase: true,
              lowercase: true,
              numbers: true,
              symbols: mode === "password",
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
      setError(`${cfg.titleLabel.replace(/\s*\*$/, "")} wajib diisi.`);
      return;
    }
    if (!password) {
      setError(
        `${effectiveSecretLabel.replace(/\s*\*$/, "")} tidak boleh kosong.`
      );
      return;
    }

    const finalEnvVar = isApiKey
      ? envVarName.trim() || suggestEnvVarName(title)
      : "";
    if (finalEnvVar && !ENV_VAR_PATTERN.test(finalEnvVar)) {
      setError(
        "Nama Env Variable hanya boleh berisi huruf A-Z, angka 0-9, dan underscore (_), serta tidak boleh diawali angka."
      );
      return;
    }

    const finalUrl = shouldShowUrl ? url.trim() : "";

    setSaving(true);
    try {
      await onSave({
        id: initialEntry?.id,
        title: title.trim(),
        username: username.trim(),
        password,
        url: finalUrl,
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
      <div className="max-h-[92vh] w-full max-w-xl overflow-x-hidden overflow-y-auto overscroll-none rounded-2xl border border-ink-700 bg-ink-900 p-6 shadow-pop animate-pop-in">
        <div className="mb-4 flex items-start justify-between gap-3">
          <div>
            <h2 className="font-display text-lg font-semibold text-cream">
              {initialEntry ? `Edit ${cfg.shortLabel}` : cfg.modalHeadingNew}
            </h2>
            <p className="mt-0.5 text-xs text-mute">{cfg.subtitle}</p>
          </div>
          <div className="flex shrink-0 items-center gap-1.5">
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

        {/* Category Selector Tabs */}
        <div className="mb-4 rounded-xl border border-ink-700/90 bg-ink-950/70 p-2">
          <div className="mb-1.5 px-1 text-[10px] font-semibold tracking-[0.12em] text-faint uppercase">
            Pilih Tipe Form
          </div>
          <div className="flex flex-wrap gap-1.5">
            {ENTRY_CATEGORIES.map((cat) => {
              const active = category === cat;
              const catMeta = CATEGORY_FORM_CONFIG[cat];
              return (
                <button
                  key={cat}
                  type="button"
                  onClick={() => handleSelectCategory(cat)}
                  aria-pressed={active}
                  className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-xs font-medium transition ${
                    active
                      ? catMeta.accentPillActive
                      : "border-transparent bg-ink-900 text-mute hover:border-ink-700 hover:text-cream-soft"
                  }`}
                >
                  {CATEGORY_ICON[cat]}
                  {catMeta.shortLabel}
                </button>
              );
            })}
          </div>
        </div>

        {/* Quick service presets for the selected category (hidden on Edit and on Other/Default) */}
        {!initialEntry && cfg.presets.length > 0 && (
          <div className="mb-4 flex flex-wrap items-center gap-1.5">
            <span className="inline-flex items-center gap-1 mr-1 text-[11px] text-faint">
              <Sparkles className="h-3 w-3 text-honey" />
              Template cepat:
            </span>
            {cfg.presets.map((preset) => {
              const isPicked =
                title.trim().toLowerCase() === preset.title.toLowerCase();
              return (
                <button
                  key={preset.label}
                  type="button"
                  onClick={() => handleApplyPreset(preset)}
                  className={`rounded-full border px-2.5 py-0.5 text-[11px] font-medium transition ${
                    isPicked
                      ? "border-honey/50 bg-honey/15 text-cream"
                      : "border-ink-700 bg-ink-850 text-cream-soft hover:border-ink-500 hover:text-cream"
                  }`}
                >
                  {preset.label}
                </button>
              );
            })}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* API KEY SPECIALIZED LAYOUT */}
          {isApiKey ? (
            <>
              <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2">
                <div>
                  <label className="mb-1 block text-xs font-medium text-cream-soft">
                    {cfg.titleLabel}
                  </label>
                  <input
                    type="text"
                    value={title}
                    onChange={(e) => handleTitleChange(e.target.value)}
                    autoFocus
                    placeholder={cfg.titlePlaceholder}
                    className={inputClass}
                  />
                </div>

                <div>
                  <label className="mb-1 flex items-center gap-1.5 text-xs font-medium text-sky">
                    <Terminal className="h-3.5 w-3.5" />
                    Nama Env Variable (AI Agent)
                  </label>
                  <input
                    type="text"
                    value={envVarName}
                    onChange={(e) =>
                      setEnvVarName(
                        e.target.value.toUpperCase().replace(/[^A-Z0-9_]/g, "")
                      )
                    }
                    placeholder={suggestEnvVarName(title) || "OPENAI_API_KEY"}
                    className="w-full rounded-xl border border-sky/35 bg-ink-950 px-3.5 py-2 font-mono text-xs text-sky placeholder:text-faint outline-none transition focus:border-sky focus:ring-4 focus:ring-sky/10"
                  />
                </div>
              </div>

              <div className="rounded-xl border border-sky/25 bg-sky/[0.04] p-3.5">
                <div className="mb-1.5 flex items-center justify-between gap-2">
                  <label className="text-xs font-medium text-cream">
                    {effectiveSecretLabel}
                  </label>
                  <button
                    type="button"
                    onClick={() => void handleQuickGenerate("token")}
                    className="inline-flex items-center gap-1 text-xs font-medium text-sky hover:text-cream"
                  >
                    <Wand2 className="h-3.5 w-3.5" />
                    Generate Token
                  </button>
                </div>
                <div className="relative">
                  <input
                    ref={secretInputRef}
                    type={showPassword ? "text" : "password"}
                    value={password}
                    disabled={loadingSecret}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder={
                      loadingSecret
                        ? "Memuat secret dari vault..."
                        : cfg.secretPlaceholder
                    }
                    className="w-full rounded-xl border border-ink-600/80 bg-ink-950 py-2 pr-10 pl-3.5 font-mono text-sm text-cream placeholder:text-faint outline-none focus:border-sky/70 focus:ring-4 focus:ring-sky/10 disabled:opacity-60"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword((prev) => !prev)}
                    className="absolute top-1/2 right-2.5 -translate-y-1/2 rounded-md p-1 text-mute hover:bg-ink-700 hover:text-cream"
                  >
                    {showPassword ? (
                      <EyeOff className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                  </button>
                </div>
                <div className="mt-2 flex flex-wrap items-center justify-between gap-2 text-[11px] text-mute">
                  <span>
                    Siap di-inject ke AI Agent sebagai{" "}
                    <code className="font-mono text-sky">${previewEnvVar}</code>
                  </span>
                  {password.length > 0 && (
                    <span className="font-mono text-faint">
                      {password.length} karakter
                    </span>
                  )}
                </div>
              </div>

              <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2">
                <div>
                  <label className="mb-1 block text-xs font-medium text-cream-soft">
                    {effectiveUsernameLabel}
                  </label>
                  <input
                    ref={usernameInputRef}
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder={effectiveUsernamePlaceholder}
                    className={`${inputClass} font-mono text-xs`}
                  />
                </div>

                <div>
                  <label className="mb-1 block text-xs font-medium text-cream-soft">
                    {cfg.urlLabel}
                  </label>
                  <input
                    type="text"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    placeholder={effectiveUrlPlaceholder}
                    className={inputClass}
                  />
                </div>
              </div>
            </>
          ) : (
            /* ACCOUNT / FINANCE / WORK / SOCIAL / PERSONAL / OTHER (DEFAULT) LAYOUTS */
            <>
              <div>
                <label className="mb-1 block text-xs font-medium text-cream-soft">
                  {cfg.titleLabel}
                </label>
                <input
                  type="text"
                  value={title}
                  onChange={(e) => handleTitleChange(e.target.value)}
                  autoFocus
                  placeholder={cfg.titlePlaceholder}
                  className={inputClass}
                />
              </div>

              {category === "Work" ? (
                <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2">
                  <div>
                    <label className="mb-1 block text-xs font-medium text-cream-soft">
                      {effectiveUsernameLabel}
                    </label>
                    <input
                      ref={usernameInputRef}
                      type="text"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      placeholder={effectiveUsernamePlaceholder}
                      className={inputClass}
                    />
                  </div>
                  <div>
                    <label className="mb-1 block text-xs font-medium text-cream-soft">
                      {cfg.urlLabel}
                    </label>
                    <input
                      type="text"
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      placeholder={effectiveUrlPlaceholder}
                      className={inputClass}
                    />
                  </div>
                </div>
              ) : (
                <div>
                  <label className="mb-1 block text-xs font-medium text-cream-soft">
                    {effectiveUsernameLabel}
                  </label>
                  <input
                    ref={usernameInputRef}
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder={effectiveUsernamePlaceholder}
                    className={`${inputClass} ${cfg.usernameMono ? "font-mono" : ""}`}
                  />
                </div>
              )}

              <div>
                <div className="mb-1 flex flex-wrap items-center justify-between gap-2">
                  <label className="text-xs font-medium text-cream-soft">
                    {effectiveSecretLabel}
                  </label>
                  <div className="flex items-center gap-3">
                    {isFinance && (
                      <button
                        type="button"
                        onClick={() => void handleQuickGenerate("pin6")}
                        className="inline-flex items-center gap-1 text-xs font-medium text-sage hover:text-cream"
                      >
                        <Hash className="h-3.5 w-3.5" />
                        PIN 6 Digit
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={() => void handleQuickGenerate("password")}
                      className="inline-flex items-center gap-1 text-xs font-medium text-honey hover:text-cream"
                    >
                      <Wand2 className="h-3.5 w-3.5" />
                      Generate Kuat
                    </button>
                  </div>
                </div>
                <div className="relative">
                  <input
                    ref={secretInputRef}
                    type={showPassword ? "text" : "password"}
                    value={password}
                    disabled={loadingSecret}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder={
                      loadingSecret
                        ? "Memuat secret dari vault..."
                        : cfg.secretPlaceholder
                    }
                    className="w-full rounded-xl border border-ink-600/80 bg-ink-950 py-2 pr-10 pl-3.5 font-mono text-sm text-cream placeholder:text-faint outline-none focus:border-honey/70 focus:ring-4 focus:ring-honey/10 disabled:opacity-60"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword((prev) => !prev)}
                    className="absolute top-1/2 right-2.5 -translate-y-1/2 rounded-md p-1 text-mute hover:bg-ink-700 hover:text-cream"
                  >
                    {showPassword ? (
                      <EyeOff className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
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

              {shouldShowUrl && category !== "Work" && (
                <div>
                  <label className="mb-1 block text-xs font-medium text-cream-soft">
                    {cfg.urlLabel}
                  </label>
                  <input
                    type="text"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    placeholder={effectiveUrlPlaceholder}
                    className={inputClass}
                  />
                </div>
              )}
            </>
          )}

          <div>
            <label className="mb-1 block text-xs font-medium text-cream-soft">
              {cfg.notesLabel}
            </label>
            <textarea
              rows={2}
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder={effectiveNotesPlaceholder}
              className="w-full resize-none rounded-xl border border-ink-600/80 bg-ink-950 px-3.5 py-2 text-sm text-cream placeholder:text-faint outline-none focus:border-honey/70 focus:ring-4 focus:ring-honey/10"
            />
          </div>

          {error && (
            <div className="rounded-xl border border-coral/30 bg-coral/10 px-3.5 py-2 text-xs text-coral">
              {error}
            </div>
          )}

          <div className="flex justify-end gap-2 pt-1">
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
              className="rounded-xl bg-honey px-4 py-2 text-xs font-semibold text-ink-950 transition hover:bg-[#f8c65a] disabled:opacity-60"
            >
              {saving
                ? "Menyimpan..."
                : initialEntry
                  ? "Simpan Perubahan"
                  : cfg.submitLabel}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
