import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  AlertTriangle,
  Bot,
  Check,
  Copy,
  ExternalLink,
  Eye,
  EyeOff,
  FolderLock,
  Globe,
  Lock,
  Pencil,
  Plus,
  Search,
  Settings,
  ShieldAlert,
  Star,
  Terminal,
  Trash2,
  Wand2,
} from "lucide-react";
import { vaultApi } from "./api";
import { EntryFormModal } from "./components/EntryFormModal";
import { LockScreen } from "./components/LockScreen";
import { PasswordGeneratorModal } from "./components/PasswordGeneratorModal";
import { SessionTimer } from "./components/SessionTimer";
import { SettingsModal } from "./components/SettingsModal";
import { VaultLogo } from "./components/VaultLogo";
import { VaultMascot } from "./components/VaultMascot";
import {
  ENTRY_CATEGORIES,
  type EntryCategory,
  type VaultEntry,
  type VaultEntryInput,
  type VaultStatus,
} from "./types";
import { CATEGORY_FORM_CONFIG } from "./utils/categoryConfig";
import { strengthFromScore } from "./utils/passwordStrength";

type SidebarFilter = "all" | "favorites" | "weak" | EntryCategory;

const ENV_VAR_PATTERN = /^[A-Z_][A-Z0-9_]*$/;

function psSingleQuote(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

function buildSafeDefaultEnvName(title: string): string {
  const cleaned = title
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
  if (!cleaned) return "VAULTPASS_API_KEY";
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

const CATEGORY_STYLE: Record<EntryCategory, { avatar: string; dot: string }> = {
  Login: { avatar: "bg-honey/15 text-honey", dot: "bg-honey" },
  "API Key": { avatar: "bg-sky/15 text-sky", dot: "bg-sky" },
  Finance: { avatar: "bg-sage/15 text-sage", dot: "bg-sage" },
  Work: { avatar: "bg-[#b6a4e8]/15 text-[#b6a4e8]", dot: "bg-[#b6a4e8]" },
  Personal: { avatar: "bg-coral/15 text-coral", dot: "bg-coral" },
  Social: { avatar: "bg-[#e89fc4]/15 text-[#e89fc4]", dot: "bg-[#e89fc4]" },
  Other: { avatar: "bg-ink-700 text-cream-soft", dot: "bg-mute" },
};

function NavButton({
  active,
  onClick,
  icon,
  label,
  count,
  tone = "default",
}: {
  active: boolean;
  onClick: () => void;
  icon: ReactNode;
  label: string;
  count?: ReactNode;
  tone?: "default" | "danger";
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-current={active ? "true" : undefined}
      className={`group relative flex w-full items-center justify-between rounded-xl px-3 py-2 text-[13px] font-medium transition ${
        active
          ? "bg-ink-800 text-cream"
          : "text-mute hover:bg-ink-850 hover:text-cream-soft"
      }`}
    >
      {active && (
        <span
          className={`absolute top-2 bottom-2 left-0 w-[3px] rounded-full ${
            tone === "danger" ? "bg-coral" : "bg-honey"
          }`}
        />
      )}
      <span className="flex items-center gap-2.5">{icon}{label}</span>
      {count}
    </button>
  );
}

function FieldCard({
  label,
  right,
  children,
}: {
  label: ReactNode;
  right?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="rounded-card border border-ink-700 bg-ink-850 p-4 hairline">
      <div className="mb-1.5 flex items-center justify-between">
        <span className="text-[11px] font-medium tracking-wide text-mute">{label}</span>
        {right}
      </div>
      {children}
    </div>
  );
}

const smallBtn =
  "inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-ink-600 bg-ink-800 px-2.5 py-1.5 text-xs font-medium text-cream-soft transition hover:border-ink-500 hover:text-cream";

export function App() {
  const [status, setStatus] = useState<VaultStatus | null>(null);
  const [entries, setEntries] = useState<VaultEntry[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [filter, setFilter] = useState<SidebarFilter>("all");
  const [search, setSearch] = useState("");
  const [showDetailPassword, setShowDetailPassword] = useState(false);
  const [revealedSecret, setRevealedSecret] = useState<string | null>(null);

  const [formOpen, setFormOpen] = useState(false);
  const [formDefaultCategory, setFormDefaultCategory] = useState<EntryCategory>("Login");
  const [editingEntry, setEditingEntry] = useState<VaultEntry | null>(null);
  const [generatorOpen, setGeneratorOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);

  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [copiedField, setCopiedField] = useState<
    "username" | "password" | "cli-get" | "cli-run" | null
  >(null);
  const [clipboardCountdown, setClipboardCountdown] = useState<number>(0);
  const [toast, setToast] = useState<string | null>(null);

  const searchInputRef = useRef<HTMLInputElement>(null);

  const showToast = useCallback((msg: string) => {
    setToast(msg);
  }, []);

  useEffect(() => {
    if (!toast) return;
    const id = setTimeout(() => setToast(null), 2600);
    return () => clearTimeout(id);
  }, [toast]);

  const loadInitialStatus = useCallback(async () => {
    try {
      const nextStatus = await vaultApi.getStatus();
      setStatus(nextStatus);
      if (nextStatus.unlocked) {
        const list = await vaultApi.listEntries();
        setEntries(list);
      }
    } catch (err) {
      showToast(typeof err === "string" ? err : "Gagal memuat status vault.");
    }
  }, [showToast]);

  useEffect(() => {
    void loadInitialStatus();
  }, [loadInitialStatus]);

  const handleLockVault = useCallback(async () => {
    await vaultApi.lockVault();
    setEntries([]);
    setSelectedId(null);
    setShowDetailPassword(false);
    setRevealedSecret(null);
    setConfirmDeleteId(null);
    setFormOpen(false);
    setSettingsOpen(false);
    setGeneratorOpen(false);
    setStatus((prev) => (prev ? { ...prev, unlocked: false } : prev));
  }, []);

  useEffect(() => {
    if (!status?.unlocked) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        searchInputRef.current?.focus();
      } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "l") {
        e.preventDefault();
        void handleLockVault();
      } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "n") {
        e.preventDefault();
        setEditingEntry(null);
        setFormDefaultCategory(
          ENTRY_CATEGORIES.includes(filter as EntryCategory)
            ? (filter as EntryCategory)
            : "Login"
        );
        setFormOpen(true);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [status?.unlocked, handleLockVault, filter]);

  useEffect(() => {
    if (clipboardCountdown <= 0) return;
    const id = window.setInterval(() => {
      setClipboardCountdown((prev) => (prev <= 1 ? 0 : prev - 1));
    }, 1000);
    return () => window.clearInterval(id);
  }, [clipboardCountdown]);

  const isWeakOrReused = useCallback((entry: VaultEntry) => {
    return entry.strengthScore <= 2 || entry.reusedCount > 1;
  }, []);

  const weakCount = useMemo(
    () => entries.filter((e) => isWeakOrReused(e)).length,
    [entries, isWeakOrReused]
  );

  const filteredEntries = useMemo(() => {
    const q = search.trim().toLowerCase();
    return entries.filter((entry) => {
      if (filter === "favorites" && !entry.favorite) return false;
      if (filter === "weak" && !isWeakOrReused(entry)) return false;
      if (
        filter !== "all" &&
        filter !== "favorites" &&
        filter !== "weak" &&
        entry.category !== filter
      ) {
        return false;
      }

      if (!q) return true;
      return (
        entry.title.toLowerCase().includes(q) ||
        entry.username.toLowerCase().includes(q) ||
        entry.url.toLowerCase().includes(q) ||
        entry.category.toLowerCase().includes(q) ||
        (entry.envVarName || "").toLowerCase().includes(q)
      );
    });
  }, [entries, filter, search, isWeakOrReused]);

  const selectedEntry = useMemo(
    () => entries.find((e) => e.id === selectedId) ?? filteredEntries[0] ?? null,
    [entries, selectedId, filteredEntries]
  );

  useEffect(() => {
    if (!status) {
      document.title = "VaultPass";
      return;
    }
    if (!status.exists) {
      document.title = "Buat Vault · VaultPass";
      return;
    }
    if (!status.unlocked) {
      document.title = "Terkunci · VaultPass";
      return;
    }
    if (filter === "all") {
      document.title = "VaultPass";
    } else if (filter === "favorites") {
      document.title = "Favorit · VaultPass";
    } else if (filter === "weak") {
      document.title = "Perlu Perhatian · VaultPass";
    } else {
      document.title = `${filter} · VaultPass`;
    }
  }, [status, filter]);

  useEffect(() => {
    setShowDetailPassword(false);
    setRevealedSecret(null);
    setConfirmDeleteId(null);
  }, [selectedEntry?.id]);

  async function handleCreateVault(masterPassword: string, passwordHint?: string) {
    const nextStatus = await vaultApi.createVault(masterPassword, passwordHint);
    setStatus(nextStatus);
    setEntries([]);
    showToast("Vault baru berhasil dibuat & dienkripsi!");
  }

  async function handleUnlockVault(masterPassword: string) {
    const list = await vaultApi.unlockVault(masterPassword);
    const nextStatus = await vaultApi.getStatus();
    setStatus(nextStatus);
    setEntries(list);
    if (list.length > 0) {
      setSelectedId(list[0].id);
    }
  }

  async function handleUnlockBiometric() {
    const list = await vaultApi.unlockVaultBiometric();
    const nextStatus = await vaultApi.getStatus();
    setStatus(nextStatus);
    setEntries(list);
    if (list.length > 0) {
      setSelectedId(list[0].id);
    }
  }

  async function handleSaveEntry(input: VaultEntryInput) {
    const result = await vaultApi.upsertEntry(input);
    setEntries(result.entries);
    setSelectedId(result.savedId);
    setShowDetailPassword(false);
    setRevealedSecret(null);
    showToast(input.id ? "Perubahan disimpan." : "Data baru ditambahkan ke vault.");
  }

  async function handleDeleteEntry(id: string) {
    const updatedEntries = await vaultApi.deleteEntry(id);
    setEntries(updatedEntries);
    if (selectedId === id) {
      setSelectedId(null);
    }
    setShowDetailPassword(false);
    setRevealedSecret(null);
    setConfirmDeleteId(null);
    showToast("Dihapus dari vault.");
  }

  async function handleToggleFavorite(id: string) {
    const updatedEntries = await vaultApi.toggleFavorite(id);
    setEntries(updatedEntries);
  }

  async function handleToggleRevealSecret(id: string) {
    if (showDetailPassword) {
      setShowDetailPassword(false);
      setRevealedSecret(null);
      return;
    }
    try {
      const secret = await vaultApi.revealEntrySecret(id);
      setRevealedSecret(secret);
      setShowDetailPassword(true);
    } catch (err) {
      showToast(typeof err === "string" ? err : "Gagal membaca secret dari vault.");
    }
  }

  async function handleCopyEntrySecret(id: string) {
    try {
      const clearSeconds = await vaultApi.copyEntrySecret(id);
      setCopiedField("password");
      setTimeout(() => setCopiedField(null), 1800);
      if (clearSeconds > 0) {
        setClipboardCountdown(clearSeconds);
        showToast(`Secret disalin (clipboard dihapus otomatis dalam ${clearSeconds}d).`);
      } else {
        showToast("Secret disalin ke clipboard.");
      }
    } catch (err) {
      showToast(typeof err === "string" ? err : "Gagal menyalin secret ke clipboard.");
    }
  }

  async function handleCopy(
    text: string,
    isSensitive: boolean,
    field?: "username" | "password" | "cli-get" | "cli-run"
  ) {
    if (!text) return;
    try {
      const clearSeconds = await vaultApi.copySecret(text, isSensitive);
      if (field) {
        setCopiedField(field);
        setTimeout(() => setCopiedField(null), 1800);
      }
      if (isSensitive && clearSeconds > 0) {
        setClipboardCountdown(clearSeconds);
        showToast(`Secret disalin (clipboard dihapus otomatis dalam ${clearSeconds}d).`);
      } else {
        showToast("Disalin ke clipboard.");
      }
    } catch (err) {
      showToast(typeof err === "string" ? err : "Gagal menyalin ke clipboard.");
    }
  }

  if (!status) {
    return (
      <div className="flex h-full w-full flex-col items-center justify-center gap-4 overflow-clip bg-ink-950 text-sm text-mute">
        <VaultMascot mood="sleeping" size={96} floating />
        Memuat VaultPass...
      </div>
    );
  }

  if (!status.exists || !status.unlocked) {
    return (
      <div className="h-full w-full animate-fade-in overflow-clip">
        <LockScreen
          vaultExists={status.exists}
          vaultPath={status.vaultPath}
          biometricEnabled={status.biometricEnabled}
          passwordHint={status.passwordHint}
          initialCooldownSeconds={status.unlockCooldownSeconds}
          onCreateVault={handleCreateVault}
          onUnlockVault={handleUnlockVault}
          onUnlockBiometric={handleUnlockBiometric}
          onPickSaveLocation={async () => {
            const next = await vaultApi.pickVaultSaveLocation();
            if (next) {
              setStatus(next);
            }
          }}
          onPickExistingFile={async () => {
            const next = await vaultApi.pickExistingVaultFile();
            if (next) {
              setStatus(next);
              setEntries([]);
              setSelectedId(null);
            }
          }}
        />
      </div>
    );
  }

  const detailStrength = selectedEntry
    ? strengthFromScore(selectedEntry.strengthScore)
    : null;
  const detailReusedCount = selectedEntry ? selectedEntry.reusedCount : 1;

  const effectiveEnvName = selectedEntry
    ? selectedEntry.envVarName?.trim() && ENV_VAR_PATTERN.test(selectedEntry.envVarName.trim())
      ? selectedEntry.envVarName.trim()
      : buildSafeDefaultEnvName(selectedEntry.title)
    : "VAULTPASS_API_KEY";

  const quotedCliBin = psSingleQuote(status.cliPath);
  const cliGetCommand = selectedEntry
    ? `& ${quotedCliBin} get ${psSingleQuote(selectedEntry.title)} --field key`
    : "";
  const cliRunCommand = selectedEntry
    ? `& ${quotedCliBin} run --key ${psSingleQuote(selectedEntry.title)} --env ${psSingleQuote(effectiveEnvName)} -- `
    : "";

  const favoriteCount = entries.filter((e) => e.favorite).length;
  const selectedStyle = selectedEntry ? CATEGORY_STYLE[selectedEntry.category] : null;
  const selectedCategoryMeta = selectedEntry
    ? CATEGORY_FORM_CONFIG[selectedEntry.category]
    : null;

  return (
    <div className="flex h-full w-full animate-fade-in overflow-clip bg-ink-950 text-cream-soft">
      {/* Sidebar */}
      <aside className="flex w-56 shrink-0 flex-col border-r border-ink-700/80 bg-ink-900 xl:w-60">
        <div className="flex items-center gap-3 px-4 pt-4 pb-3.5">
          <VaultLogo size={38} className="shrink-0" />
          <div className="min-w-0">
            <div className="font-display text-[17px] leading-tight font-semibold tracking-tight text-cream">
              VaultPass
            </div>
            <div className="text-[11px] text-mute">{entries.length} item tersimpan</div>
          </div>
        </div>

        <div className="flex-1 space-y-6 overflow-y-auto overscroll-none px-3 py-2">
          <div className="space-y-0.5">
            <NavButton
              active={filter === "all"}
              onClick={() => setFilter("all")}
              icon={<FolderLock className="h-4 w-4" />}
              label="Semua Item"
              count={<span className="text-[11px] text-faint tabular-nums">{entries.length}</span>}
            />
            <NavButton
              active={filter === "favorites"}
              onClick={() => setFilter("favorites")}
              icon={<Star className="h-4 w-4 text-honey" />}
              label="Favorit"
              count={<span className="text-[11px] text-faint tabular-nums">{favoriteCount}</span>}
            />
            <NavButton
              active={filter === "weak"}
              tone="danger"
              onClick={() => setFilter("weak")}
              icon={<ShieldAlert className="h-4 w-4 text-coral" />}
              label="Perlu Perhatian"
              count={
                weakCount > 0 ? (
                  <span className="rounded-full bg-coral/15 px-1.5 py-0.5 text-[10px] font-semibold text-coral tabular-nums">
                    {weakCount}
                  </span>
                ) : undefined
              }
            />
          </div>

          <div>
            <div className="mb-1.5 px-3 text-[10px] font-semibold tracking-[0.14em] text-faint uppercase">
              Kategori
            </div>
            <div className="space-y-0.5">
              {ENTRY_CATEGORIES.map((cat) => {
                const count = entries.filter((e) => e.category === cat).length;
                return (
                  <NavButton
                    key={cat}
                    active={filter === cat}
                    onClick={() => setFilter(cat)}
                    icon={<span className={`h-2 w-2 rounded-full ${CATEGORY_STYLE[cat].dot}`} />}
                    label={cat}
                    count={<span className="text-[11px] text-faint tabular-nums">{count}</span>}
                  />
                );
              })}
            </div>
          </div>
        </div>

        <div className="space-y-1 border-t border-ink-700/80 p-3">
          <SessionTimer
            minutes={status.autoLockMinutes}
            onLock={() => void handleLockVault()}
          />
          <div className="pt-1.5">
            <button
              type="button"
              onClick={() => setGeneratorOpen(true)}
              className="flex w-full items-center gap-2.5 rounded-xl px-3 py-2 text-[13px] font-medium text-mute transition hover:bg-ink-850 hover:text-cream-soft"
            >
              <Wand2 className="h-4 w-4 text-honey" />
              Password Generator
            </button>
            <button
              type="button"
              onClick={() => setSettingsOpen(true)}
              className="flex w-full items-center gap-2.5 rounded-xl px-3 py-2 text-[13px] font-medium text-mute transition hover:bg-ink-850 hover:text-cream-soft"
            >
              <Settings className="h-4 w-4" />
              Pengaturan & Backup
            </button>
            <button
              type="button"
              onClick={() => void handleLockVault()}
              className="flex w-full items-center justify-between rounded-xl px-3 py-2 text-[13px] font-medium text-honey transition hover:bg-honey/10"
              title="Shortcut: Ctrl+L"
            >
              <span className="flex items-center gap-2.5">
                <Lock className="h-4 w-4" />
                Kunci Vault
              </span>
              <kbd className="rounded border border-ink-600 px-1 font-mono text-[10px] text-faint">
                Ctrl L
              </kbd>
            </button>
          </div>
        </div>
      </aside>

      {/* Account List Pane */}
      <section className="flex w-72 shrink-0 flex-col border-r border-ink-700/80 bg-[#10131b] xl:w-80">
        <div className="flex items-center gap-2 border-b border-ink-700/80 p-3">
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute top-1/2 left-3 h-3.5 w-3.5 -translate-y-1/2 text-faint" />
            <input
              ref={searchInputRef}
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Cari akun atau API key"
              aria-label="Cari akun"
              className="h-9 w-full rounded-xl border border-ink-700 bg-ink-850 pr-12 pl-8 text-xs text-cream placeholder:text-faint outline-none transition focus:border-honey/70 focus:ring-4 focus:ring-honey/10"
            />
            <kbd className="pointer-events-none absolute top-1/2 right-2.5 -translate-y-1/2 rounded border border-ink-600 px-1 font-mono text-[10px] text-faint">
              Ctrl K
            </kbd>
          </div>
          <button
            type="button"
            onClick={() => {
              setEditingEntry(null);
              setFormDefaultCategory(
                ENTRY_CATEGORIES.includes(filter as EntryCategory)
                  ? (filter as EntryCategory)
                  : "Login"
              );
              setFormOpen(true);
            }}
            className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-honey text-ink-950 shadow-[0_6px_16px_-6px_rgb(245_183_59/0.5)] transition hover:bg-[#f8c65a] active:translate-y-px"
            title="Tambah Item Baru (Ctrl+N)"
            aria-label="Tambah akun atau API key"
          >
            <Plus className="h-4 w-4 stroke-[2.4]" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto overscroll-none p-2">
          {filteredEntries.length === 0 ? (
            <div className="flex h-full animate-fade-up flex-col items-center justify-center px-6 text-center">
              <VaultMascot mood={entries.length === 0 ? "sleeping" : "shocked"} size={104} />
              <p className="mt-3 font-display text-sm font-semibold text-cream">
                {entries.length === 0 ? "Vault masih kosong" : "Tidak ada yang cocok"}
              </p>
              <p className="mt-1 text-xs leading-relaxed text-mute">
                {entries.length === 0
                  ? "Klik tombol + untuk menyimpan akun atau API key pertamamu."
                  : "Coba ubah kata kunci pencarian atau filter kategori."}
              </p>
            </div>
          ) : (
            <div className="space-y-0.5">
              {filteredEntries.map((entry, index) => {
                const isSelected = selectedEntry?.id === entry.id;
                const initial = entry.title.trim().charAt(0).toUpperCase() || "?";
                return (
                  <button
                    key={entry.id}
                    type="button"
                    onClick={() => setSelectedId(entry.id)}
                    aria-current={isSelected ? "true" : undefined}
                    style={{ animationDelay: `${Math.min(index, 10) * 28}ms` }}
                    className={`flex w-full animate-slide-in items-center gap-3 rounded-xl border px-3 py-2.5 text-left transition ${
                      isSelected
                        ? "border-ink-600 bg-ink-800"
                        : "border-transparent hover:bg-ink-850"
                    }`}
                  >
                    <div
                      className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-[0.7rem] font-display text-sm font-semibold ${
                        CATEGORY_STYLE[entry.category].avatar
                      }`}
                    >
                      {initial}
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center justify-between gap-1">
                        <span className="truncate text-[13px] font-medium text-cream">
                          {entry.title}
                        </span>
                        {entry.favorite && (
                          <Star className="h-3 w-3 shrink-0 fill-honey text-honey" />
                        )}
                      </div>
                      <div
                        className={`truncate text-[11px] ${
                          entry.envVarName ? "font-mono text-faint" : "text-mute"
                        }`}
                      >
                        {entry.envVarName
                          ? entry.envVarName
                          : entry.username || entry.category}
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>
      </section>

      {/* Main Detail Pane */}
      <main className="relative flex min-w-0 flex-1 flex-col overflow-x-hidden overflow-y-auto overscroll-none bg-ink-950">
        <div
          aria-hidden
          className="pointer-events-none absolute inset-x-0 top-0 h-72"
          style={{
            background:
              "radial-gradient(ellipse 60% 100% at 50% 0%, rgb(45 58 89 / 0.2), transparent 70%)",
          }}
        />
        {clipboardCountdown > 0 && (
          <div className="relative z-10 flex animate-fade-in items-center justify-between border-b border-honey/20 bg-honey/10 px-6 py-2 text-xs text-cream-soft">
            <span>Clipboard berisi secret/password sensitif.</span>
            <span className="font-mono font-medium text-honey tabular-nums">
              Auto-hapus dalam {clipboardCountdown}s
            </span>
          </div>
        )}

        {selectedEntry && selectedStyle && selectedCategoryMeta ? (
          <div key={selectedEntry.id} className="relative mx-auto w-full max-w-2xl animate-fade-up p-8">
            <div className="flex items-start justify-between gap-4 border-b border-ink-700/80 pb-6">
              <div className="flex min-w-0 items-center gap-4">
                <div
                  className={`flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl font-display text-2xl font-semibold ${selectedStyle.avatar}`}
                >
                  {selectedEntry.title.trim().charAt(0).toUpperCase() || "?"}
                </div>
                <div className="min-w-0">
                  <h1
                    data-selectable
                    className="truncate font-display text-2xl leading-tight font-semibold tracking-tight text-cream"
                  >
                    {selectedEntry.title}
                  </h1>
                  <div className="mt-1.5 flex flex-wrap items-center gap-2">
                    <span className="inline-flex items-center gap-1.5 rounded-full border border-ink-600 bg-ink-850 px-2.5 py-0.5 text-[11px] text-cream-soft">
                      <span className={`h-1.5 w-1.5 rounded-full ${selectedStyle.dot}`} />
                      {selectedEntry.category}
                    </span>
                    {selectedEntry.envVarName && (
                      <span className="rounded-full border border-sky/30 bg-sky/10 px-2.5 py-0.5 font-mono text-[11px] text-sky">
                        {selectedEntry.envVarName}
                      </span>
                    )}
                    <span className="text-[11px] text-faint">
                      Diperbarui{" "}
                      {new Date(selectedEntry.updatedAt).toLocaleString("id-ID", {
                        dateStyle: "medium",
                        timeStyle: "short",
                      })}
                    </span>
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => void handleToggleFavorite(selectedEntry.id)}
                  className={`rounded-xl border p-2 transition ${
                    selectedEntry.favorite
                      ? "border-honey/30 bg-honey/10 text-honey"
                      : "border-ink-600 bg-ink-850 text-mute hover:text-cream"
                  }`}
                  title="Favorit"
                  aria-label="Tandai favorit"
                  aria-pressed={selectedEntry.favorite}
                >
                  <Star className={`h-4 w-4 ${selectedEntry.favorite ? "fill-honey" : ""}`} />
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setEditingEntry(selectedEntry);
                    setFormOpen(true);
                  }}
                  className="inline-flex items-center gap-1.5 rounded-xl border border-ink-600 bg-ink-850 px-3 py-2 text-xs font-medium text-cream-soft transition hover:border-ink-500 hover:text-cream"
                >
                  <Pencil className="h-3.5 w-3.5" />
                  Edit
                </button>
                {confirmDeleteId === selectedEntry.id ? (
                  <button
                    type="button"
                    onClick={() => void handleDeleteEntry(selectedEntry.id)}
                    className="inline-flex animate-pop-in items-center gap-1.5 rounded-xl bg-coral px-3 py-2 text-xs font-semibold text-ink-950 transition hover:brightness-110"
                  >
                    Konfirmasi Hapus
                  </button>
                ) : (
                  <button
                    type="button"
                    onClick={() => setConfirmDeleteId(selectedEntry.id)}
                    className="rounded-xl border border-ink-600 bg-ink-850 p-2 text-mute transition hover:border-coral/40 hover:bg-coral/10 hover:text-coral"
                    title="Hapus akun"
                    aria-label="Hapus akun"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                )}
              </div>
            </div>

            <div className="mt-6 space-y-3.5">
              {/* Username / Email / Account / Project ID */}
              {selectedEntry.username && (
                <FieldCard label={selectedCategoryMeta.detailUsernameLabel}>
                  <div className="flex items-center justify-between gap-3">
                    <span
                      data-selectable
                      className={`text-sm break-all text-cream ${
                        selectedCategoryMeta.usernameMono ? "font-mono" : ""
                      }`}
                    >
                      {selectedEntry.username}
                    </span>
                    <button
                      type="button"
                      onClick={() => void handleCopy(selectedEntry.username, false, "username")}
                      className={smallBtn}
                    >
                      {copiedField === "username" ? (
                        <Check className="h-3.5 w-3.5 text-sage" />
                      ) : (
                        <Copy className="h-3.5 w-3.5" />
                      )}
                      Salin
                    </button>
                  </div>
                </FieldCard>
              )}

              {/* Password / PIN / API Secret Key */}
              <FieldCard
                label={selectedCategoryMeta.detailSecretLabel}
                right={
                  detailStrength && (
                    <span className={`text-[11px] font-medium ${detailStrength.colorClass}`}>
                      {detailStrength.label}
                    </span>
                  )
                }
              >
                <div className="flex items-center justify-between gap-3">
                  <code className="font-mono text-sm break-all text-cream">
                    {showDetailPassword && revealedSecret !== null
                      ? revealedSecret
                      : "•".repeat(Math.min(Math.max(selectedEntry.passwordLength, 8), 24))}
                  </code>
                  <div className="flex shrink-0 items-center gap-1.5">
                    <button
                      type="button"
                      onClick={() => void handleToggleRevealSecret(selectedEntry.id)}
                      className="rounded-lg border border-ink-600 bg-ink-800 p-1.5 text-cream-soft transition hover:border-ink-500 hover:text-cream"
                      title={showDetailPassword ? "Sembunyikan" : "Tampilkan"}
                      aria-label={showDetailPassword ? "Sembunyikan secret" : "Tampilkan secret"}
                    >
                      {showDetailPassword ? (
                        <EyeOff className="h-3.5 w-3.5" />
                      ) : (
                        <Eye className="h-3.5 w-3.5" />
                      )}
                    </button>
                    <button
                      type="button"
                      onClick={() => void handleCopyEntrySecret(selectedEntry.id)}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-honey px-3 py-1.5 text-xs font-semibold text-ink-950 transition hover:bg-[#f8c65a] active:translate-y-px"
                    >
                      {copiedField === "password" ? (
                        <Check className="h-3.5 w-3.5" />
                      ) : (
                        <Copy className="h-3.5 w-3.5" />
                      )}
                      {selectedCategoryMeta.detailCopySecretLabel}
                    </button>
                  </div>
                </div>

                {(detailReusedCount > 1 || (detailStrength && detailStrength.score <= 2)) && (
                  <div className="mt-3 flex items-start gap-2 rounded-xl border border-honey/25 bg-honey/10 p-2.5 text-xs text-cream-soft">
                    <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-honey" />
                    <div>
                      {detailReusedCount > 1 && (
                        <div>
                          Secret/password ini juga dipakai di {detailReusedCount} item berbeda.
                        </div>
                      )}
                      {detailStrength && detailStrength.score <= 2 && (
                        <div>
                          Kekuatan secret/password ini masih {detailStrength.label.toLowerCase()}.
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </FieldCard>

              {/* AI Agent Validation & Access Box (API Key category only) */}
              {selectedEntry.category === "API Key" && (
                <div className="rounded-card border border-sky/20 bg-sky/[0.04] p-4">
                  <div className="mb-1.5 flex items-center justify-between gap-3">
                    <div className="flex items-center gap-2 text-xs font-semibold text-sky">
                      <Bot className="h-4 w-4" />
                      Akses & Validasi Key untuk AI Agent (CLI)
                    </div>
                    <span className="shrink-0 text-[11px] text-mute">
                      {status.biometricEnabled
                        ? "Dijaga Windows Hello"
                        : "Dijaga Dialog Keamanan Windows"}
                    </span>
                  </div>
                  <p className="mb-3 text-xs leading-relaxed text-mute">
                    Berikan perintah ini ke AI Agent agar ia bisa menyuntikkan atau membaca key{" "}
                    <strong className="text-cream-soft">{selectedEntry.title}</strong> dengan
                    persetujuanmu, tanpa menempel key mentah di chat:
                  </p>

                  <div className="space-y-2">
                    <div className="flex items-center justify-between gap-2 rounded-xl border border-ink-700 bg-ink-950 px-3 py-2">
                      <div className="min-w-0 flex-1">
                        <div className="text-[10px] font-medium text-faint">
                          1. Direkomendasikan: Inject ke env variable ({effectiveEnvName}) tanpa bocor di log chat
                        </div>
                        <code className="block truncate font-mono text-[11px] text-sky">
                          {cliRunCommand}&lt;perintah-validasi&gt;
                        </code>
                      </div>
                      <button
                        type="button"
                        onClick={() => void handleCopy(cliRunCommand, false, "cli-run")}
                        className={smallBtn}
                      >
                        {copiedField === "cli-run" ? (
                          <Check className="h-3 w-3 text-sage" />
                        ) : (
                          <Copy className="h-3 w-3" />
                        )}
                        Salin
                      </button>
                    </div>

                    <div className="flex items-center justify-between gap-2 rounded-xl border border-ink-700 bg-ink-950 px-3 py-2">
                      <div className="min-w-0 flex-1">
                        <div className="text-[10px] font-medium text-faint">
                          2. Baca nilai key langsung lewat CLI
                        </div>
                        <code className="block truncate font-mono text-[11px] text-cream-soft">
                          {cliGetCommand}
                        </code>
                      </div>
                      <button
                        type="button"
                        onClick={() => void handleCopy(cliGetCommand, false, "cli-get")}
                        className={smallBtn}
                      >
                        {copiedField === "cli-get" ? (
                          <Check className="h-3 w-3 text-sage" />
                        ) : (
                          <Copy className="h-3 w-3" />
                        )}
                        Salin
                      </button>
                    </div>
                  </div>
                </div>
              )}

              {/* URL */}
              {selectedEntry.url && (
                <FieldCard label={selectedCategoryMeta.detailUrlLabel}>
                  <div className="flex items-center justify-between gap-3">
                    <span className="flex min-w-0 items-center gap-2 text-sm text-honey">
                      <Globe className="h-4 w-4 shrink-0 text-faint" />
                      <span data-selectable className="truncate">
                        {selectedEntry.url}
                      </span>
                    </span>
                    <button
                      type="button"
                      onClick={() => void handleCopy(selectedEntry.url, false)}
                      className={smallBtn}
                    >
                      <ExternalLink className="h-3.5 w-3.5" />
                      Salin URL
                    </button>
                  </div>
                </FieldCard>
              )}

              {/* Notes */}
              {selectedEntry.notes && (
                <FieldCard label="Catatan">
                  <p
                    data-selectable
                    className="text-sm leading-relaxed whitespace-pre-wrap text-cream-soft"
                  >
                    {selectedEntry.notes}
                  </p>
                </FieldCard>
              )}
            </div>
          </div>
        ) : (
          <div className="relative flex flex-1 flex-col items-center justify-center overflow-clip p-8 text-center">
            <div
              aria-hidden
              className="pointer-events-none absolute inset-0"
              style={{
                background:
                  "radial-gradient(circle 320px at 50% 45%, rgb(45 58 89 / 0.24), transparent 75%)",
              }}
            />
            <div className="relative z-10 flex flex-col items-center animate-fade-up">
              <VaultMascot mood="awake" size={150} floating />
              <h2 className="mt-5 font-display text-xl font-semibold text-cream">
                Vault terbuka dan terenkripsi lokal
              </h2>
              <p className="mt-2 max-w-sm text-sm leading-relaxed text-mute">
                Simpan password akun maupun API key sekali-tampil (OpenAI, GitHub, AWS, dll.)
                agar tidak pernah hilang dan bisa diakses AI Agent dengan aman.
              </p>
              <div className="mt-6 flex flex-wrap justify-center gap-2.5">
                <button
                  type="button"
                  onClick={() => {
                    setEditingEntry(null);
                    setFormDefaultCategory("Login");
                    setFormOpen(true);
                  }}
                  className="inline-flex items-center gap-2 rounded-xl bg-honey px-4 py-2.5 text-xs font-semibold text-ink-950 shadow-[0_8px_20px_-8px_rgb(245_183_59/0.5)] transition hover:bg-[#f8c65a] active:translate-y-px"
                >
                  <Plus className="h-4 w-4" />
                  Tambah Akun Login
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setEditingEntry(null);
                    setFormDefaultCategory("API Key");
                    setFormOpen(true);
                  }}
                  className="inline-flex items-center gap-2 rounded-xl border border-sky/30 bg-sky/10 px-4 py-2.5 text-xs font-semibold text-sky transition hover:bg-sky/20"
                >
                  <Terminal className="h-4 w-4" />
                  Simpan API Key / Token
                </button>
              </div>
            </div>
          </div>
        )}

        {toast && (
          <div
            role="status"
            className="fixed right-5 bottom-5 z-50 flex animate-pop-in items-center gap-2.5 rounded-xl border border-ink-600 bg-ink-850 px-4 py-2.5 text-xs font-medium text-cream shadow-pop"
          >
            <span className="h-1.5 w-1.5 rounded-full bg-honey" />
            {toast}
          </div>
        )}
      </main>

      <EntryFormModal
        open={formOpen}
        initialEntry={editingEntry}
        defaultCategory={formDefaultCategory}
        onClose={() => setFormOpen(false)}
        onSave={handleSaveEntry}
      />

      <PasswordGeneratorModal
        open={generatorOpen}
        onClose={() => setGeneratorOpen(false)}
        onCopySensitive={(text) => void handleCopy(text, true)}
      />

      <SettingsModal
        open={settingsOpen}
        status={status}
        onClose={() => setSettingsOpen(false)}
        onStatusChange={setStatus}
        onEntriesImported={async () => {
          const list = await vaultApi.listEntries();
          setEntries(list);
          const nextStatus = await vaultApi.getStatus();
          setStatus(nextStatus);
        }}
      />
    </div>
  );
}

export default App;
