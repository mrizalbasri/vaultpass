import { useEffect, useRef, useState } from "react";
import {
  AlertTriangle,
  Eye,
  EyeOff,
  Fingerprint,
  FolderOpen,
  FolderPlus,
  HardDrive,
  HelpCircle,
  KeyRound,
  Lightbulb,
  Loader2,
  ShieldCheck,
} from "lucide-react";
import { evaluatePasswordStrength } from "../utils/passwordStrength";
import { Grain } from "./Grain";
import { VaultLogo } from "./VaultLogo";
import { VaultMascot, type MascotMood } from "./VaultMascot";

interface LockScreenProps {
  vaultExists: boolean;
  vaultPath: string;
  biometricEnabled: boolean;
  passwordHint: string | null;
  onCreateVault: (masterPassword: string, passwordHint?: string) => Promise<void>;
  onUnlockVault: (masterPassword: string) => Promise<void>;
  onUnlockBiometric: () => Promise<void>;
  onPickSaveLocation: () => Promise<void>;
  onPickExistingFile: () => Promise<void>;
}

const inputBase =
  "w-full rounded-xl border border-ink-700 bg-ink-950 text-sm text-cream placeholder:text-faint outline-none transition focus:border-honey/70 focus:ring-4 focus:ring-honey/10";

export function LockScreen({
  vaultExists,
  vaultPath,
  biometricEnabled,
  passwordHint,
  onCreateVault,
  onUnlockVault,
  onUnlockBiometric,
  onPickSaveLocation,
  onPickExistingFile,
}: LockScreenProps) {
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [newHint, setNewHint] = useState("");
  const [showHint, setShowHint] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [bioLoading, setBioLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [focused, setFocused] = useState(false);
  const [shocked, setShocked] = useState(false);

  const fieldRef = useRef<HTMLDivElement>(null);
  const strength = evaluatePasswordStrength(password);

  useEffect(() => {
    if (!shocked) return;
    const id = window.setTimeout(() => setShocked(false), 1800);
    return () => window.clearTimeout(id);
  }, [shocked]);

  function fail(message: string) {
    setError(message);
    setShocked(true);
    fieldRef.current?.animate(
      [
        { transform: "translateX(0)" },
        { transform: "translateX(-8px)" },
        { transform: "translateX(7px)" },
        { transform: "translateX(-5px)" },
        { transform: "translateX(3px)" },
        { transform: "translateX(0)" },
      ],
      { duration: 420, easing: "ease-out" }
    );
  }

  const mood: MascotMood = shocked
    ? "shocked"
    : !vaultExists && password.length > 0 && strength.score >= 3
      ? "happy"
      : focused || loading || bioLoading || password.length > 0
        ? "awake"
        : "sleeping";

  async function handleBiometric() {
    setError(null);
    setBioLoading(true);
    try {
      await onUnlockBiometric();
    } catch (err) {
      fail(typeof err === "string" ? err : "Gagal verifikasi Windows Hello.");
    } finally {
      setBioLoading(false);
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (!vaultExists) {
      if (password.length < 10) {
        fail("Master password minimal 10 karakter agar vault benar-benar aman.");
        return;
      }
      if (password !== confirmPassword) {
        fail("Konfirmasi master password tidak cocok.");
        return;
      }
      if (newHint.trim() && newHint.trim().toLowerCase() === password.trim().toLowerCase()) {
        fail("Pengingat tidak boleh sama persis dengan master password kamu.");
        return;
      }
    } else if (!password) {
      fail("Masukkan master password.");
      return;
    }

    setLoading(true);
    try {
      if (vaultExists) {
        await onUnlockVault(password);
      } else {
        await onCreateVault(password, newHint);
      }
      setPassword("");
      setConfirmPassword("");
      setNewHint("");
    } catch (err) {
      fail(typeof err === "string" ? err : "Gagal membuka vault.");
      if (vaultExists && passwordHint) {
        setShowHint(true);
      }
    } finally {
      setLoading(false);
    }
  }

  const busy = loading || bioLoading;

  return (
    <div className="relative flex h-screen overflow-hidden bg-ink-950 text-cream-soft">
      {/* Brand side */}
      <section className="relative hidden flex-1 items-center justify-center overflow-hidden md:flex">
        <div
          aria-hidden
          className="absolute inset-0"
          style={{
            background:
              "radial-gradient(ellipse 60% 55% at 50% 46%, rgb(233 180 76 / 0.13), transparent 70%)",
          }}
        />
        <div aria-hidden className="dial-rings absolute inset-0" />
        <Grain opacity={0.09} />

        <div className="relative z-10 flex flex-col items-center px-10 text-center">
          <div className="relative animate-fade-up">
            <VaultMascot mood={mood} size={236} floating />
            <div
              aria-hidden
              className="mx-auto -mt-1 h-3 w-28 rounded-[50%] bg-black/60 blur-md"
            />
          </div>
          <h1
            className="mt-9 animate-fade-up font-display text-5xl font-semibold tracking-tight text-cream"
            style={{ animationDelay: "90ms" }}
          >
            VaultPass
          </h1>
          <p
            className="mt-3 max-w-xs animate-fade-up text-sm leading-relaxed text-mute"
            style={{ animationDelay: "170ms" }}
          >
            Brankas password pribadimu. Terkunci rapat dan tersimpan di komputermu sendiri.
          </p>
          <div
            className="mt-7 flex animate-fade-up flex-wrap justify-center gap-2"
            style={{ animationDelay: "250ms" }}
          >
            {[
              { icon: ShieldCheck, label: "AES-256-GCM" },
              { icon: KeyRound, label: "Argon2id" },
              { icon: HardDrive, label: "100% offline" },
            ].map(({ icon: Icon, label }) => (
              <span
                key={label}
                className="inline-flex items-center gap-1.5 rounded-full border border-ink-700 bg-ink-900/70 px-3 py-1 text-[11px] font-medium text-cream-soft backdrop-blur"
              >
                <Icon className="h-3.5 w-3.5 text-honey" />
                {label}
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* Form side */}
      <section className="relative flex w-full shrink-0 overflow-y-auto border-ink-700 bg-ink-900 md:w-[460px] md:border-l">
        <div className="m-auto w-full max-w-sm px-7 py-9">
          <div className="mb-7 animate-fade-up">
            <VaultLogo size={46} mood={mood} className="mb-5 md:hidden" />
            <h2 className="font-display text-3xl font-semibold tracking-tight text-cream">
              {vaultExists ? "Selamat datang kembali" : "Buat vault pertamamu"}
            </h2>
            <p className="mt-2 text-sm leading-relaxed text-mute">
              {vaultExists
                ? "Buka dengan sidik jari Windows Hello atau master password."
                : "Satu master password untuk semua akun dan API key. Dienkripsi penuh di perangkat ini."}
            </p>
          </div>

          {vaultExists && biometricEnabled && (
            <div className="mb-5 animate-fade-up" style={{ animationDelay: "60ms" }}>
              <button
                type="button"
                disabled={busy}
                onClick={() => void handleBiometric()}
                className="group flex h-12 w-full items-center justify-center gap-2.5 rounded-xl border border-ink-600 bg-ink-800 text-sm font-medium text-cream transition hover:border-honey/50 hover:bg-ink-700 disabled:opacity-60"
              >
                {bioLoading ? (
                  <Loader2 className="h-5 w-5 animate-spin text-honey" />
                ) : (
                  <Fingerprint className="h-5 w-5 text-honey transition group-hover:scale-110" />
                )}
                {bioLoading ? "Menunggu Windows Hello..." : "Buka dengan Windows Hello"}
              </button>
              <div className="my-4 flex items-center gap-3 text-[11px] text-faint">
                <div className="h-px flex-1 bg-ink-700" />
                <span>atau pakai master password</span>
                <div className="h-px flex-1 bg-ink-700" />
              </div>
            </div>
          )}

          <form
            onSubmit={handleSubmit}
            onFocus={() => setFocused(true)}
            onBlur={() => setFocused(false)}
            className="animate-fade-up space-y-4"
            style={{ animationDelay: "110ms" }}
          >
            <div>
              <div className="mb-1.5 flex items-center justify-between">
                <label htmlFor="master-password" className="text-xs font-medium text-cream-soft">
                  Master password
                </label>
                {vaultExists && passwordHint && (
                  <button
                    type="button"
                    onClick={() => setShowHint((prev) => !prev)}
                    className="inline-flex items-center gap-1 text-[11px] font-medium text-honey hover:text-cream"
                  >
                    <HelpCircle className="h-3.5 w-3.5" />
                    {showHint ? "Sembunyikan pengingat" : "Lihat pengingat"}
                  </button>
                )}
              </div>
              <div ref={fieldRef} className="relative">
                <KeyRound className="pointer-events-none absolute top-1/2 left-3.5 h-4 w-4 -translate-y-1/2 text-faint" />
                <input
                  id="master-password"
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoFocus
                  autoComplete={vaultExists ? "current-password" : "new-password"}
                  placeholder={
                    vaultExists ? "Masukkan master password" : "Minimal 10 karakter"
                  }
                  className={`${inputBase} h-11 pr-11 pl-10 ${
                    error ? "border-coral/60!" : ""
                  }`}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((prev) => !prev)}
                  className="absolute top-1/2 right-2 -translate-y-1/2 rounded-lg p-1.5 text-mute transition hover:bg-ink-700 hover:text-cream"
                  title={showPassword ? "Sembunyikan" : "Tampilkan"}
                  aria-label={showPassword ? "Sembunyikan password" : "Tampilkan password"}
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>

              {vaultExists && showHint && passwordHint && (
                <div className="mt-2.5 flex animate-pop-in items-start gap-2 rounded-xl border border-honey/25 bg-honey/10 px-3 py-2.5 text-xs text-cream-soft">
                  <Lightbulb className="mt-0.5 h-4 w-4 shrink-0 text-honey" />
                  <div>
                    <span className="font-semibold text-cream">Pengingatmu: </span>
                    <span>{passwordHint}</span>
                  </div>
                </div>
              )}

              {!vaultExists && password.length > 0 && (
                <div className="mt-2.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-mute">Kekuatan password</span>
                    <span className={`font-medium ${strength.colorClass}`}>{strength.label}</span>
                  </div>
                  <div className="mt-1.5 grid grid-cols-4 gap-1.5">
                    {[1, 2, 3, 4].map((step) => (
                      <div
                        key={step}
                        className={`h-1.5 rounded-full transition-colors duration-300 ${
                          strength.score >= step ? strength.barClass : "bg-ink-700"
                        }`}
                      />
                    ))}
                  </div>
                </div>
              )}
            </div>

            {!vaultExists && (
              <>
                <div>
                  <label
                    htmlFor="confirm-password"
                    className="mb-1.5 block text-xs font-medium text-cream-soft"
                  >
                    Konfirmasi master password
                  </label>
                  <input
                    id="confirm-password"
                    type={showPassword ? "text" : "password"}
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    autoComplete="new-password"
                    placeholder="Ketik ulang master password"
                    className={`${inputBase} h-11 px-3.5`}
                  />
                </div>

                <div>
                  <label
                    htmlFor="password-hint"
                    className="mb-1.5 flex items-center gap-1.5 text-xs font-medium text-cream-soft"
                  >
                    <Lightbulb className="h-3.5 w-3.5 text-honey" />
                    Pengingat saat login
                    <span className="font-normal text-faint">(opsional)</span>
                  </label>
                  <input
                    id="password-hint"
                    type="text"
                    value={newHint}
                    onChange={(e) => setNewHint(e.target.value)}
                    placeholder="Contoh: nama panggilan + tahun motor pertama"
                    className={`${inputBase} h-11 px-3.5 text-xs`}
                  />
                </div>

                <div className="flex items-start gap-2.5 rounded-xl border border-honey/20 bg-honey/[0.07] p-3 text-xs leading-relaxed text-cream-soft">
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-honey" />
                  <span>
                    Master password tidak disimpan di mana pun dan tidak bisa dipulihkan. Isi{" "}
                    <strong className="text-cream">pengingat</strong> agar kamu tidak lupa.
                  </span>
                </div>
              </>
            )}

            {error && (
              <div
                role="alert"
                className="flex animate-pop-in items-start gap-2 rounded-xl border border-coral/30 bg-coral/10 px-3.5 py-2.5 text-xs text-coral"
              >
                <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={busy}
              className="flex h-11 w-full items-center justify-center gap-2 rounded-xl bg-cream text-sm font-semibold text-ink-950 shadow-[0_8px_24px_-8px_rgb(243_233_198/0.45)] transition hover:bg-[#fff5d2] active:translate-y-px disabled:cursor-not-allowed disabled:opacity-60"
            >
              {loading && <Loader2 className="h-4 w-4 animate-spin" />}
              {loading
                ? vaultExists
                  ? "Membuka vault..."
                  : "Membuat vault..."
                : vaultExists
                  ? "Buka vault"
                  : "Buat dan enkripsi vault"}
            </button>
          </form>

          {/* Vault location */}
          <div
            className="surface mt-6 animate-fade-up rounded-xl p-3.5"
            style={{ animationDelay: "170ms" }}
          >
            <div className="text-[11px] font-medium text-mute">Lokasi vault</div>
            <div
              className="mt-1 truncate font-mono text-[11px] text-cream-soft"
              title={vaultPath}
            >
              {vaultPath}
            </div>
            <div className="mt-3 flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => void onPickSaveLocation()}
                className="inline-flex flex-1 items-center justify-center gap-1.5 rounded-lg border border-ink-600 bg-ink-800 px-2.5 py-1.5 text-[11px] font-medium text-cream-soft transition hover:border-ink-500 hover:text-cream"
              >
                <FolderPlus className="h-3.5 w-3.5 text-honey" />
                {vaultExists ? "Pindah lokasi" : "Pilih lokasi"}
              </button>
              <button
                type="button"
                onClick={() => void onPickExistingFile()}
                className="inline-flex flex-1 items-center justify-center gap-1.5 rounded-lg border border-ink-600 bg-ink-800 px-2.5 py-1.5 text-[11px] font-medium text-cream-soft transition hover:border-ink-500 hover:text-cream"
              >
                <FolderOpen className="h-3.5 w-3.5 text-honey" />
                Buka file .vpass
              </button>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
