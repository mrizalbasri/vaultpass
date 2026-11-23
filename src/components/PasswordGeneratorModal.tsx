import { useCallback, useEffect, useState } from "react";
import { Check, Copy, RefreshCw, X } from "lucide-react";
import { vaultApi } from "../api";
import type { PasswordGenOptions } from "../types";
import { evaluatePasswordStrength } from "../utils/passwordStrength";
import { useEscapeKey } from "../utils/useEscapeKey";

interface PasswordGeneratorModalProps {
  open: boolean;
  onClose: () => void;
  onUsePassword?: (password: string) => void;
  onCopySensitive: (text: string) => void;
}

const DEFAULT_OPTIONS: PasswordGenOptions = {
  length: 20,
  uppercase: true,
  lowercase: true,
  numbers: true,
  symbols: true,
  excludeAmbiguous: true,
};

export function PasswordGeneratorModal({
  open,
  onClose,
  onUsePassword,
  onCopySensitive,
}: PasswordGeneratorModalProps) {
  const [options, setOptions] = useState<PasswordGenOptions>(DEFAULT_OPTIONS);
  const [generated, setGenerated] = useState("");
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const regenerate = useCallback(async (opts: PasswordGenOptions) => {
    setError(null);
    try {
      const pw = await vaultApi.generatePassword(opts);
      setGenerated(pw);
      setCopied(false);
    } catch (err) {
      setError(typeof err === "string" ? err : "Gagal membuat password.");
    }
  }, []);

  useEffect(() => {
    if (open) {
      void regenerate(options);
    }
  }, [open, options, regenerate]);

  useEscapeKey(open, onClose);

  if (!open) return null;

  const strength = evaluatePasswordStrength(generated);

  function updateOption<K extends keyof PasswordGenOptions>(
    key: K,
    value: PasswordGenOptions[K]
  ) {
    setOptions((prev) => {
      const next = { ...prev, [key]: value };
      const hasAnyCharset =
        next.uppercase || next.lowercase || next.numbers || next.symbols;
      if (!hasAnyCharset) {
        return prev;
      }
      return next;
    });
  }

  function handleCopy() {
    if (!generated) return;
    onCopySensitive(generated);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-xs animate-fade-in">
      <div className="w-full max-w-md rounded-2xl border border-ink-700 bg-ink-900 p-6 shadow-pop animate-pop-in">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="font-display text-lg font-semibold text-cream">Password Generator</h2>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-1.5 text-mute hover:bg-ink-700 hover:text-cream"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="rounded-xl border border-ink-700 bg-ink-950 p-3.5">
          <div className="flex items-center justify-between gap-2">
            <code className="break-all font-mono text-sm text-cream">
              {generated || "..."}
            </code>
            <div className="flex shrink-0 items-center gap-1">
              <button
                type="button"
                onClick={() => void regenerate(options)}
                className="rounded-lg p-2 text-mute hover:bg-ink-700 hover:text-cream"
                title="Generate ulang"
              >
                <RefreshCw className="h-4 w-4" />
              </button>
              <button
                type="button"
                onClick={handleCopy}
                className="rounded-lg p-2 text-mute hover:bg-ink-700 hover:text-cream"
                title="Salin password"
              >
                {copied ? (
                  <Check className="h-4 w-4 text-sage" />
                ) : (
                  <Copy className="h-4 w-4" />
                )}
              </button>
            </div>
          </div>

          <div className="mt-3 flex items-center justify-between text-xs">
            <span className="text-faint">Entropy acak via OS CSPRNG</span>
            <span className={strength.colorClass}>{strength.label}</span>
          </div>
          <div className="mt-1.5 grid grid-cols-4 gap-1">
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

        <div className="mt-5 space-y-4">
          <div>
            <div className="mb-1.5 flex items-center justify-between text-xs">
              <span className="font-medium text-cream-soft">Panjang Karakter</span>
              <span className="rounded bg-ink-700 px-2 py-0.5 font-mono text-cream">
                {options.length}
              </span>
            </div>
            <input
              type="range"
              min={8}
              max={64}
              value={options.length}
              onChange={(e) => updateOption("length", Number(e.target.value))}
              className="w-full accent-honey"
            />
          </div>

          <div className="grid grid-cols-2 gap-2.5 text-sm">
            {[
              { key: "uppercase" as const, label: "Huruf Besar (A-Z)" },
              { key: "lowercase" as const, label: "Huruf Kecil (a-z)" },
              { key: "numbers" as const, label: "Angka (0-9)" },
              { key: "symbols" as const, label: "Simbol (!@#$%)" },
            ].map((item) => (
              <label
                key={item.key}
                className="flex cursor-pointer items-center gap-2.5 rounded-xl border border-ink-700 bg-ink-950/60 px-3 py-2 text-xs text-cream hover:border-ink-600"
              >
                <input
                  type="checkbox"
                  checked={options[item.key]}
                  onChange={(e) => updateOption(item.key, e.target.checked)}
                  className="h-4 w-4 rounded accent-honey"
                />
                <span>{item.label}</span>
              </label>
            ))}
          </div>

          <label className="flex cursor-pointer items-center gap-2.5 rounded-xl border border-ink-700 bg-ink-950/60 px-3 py-2 text-xs text-cream-soft hover:border-ink-600">
            <input
              type="checkbox"
              checked={options.excludeAmbiguous}
              onChange={(e) => updateOption("excludeAmbiguous", e.target.checked)}
              className="h-4 w-4 rounded accent-honey"
            />
            <span>Hindari karakter ambigu (0, O, I, l, 1)</span>
          </label>
        </div>

        {error && (
          <p className="mt-3 text-xs text-coral">{error}</p>
        )}

        <div className="mt-6 flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-xl border border-ink-600 px-4 py-2 text-xs font-medium text-cream-soft hover:bg-ink-700"
          >
            Tutup
          </button>
          {onUsePassword && (
            <button
              type="button"
              onClick={() => {
                onUsePassword(generated);
                onClose();
              }}
              className="rounded-xl bg-cream px-4 py-2 text-xs font-medium text-ink-950 hover:bg-[#fff5d2]"
            >
              Pakai Password Ini
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
