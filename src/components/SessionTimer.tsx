import { useCallback, useEffect, useRef, useState } from "react";
import { Timer, TimerOff } from "lucide-react";
import { VaultLogo } from "./VaultLogo";

const WARNING_SECONDS = 30;
const ACTIVITY_EVENTS = ["mousedown", "keydown", "mousemove", "scroll"] as const;

interface SessionTimerProps {
  /** Idle minutes before the vault locks. 0 or less disables auto-lock. */
  minutes: number;
  onLock: () => void;
}

function formatClock(totalSeconds: number) {
  const m = Math.floor(totalSeconds / 60);
  const s = totalSeconds % 60;
  return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

/**
 * Owns the idle auto-lock timer. Renders a countdown chip (for the sidebar) and,
 * during the last 30 seconds, a floating warning with a "stay active" button.
 */
export function SessionTimer({ minutes, onLock }: SessionTimerProps) {
  const enabled = minutes > 0;
  const totalSeconds = Math.max(0, Math.round(minutes * 60));
  const [remaining, setRemaining] = useState(totalSeconds);

  const deadline = useRef(Date.now() + totalSeconds * 1000);
  const locked = useRef(false);
  const onLockRef = useRef(onLock);

  useEffect(() => {
    onLockRef.current = onLock;
  }, [onLock]);

  const extend = useCallback(() => {
    deadline.current = Date.now() + totalSeconds * 1000;
    setRemaining(totalSeconds);
  }, [totalSeconds]);

  useEffect(() => {
    if (!enabled) return;
    locked.current = false;
    extend();

    const tick = () => {
      const left = Math.max(0, Math.ceil((deadline.current - Date.now()) / 1000));
      setRemaining(left);
      if (left <= 0 && !locked.current) {
        locked.current = true;
        onLockRef.current();
      }
    };

    const onActivity = (e: Event) => {
      const left = (deadline.current - Date.now()) / 1000;
      // During the warning, ignore incidental pointer movement. Deliberate
      // input (click/key) or the button keeps the session alive.
      if (left <= WARNING_SECONDS && (e.type === "mousemove" || e.type === "scroll")) {
        return;
      }
      extend();
    };

    const id = window.setInterval(tick, 1000);
    for (const evt of ACTIVITY_EVENTS) {
      window.addEventListener(evt, onActivity, { passive: true });
    }
    return () => {
      window.clearInterval(id);
      for (const evt of ACTIVITY_EVENTS) {
        window.removeEventListener(evt, onActivity);
      }
    };
  }, [enabled, extend]);

  if (!enabled) {
    return (
      <div className="flex items-center gap-2 rounded-xl px-3 py-2 text-[11px] text-faint">
        <TimerOff className="h-3.5 w-3.5" />
        Auto-lock nonaktif
      </div>
    );
  }

  const warning = remaining <= WARNING_SECONDS;
  const soon = remaining <= 60;
  const progress = totalSeconds > 0 ? remaining / totalSeconds : 0;

  return (
    <>
      <div
        className="rounded-xl border border-ink-700 bg-ink-850 px-3 py-2"
        title="Vault terkunci otomatis saat tidak ada aktivitas"
      >
        <div className="flex items-center justify-between text-[11px]">
          <span
            className={`flex items-center gap-1.5 ${
              warning ? "text-coral" : soon ? "text-honey" : "text-mute"
            }`}
          >
            <Timer className="h-3.5 w-3.5" />
            Terkunci dalam
          </span>
          <span
            className={`font-mono font-medium tabular-nums ${
              warning ? "text-coral" : soon ? "text-honey" : "text-cream-soft"
            }`}
          >
            {formatClock(remaining)}
          </span>
        </div>
        <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-ink-700">
          <div
            className={`h-full rounded-full transition-[width] duration-1000 ease-linear ${
              warning ? "bg-coral" : soon ? "bg-honey" : "bg-cream/70"
            }`}
            style={{ width: `${progress * 100}%` }}
          />
        </div>
      </div>

      {warning && (
        <div
          role="alertdialog"
          aria-live="assertive"
          aria-label="Vault akan segera terkunci"
          className="fixed bottom-5 left-1/2 z-[60] flex w-[min(92vw,26rem)] -translate-x-1/2 animate-pop-in items-center gap-3 rounded-2xl border border-honey/30 bg-ink-850 p-3 pr-3.5 shadow-pop"
        >
          <VaultLogo size={40} mood="sleeping" className="shrink-0" />
          <div className="min-w-0 flex-1">
            <div className="font-display text-sm font-semibold text-cream">
              Vault terkunci dalam {remaining} detik
            </div>
            <div className="text-[11px] text-mute">Tidak ada aktivitas terdeteksi.</div>
          </div>
          <button
            type="button"
            onClick={extend}
            className="shrink-0 rounded-xl bg-cream px-3.5 py-2 text-xs font-semibold text-ink-950 transition hover:bg-[#fff5d2] active:translate-y-px"
          >
            Tetap aktif
          </button>
        </div>
      )}
    </>
  );
}
