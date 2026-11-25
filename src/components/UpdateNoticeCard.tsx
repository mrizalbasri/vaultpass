import { Download, Loader2, X } from "lucide-react";
import type { AppUpdaterState } from "../utils/useAppUpdater";

interface UpdateNoticeCardProps {
  updater?: AppUpdaterState;
  variant?: "banner" | "sidebar";
}

export function UpdateNoticeCard({
  updater,
  variant = "sidebar",
}: UpdateNoticeCardProps) {
  if (!updater?.availableUpdate || updater.dismissed) {
    return null;
  }

  const version = updater.availableUpdate.version;
  const pct = updater.progressPercent ?? 0;

  return (
    <div
      className={
        variant === "banner"
          ? "mb-5 animate-fade-up rounded-xl border border-sky/35 bg-sky/10 p-3.5"
          : "mb-2 rounded-xl border border-sky/35 bg-sky/10 p-2.5"
      }
    >
      <div className="flex items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-1.5 text-xs font-semibold text-sky">
          <Download className="h-3.5 w-3.5 shrink-0" />
          <span className="truncate">Update v{version} tersedia</span>
        </div>
        {!updater.installing && (
          <button
            type="button"
            onClick={updater.dismissBanner}
            aria-label="Tutup pemberitahuan update"
            title="Nanti saja"
            className="shrink-0 rounded-md p-0.5 text-mute transition hover:bg-ink-800 hover:text-cream"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        )}
      </div>

      <button
        type="button"
        disabled={updater.installing}
        onClick={() => void updater.installUpdate()}
        className="mt-2 flex w-full items-center justify-center gap-1.5 rounded-lg bg-sky px-3 py-1.5 text-xs font-semibold text-ink-950 transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-75"
      >
        {updater.installing && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
        {updater.installing
          ? `Mengunduh ${pct}%...`
          : variant === "banner"
            ? "Update Sekarang"
            : "Update & Restart"}
      </button>

      {updater.installing && (
        <div className="mt-2 h-1 w-full overflow-hidden rounded-full bg-ink-800">
          <div
            className="h-full rounded-full bg-sky transition-[width] duration-200"
            style={{ width: `${pct}%` }}
          />
        </div>
      )}

      {updater.feedback?.type === "err" && (
        <p className="mt-1.5 text-[11px] leading-snug text-coral">
          {updater.feedback.text}
        </p>
      )}
    </div>
  );
}
