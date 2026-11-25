import { useCallback, useEffect, useRef, useState } from "react";
import { relaunch } from "@tauri-apps/plugin-process";
import { check, type Update } from "@tauri-apps/plugin-updater";

export interface AvailableUpdateInfo {
  version: string;
  body?: string;
  date?: string;
}

export interface UpdaterFeedback {
  type: "ok" | "err" | "info";
  text: string;
}

export interface AppUpdaterState {
  availableUpdate: AvailableUpdateInfo | null;
  dismissed: boolean;
  checking: boolean;
  installing: boolean;
  progressPercent: number | null;
  feedback: UpdaterFeedback | null;
  checkForUpdate: (manual?: boolean) => Promise<void>;
  installUpdate: () => Promise<void>;
  dismissBanner: () => void;
}

export function useAppUpdater(): AppUpdaterState {
  const [availableUpdate, setAvailableUpdate] = useState<AvailableUpdateInfo | null>(null);
  const [dismissed, setDismissed] = useState(false);
  const [checking, setChecking] = useState(false);
  const [installing, setInstalling] = useState(false);
  const [progressPercent, setProgressPercent] = useState<number | null>(null);
  const [feedback, setFeedback] = useState<UpdaterFeedback | null>(null);

  const updateRef = useRef<Update | null>(null);
  const checkingRef = useRef(false);
  const installingRef = useRef(false);

  const replaceUpdateHandle = useCallback((next: Update | null) => {
    const prev = updateRef.current;
    if (prev && prev !== next) {
      void prev.close().catch(() => {});
    }
    updateRef.current = next;
  }, []);

  const checkForUpdate = useCallback(
    async (manual = false) => {
      if (checkingRef.current || installingRef.current) return;
      checkingRef.current = true;
      setChecking(true);
      if (manual) {
        setDismissed(false);
        setFeedback(null);
      }

      try {
        const update = await check();
        if (update) {
          replaceUpdateHandle(update);
          setAvailableUpdate({
            version: update.version,
            body: update.body,
            date: update.date,
          });
          if (manual) {
            setFeedback({
              type: "info",
              text: `Pembaruan v${update.version} tersedia dan siap dipasang.`,
            });
          }
        } else {
          replaceUpdateHandle(null);
          setAvailableUpdate(null);
          if (manual) {
            setFeedback({
              type: "ok",
              text: "VaultPass sudah menggunakan versi paling baru.",
            });
          }
        }
      } catch {
        if (manual) {
          setFeedback({
            type: "err",
            text: "Belum dapat memeriksa pembaruan. Pastikan koneksi internet aktif atau rilis terbaru sudah tersedia di GitHub.",
          });
        }
      } finally {
        checkingRef.current = false;
        setChecking(false);
      }
    },
    [replaceUpdateHandle]
  );

  const installUpdate = useCallback(async () => {
    const update = updateRef.current;
    if (!update || installingRef.current) return;

    installingRef.current = true;
    setInstalling(true);
    setProgressPercent(0);
    setFeedback(null);

    let downloadedBytes = 0;
    let totalBytes = 0;

    try {
      await update.downloadAndInstall((event) => {
        switch (event.event) {
          case "Started":
            totalBytes = event.data.contentLength ?? 0;
            downloadedBytes = 0;
            setProgressPercent(0);
            break;
          case "Progress":
            downloadedBytes += event.data.chunkLength;
            if (totalBytes > 0) {
              const pct = Math.min(100, Math.round((downloadedBytes / totalBytes) * 100));
              setProgressPercent(pct);
            }
            break;
          case "Finished":
            setProgressPercent(100);
            break;
        }
      });

      await relaunch();
    } catch (err) {
      installingRef.current = false;
      setInstalling(false);
      setProgressPercent(null);
      setFeedback({
        type: "err",
        text:
          typeof err === "string"
            ? err
            : "Gagal mengunduh atau memasang pembaruan.",
      });
    }
  }, []);

  const dismissBanner = useCallback(() => {
    if (!installingRef.current) {
      setDismissed(true);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void checkForUpdate(false);
    }, 1200);
    return () => {
      window.clearTimeout(timer);
      replaceUpdateHandle(null);
    };
  }, [checkForUpdate, replaceUpdateHandle]);

  return {
    availableUpdate,
    dismissed,
    checking,
    installing,
    progressPercent,
    feedback,
    checkForUpdate,
    installUpdate,
    dismissBanner,
  };
}
