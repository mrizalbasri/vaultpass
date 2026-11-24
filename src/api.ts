import { invoke } from "@tauri-apps/api/core";
import type {
  PasswordGenOptions,
  UpsertEntryResponse,
  VaultEntry,
  VaultEntryInput,
  VaultStatus,
} from "./types";

export const vaultApi = {
  getStatus: () => invoke<VaultStatus>("vault_status"),

  createVault: (masterPassword: string, passwordHint?: string) =>
    invoke<VaultStatus>("create_vault", {
      masterPassword,
      passwordHint: passwordHint?.trim() || null,
    }),

  updatePasswordHint: (passwordHint: string | null) =>
    invoke<VaultStatus>("update_password_hint", {
      passwordHint: passwordHint?.trim() || null,
    }),

  unlockVault: (masterPassword: string) =>
    invoke<VaultEntry[]>("unlock_vault", { masterPassword }),

  unlockVaultBiometric: () =>
    invoke<VaultEntry[]>("unlock_vault_biometric"),

  enableBiometricUnlock: () =>
    invoke<VaultStatus>("enable_biometric_unlock"),

  disableBiometricUnlock: () =>
    invoke<VaultStatus>("disable_biometric_unlock"),

  lockVault: () => invoke<void>("lock_vault"),

  listEntries: () => invoke<VaultEntry[]>("list_entries"),

  revealEntrySecret: (id: string) =>
    invoke<string>("reveal_entry_secret", { id }),

  copyEntrySecret: (id: string) =>
    invoke<number>("copy_entry_secret", { id }),

  upsertEntry: (entry: VaultEntryInput) =>
    invoke<UpsertEntryResponse>("upsert_entry", { entry }),

  deleteEntry: (id: string) => invoke<VaultEntry[]>("delete_entry", { id }),

  toggleFavorite: (id: string) =>
    invoke<VaultEntry[]>("toggle_favorite", { id }),

  changeMasterPassword: (currentPassword: string, newPassword: string) =>
    invoke<void>("change_master_password", { currentPassword, newPassword }),

  updateSettings: (autoLockMinutes: number, clipboardClearSeconds: number) =>
    invoke<VaultStatus>("update_settings", {
      autoLockMinutes,
      clipboardClearSeconds,
    }),

  generatePassword: (options: PasswordGenOptions) =>
    invoke<string>("generate_password", { options }),

  copySecret: (text: string, isSensitive: boolean) =>
    invoke<number>("copy_secret", { text, isSensitive }),

  exportEncryptedBackup: () =>
    invoke<string | null>("export_encrypted_backup"),

  importEncryptedBackup: (backupPassword: string) =>
    invoke<number>("import_encrypted_backup", { backupPassword }),

  pickVaultSaveLocation: () =>
    invoke<VaultStatus | null>("pick_vault_save_location"),

  pickExistingVaultFile: () =>
    invoke<VaultStatus | null>("pick_existing_vault_file"),
};
