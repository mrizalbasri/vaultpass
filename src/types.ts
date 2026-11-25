export type EntryCategory =
  | "Login"
  | "API Key"
  | "Finance"
  | "Work"
  | "Personal"
  | "Social"
  | "Other";

export const ENTRY_CATEGORIES: EntryCategory[] = [
  "Login",
  "API Key",
  "Finance",
  "Work",
  "Personal",
  "Social",
  "Other",
];

export interface VaultStatus {
  appVersion: string;
  exists: boolean;
  unlocked: boolean;
  vaultPath: string;
  cliPath: string;
  entryCount: number;
  autoLockMinutes: number;
  clipboardClearSeconds: number;
  windowsHelloAvailable: boolean;
  biometricEnabled: boolean;
  passwordHint: string | null;
  unlockCooldownSeconds: number;
}

export interface VaultEntry {
  id: string;
  title: string;
  username: string;
  url: string;
  category: EntryCategory;
  envVarName: string;
  notes: string;
  favorite: boolean;
  passwordLength: number;
  strengthScore: 0 | 1 | 2 | 3 | 4;
  reusedCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface VaultEntryInput {
  id?: string;
  title: string;
  username: string;
  password: string;
  url: string;
  category: EntryCategory;
  envVarName: string;
  notes: string;
  favorite: boolean;
}

export interface UpsertEntryResponse {
  savedId: string;
  entries: VaultEntry[];
}

export interface PasswordGenOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
  excludeAmbiguous: boolean;
}
