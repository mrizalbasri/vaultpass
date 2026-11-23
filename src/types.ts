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
  exists: boolean;
  unlocked: boolean;
  vaultPath: string;
  entryCount: number;
  autoLockMinutes: number;
  clipboardClearSeconds: number;
  windowsHelloAvailable: boolean;
  biometricEnabled: boolean;
  passwordHint: string | null;
}

export interface VaultEntry {
  id: string;
  title: string;
  username: string;
  password: string;
  url: string;
  category: EntryCategory;
  envVarName: string;
  notes: string;
  favorite: boolean;
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

export interface PasswordGenOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
  excludeAmbiguous: boolean;
}
