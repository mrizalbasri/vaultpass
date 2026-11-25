import type { EntryCategory } from "../types";

export interface PasswordStrengthResult {
  score: 0 | 1 | 2 | 3 | 4;
  label: "Sangat Lemah" | "Lemah" | "Cukup" | "Kuat" | "Sangat Kuat";
  colorClass: string;
  barClass: string;
}

function isSequentialDigits(pin: string): boolean {
  if (pin.length < 2) return false;
  let asc = true;
  let desc = true;
  for (let i = 1; i < pin.length; i += 1) {
    const diff = pin.charCodeAt(i) - pin.charCodeAt(i - 1);
    if (diff !== 1) asc = false;
    if (diff !== -1) desc = false;
  }
  return asc || desc;
}

export function evaluatePasswordStrength(
  password: string,
  category?: EntryCategory
): PasswordStrengthResult {
  if (!password) {
    return {
      score: 0,
      label: "Sangat Lemah",
      colorClass: "text-mute",
      barClass: "bg-ink-600",
    };
  }

  if (category === "Finance" && /^\d{6,8}$/.test(password)) {
    if (/^(.)\1+$/.test(password) || isSequentialDigits(password)) {
      return strengthFromScore(1);
    }
    return strengthFromScore(3);
  }

  let points = 0;
  if (password.length >= 8) points += 1;
  if (password.length >= 12) points += 1;
  if (password.length >= 16) points += 1;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) points += 1;
  if (/\d/.test(password)) points += 1;
  if (/[^A-Za-z0-9]/.test(password)) points += 1;

  // Penalize obvious repeats or short passwords
  if (password.length < 8) {
    points = Math.min(points, 1);
  }
  if (/^(.)\1+$/.test(password)) {
    points = 0;
  }

  if (points <= 1) {
    return strengthFromScore(1);
  }
  if (points <= 3) {
    return strengthFromScore(2);
  }
  if (points <= 4) {
    return strengthFromScore(3);
  }
  return strengthFromScore(4);
}

export function strengthFromScore(score: number): PasswordStrengthResult {
  switch (score) {
    case 0:
      return {
        score: 0,
        label: "Sangat Lemah",
        colorClass: "text-mute",
        barClass: "bg-ink-600",
      };
    case 1:
      return {
        score: 1,
        label: "Lemah",
        colorClass: "text-coral",
        barClass: "bg-coral",
      };
    case 2:
      return {
        score: 2,
        label: "Cukup",
        colorClass: "text-honey",
        barClass: "bg-honey",
      };
    case 3:
      return {
        score: 3,
        label: "Kuat",
        colorClass: "text-sage",
        barClass: "bg-sage",
      };
    default:
      return {
        score: 4,
        label: "Sangat Kuat",
        colorClass: "text-sky",
        barClass: "bg-sky",
      };
  }
}
