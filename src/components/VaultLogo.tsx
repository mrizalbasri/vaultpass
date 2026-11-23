import { useId } from "react";
import { MascotArt, type MascotMood } from "./VaultMascot";

interface VaultLogoProps {
  size?: number;
  className?: string;
  mood?: MascotMood;
}

/** App icon: the mascot on a charcoal squircle with a soft top light and edge highlight. */
export function VaultLogo({ size = 40, className = "", mood = "awake" }: VaultLogoProps) {
  const uid = useId().replace(/:/g, "");
  const base = `vp-base-${uid}`;
  const edge = `vp-edge-${uid}`;
  const gloss = `vp-gloss-${uid}`;

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 128 128"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      role="img"
      aria-label="VaultPass"
    >
      <defs>
        <linearGradient id={base} x1="64" y1="4" x2="64" y2="124" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#3b372e" />
          <stop offset="1" stopColor="#14120e" />
        </linearGradient>
        <linearGradient id={edge} x1="64" y1="4" x2="64" y2="124" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#ffffff" stopOpacity="0.34" />
          <stop offset="0.5" stopColor="#ffffff" stopOpacity="0.06" />
          <stop offset="1" stopColor="#ffffff" stopOpacity="0.12" />
        </linearGradient>
        <radialGradient
          id={gloss}
          cx="0"
          cy="0"
          r="1"
          gradientUnits="userSpaceOnUse"
          gradientTransform="translate(48 10) rotate(60) scale(84 110)"
        >
          <stop offset="0" stopColor="#f3e9c6" stopOpacity="0.2" />
          <stop offset="1" stopColor="#f3e9c6" stopOpacity="0" />
        </radialGradient>
      </defs>

      <rect x="4" y="4" width="120" height="120" rx="28" fill={`url(#${base})`} />
      <rect x="4" y="4" width="120" height="120" rx="28" fill={`url(#${gloss})`} />
      <rect
        x="4.75"
        y="4.75"
        width="118.5"
        height="118.5"
        rx="27.25"
        stroke={`url(#${edge})`}
        strokeWidth="1.5"
      />

      <g transform="translate(24 20.4) scale(0.8)">
        <MascotArt mood={mood} />
      </g>
    </svg>
  );
}
