import { useId } from "react";

/**
 * Fine film grain drawn with an inline SVG filter. Inline SVG is used on
 * purpose: the Tauri CSP blocks data: image URLs.
 */
export function Grain({ opacity = 0.07 }: { opacity?: number }) {
  const id = `grain-${useId().replace(/:/g, "")}`;
  return (
    <svg
      aria-hidden
      className="pointer-events-none absolute inset-0 h-full w-full mix-blend-overlay"
      style={{ opacity }}
    >
      <filter id={id}>
        <feTurbulence type="fractalNoise" baseFrequency="0.85" numOctaves="2" stitchTiles="stitch" />
        <feColorMatrix type="saturate" values="0" />
      </filter>
      <rect width="100%" height="100%" filter={`url(#${id})`} />
    </svg>
  );
}
