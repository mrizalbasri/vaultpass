export type MascotMood = "sleeping" | "awake" | "shocked" | "happy";

const BODY = "#f3e9c6";
const INK = "#1a1812";
const BLUSH = "#e9b44c";

const fade = (visible: boolean) => ({
  opacity: visible ? 1 : 0,
  transition: "opacity 0.22s ease",
});

const eyeBox = { transformBox: "fill-box", transformOrigin: "center" } as const;

interface MascotArtProps {
  mood: MascotMood;
}

/**
 * The vault mascot drawn in a 100x100 box (content spans x 14..86, y 20..89).
 * Reused by the standalone mascot and by the app logo.
 */
export function MascotArt({ mood }: MascotArtProps) {
  return (
    <g>
      {/* feet */}
      <rect x="26" y="78" width="17" height="11" rx="5.5" fill={BODY} />
      <rect x="57" y="78" width="17" height="11" rx="5.5" fill={BODY} />

      {/* body */}
      <rect x="14" y="20" width="72" height="64" rx="21" fill={BODY} />

      {/* door seam + dial */}
      <path
        d="M68 31V73"
        stroke={INK}
        strokeOpacity="0.9"
        strokeWidth="3.2"
        strokeLinecap="round"
      />
      <circle cx="77.2" cy="52" r="3.4" stroke={INK} strokeWidth="2.4" fill="none" />
      <circle cx="77.2" cy="52" r="0.9" fill={INK} />

      {/* sleeping */}
      <g style={fade(mood === "sleeping")}>
        <path
          d="M26 48Q31 53.5 36 48M46 48Q51 53.5 56 48"
          stroke={INK}
          strokeWidth="3.1"
          strokeLinecap="round"
          fill="none"
        />
        <path
          d="M37.5 62Q41 64.6 44.5 62"
          stroke={INK}
          strokeWidth="2.8"
          strokeLinecap="round"
          fill="none"
        />
      </g>

      {/* awake */}
      <g style={fade(mood === "awake")}>
        <g className="animate-blink" style={eyeBox}>
          <ellipse cx="31" cy="47" rx="4.3" ry="6.4" fill={INK} />
          <circle cx="32.4" cy="44.4" r="1.5" fill={BODY} />
        </g>
        <g className="animate-blink" style={eyeBox}>
          <ellipse cx="51" cy="47" rx="4.3" ry="6.4" fill={INK} />
          <circle cx="52.4" cy="44.4" r="1.5" fill={BODY} />
        </g>
        <path
          d="M34.5 60.5Q41 67.5 47.5 60.5"
          stroke={INK}
          strokeWidth="3.1"
          strokeLinecap="round"
          fill="none"
        />
      </g>

      {/* shocked */}
      <g style={fade(mood === "shocked")}>
        <ellipse cx="30" cy="46" rx="5.2" ry="7.8" fill={INK} />
        <circle cx="31.6" cy="43" r="1.7" fill={BODY} />
        <ellipse cx="52" cy="46" rx="5.2" ry="7.8" fill={INK} />
        <circle cx="53.6" cy="43" r="1.7" fill={BODY} />
        <ellipse cx="41" cy="64.5" rx="3.5" ry="4.6" fill={INK} />
      </g>

      {/* happy */}
      <g style={fade(mood === "happy")}>
        <path
          d="M26 50Q31 43 36 50M46 50Q51 43 56 50"
          stroke={INK}
          strokeWidth="3.2"
          strokeLinecap="round"
          fill="none"
        />
        <path d="M33.5 58.5Q41 73 48.5 58.5Z" fill={INK} stroke={INK} strokeWidth="2" strokeLinejoin="round" />
        <circle cx="22.5" cy="58" r="3.4" fill={BLUSH} fillOpacity="0.55" />
        <circle cx="59.5" cy="58" r="3.4" fill={BLUSH} fillOpacity="0.55" />
      </g>
    </g>
  );
}

interface VaultMascotProps {
  mood?: MascotMood;
  size?: number;
  floating?: boolean;
  className?: string;
}

export function VaultMascot({
  mood = "awake",
  size = 160,
  floating = false,
  className = "",
}: VaultMascotProps) {
  const motion =
    mood === "shocked" ? "animate-shake" : mood === "happy" ? "animate-hop" : "";
  return (
    <div className={`${floating ? "animate-float" : ""} ${className}`}>
      <svg
        width={size}
        height={size}
        viewBox="0 0 100 100"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        role="img"
        aria-label="Maskot VaultPass"
        className={motion}
      >
        <MascotArt mood={mood} />
      </svg>
    </div>
  );
}
