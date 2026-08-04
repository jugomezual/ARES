import { useState, useEffect, useRef } from "react";
import "../styles/Spider.css";

export default function Spider({ onOpen, onLeave, hidden }) {
  const [phase, setPhase] = useState("idle"); // "idle" | "hidden" | "entering"
  const firstRender = useRef(true);

  useEffect(() => {
    if (firstRender.current) { firstRender.current = false; return; }
    if (hidden) {
      setPhase("hidden");
    } else {
      setPhase("entering");
      const t = setTimeout(() => setPhase("idle"), 800);
      return () => clearTimeout(t);
    }
  }, [hidden]);

  const cls = `aracni-root${phase === "hidden" ? " aracni-root--hidden" : phase === "entering" ? " aracni-root--entering" : ""}`;

  return (
    <div
      className={cls}
      onMouseEnter={phase === "idle" ? onOpen : undefined}
      onMouseLeave={phase === "idle" ? onLeave : undefined}
      title="Hablar con Aracni"
    >

      {/*
        Single SVG with overflow:visible.
        The silk thread is a <line> that starts at y=-600 (off-screen top) and
        reaches the spider's attachment point — so thread and body are one element,
        they oscillate together and never separate.
      */}
      <svg
        className="aracni-svg"
        viewBox="0 0 80 90"
        xmlns="http://www.w3.org/2000/svg"
        overflow="visible"
      >
        <defs>
          <filter id="spGlow" x="-120%" y="-120%" width="340%" height="340%">
            <feGaussianBlur in="SourceAlpha" stdDeviation="2.5" result="b" />
            <feFlood floodColor="#cc001a" floodOpacity="0.85" result="c" />
            <feComposite in="c" in2="b" operator="in" result="g" />
            <feMerge>
              <feMergeNode in="g" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* ── Silk thread: extends up off-screen through overflow:visible ── */}
        <line
          x1="40" y1="-600" x2="40" y2="-3"
          stroke="#cc001a" strokeWidth="0.9" strokeOpacity="0.5"
        />

        {/* ── 8 legs — 4 segments each, angular/realistic ── */}
        {/* Legs render BEHIND the body (z-order: legs first) */}
        <g
          className="aracni-legs"
          stroke="#c4001a" strokeWidth="1.1"
          fill="none" strokeLinecap="round" strokeLinejoin="round"
        >
          {/* Left legs */}
          {/* L1 — upper-front: sharp upward */}
          <polyline points="28,12 20,6 12,1 4,-4" />
          {/* L2 — front-mid */}
          <polyline points="27,24 16,22 7,22 0,26" />
          {/* L3 — back-mid */}
          <polyline points="30,38 18,44 8,50 0,56" />
          {/* L4 — lower-back: sharp downward */}
          <polyline points="33,54 22,64 14,74 6,82" />

          {/* Right legs (mirror) */}
          {/* R1 */}
          <polyline points="52,12 60,6 68,1 76,-4" />
          {/* R2 */}
          <polyline points="53,24 64,22 73,22 80,26" />
          {/* R3 */}
          <polyline points="50,38 62,44 72,50 80,56" />
          {/* R4 */}
          <polyline points="47,54 58,64 66,74 74,82" />
        </g>

        {/* ── Abdomen (top — upside-down, elongated teardrop) ── */}
        <ellipse
          cx="40" cy="18" rx="13" ry="21"
          fill="#c4001a"
          filter="url(#spGlow)"
        />

        {/* ── Cephalothorax (bottom — slender) ── */}
        <ellipse
          cx="40" cy="52" rx="9" ry="11"
          fill="#b8001a"
          filter="url(#spGlow)"
        />

        {/* ── Pedicel connecting abdomen and cephalothorax ── */}
        <ellipse cx="40" cy="40" rx="4" ry="3" fill="#a8001a" />
      </svg>

      {/* ── Speech bubble ── */}
      <div className="aracni-bubble">
        Hola, soy Aracni,<br />tu asistente<br />de ataque! 🕷️
        <span className="aracni-arrow" />
      </div>

    </div>
  );
}
