const menuItems = [
  { id: "dashboard",           icon: "fas fa-tachometer-alt",  label: "Dashboard" },
  { id: "network-scan",        icon: "fas fa-search",          label: "Network Scan" },
  { id: "exploitation",        icon: "fas fa-skull-crossbones",label: "Exploitation" },
  { id: "session-manager",     icon: "fas fa-satellite-dish",  label: "Sessions" },
  { id: "results",             icon: "fas fa-file-alt",        label: "Results & Reports" },
  { id: "settings",            icon: "fas fa-cogs",            label: "Settings" },
  { id: "auth",                icon: "fas fa-user-shield",     label: "Authentication" },
  { id: "ai-assistant",        icon: "fas fa-robot",           label: "AI Assistant" },
];

export default function Sidebar({ activePage, onNavigate }) {
  return (
    <div className="sidebar">

      {/* ── Network-graph background — z-index:-1 dentro del stacking context
            del sidebar (creado por sidebarFadeSlideIn que anima opacity+transform).
            .sidebar tiene overflow:hidden → el SVG NUNCA scrollea.
            preserveAspectRatio="xMidYMid slice" → rellena todo el rectángulo. ── */}
      <svg className="sidebar-tribal" aria-hidden="true"
        xmlns="http://www.w3.org/2000/svg" viewBox="0 0 250 700"
        preserveAspectRatio="xMidYMid slice">
        <defs>
          <filter id="sNeon" x="-30%" y="-30%" width="160%" height="160%">
            <feGaussianBlur in="SourceAlpha" stdDeviation="5"   result="bigB"/>
            <feGaussianBlur in="SourceAlpha" stdDeviation="1.5" result="smlB"/>
            <feFlood floodColor="#ff0022" floodOpacity="0.65" result="bigC"/>
            <feFlood floodColor="#ff6677" floodOpacity="0.40" result="smlC"/>
            <feComposite in="bigC" in2="bigB" operator="in" result="bigG"/>
            <feComposite in="smlC" in2="smlB" operator="in" result="smlG"/>
            <feMerge>
              <feMergeNode in="bigG"/>
              <feMergeNode in="smlG"/>
              <feMergeNode in="SourceGraphic"/>
            </feMerge>
          </filter>
        </defs>

        {/* ── Primary edges ── */}
        <g stroke="#cc1133" strokeWidth="0.7" fill="none" filter="url(#sNeon)">
          <line x1="35"  y1="55"  x2="190" y2="35"/>
          <line x1="35"  y1="55"  x2="25"  y2="195"/>
          <line x1="190" y1="35"  x2="225" y2="115"/>
          <line x1="190" y1="35"  x2="105" y2="125"/>
          <line x1="225" y1="115" x2="105" y2="125"/>
          <line x1="225" y1="115" x2="215" y2="255"/>
          <line x1="105" y1="125" x2="25"  y2="195"/>
          <line x1="105" y1="125" x2="165" y2="185"/>
          <line x1="25"  y1="195" x2="75"  y2="295"/>
          <line x1="165" y1="185" x2="215" y2="255"/>
          <line x1="165" y1="185" x2="75"  y2="295"/>
          <line x1="215" y1="255" x2="215" y2="375"/>
          <line x1="75"  y1="295" x2="145" y2="345"/>
          <line x1="145" y1="345" x2="215" y2="375"/>
          <line x1="145" y1="345" x2="45"  y2="415"/>
          <line x1="145" y1="345" x2="175" y2="445"/>
          <line x1="45"  y1="415" x2="95"  y2="515"/>
          <line x1="175" y1="445" x2="215" y2="505"/>
          <line x1="175" y1="445" x2="95"  y2="515"/>
          <line x1="95"  y1="515" x2="35"  y2="575"/>
          <line x1="95"  y1="515" x2="215" y2="505"/>
          <line x1="215" y1="505" x2="185" y2="615"/>
          <line x1="35"  y1="575" x2="115" y2="645"/>
          <line x1="185" y1="615" x2="115" y2="645"/>
        </g>

        {/* ── Secondary dashed cross-edges ── */}
        <g stroke="#881122" strokeWidth="0.5" strokeDasharray="3 7" fill="none">
          <line x1="35"  y1="55"  x2="165" y2="185"/>
          <line x1="75"  y1="295" x2="215" y2="375"/>
          <line x1="45"  y1="415" x2="175" y2="445"/>
          <line x1="35"  y1="575" x2="185" y2="615"/>
        </g>

        {/* ── Node rings ── */}
        <g fill="none" stroke="#ff2244" filter="url(#sNeon)">
          <circle cx="35"  cy="55"  r="5"  strokeWidth="1.2"/>
          <circle cx="190" cy="35"  r="6"  strokeWidth="1.4"/>
          <circle cx="225" cy="115" r="4"  strokeWidth="1.1"/>
          <circle cx="105" cy="125" r="5"  strokeWidth="1.2"/>
          <circle cx="25"  cy="195" r="4"  strokeWidth="1.1"/>
          <circle cx="165" cy="185" r="6"  strokeWidth="1.4"/>
          <circle cx="215" cy="255" r="4"  strokeWidth="1.1"/>
          <circle cx="75"  cy="295" r="5"  strokeWidth="1.2"/>
          <circle cx="145" cy="345" r="8"  strokeWidth="1.8"/>
          <circle cx="215" cy="375" r="4"  strokeWidth="1.1"/>
          <circle cx="45"  cy="415" r="4"  strokeWidth="1.1"/>
          <circle cx="175" cy="445" r="6"  strokeWidth="1.4"/>
          <circle cx="95"  cy="515" r="5"  strokeWidth="1.2"/>
          <circle cx="215" cy="505" r="4"  strokeWidth="1.1"/>
          <circle cx="35"  cy="575" r="4"  strokeWidth="1.1"/>
          <circle cx="185" cy="615" r="5"  strokeWidth="1.2"/>
          <circle cx="115" cy="645" r="6"  strokeWidth="1.4"/>
        </g>

        {/* ── Node filled centers ── */}
        <g fill="#cc1133">
          <circle cx="35"  cy="55"  r="2.5"/>
          <circle cx="190" cy="35"  r="3"/>
          <circle cx="225" cy="115" r="2"/>
          <circle cx="105" cy="125" r="2.5"/>
          <circle cx="25"  cy="195" r="2"/>
          <circle cx="165" cy="185" r="3"/>
          <circle cx="215" cy="255" r="2"/>
          <circle cx="75"  cy="295" r="2.5"/>
          <circle cx="145" cy="345" r="4"/>
          <circle cx="215" cy="375" r="2"/>
          <circle cx="45"  cy="415" r="2"/>
          <circle cx="175" cy="445" r="3"/>
          <circle cx="95"  cy="515" r="2.5"/>
          <circle cx="215" cy="505" r="2"/>
          <circle cx="35"  cy="575" r="2"/>
          <circle cx="185" cy="615" r="2.5"/>
          <circle cx="115" cy="645" r="3"/>
        </g>

        {/* ── Target brackets around hub node (145,345) ── */}
        <g stroke="#ff3344" strokeWidth="1.1" fill="none" filter="url(#sNeon)">
          <polyline points="130,330 130,337 137,337"/>
          <polyline points="160,330 160,337 153,337"/>
          <polyline points="130,360 130,353 137,353"/>
          <polyline points="160,360 160,353 153,353"/>
        </g>
      </svg>

      {/* ── All scrollable sidebar content lives here ── */}
      <div className="sidebar-inner">
        <div className="sidebar-header">
          {/* ── Spider blackout logo ── */}
          <svg className="logo-spider" viewBox="0 0 70 60"
            xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
            {/* Patas izquierda */}
            <polyline points="26,18 11,7 3,13"   fill="none" stroke="#cc1133" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"/>
            <polyline points="24,24 7,18 0,27"    fill="none" stroke="#cc1133" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"/>
            <polyline points="24,29 7,35 0,43"    fill="none" stroke="#cc1133" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"/>
            <polyline points="26,34 11,46 3,42"   fill="none" stroke="#cc1133" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"/>
            {/* Patas derecha */}
            <polyline points="44,18 59,7 67,13"   fill="none" stroke="#cc1133" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"/>
            <polyline points="46,24 63,18 70,27"  fill="none" stroke="#cc1133" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"/>
            <polyline points="46,29 63,35 70,43"  fill="none" stroke="#cc1133" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"/>
            <polyline points="44,34 59,46 67,42"  fill="none" stroke="#cc1133" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"/>
            {/* Cefalotórax */}
            <ellipse cx="35" cy="22" rx="9" ry="8" fill="#cc1133"/>
            {/* Quelíceros (colmillos) */}
            <path d="M 30,29 C 28,33 27,37 29,41" fill="none" stroke="#cc1133" strokeWidth="1.8" strokeLinecap="round"/>
            <path d="M 40,29 C 42,33 43,37 41,41" fill="none" stroke="#cc1133" strokeWidth="1.8" strokeLinecap="round"/>
            {/* Abdomen */}
            <ellipse cx="35" cy="43" rx="13" ry="15" fill="#cc1133"/>
            {/* Ojos */}
            <circle cx="31" cy="20" r="2.5" fill="#ff3355"/>
            <circle cx="39" cy="20" r="2.5" fill="#ff3355"/>
            <circle cx="31" cy="20" r="1"   fill="white" fillOpacity="0.65"/>
            <circle cx="39" cy="20" r="1"   fill="white" fillOpacity="0.65"/>
          </svg>

          <div className="logo-title">ARES</div>
          <div className="logo-subtitle">Auto Red-team Exploit Sys</div>
        </div>
        <div className="sidebar-separator-title"></div>
        <div className="menu-label">Menú</div>
        <nav>
          <ul>
            {menuItems.map((item) => (
              <li
                key={item.id}
                className={activePage === item.id ? "active" : ""}
                onClick={() => onNavigate(item.id)}
              >
                <i className={item.icon}></i> {item.label}
              </li>
            ))}
          </ul>
        </nav>
      </div>
    </div>
  );
}
