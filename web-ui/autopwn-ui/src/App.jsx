import { useState, useEffect, useRef, useCallback } from "react";

// ── localStorage helpers ───────────────────────────────────────────────────
function load(key, fallback) {
  try { return JSON.parse(sessionStorage.getItem(key)) ?? fallback; }
  catch { return fallback; }
}
function save(key, value) {
  try { sessionStorage.setItem(key, JSON.stringify(value)); } catch { /* quota exceeded */ }
}
import Sidebar from "./components/Sidebar";
import Dashboard from "./components/Dashboard";
import NetworkScan from "./components/NetworkScan";
import AIAssistant from "./components/AIAssistant";
import Exploitation from "./components/Exploitation";
import Results from "./components/Results";
import TargetAcquired from "./components/TargetAcquired";
import ComingSoon from "./components/ComingSoon";
import AracniButton from "./components/AracniButton";
import "./styles/AracniButton.css";
import ToastContainer from "./components/Toast";
import SessionManager from "./components/SessionManager";
import "./styles/style.css";

export default function App() {
  const [activePage,       setActivePage]       = useState("dashboard");
  const [scanHosts,        setScanHosts]        = useState(() => load("autopwn_hosts",   []));
  const [jobId,            setJobId]            = useState(() => load("autopwn_job_id", null));
  const [scanResults,      setScanResults]      = useState(() => load("autopwn_results", {}));
  const [findVulnsLoading, setFindVulnsLoading] = useState({}); // { [ip]: true } — persists across tab switches
  const [targetSession,    setTargetSession]    = useState(null);
  const [introFinished,    setIntroFinished]    = useState(false);
  const [chatOpen,         setChatOpen]         = useState(false);
  const [toasts,           setToasts]           = useState([]);
  const closeTimerRef = useRef(null);

  const showToast = useCallback((message, type = "info") => {
    const id = Date.now() + Math.random();
    setToasts(prev => [...prev, { id, message, type }]);
  }, []);

  const removeToast = useCallback((id) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  const openChat = useCallback(() => {
    clearTimeout(closeTimerRef.current);
    setChatOpen(true);
  }, []);

  const scheduleClose = useCallback(() => {
    closeTimerRef.current = setTimeout(() => setChatOpen(false), 150);
  }, []);

  // ── Reset en cada carga de página ────────────────────────────────────────
  useEffect(() => {
    // Limpiar estado local
    sessionStorage.clear();
    setScanHosts([]);
    setJobId(null);
    setScanResults({});
    setTargetSession(null);
    // Limpiar estado del backend
    fetch("http://localhost:3000/reset", { method: "POST" }).catch(() => {});
  }, []);

  // Persist to localStorage whenever state changes
  useEffect(() => { save("autopwn_hosts",   scanHosts);   }, [scanHosts]);
  useEffect(() => { save("autopwn_results", scanResults); }, [scanResults]);
  useEffect(() => { save("autopwn_job_id",  jobId);       }, [jobId]);
  // Quitar el intro-screen del DOM una vez que la animación CSS ha terminado
  useEffect(() => { const t = setTimeout(() => setIntroFinished(true), 4600); return () => clearTimeout(t); }, []);

  const saveResult = (ip, actionKey, data) => {
    setScanResults((prev) => ({
      ...prev,
      [ip]: { ...(prev[ip] ?? {}), [actionKey]: data },
    }));
  };

  const onFindVulnsStart = useCallback((ip) =>
    setFindVulnsLoading((prev) => ({ ...prev, [ip]: true })), []);

  const onFindVulnsEnd = useCallback((ip) =>
    setFindVulnsLoading((prev) => { const n = { ...prev }; delete n[ip]; return n; }), []);

  const onExploitSuccess = (ip, sessionId, exploitModule, exploitOptions) => {
    setTargetSession({ ip, sessionId, exploitModule, exploitOptions });
    setActivePage("target-acquired");
  };

  // Intercept ai-assistant → open panel instead of navigating
  const handleNavigate = (page) => {
    if (page === "ai-assistant") { setChatOpen(true); return; }
    setActivePage(page);
  };

  // Derived maps shared by Dashboard and Results
  const hostScans    = Object.fromEntries(Object.keys(scanResults).map((ip) => [ip, scanResults[ip]?.["deep-scan"]  ?? null]));
  const hostVulns    = Object.fromEntries(Object.keys(scanResults).map((ip) => [ip, scanResults[ip]?.["find-vulns"] ?? null]));
  const hostExploits = Object.fromEntries(Object.keys(scanResults).map((ip) => [ip, scanResults[ip]?.["exploit"]  ?? null]));

  const pages = {
    "dashboard": <Dashboard
      hosts={scanHosts}
      hostScans={hostScans}
      hostVulns={hostVulns}
      hostExploits={hostExploits}
    />,
    "network-scan":       <NetworkScan hosts={scanHosts} onScanComplete={(hosts, id) => { setScanHosts(hosts); setJobId(id); }} onNavigate={setActivePage} showToast={showToast} />,
    "exploitation": <Exploitation hosts={scanHosts} savedVulns={hostVulns} jobId={jobId} onResultSaved={saveResult} onExploitSuccess={onExploitSuccess} showToast={showToast} vulnsLoading={findVulnsLoading} onFindVulnsStart={onFindVulnsStart} onFindVulnsEnd={onFindVulnsEnd} />,
    "session-manager": <SessionManager
      onConnect={s => { setTargetSession({ ip: s.ip, sessionId: s.id }); setActivePage("target-acquired"); }}
      showToast={showToast}
    />,
    "target-acquired": <TargetAcquired
      ip={targetSession?.ip}
      sessionId={targetSession?.sessionId}
      exploitModule={targetSession?.exploitModule}
      exploitOptions={targetSession?.exploitOptions}
      onTerminate={() => { setTargetSession(null); setActivePage("session-manager"); }}
      onBack={() => setActivePage("session-manager")}
    />,
    "results": <Results
      hosts={scanHosts}
      hostScans={hostScans}
      hostVulns={hostVulns}
      hostExploits={hostExploits}
      jobId={jobId}
    />,
    "settings":     <ComingSoon title="Settings" />,
    "auth":         <ComingSoon title="Authentication" />,
  };

  return (
    <>
    {!introFinished && (
      <div className="intro-screen">
        <svg className="intro-web" viewBox="0 0 600 600"
          xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
          <defs>
            <filter id="iNeon" x="-30%" y="-30%" width="160%" height="160%">
              <feGaussianBlur in="SourceAlpha" stdDeviation="6"   result="bigB"/>
              <feGaussianBlur in="SourceAlpha" stdDeviation="2"   result="smlB"/>
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

          <g filter="url(#iNeon)">
            {/* ── Araña central: fill fade-in ── */}
            <ellipse cx="300" cy="320" rx="25" ry="32" fill="#cc1133"
              className="intro-fill" style={{"--dl":"0s",    "--d":"0.3s"}}/>
            <ellipse cx="300" cy="282" rx="18" ry="15" fill="#cc1133"
              className="intro-fill" style={{"--dl":"0.1s",  "--d":"0.25s"}}/>
            <circle  cx="293" cy="278" r="3.5"  fill="#ff3355"
              className="intro-fill" style={{"--dl":"0.25s", "--d":"0.15s"}}/>
            <circle  cx="307" cy="278" r="3.5"  fill="#ff3355"
              className="intro-fill" style={{"--dl":"0.25s", "--d":"0.15s"}}/>
            <circle  cx="293" cy="278" r="1.2"  fill="white" fillOpacity="0.65"
              className="intro-fill" style={{"--dl":"0.3s",  "--d":"0.1s"}}/>
            <circle  cx="307" cy="278" r="1.2"  fill="white" fillOpacity="0.65"
              className="intro-fill" style={{"--dl":"0.3s",  "--d":"0.1s"}}/>

            {/* ── Araña: patas y quelíceros stroke draw ── */}
            <path d="M 293,295 C 290,303 289,311 291,316" fill="none"
              stroke="#cc1133" strokeWidth="1.8" strokeLinecap="round" pathLength="1000"
              className="intro-draw" style={{"--dl":"0.2s", "--d":"0.3s"}}/>
            <path d="M 307,295 C 310,303 311,311 309,316" fill="none"
              stroke="#cc1133" strokeWidth="1.8" strokeLinecap="round" pathLength="1000"
              className="intro-draw" style={{"--dl":"0.2s", "--d":"0.3s"}}/>
            {[
              ["283,280 264,265 252,252", "0.1s"],
              ["281,289 257,283 242,277", "0.15s"],
              ["281,298 257,304 242,312", "0.2s"],
              ["283,310 264,328 252,340", "0.25s"],
              ["317,280 336,265 348,252", "0.1s"],
              ["319,289 343,283 358,277", "0.15s"],
              ["319,298 343,304 358,312", "0.2s"],
              ["317,310 336,328 348,340", "0.25s"],
            ].map(([pts, dl], i) => (
              <polyline key={i} points={pts} fill="none"
                stroke="#cc1133" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
                pathLength="1000" className="intro-draw" style={{"--dl":dl,"--d":"0.25s"}}/>
            ))}

            {/* ── Roseta interior ── */}
            <circle cx="300" cy="300" r="30" fill="none" stroke="#cc1133" strokeWidth="0.7"
              pathLength="1000" className="intro-draw" style={{"--dl":"0.4s","--d":"0.45s"}}/>
            <circle cx="300" cy="300" r="36" fill="none" stroke="#cc1133" strokeWidth="1.6"
              pathLength="1000" className="intro-draw" style={{"--dl":"0.45s","--d":"0.45s"}}/>
            {Array.from({length:8},(_,i)=>{
              const a=i*Math.PI/4;
              const x=Math.round(300+36*Math.sin(a)), y=Math.round(300-36*Math.cos(a));
              return <polygon key={i} fill="#cc1133"
                points={`${x},${y-4} ${x+3},${y} ${x},${y+4} ${x-3},${y}`}
                className="intro-fill" style={{"--dl":`${0.55+i*0.04}s`,"--d":"0.2s"}}/>;
            })}

            {/* ── 8 radios (dibujan desde el centro hacia afuera) ── */}
            <g stroke="#cc1133" strokeWidth="0.9" fill="none">
              {[[300,0],[600,0],[600,300],[600,600],[300,600],[0,600],[0,300],[0,0]]
                .map(([x2,y2],i)=>(
                  <line key={i} x1={300} y1={300} x2={x2} y2={y2} pathLength="1000"
                    className="intro-draw" style={{"--dl":"0.65s","--d":"1.6s"}}/>
              ))}
            </g>

            {/* ── Anillos octagonales (expandiéndose hacia afuera) ── */}
            {[
              [70,  49, "0.7s"],
              [115, 81, "1.0s"],
              [160,113, "1.3s"],
              [205,145, "1.6s"],
              [250,177, "1.9s"],
              [285,202, "2.1s", true],
            ].map(([r,d,dl,outer])=>{
              const pts=[
                `300,${300-r}`,`${300+d},${300-d}`,
                `${300+r},300`,`${300+d},${300+d}`,
                `300,${300+r}`,`${300-d},${300+d}`,
                `${300-r},300`,`${300-d},${300-d}`,
              ].join(' ');
              return <polygon key={r} points={pts} fill="none" stroke="#cc1133"
                strokeWidth={outer?1.6:0.85} pathLength="1000"
                className="intro-draw" style={{"--dl":dl,"--d":"0.4s"}}/>;
            })}

            {/* ── 16 dientes en anillo exterior ── */}
            {Array.from({length:16},(_,i)=>{
              const a=i*Math.PI/8;
              const x=Math.round(300+288*Math.sin(a)), y=Math.round(300-288*Math.cos(a));
              return <polygon key={i} fill="#cc1133"
                points={`${x},${y-6} ${x+4},${y} ${x},${y+6} ${x-4},${y}`}
                className="intro-fill" style={{"--dl":"2.2s","--d":"0.3s"}}/>;
            })}

            {/* ── Decoraciones de esquinas ── */}
            <g fill="none" stroke="#cc1133">
              {/* Superior-derecha (600,0) */}
              <path d="M 502,98 C 570,30 600,0 600,300" pathLength="1000" strokeWidth="1.4"
                className="intro-draw" style={{"--dl":"2.3s","--d":"0.35s"}}/>
              <path d="M 545,55 C 588,18 598,5 596,240" pathLength="1000" strokeWidth="0.8"
                className="intro-draw" style={{"--dl":"2.35s","--d":"0.35s"}}/>
              <line x1="600" y1="0" x2="535" y2="58"  pathLength="1000" strokeWidth="1.0"
                className="intro-draw" style={{"--dl":"2.3s","--d":"0.2s"}}/>
              <line x1="600" y1="0" x2="575" y2="95"  pathLength="1000" strokeWidth="0.7"
                className="intro-draw" style={{"--dl":"2.35s","--d":"0.2s"}}/>
              <circle cx="570" cy="42" r="8" strokeWidth="1.4" pathLength="1000"
                className="intro-draw" style={{"--dl":"2.45s","--d":"0.25s"}}/>
              <circle cx="570" cy="42" r="3.5" fill="#cc1133" stroke="none"
                className="intro-fill" style={{"--dl":"2.55s","--d":"0.15s"}}/>
              {/* Superior-izquierda (0,0) */}
              <path d="M 98,98 C 30,30 0,0 0,300"      pathLength="1000" strokeWidth="1.4"
                className="intro-draw" style={{"--dl":"2.3s","--d":"0.35s"}}/>
              <path d="M 55,55 C 12,18 2,5 4,240"       pathLength="1000" strokeWidth="0.8"
                className="intro-draw" style={{"--dl":"2.35s","--d":"0.35s"}}/>
              <line x1="0" y1="0" x2="65"  y2="58"  pathLength="1000" strokeWidth="1.0"
                className="intro-draw" style={{"--dl":"2.3s","--d":"0.2s"}}/>
              <line x1="0" y1="0" x2="25"  y2="95"  pathLength="1000" strokeWidth="0.7"
                className="intro-draw" style={{"--dl":"2.35s","--d":"0.2s"}}/>
              <circle cx="30"  cy="42" r="8" strokeWidth="1.4" pathLength="1000"
                className="intro-draw" style={{"--dl":"2.45s","--d":"0.25s"}}/>
              <circle cx="30"  cy="42" r="3.5" fill="#cc1133" stroke="none"
                className="intro-fill" style={{"--dl":"2.55s","--d":"0.15s"}}/>
              {/* Inferior-derecha (600,600) */}
              <path d="M 502,502 C 570,570 600,600 600,300" pathLength="1000" strokeWidth="1.4"
                className="intro-draw" style={{"--dl":"2.3s","--d":"0.35s"}}/>
              <path d="M 545,545 C 588,582 598,595 596,360" pathLength="1000" strokeWidth="0.8"
                className="intro-draw" style={{"--dl":"2.35s","--d":"0.35s"}}/>
              <line x1="600" y1="600" x2="535" y2="542" pathLength="1000" strokeWidth="1.0"
                className="intro-draw" style={{"--dl":"2.3s","--d":"0.2s"}}/>
              <line x1="600" y1="600" x2="575" y2="505" pathLength="1000" strokeWidth="0.7"
                className="intro-draw" style={{"--dl":"2.35s","--d":"0.2s"}}/>
              <circle cx="570" cy="558" r="8" strokeWidth="1.4" pathLength="1000"
                className="intro-draw" style={{"--dl":"2.45s","--d":"0.25s"}}/>
              <circle cx="570" cy="558" r="3.5" fill="#cc1133" stroke="none"
                className="intro-fill" style={{"--dl":"2.55s","--d":"0.15s"}}/>
              {/* Inferior-izquierda (0,600) */}
              <path d="M 98,502 C 30,570 0,600 0,300"  pathLength="1000" strokeWidth="1.4"
                className="intro-draw" style={{"--dl":"2.3s","--d":"0.35s"}}/>
              <path d="M 55,545 C 12,582 2,595 4,360"  pathLength="1000" strokeWidth="0.8"
                className="intro-draw" style={{"--dl":"2.35s","--d":"0.35s"}}/>
              <line x1="0" y1="600" x2="65"  y2="542" pathLength="1000" strokeWidth="1.0"
                className="intro-draw" style={{"--dl":"2.3s","--d":"0.2s"}}/>
              <line x1="0" y1="600" x2="25"  y2="505" pathLength="1000" strokeWidth="0.7"
                className="intro-draw" style={{"--dl":"2.35s","--d":"0.2s"}}/>
              <circle cx="30"  cy="558" r="8" strokeWidth="1.4" pathLength="1000"
                className="intro-draw" style={{"--dl":"2.45s","--d":"0.25s"}}/>
              <circle cx="30"  cy="558" r="3.5" fill="#cc1133" stroke="none"
                className="intro-fill" style={{"--dl":"2.55s","--d":"0.15s"}}/>
            </g>
          </g>
        </svg>

        <div className="intro-title">ARES</div>
        <div className="intro-subtitle">Auto Red-team Exploit Sys</div>
      </div>
    )}

    <div className="page-container">

      <Sidebar activePage={activePage} onNavigate={handleNavigate} />
      <div className="main-wrapper">
      {/* ── Spider-web mandala — fuera del main con key para no re-montar ── */}
      <svg className="tribal-logo" aria-hidden="true"
        xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1400 850"
        preserveAspectRatio="none">
        <defs/>

        {/* ── 8 radios desde el centro (700,425) hasta los bordes/esquinas ── */}
        <g stroke="#cc1133" strokeWidth="0.9" fill="none">
          {[[700,0],[1125,0],[1400,425],[1125,850],[700,850],[275,850],[0,425],[275,0]]
            .map(([x2,y2], i) => <line key={i} x1={700} y1={425} x2={x2} y2={y2}/>)}
        </g>

        {/* ── Anillos octagonales de la telaraña ── */}
        <g fill="none">
          {[75, 135, 205, 275, 345, 415].map((r, i) => {
            const d = Math.round(r * 0.707);
            const pts = [
              `700,${425-r}`,   `${700+d},${425-d}`,
              `${700+r},425`,   `${700+d},${425+d}`,
              `700,${425+r}`,   `${700-d},${425+d}`,
              `${700-r},425`,   `${700-d},${425-d}`,
            ].join(' ');
            return <polygon key={r} points={pts} stroke="#cc1133"
              strokeWidth={i === 5 ? 1.6 : 0.85}
              strokeDasharray={i % 2 === 1 ? "6 10" : undefined}/>;
          })}
        </g>

        {/* ── 16 dientes en el anillo exterior (r≈415) ── */}
        <g fill="#cc1133">
          {Array.from({length: 16}, (_, i) => {
            const a = i * Math.PI / 8;
            const x = Math.round(700 + 418 * Math.sin(a));
            const y = Math.round(425 - 418 * Math.cos(a));
            return <polygon key={i}
              points={`${x},${y-7} ${x+5},${y} ${x},${y+7} ${x-5},${y}`}/>;
          })}
        </g>

        {/* ── Decoraciones en las 4 esquinas ── */}
        <g fill="none" stroke="#cc1133">
          {/* Esquina superior-derecha */}
          <path d="M 1125,0 C 1310,0 1400,0 1400,425"   strokeWidth="1.4"/>
          <path d="M 1220,0 C 1375,10 1392,25 1390,360"  strokeWidth="0.9"/>
          <path d="M 1060,0 C 1285,28 1370,95 1373,425"  strokeWidth="0.6" strokeDasharray="5 9"/>
          <path d="M 1125,0 C 1250,30 1340,90 1400,200"  strokeWidth="0.6" strokeDasharray="3 8"/>
          <line x1="1400" y1="0" x2="1325" y2="62"  stroke="#cc1133" strokeWidth="1.1"/>
          <line x1="1400" y1="0" x2="1360" y2="125" stroke="#cc1133" strokeWidth="0.75"/>
          <line x1="1400" y1="0" x2="1300" y2="20"  stroke="#cc1133" strokeWidth="0.75"/>
          <circle cx="1365" cy="48" r="10" stroke="#ff2244" strokeWidth="1.4"/>
          <circle cx="1365" cy="48" r="4"  fill="#cc1133" stroke="none"/>

          {/* Esquina superior-izquierda */}
          <path d="M 275,0 C 90,0 0,0 0,425"    strokeWidth="1.4"/>
          <path d="M 180,0 C 25,10 8,25 10,360"  strokeWidth="0.9"/>
          <path d="M 340,0 C 115,28 30,95 27,425" strokeWidth="0.6" strokeDasharray="5 9"/>
          <path d="M 275,0 C 150,30 60,90 0,200"  strokeWidth="0.6" strokeDasharray="3 8"/>
          <line x1="0" y1="0" x2="75"  y2="62"  stroke="#cc1133" strokeWidth="1.1"/>
          <line x1="0" y1="0" x2="40"  y2="125" stroke="#cc1133" strokeWidth="0.75"/>
          <line x1="0" y1="0" x2="100" y2="20"  stroke="#cc1133" strokeWidth="0.75"/>
          <circle cx="35"   cy="48" r="10" stroke="#ff2244" strokeWidth="1.4"/>
          <circle cx="35"   cy="48" r="4"  fill="#cc1133" stroke="none"/>

          {/* Esquina inferior-derecha */}
          <path d="M 1125,850 C 1310,850 1400,850 1400,425"  strokeWidth="1.4"/>
          <path d="M 1220,850 C 1375,840 1392,825 1390,490"  strokeWidth="0.9"/>
          <path d="M 1060,850 C 1285,822 1370,755 1373,425"  strokeWidth="0.6" strokeDasharray="5 9"/>
          <path d="M 1125,850 C 1250,820 1340,760 1400,650"  strokeWidth="0.6" strokeDasharray="3 8"/>
          <line x1="1400" y1="850" x2="1325" y2="788" stroke="#cc1133" strokeWidth="1.1"/>
          <line x1="1400" y1="850" x2="1360" y2="725" stroke="#cc1133" strokeWidth="0.75"/>
          <line x1="1400" y1="850" x2="1300" y2="830" stroke="#cc1133" strokeWidth="0.75"/>
          <circle cx="1365" cy="802" r="10" stroke="#ff2244" strokeWidth="1.4"/>
          <circle cx="1365" cy="802" r="4"  fill="#cc1133" stroke="none"/>

          {/* Esquina inferior-izquierda */}
          <path d="M 275,850 C 90,850 0,850 0,425"   strokeWidth="1.4"/>
          <path d="M 180,850 C 25,840 8,825 10,490"  strokeWidth="0.9"/>
          <path d="M 340,850 C 115,822 30,755 27,425" strokeWidth="0.6" strokeDasharray="5 9"/>
          <path d="M 275,850 C 150,820 60,760 0,650"  strokeWidth="0.6" strokeDasharray="3 8"/>
          <line x1="0" y1="850" x2="75"  y2="788" stroke="#cc1133" strokeWidth="1.1"/>
          <line x1="0" y1="850" x2="40"  y2="725" stroke="#cc1133" strokeWidth="0.75"/>
          <line x1="0" y1="850" x2="100" y2="830" stroke="#cc1133" strokeWidth="0.75"/>
          <circle cx="35"   cy="802" r="10" stroke="#ff2244" strokeWidth="1.4"/>
          <circle cx="35"   cy="802" r="4"  fill="#cc1133" stroke="none"/>
        </g>

        {/* ── Araña central ── */}
        <g>
          {/* Patas — izquierda */}
          <path d="M 681,418 Q 618,384 565,353" fill="none" stroke="#ff2244" strokeWidth="1.4"/>
          <path d="M 679,428 Q 602,422 549,418" fill="none" stroke="#ff2244" strokeWidth="1.4"/>
          <path d="M 679,443 Q 602,451 549,459" fill="none" stroke="#ff2244" strokeWidth="1.4"/>
          <path d="M 681,453 Q 618,482 565,514" fill="none" stroke="#ff2244" strokeWidth="1.4"/>
          {/* Patas — derecha */}
          <path d="M 719,418 Q 782,384 835,353" fill="none" stroke="#ff2244" strokeWidth="1.4"/>
          <path d="M 721,428 Q 798,422 851,418" fill="none" stroke="#ff2244" strokeWidth="1.4"/>
          <path d="M 721,443 Q 798,451 851,459" fill="none" stroke="#ff2244" strokeWidth="1.4"/>
          <path d="M 719,453 Q 782,482 835,514" fill="none" stroke="#ff2244" strokeWidth="1.4"/>
          {/* Abdomen */}
          <ellipse cx="700" cy="450" rx="34" ry="43"
            fill="#770011" fillOpacity="0.65" stroke="#ff2244" strokeWidth="1.5"/>
          {/* Cefalotórax */}
          <ellipse cx="700" cy="406" rx="24" ry="20"
            fill="#990022" fillOpacity="0.75" stroke="#ff2244" strokeWidth="1.5"/>
          {/* Ojos */}
          <circle cx="693" cy="400" r="4.5" fill="#ff2244"/>
          <circle cx="707" cy="400" r="4.5" fill="#ff2244"/>
          <circle cx="693" cy="400" r="1.8" fill="white" fillOpacity="0.7"/>
          <circle cx="707" cy="400" r="1.8" fill="white" fillOpacity="0.7"/>
        </g>

        {/* ── Roseta interior alrededor de la araña ── */}
        <g fill="none" stroke="#cc1133">
          <circle cx="700" cy="425" r="60" strokeWidth="0.7"/>
          <circle cx="700" cy="425" r="54" strokeWidth="1.7"/>
          {Array.from({length: 8}, (_, i) => {
            const a = i * Math.PI / 4;
            const x = Math.round(700 + 54 * Math.sin(a));
            const y = Math.round(425 - 54 * Math.cos(a));
            return <polygon key={i} fill="#cc1133" stroke="none"
              points={`${x},${y-5} ${x+4},${y} ${x},${y+5} ${x-4},${y}`}/>;
          })}
        </g>
      </svg>

        <main className="main-content" key={activePage}>
          {pages[activePage] ?? <ComingSoon title={activePage} />}
        </main>
      </div>
    </div>

    <ToastContainer toasts={toasts} onRemove={removeToast} />
    <AracniButton active={chatOpen} onClick={() => chatOpen ? setChatOpen(false) : setChatOpen(true)} onMouseEnter={openChat} />

    {/* Visible pull tab on right edge */}
    {!chatOpen && (
      <div className="aracni-pull-tab" onMouseEnter={openChat} onClick={openChat}>
        <i className="fas fa-chevron-left" />
      </div>
    )}

    {/* AI assistant slide-in panel */}
    <AIAssistant
      open={chatOpen}
      onClose={() => setChatOpen(false)}
      onHoverEnter={openChat}
      onHoverLeave={scheduleClose}
      jobId={jobId}
      onJobCreated={(id) => setJobId(id)}
    />
  </>
  );
}
