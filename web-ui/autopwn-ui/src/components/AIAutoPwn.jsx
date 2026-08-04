import { useState, useRef, useEffect, useCallback } from "react";
import PageHeader from "./PageHeader";

const API_BASE = "http://localhost:3000";

const PHASES = {
  idle:        { label: "En espera",                  icon: "fa-circle",       color: "#666" },
  scanning:    { label: "Escaneando red...",           icon: "fa-sync fa-spin", color: "#00ffc3" },
  context:     { label: "Consultando historial BD...", icon: "fa-sync fa-spin", color: "#60a5fa" },
  planning:    { label: "IA planificando ataque...",   icon: "fa-sync fa-spin", color: "#a78bfa" },
  deep:        { label: "Escaneando servicios...",     icon: "fa-sync fa-spin", color: "#00ffc3" },
  vulns:       { label: "Buscando CVEs...",            icon: "fa-sync fa-spin", color: "#f0a500" },
  ai:          { label: "IA analizando host...",       icon: "fa-sync fa-spin", color: "#a78bfa" },
  exploiting:  { label: "Explotando...",              icon: "fa-sync fa-spin", color: "#e05555" },
  done:        { label: "Completado",                 icon: "fa-check-circle", color: "#4ade80" },
  stopped:     { label: "Detenido",                   icon: "fa-stop-circle",  color: "#888" },
};

const LOG_COLOR = {
  info:    "#9ca3af",
  ai:      "#c4b5fd",
  cmd:     "#00ffc3",
  success: "#4ade80",
  error:   "#f87171",
  warn:    "#fbbf24",
  ctx:     "#60a5fa",   // historial/contexto de BD
  plan:    "#f9a8d4",   // decisiones del plan de la IA
};

export default function AIAutoPwn() {
  const [network, setNetwork] = useState("10.0.0.0/24");
  const [phase,   setPhase]   = useState("idle");
  const [running, setRunning] = useState(false);
  const [log,     setLog]     = useState([]);
  const [summary, setSummary] = useState(null);

  const stopRef   = useRef(false);
  const outputRef = useRef(null);

  useEffect(() => {
    if (outputRef.current)
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
  }, [log]);

  const addLog = useCallback((text, type = "info") => {
    setLog((prev) => [...prev, { text, type }]);
  }, []);

  const stopped = () => stopRef.current;

  // ── Main AI attack flow ─────────────────────────────────────────────────
  const runAIFlow = async () => {
    stopRef.current = false;
    setRunning(true);
    setLog([]);
    setSummary(null);

    addLog("════════════════════════════════════════════", "info");
    addLog(" ARES AI AUTO-ATTACK — Iniciando flujo      ", "ai");
    addLog("════════════════════════════════════════════", "info");

    // ── FASE 1: Network Scan ─────────────────────────────────────────────
    setPhase("scanning");
    addLog(`\n[FASE 1/5] Descubrimiento de hosts en ${network}`, "ai");
    addLog(`[*] POST /scan-network { network: "${network}" }`, "cmd");

    let discoveredHosts = [];
    try {
      const res  = await fetch(`${API_BASE}/scan-network`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ network }),
      });
      const data = await res.json();
      discoveredHosts = Array.isArray(data.hosts) ? data.hosts : [];

      if (discoveredHosts.length === 0) {
        addLog("[-] No se encontraron hosts activos.", "error");
        setPhase("done"); setRunning(false); return;
      }
      addLog(`[+] ${discoveredHosts.length} host(s) descubiertos:`, "success");
      discoveredHosts.forEach((h) =>
        addLog(`    • ${h.ip}  puertos: [${h.ports.join(", ")}]`, "success")
      );
    } catch (e) {
      addLog(`[-] Error en escaneo de red: ${e.message}`, "error");
      setPhase("stopped"); setRunning(false); return;
    }

    if (stopped()) { setPhase("stopped"); setRunning(false); return; }

    // ── FASE 2: Cargar contexto histórico de la BD ───────────────────────
    setPhase("context");
    addLog(`\n[FASE 2/5] Consultando historial de ataques en BD`, "ctx");

    let contexto = null;
    try {
      const res = await fetch(`${API_BASE}/ai-context`);
      contexto  = await res.json();

      const nComp = contexto.compromised?.length ?? 0;
      const nCves = contexto.workingCves?.length  ?? 0;
      addLog(`[BD] ${nComp} sesión(es) de compromiso registrada(s)`, "ctx");
      addLog(`[BD] ${nCves} CVE(s) con éxito previo en esta red`, "ctx");

      if (nCves > 0)
        contexto.workingCves.forEach((c) =>
          addLog(`[BD] ✓ ${c.cve} funcionó ${c.veces}× en [${c.hosts}]`, "ctx")
        );

      if (contexto.successPatterns?.length > 0) {
        const exitosos = contexto.successPatterns.filter((p) => p.exitos > 0);
        exitosos.forEach((p) =>
          addLog(`[BD] Puerto ${p.port}: ${p.exitos}/${p.total_intentos} intentos con éxito`, "ctx")
        );
      }
    } catch (e) {
      addLog(`[BD] No se pudo cargar historial (${e.message}) — la IA trabajará sin él`, "warn");
    }

    if (stopped()) { setPhase("stopped"); setRunning(false); return; }

    // ── FASE 3: IA planifica el ataque ───────────────────────────────────
    setPhase("planning");
    addLog(`\n[FASE 3/5] IA planificando el ataque`, "ai");
    addLog(`[AI] Analizando ${discoveredHosts.length} host(s) con contexto histórico...`, "ai");

    let plan = discoveredHosts.map((h, i) => ({
      ip: h.ip, accion: "scan_and_exploit", prioridad: i + 1,
      razon: "sin historial — usando orden por defecto", cves_sugeridos: [],
    }));

    try {
      const res  = await fetch(`${API_BASE}/ai-plan`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ hosts: discoveredHosts, contexto }),
      });
      const data = await res.json();

      if (Array.isArray(data.plan) && data.plan.length > 0) {
        plan = data.plan;
        if (data.resumen) addLog(`[AI] ${data.resumen}`, "ai");
        addLog(`\n[AI] Plan de ataque:`, "plan");
        plan.forEach((p) =>
          addLog(
            `    [${p.prioridad}] ${p.ip}  → ${p.accion.toUpperCase()}` +
            (p.cves_sugeridos?.length > 0 ? `  (${p.cves_sugeridos.join(", ")})` : "") +
            `\n         ↳ ${p.razon}`,
            "plan"
          )
        );
      } else {
        addLog("[AI] No se recibió plan válido — usando orden por defecto", "warn");
      }
    } catch (e) {
      addLog(`[AI] Error en planificación (${e.message}) — usando orden por defecto`, "warn");
    }

    if (stopped()) { setPhase("stopped"); setRunning(false); return; }

    // Separar hosts por acción
    const hostsToSkip   = plan.filter((p) => p.accion === "skip");
    const hostsToWork   = plan.filter((p) => p.accion !== "skip")
                              .sort((a, b) => (a.prioridad ?? 99) - (b.prioridad ?? 99));
    let compromised = 0; // contador global, compartido entre fast path y flujo normal

    if (hostsToSkip.length > 0) {
      addLog(`\n[AI] Saltando ${hostsToSkip.length} host(s) sin vector prometedor:`, "warn");
      hostsToSkip.forEach((p) => addLog(`    ✗ ${p.ip} — ${p.razon}`, "warn"));
    }

    if (hostsToWork.length === 0) {
      addLog("[AI] La IA no recomienda atacar ningún host. Finalizando.", "ai");
      setPhase("done"); setRunning(false); return;
    }

    // ── FAST PATH: hosts con combinación ganadora conocida ───────────────
    // Para cada host que ya fue comprometido antes, intentamos exactamente
    // el mismo módulo + payload que funcionó — UNA sola llamada, sin iterar.
    const winningByIp = {};
    (contexto?.winningCombinations ?? []).forEach((w) => {
      if (!winningByIp[w.ip]) winningByIp[w.ip] = [];
      winningByIp[w.ip].push(w);
    });

    const fastPathFailed = new Set(); // hosts donde el fast path no funcionó

    // Dedup por IP: si la IA generó varias entradas para el mismo host
    // (p.ej. EXPLOIT_DIRECT + SSH_BRUTE), el fast path solo corre una vez
    const _fpSeen = new Set();
    const fastPathHosts = hostsToWork.filter((e) => {
      if (!winningByIp[e.ip]?.length) return false;
      if (_fpSeen.has(e.ip)) return false;
      _fpSeen.add(e.ip); return true;
    });
    if (fastPathHosts.length > 0) {
      setPhase("exploiting");
      addLog(`\n[AI] Fast path — re-intentando combinaciones ganadoras en ${fastPathHosts.length} host(s)`, "plan");
      addLog(`[AI] Sin escanear, sin iterar payloads — directo al módulo que ya funcionó`, "plan");
    }

    for (const entry of fastPathHosts) {
      if (stopped()) break;
      const combos = winningByIp[entry.ip];

      // Dedup por módulo: el mismo módulo en puertos distintos es ruido
      // (el puerto ya viene corregido del host_vuln vía SQL)
      const seen = new Set();
      const unique = combos.filter((c) => {
        if (seen.has(c.module)) return false;
        seen.add(c.module); return true;
      });

      let fastSuccess = false;
      for (const combo of unique) {
        if (stopped() || fastSuccess) break;

        // payloads es un array ordenado: x64 primero, x86 fallback
        const payloads = Array.isArray(combo.payloads) ? combo.payloads : [combo.payloads ?? combo.payload];

        addLog(`\n── ${entry.ip} (fast path) ─────────────────────────────`, "info");
        addLog(`[AI] Último éxito: ${combo.cve} el ${combo.last_success}`, "ctx");
        addLog(`[AI] Payloads a probar: ${payloads.join(" → ")}`, "ai");

        for (const payload of payloads) {
          if (stopped() || fastSuccess) break;
          addLog(`[*] /run-exploit  módulo=${combo.module}  payload=${payload}  port=${combo.port}`, "cmd");

          try {
            const res  = await fetch(`${API_BASE}/run-exploit`, {
              method:  "POST",
              headers: { "Content-Type": "application/json" },
              body:    JSON.stringify({
                ip:      entry.ip,
                module:  combo.module,
                payload,
                port:    combo.port,
              }),
            });
            const data = await res.json();
            const text = data.output ?? "";
            text.split("\n").filter((l) => l.trim()).forEach((l) =>
              addLog(l, data.success ? "success" : "info")
            );

            if (data.success) {
              compromised++;
              fastSuccess = true;
              addLog(`[+] ¡ACCESO OBTENIDO (fast path) — ${entry.ip}!  sesión: ${data.sessionId}`, "success");
              break;
            }
            addLog(`[-] ${payload} sin éxito — ${payloads.indexOf(payload) + 1 < payloads.length ? "probando fallback..." : "sin más opciones"}`, "warn");
          } catch (e) {
            addLog(`[-] Error en fast path: ${e.message}`, "error");
          }
        }
      }

      if (!fastSuccess) {
        fastPathFailed.add(entry.ip);
        addLog(`[-] Fast path sin éxito en ${entry.ip} — pasando a flujo normal`, "warn");
      }
    }

    if (stopped()) { setPhase("stopped"); setRunning(false); return; }

    // Hosts que siguen pendientes: los que no tenían fast path + los que fallaron en fast path
    const hostsForNormalFlow = hostsToWork.filter(
      (e) => !winningByIp[e.ip]?.length || fastPathFailed.has(e.ip)
    );

    if (hostsForNormalFlow.length === 0 && fastPathHosts.length > 0) {
      addLog("\n[AI] Todos los hosts procesados por fast path.", "ai");
      // Ir directo al resumen
    }

    // ── FASE 4: Find Vulns (solo hosts que no se resolvieron por fast path) ─
    const hostVulns = {};

    if (hostsForNormalFlow.length === 0) {
      // Todos se resolvieron por fast path — saltar directamente al resumen
      addLog("\n[AI] Todos los hosts procesados — sin flujo normal necesario.", "ai");
    } else {
      setPhase("vulns");
      const nRetry  = hostsForNormalFlow.filter((e) => fastPathFailed.has(e.ip)).length;
      const nNew    = hostsForNormalFlow.length - nRetry;
      addLog(`\n[FASE 4/5] Búsqueda de CVEs en paralelo (nmap -sV + scripts vuln)`, "ai");
      addLog(
        `[AI] ${hostsForNormalFlow.length} host(s): ${nNew} nuevo(s)` +
        (nRetry > 0 ? ` + ${nRetry} con fast path fallido` : ""),
        "ai"
      );
    }

    await Promise.all(
      hostsForNormalFlow.map(async (entry) => {
        const host = discoveredHosts.find((h) => h.ip === entry.ip);
        if (!host || stopped()) return;

        addLog(`[*] find-vulns → ${host.ip}`, "cmd");
        try {
          const res  = await fetch(`${API_BASE}/find-vulns`, {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify({ ip: host.ip }),
          });
          const data = await res.json();
          const vulns = Array.isArray(data.vulns) ? data.vulns : [];

          // Inyectar CVEs del historial que nmap no haya detectado
          const suggested = entry.cves_sugeridos ?? [];
          const merged    = [...vulns];
          suggested.forEach((cve) => {
            if (!merged.some((v) => v.cve === cve))
              merged.push({ cve, severity: "critical", port: null, service: "histórico" });
          });
          hostVulns[host.ip] = merged;

          const injected = merged.length - vulns.length;
          if (merged.length > 0) {
            const crit = merged.filter((v) => v.severity === "critical").length;
            addLog(
              `[+] ${host.ip}: ${vulns.length} CVE(s)` +
              (crit  > 0 ? ` [${crit} críticos]` : "") +
              (injected > 0 ? ` + ${injected} del historial IA` : ""),
              "success"
            );
          } else {
            addLog(`[~] ${host.ip}: sin CVEs detectados`, "info");
          }
        } catch (e) {
          addLog(`[-] ${host.ip}: error buscando CVEs: ${e.message}`, "error");
          // Si falla nmap, al menos intentamos con los CVEs históricos sugeridos
          hostVulns[host.ip] = (entry.cves_sugeridos ?? []).map((cve) =>
            ({ cve, severity: "critical", port: null, service: "histórico" })
          );
        }
      })
    );

    if (stopped()) { setPhase("stopped"); setRunning(false); return; }

    // ── FASE 5: Explotación (flujo normal — solo hosts sin fast path) ────
    addLog(`\n[FASE 5/5] Explotación — flujo normal`, "ai");

    for (const entry of hostsForNormalFlow) {
      if (stopped()) break;

      const host    = discoveredHosts.find((h) => h.ip === entry.ip);
      if (!host) continue;

      const vulns    = hostVulns[host.ip] ?? [];
      // Derivar servicios desde los CVEs encontrados (find-vulns ya corre -sV)
      const services = [...new Map(
        vulns.filter((v) => v.port && v.service)
             .map((v) => [`${v.port}/${v.service}`, { port: v.port, proto: "tcp", service: v.service }])
      ).values()];

      addLog(`\n── ${host.ip} ──────────────────────────────────────────`, "info");

      if (vulns.length === 0) {
        addLog(`[AI] ${host.ip}: sin CVEs — saltando explotación MSF`, "warn");
        continue;
      }

      // IA analiza este host concreto con contexto histórico
      setPhase("ai");
      addLog(`[AI] Consultando IA para ${host.ip}...`, "ai");
      let aiDecision = null;
      try {
        const res = await fetch(`${API_BASE}/ai-analyze`, {
          method:  "POST",
          headers: { "Content-Type": "application/json" },
          body:    JSON.stringify({ ip: host.ip, services, vulns, contexto }),
        });
        aiDecision = await res.json();
        if (aiDecision?.resumen)
          addLog(`[AI] ${aiDecision.resumen}`, "ai");
        if (Array.isArray(aiDecision?.advertencias))
          aiDecision.advertencias.forEach((w) => addLog(`[AI] ⚠  ${w}`, "warn"));
      } catch (e) {
        addLog(`[AI] No disponible (${e.message}) — usando orden por severidad`, "warn");
      }

      if (stopped()) break;

      // Reordenar CVEs según la IA (prioriza los que históricamente funcionaron)
      let orderedVulns = [...vulns];
      if (aiDecision?.prioridad?.length > 0) {
        const aiOrder  = aiDecision.prioridad.map((p) => p.cve);
        const sorted   = aiOrder.map((cve) => vulns.find((v) => v.cve === cve)).filter(Boolean);
        const rest     = vulns.filter((v) => !aiOrder.includes(v.cve));
        orderedVulns   = [...sorted, ...rest];
        addLog(`[AI] Orden: ${orderedVulns.slice(0, 5).map((v) => v.cve).join(" → ")}${orderedVulns.length > 5 ? " ..." : ""}`, "plan");
      }

      setPhase("exploiting");
      addLog(`[*] Explotando → ${host.ip}`, "cmd");
      try {
        const res  = await fetch(`${API_BASE}/exploit`, {
          method:  "POST",
          headers: { "Content-Type": "application/json" },
          body:    JSON.stringify({ ip: host.ip, vulns: orderedVulns }),
        });
        const data = await res.json();
        const text = data.output ?? data.result ?? "";
        text.split("\n").filter((l) => l.trim()).forEach((l) =>
          addLog(l, data.success ? "success" : "info")
        );
        if (data.success) {
          compromised++;
          addLog(`[+] ¡ACCESO OBTENIDO — ${host.ip}!  sesión: ${data.sessionId}`, "success");
        } else {
          addLog(`[-] ${host.ip}: sin sesión tras todos los intentos`, "error");
        }
      } catch (e) {
        addLog(`[-] ${host.ip}: error en explotación: ${e.message}`, "error");
      }
    }

    // ── Resumen ──────────────────────────────────────────────────────────
    addLog("\n════════════════════════════════════════════", "info");
    addLog(" RESUMEN FINAL", "ai");
    addLog("════════════════════════════════════════════", "info");
    addLog(`[AI] Hosts descubiertos:   ${discoveredHosts.length}`, "ai");
    addLog(`[AI] Analizados por IA:    ${hostsToWork.length}`, "ai");
    addLog(`[AI] Saltados por IA:      ${hostsToSkip.length}`, "ai");
    addLog(`[AI] Comprometidos:        ${compromised}`, compromised > 0 ? "success" : "info");
    if (stopped()) addLog("[!] Flujo detenido manualmente.", "warn");
    else addLog("[AI] Flujo completado.", "ai");

    setSummary({
      total:       discoveredHosts.length,
      analyzed:    hostsToWork.length,
      skipped:     hostsToSkip.length,
      compromised,
    });
    setPhase(stopped() ? "stopped" : "done");
    setRunning(false);
  };

  const handleStop = () => {
    stopRef.current = true;
    addLog("\n[!] Señal de parada — finalizando operación actual...", "warn");
  };

  const phaseInfo = PHASES[phase] ?? PHASES.idle;

  return (
    <>
      <PageHeader icon="fa-spider" title="AI Auto-Attack" subtitle="automated attack orchestrated by Aracni" />

      <div className="ai-autopwn-layout">

        {/* ── Control bar ── */}
        <div className="ai-autopwn-controls card">
          <div className="ai-autopwn-controls-inner">
            <div className="ai-autopwn-network-row">
              <i className="fas fa-network-wired ai-autopwn-net-icon"></i>
              <input
                className="ai-autopwn-input"
                value={network}
                onChange={(e) => setNetwork(e.target.value)}
                placeholder="Red objetivo (ej: 10.0.0.0/24)"
                disabled={running}
              />
            </div>

            <div className="ai-autopwn-actions-row">
              <div className="ai-autopwn-status">
                <i className={`fas ${phaseInfo.icon}`}
                   style={{ color: phaseInfo.color, marginRight: "0.4rem" }} />
                <span style={{ color: phaseInfo.color, fontSize: "0.85rem" }}>
                  {phaseInfo.label}
                </span>
              </div>

              {!running ? (
                <button
                  className="action-btn action-btn--exploit ai-autopwn-btn"
                  onClick={runAIFlow}
                  style={{ minWidth: 160 }}
                >
                  <i className="fas fa-play"></i> Iniciar flujo IA
                </button>
              ) : (
                <button
                  className="action-btn ai-autopwn-btn ai-autopwn-btn--stop"
                  onClick={handleStop}
                  style={{ minWidth: 160 }}
                >
                  <i className="fas fa-stop"></i> Detener
                </button>
              )}
            </div>
          </div>

          {summary && (
            <div className="ai-autopwn-summary">
              <span className="ai-autopwn-badge ai-autopwn-badge--total">
                <i className="fas fa-server"></i> {summary.total} descubiertos
              </span>
              <span className="ai-autopwn-badge ai-autopwn-badge--clean">
                <i className="fas fa-brain"></i> {summary.analyzed} analizados
              </span>
              <span className="ai-autopwn-badge ai-autopwn-badge--skip">
                <i className="fas fa-forward"></i> {summary.skipped} saltados por IA
              </span>
              <span className={`ai-autopwn-badge ${summary.compromised > 0 ? "ai-autopwn-badge--pwned" : "ai-autopwn-badge--skip"}`}>
                <i className="fas fa-skull-crossbones"></i> {summary.compromised} comprometidos
              </span>
            </div>
          )}
        </div>

        {/* ── Terminal ── */}
        <div className="ai-autopwn-terminal card">
          <div className="terminal-header">
            <span className="terminal-dot red"></span>
            <span className="terminal-dot yellow"></span>
            <span className="terminal-dot green"></span>
            <span className="terminal-title">aracni@autopwn:~$</span>
            {running && (
              <div className="spinner" style={{ marginLeft: "auto", marginTop: 0 }}>
                <svg viewBox="0 0 50 50" style={{ width: 16, height: 16 }}>
                  <g fill="none" fillRule="evenodd" strokeWidth="4"
                    transform="translate(2 2)" stroke="#a78bfa">
                    <circle cx="22" cy="22" r="6" strokeOpacity=".5" />
                    <path d="M22 4c9.94 0 18 8.06 18 18" />
                  </g>
                </svg>
              </div>
            )}
          </div>

          <pre ref={outputRef} className="terminal-output ai-autopwn-output">
            {log.length === 0 ? (
              <span style={{ color: "#555" }}>
                {"Configura la red objetivo y pulsa [Iniciar flujo IA].\n\n"}
                {"Lo que hace diferente al flujo manual:\n"}
                {"  • Consulta el historial de ataques en la BD antes de actuar\n"}
                {"  • La IA decide qué hosts atacar y en qué orden\n"}
                {"  • Prioriza CVEs que ya funcionaron en esta red\n"}
                {"  • Salta hosts sin vectores prometedores según historial\n"}
                {"  • Inyecta CVEs históricos aunque nmap no los detecte\n"}
              </span>
            ) : (
              log.map((l, i) => (
                <span key={i} style={{ color: LOG_COLOR[l.type] ?? "#aaa" }}>
                  {l.text}{"\n"}
                </span>
              ))
            )}
          </pre>
        </div>

      </div>
    </>
  );
}
