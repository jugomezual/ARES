// ══════════════════════════════════════════════════════════════════════════════
// MODO PRODUCCIÓN — contexto histórico + fast path activos, agentes frescos
// ══════════════════════════════════════════════════════════════════════════════
import { useState, useRef, useEffect, useCallback } from "react";

const API_BASE = "http://localhost:3000";

// ── Typewriter helpers ────────────────────────────────────────────────────────
const INSTANT_TYPES = new Set(["info"]);  // these lines appear instantly
const CHARS_PER_TICK = 2;
const TICK_MS = 12;

const PHASES = {
  idle:       { label: "en espera",             color: "#3a3040" },
  scanning:   { label: "escaneando red...",      color: "#00ffc3" },
  context:    { label: "consultando historial…", color: "#6090d0" },
  planning:   { label: "aracni planificando…",    color: "#b090e0" },
  vulns:      { label: "buscando cves…",         color: "#f0a500" },
  ai:         { label: "aracni analizando host…", color: "#b090e0" },
  exploiting: { label: "explotando…",            color: "#e83050" },
  done:       { label: "completado",             color: "#4ade80" },
  stopped:    { label: "detenido",               color: "#3a3040" },
};

const LINE_COLOR = {
  info:    "#3a3040",
  ai:      "#b090e0",
  cmd:     "#00ffc388",
  success: "#4ade80",
  error:   "#e83050",
  warn:    "#f0a500",
  ctx:     "#6090d0",
  plan:    "#e8305088",
};

export default function AracniAttack({ jobId = null, onJobCreated }) {
  const [network,    setNetwork]    = useState("10.0.0.0/24");
  const [phase,      setPhase]      = useState("idle");
  const [running,    setRunning]    = useState(false);
  const [summary,    setSummary]    = useState(null);

  // Typewriter state
  const [displayLog,  setDisplayLog]  = useState([]);   // fully typed lines
  const [typingLine,  setTypingLine]  = useState(null); // { text, type, pos }
  const [tick,        setTick]        = useState(0);    // triggers dequeue effect
  const queueRef = useRef([]);                          // pending lines

  const stopRef = useRef(false);
  const logRef  = useRef(null);

  // Scroll on every render update to log
  useEffect(() => {
    if (logRef.current)
      logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [displayLog, typingLine]);

  // ── Dequeue: fire when a line finishes or new items arrive ────────────────
  useEffect(() => {
    if (typingLine !== null) return;          // busy — wait for it to finish
    if (queueRef.current.length === 0) return;

    // Flush all instant lines in one batch
    const instants = [];
    while (queueRef.current.length > 0 && INSTANT_TYPES.has(queueRef.current[0].type)) {
      instants.push(queueRef.current.shift());
    }
    if (instants.length) {
      setDisplayLog(prev => [...prev, ...instants]);
      setTick(t => t + 1);   // check again for any remaining non-instant lines
      return;
    }

    // Start typing the next non-instant line
    const next = queueRef.current.shift();
    setTypingLine({ text: next.text, type: next.type, pos: 0 });
  }, [typingLine, tick]);

  // ── Typewriter ticker ─────────────────────────────────────────────────────
  useEffect(() => {
    if (!typingLine) return;
    const id = setTimeout(() => {
      const newPos = typingLine.pos + CHARS_PER_TICK;
      if (newPos >= typingLine.text.length) {
        setDisplayLog(prev => [...prev, { text: typingLine.text, type: typingLine.type }]);
        setTypingLine(null);                  // triggers dequeue effect
      } else {
        setTypingLine({ ...typingLine, pos: newPos });
      }
    }, TICK_MS);
    return () => clearTimeout(id);
  }, [typingLine]);

  const addLog = useCallback((text, type = "info") => {
    queueRef.current.push({ text, type });
    setTick(t => t + 1);    // wake up dequeue effect
  }, []);

  const stopped = () => stopRef.current;

  const run = async () => {
    stopRef.current = false;
    setRunning(true);
    setDisplayLog([]);
    setTypingLine(null);
    queueRef.current = [];
    setTick(0);
    setSummary(null);

    // ── Fase 1: Network scan ─────────────────────────────────────────────
    setPhase("scanning");
    addLog("// iniciando flujo de ataque", "ai");
    addLog(`> scan-network ${network}`, "cmd");

    let hosts = [];
    let activeJobId = jobId; // local — se actualiza con el jobId devuelto por scan-network
    try {
      const r = await fetch(`${API_BASE}/scan-network`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ network, jobType: "IA" }),
      });
      const d = await r.json();
      hosts = Array.isArray(d.hosts) ? d.hosts : [];
      if (d.jobId) {
        activeJobId = d.jobId;
        onJobCreated?.(d.jobId);
      }
      if (!hosts.length) {
        addLog("sin hosts activos — abortando", "error");
        setPhase("done"); setRunning(false); return;
      }
      addLog(`${hosts.length} host(s): ${hosts.map(h => h.ip).join("  ")}`, "success");
      // Excluir IPs de infraestructura de red (gateway, DNS)
      const FORBIDDEN_IPS = ["10.0.0.1", "10.0.0.2"];
      hosts = hosts.filter(h => !FORBIDDEN_IPS.includes(h.ip));
      addLog(`// pruebas: hosts objetivo (${hosts.length}): ${hosts.map(h => h.ip).join("  ")}`, "ctx");
    } catch (e) {
      addLog(`error: ${e.message}`, "error");
      setPhase("stopped"); setRunning(false); return;
    }

    if (stopped()) { setPhase("stopped"); setRunning(false); return; }

    // ── Fase 2: MODO PRODUCCIÓN — cargar caché real de la BD por host ────
    setPhase("context");
    let hostCache = {};
    try {
      const hc = await (await fetch(`${API_BASE}/host-cache`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ips: hosts.map(h => h.ip) }),
      })).json();
      hostCache = hc.cache ?? {};
      const nCached = Object.keys(hostCache).length;
      addLog(`// caché BD: ${nCached} host(s) con datos previos, se reutilizan (sin re-escanear)`, "ctx");
    } catch (e) {
      addLog(`// error cargando caché de BD (${e.message}) — se escaneará todo fresco`, "warn");
    }

    if (stopped()) { setPhase("stopped"); setRunning(false); return; }

    // ── Fase 3: Historial BD (solo para fast path — no se pasa a la IA) ────
    let ctx = null;
    try {
      ctx = await (await fetch(`${API_BASE}/ai-context`)).json();
    } catch (e) {
      // no crítico — si falla, contexto queda null y se degrada a modo sin historial
    }

    if (stopped()) { setPhase("stopped"); setRunning(false); return; }

    // ── Fase 3: IA planifica ─────────────────────────────────────────────
    setPhase("planning");
    addLog("// aracni planificando ataque (con contexto histórico completo)", "ai");

    let plan = hosts.map((h, i) => ({
      ip: h.ip, accion: "scan_and_exploit", prioridad: i + 1,
      razon: "sin historial", cves_sugeridos: [],
    }));

    try {
      const d = await (await fetch(`${API_BASE}/ai-plan`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hosts, contexto: ctx,
            hostCache }),
      })).json();

      if (Array.isArray(d.plan) && d.plan.length) {
        // Dedup by IP — keep first occurrence (highest priority)
        const seen = new Set();
        plan = d.plan.filter(p => { if (seen.has(p.ip)) return false; seen.add(p.ip); return true; });

        // Fallback: hosts no mencionados por la IA → scan_and_exploit
        const plannedIps = new Set(plan.map(p => p.ip));
        hosts.forEach((h, i) => {
          if (!plannedIps.has(h.ip)) {
            plan.push({ ip: h.ip, accion: "scan_and_exploit", prioridad: 50 + i, razon: "fallback — no incluido en plan IA", cves_sugeridos: [] });
          }
        });

        if (d.resumen) addLog(`🕷️ Aracni: ${d.resumen}`, "ai");
        plan.forEach(p =>
          addLog(
            `  [${p.prioridad}] ${p.ip} → ${p.accion}` +
            (p.cves_sugeridos?.length ? `  (${p.cves_sugeridos.slice(0,2).join(", ")})` : ""),
            p.accion === "skip" ? "warn" : "plan"
          )
        );
      }
    } catch (e) {
      addLog(`aracni no disponible (${e.message})`, "warn");
    }

    if (stopped()) { setPhase("stopped"); setRunning(false); return; }

    const hostsToSkip = plan.filter(p => p.accion === "skip");
    const hostsToWork = plan.filter(p => p.accion !== "skip")
                            .sort((a, b) => (a.prioridad ?? 99) - (b.prioridad ?? 99));
    let compromised = 0;

    if (hostsToSkip.length)
      addLog(`descartando ${hostsToSkip.length} host(s) sin vector: ${hostsToSkip.map(p => p.ip).join(", ")}`, "warn");

    // ── Fast path ────────────────────────────────────────────────────────
    const winningByIp = {};
    (ctx?.winningCombinations ?? []).forEach(w => {
      if (!winningByIp[w.ip]) winningByIp[w.ip] = [];
      winningByIp[w.ip].push(w);
    });

    const _fpSeen = new Set();
    const fastPathHosts = hostsToWork.filter(e => {
      if (!winningByIp[e.ip]?.length) return false;
      if (_fpSeen.has(e.ip)) return false;
      _fpSeen.add(e.ip); return true;
    });
    const fastPathFailed = new Set();

    if (fastPathHosts.length) {
      setPhase("exploiting");
      addLog(`// fast path — ${fastPathHosts.length} host(s) con combo exacto conocido`, "plan");
    }

    for (const entry of fastPathHosts) {
      if (stopped()) break;
      const seen = new Set();
      const unique = (winningByIp[entry.ip] ?? []).filter(c => {
        if (seen.has(c.module)) return false;
        seen.add(c.module); return true;
      });

      let ok = false;
      for (const combo of unique) {
        if (stopped() || ok) break;
        const payloads = Array.isArray(combo.payloads) ? combo.payloads : [combo.payload];
        addLog(`> ${entry.ip}  ${combo.module.split("/").pop()}  port=${combo.port}`, "cmd");
        addLog(`  último éxito: ${combo.cve} el ${combo.last_success}`, "ctx");

        for (const payload of payloads) {
          if (stopped() || ok) break;
          addLog(`  payload: ${payload}`, "cmd");
          try {
            const d = await (await fetch(`${API_BASE}/run-exploit`, {
              method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ ip: entry.ip, module: combo.module, payload, port: combo.port, cve: combo.cve, jobId: activeJobId }),
            })).json();

            if (d.success) {
              ok = true; compromised++;
              addLog(`[+] acceso obtenido — ${entry.ip}  sesión ${d.sessionId}`, "success");
            } else {
              addLog(`  sin sesión — ${payloads.indexOf(payload) + 1 < payloads.length ? "probando fallback…" : "fast path agotado"}`, "warn");
            }
          } catch (e) { addLog(`  error: ${e.message}`, "error"); }
        }
      }
      if (!ok) fastPathFailed.add(entry.ip);
    }

    if (stopped()) { setPhase("stopped"); setRunning(false); return; }

    // ── Fase 4a: Deep scan en paralelo (solo hosts sin fast path) ────────
    // Hosts que siguen pendientes: los que no tenían fast path + los que fallaron en fast path
    const normalFlow = hostsToWork.filter(
      e => !winningByIp[e.ip]?.length || fastPathFailed.has(e.ip)
    );
    const hostVulns  = {};

    // Hosts que necesitan deep scan (sin datos de servicios en BD)
    const needDeepScan = normalFlow.filter(e => !hostCache[e.ip]?.ports?.length);
    const fromCache    = normalFlow.filter(e =>  hostCache[e.ip]?.ports?.length);

    // Cargar servicios de BD para hosts con datos cacheados
    fromCache.forEach(entry => {
      const svcList = hostCache[entry.ip].ports.slice(0, 4)
        .map(s => `${s.port}/${s.service ?? "?"}`).join("  ");
      addLog(
        `  ${entry.ip}: ${hostCache[entry.ip].ports.length} servicio(s) desde BD` +
        (svcList ? `  [${svcList}${hostCache[entry.ip].ports.length > 4 ? " …" : ""}]` : ""),
        "ctx"
      );
    });

    setPhase("recon");
    if (needDeepScan.length) {
      addLog(`// deep scan en paralelo — ${needDeepScan.length} host(s)`, "ai");
      await Promise.all(needDeepScan.map(async entry => {
        if (stopped()) return;
        const host = hosts.find(h => h.ip === entry.ip);
        if (!host) return;
        addLog(`> scan-host ${host.ip}`, "cmd");
        try {
          const r = await fetch(`${API_BASE}/scan-host`, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target: host.ip, jobId: activeJobId }),
          });
          if (!r.ok) throw new Error(`HTTP ${r.status}`);
          const ds = await r.json();
          const svcCount = ds.services?.length ?? 0;
          const svcList = ds.services?.slice(0, 4).map(s => `${s.port}/${s.service ?? "?"}`).join("  ") ?? "";
          hostCache[host.ip] = { ...(hostCache[host.ip] ?? {}), ports: ds.services ?? [], osInfo: ds.osInfo ?? null };
          addLog(`  ${host.ip}: ${svcCount} servicio(s)${svcList ? `  [${svcList}${svcCount > 4 ? " …" : ""}]` : ""}${ds.osInfo ? `  (SO: ${ds.osInfo})` : ""}`, "success");
        } catch (e) {
          addLog(`  ${host.ip}: error deep scan — ${e.message}`, "error");
        }
      }));
    } else if (normalFlow.length) {
      addLog("// deep scan omitido — todos los hosts tienen servicios en BD", "ctx");
    }

    if (stopped()) { setPhase("stopped"); setRunning(false); return; }

    // ── Fase 4b: Find vulns en paralelo ──────────────────────────────────
    // Pre-cargar desde caché los hosts que ya tienen datos en BD
    for (const entry of normalFlow) {
      if (hostCache[entry.ip]?.vulns?.length) {
        hostVulns[entry.ip] = hostCache[entry.ip].vulns;
        const crit = hostCache[entry.ip].vulns.filter(v => v.severity === "critical").length;
        addLog(
          `  ${entry.ip}: ${hostCache[entry.ip].vulns.length} cve(s) desde BD` +
          (crit ? `  [${crit} críticos]` : ""),
          "ctx"
        );
      }
    }

    // Solo ejecutar find-vulns para hosts sin CVEs en BD (ni de caché ni de este run)
    const needScan = normalFlow.filter(e => !hostVulns[e.ip] && !hostCache[e.ip]?.vulns?.length);
    // Cargar vulns de BD para hosts que ya las tienen pero no las cargamos antes
    normalFlow.filter(e => !hostVulns[e.ip] && hostCache[e.ip]?.vulns?.length).forEach(entry => {
      hostVulns[entry.ip] = hostCache[entry.ip].vulns;
    });
    if (needScan.length) {
      setPhase("vulns");
      const nNew = needScan.length;
      addLog(`// find-vulns en paralelo — ${nNew} host(s) sin datos en BD`, "ai");

      await Promise.all(needScan.map(async entry => {
        if (stopped()) return;
        const host = hosts.find(h => h.ip === entry.ip);
        if (!host) return;
        addLog(`> find-vulns ${host.ip}`, "cmd");
        try {
          const d = await (await fetch(`${API_BASE}/find-vulns`, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip: host.ip, jobId: activeJobId }),
          })).json();
          const vulns = Array.isArray(d.vulns) ? d.vulns : [];
          hostVulns[host.ip] = vulns;
          if (d.osInfo) {
            // find-vulns corre smb-os-discovery (más específico, ej. "Windows 10 Pro 10240")
            // scan-host solo tiene el CPE genérico de -sV (ej. "Windows windows"); el de aquí manda.
            hostCache[host.ip] = { ...(hostCache[host.ip] ?? {}), osInfo: d.osInfo };
          }
          const crit = vulns.filter(v => v.severity === "critical").length;
          addLog(
            `  ${host.ip}: ${vulns.length} cve(s)` +
            (crit ? `  [${crit} críticos]` : "") +
            (!vulns.length ? " — sin vectores" : ""),
            vulns.length ? "success" : "info"
          );
        } catch (e) {
          addLog(`  ${host.ip}: error — ${e.message}`, "error");
          hostVulns[host.ip] = [];
        }
      }));
    } else if (normalFlow.length) {
      addLog("// find-vulns omitido — todos los hosts tienen datos en BD", "ctx");
    }

    if (stopped()) { setPhase("stopped"); setRunning(false); return; }

    // ── Fase 5: Exploit normal ───────────────────────────────────────────
    // Reordenar: primero hosts con más éxitos históricos, luego por vulns críticas
    const historicSuccessCount = {};
    (ctx?.winningCombinations ?? []).forEach(w => {
      historicSuccessCount[w.ip] = (historicSuccessCount[w.ip] ?? 0) + 1;
    });

    normalFlow.sort((a, b) => {
      const aHist = historicSuccessCount[a.ip] ?? 0;
      const bHist = historicSuccessCount[b.ip] ?? 0;
      if (aHist !== bHist) return bHist - aHist; // más éxitos históricos primero
      // Sin histórico: más vulnerabilidades críticas primero
      const aCrit = (hostVulns[a.ip] ?? []).filter(v => v.severity === "critical").length;
      const bCrit = (hostVulns[b.ip] ?? []).filter(v => v.severity === "critical").length;
      if (aCrit !== bCrit) return bCrit - aCrit;
      // Finalmente por total de vulns
      return (hostVulns[b.ip] ?? []).length - (hostVulns[a.ip] ?? []).length;
    });

    addLog(
      `// orden de explotación: ${normalFlow.map(e =>
        `${e.ip}(hist:${historicSuccessCount[e.ip] ?? 0},crit:${(hostVulns[e.ip] ?? []).filter(v => v.severity === "critical").length})`
      ).join(" → ")}`,
      "plan"
    );

    for (const entry of normalFlow) {
      if (stopped()) break;
      const host   = hosts.find(h => h.ip === entry.ip);
      if (!host) continue;
      const vulns  = hostVulns[host.ip] ?? [];

      // La IA puede trabajar incluso sin CVEs del scanner — usará su propio criterio
      // IA por host — tiene libertad total para elegir CVEs
      setPhase("ai");
      let aiDecision = null;
      try {
        const services = [...new Map(
          vulns.filter(v => v.port && v.service)
               .map(v => [`${v.port}/${v.service}`, { port: v.port, proto: "tcp", service: v.service }])
        ).values()];
        const d = await (await fetch(`${API_BASE}/ai-analyze`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            ip: host.ip, services, vulns, contexto: ctx,
            cacheHost: hostCache[host.ip] ?? null,   // puertos + OS + vulns de BD
          }),
        })).json();
        aiDecision = d;
        if (d?.resumen) addLog(`  🕷️ Aracni: ${d.resumen}`, "ai");
      } catch (_) {}

      // La IA puede haber añadido CVEs propios (fuente: "ia") además de los del scanner
      let ordered = [...vulns];
      if (aiDecision?.prioridad?.length) {
        // Construir lista final: CVEs del scanner reordenados + CVEs propios de la IA
        const aiPlan = aiDecision.prioridad;
        const iaCves = aiPlan.filter(p => p.fuente === "ia").map(p => ({
          cve: p.cve, severity: "high", service: p.servicio ?? null, port: p.puerto ?? null,
        }));
        const aiOrder = aiPlan.map(p => p.cve);
        ordered = [
          ...aiOrder.map(cve =>
            vulns.find(v => v.cve === cve) ?? iaCves.find(v => v.cve === cve)
          ).filter(Boolean),
          ...vulns.filter(v => !aiOrder.includes(v.cve)),
        ];
        const iaCount = iaCves.filter(v => ordered.some(o => o.cve === v.cve)).length;
        addLog(
          `  🕷️ orden: ${ordered.slice(0, 3).map(v => v.cve).join(" → ")}${ordered.length > 3 ? " …" : ""}` +
          (iaCount ? `  (+${iaCount} CVE(s) propios de Aracni)` : ""),
          "plan"
        );
      }

      if (!ordered.length) {
        addLog(`  ${host.ip}: sin vectores de ataque — saltando`, "warn"); continue;
      }
      // Si la IA devolvió un plan con módulos exactos, ejecutar cada intento con /run-exploit
      // Si no, caer a /exploit (flujo ARES estándar con sus CVEs)
      const aiPlan = aiDecision?.prioridad ?? [];
      const hasExactPlan = aiPlan.length > 0 && aiPlan.some(p => p.modulo_msf);

      setPhase("exploiting");
      addLog(`> exploit ${host.ip}${hasExactPlan ? ` (plan IA: ${aiPlan.length} intentos exactos)` : ""}`, "cmd");

      let sessionOpened = false;
      if (hasExactPlan) {
        // IA controla exactamente qué módulo+payload+puerto probar
        for (const item of aiPlan.slice(0, 10)) {
          if (stopped() || sessionOpened) break;
          addLog(`  > ${item.modulo_msf}  payload=${item.payload ?? "self-contained"}  port=${item.puerto}`, "cmd");
          try {
            const d = await (await fetch(`${API_BASE}/run-exploit`, {
              method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                ip: host.ip, module: item.modulo_msf, payload: item.payload ?? null,
                port: item.puerto, cve: item.cve, jobId: activeJobId,
                options: item.opciones ?? {},
              }),
            })).json();
            if (d.success) {
              sessionOpened = true; compromised++;
              addLog(`[+] acceso obtenido — ${host.ip}  sesión ${d.sessionId}`, "success");
            } else {
              addLog(`  sin sesión`, "warn");
            }
          } catch (e) { addLog(`  error: ${e.message}`, "error"); }
        }
        if (!sessionOpened) addLog(`  ${host.ip}: sin sesión tras ${aiPlan.slice(0,10).length} intentos IA`, "warn");
      } else {
        // Fallback: flujo ARES estándar
        try {
          const d = await (await fetch(`${API_BASE}/exploit`, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip: host.ip, vulns: ordered, jobId: activeJobId, maxAttempts: 10 }),
          })).json();
          const text = d.output ?? "";
          text.split("\n").filter(l => l.trim()).slice(-8).forEach(l =>
            addLog(`  ${l}`, d.success ? "success" : "info")
          );
          if (d.success) { sessionOpened = true; compromised++;
            addLog(`[+] acceso obtenido — ${host.ip}  sesión ${d.sessionId}`, "success");
          } else { addLog(`  ${host.ip}: sin sesión`, "warn"); }
        } catch (e) { addLog(`  error: ${e.message}`, "error"); }
      }
    }

    // ── Resumen ──────────────────────────────────────────────────────────
    addLog("//", "info");
    addLog(`hosts: ${hosts.length}  ·  comprometidos: ${compromised}  ·  saltados: ${hostsToSkip.length}`, compromised ? "success" : "ai");
    if (stopped()) addLog("detenido manualmente", "warn");
    else addLog("flujo completado", "ai");

    setSummary({ total: hosts.length, compromised, skipped: hostsToSkip.length });
    setPhase(stopped() ? "stopped" : "done");
    setRunning(false);
  };

  const phaseInfo = PHASES[phase] ?? PHASES.idle;

  return (
    <div className="aracni-attack">

      {/* ── Phase bar ── */}
      <div className="aracni-attack-phasebar">
        <span
          className={`aracni-attack-phase-dot${running ? " aracni-attack-phase-dot--pulse" : ""}`}
          style={{ background: phaseInfo.color, boxShadow: `0 0 6px ${phaseInfo.color}88` }}
        />
        <span className="aracni-attack-phase-label" style={{ color: phaseInfo.color }}>
          {phaseInfo.label}
        </span>
        {summary && (
          <span className="aracni-attack-badges">
            <span className="aracni-attack-badge" style={{ color: "#6090d0" }}>{summary.total} hosts</span>
            <span className="aracni-attack-badge" style={{ color: summary.compromised ? "#4ade80" : "#3a3040" }}>
              {summary.compromised} pwned
            </span>
            <span className="aracni-attack-badge" style={{ color: "#3a3040" }}>{summary.skipped} skip</span>
          </span>
        )}
      </div>

      {/* ── Log ── */}
      <div className="aracni-attack-log" ref={logRef}>
        {displayLog.length === 0 && !typingLine && !running ? (
          <div className="aracni-attack-empty">
            <p>configura la red y pulsa <span>iniciar</span> para comenzar el flujo autónomo.</p>
            <p className="aracni-attack-hints">
              · consulta historial de la bd antes de atacar<br />
              · fast path con combos exactos de ataques previos<br />
              · la ia decide el orden y qué hosts saltar
            </p>
          </div>
        ) : (
          <>
            {displayLog.map((l, i) => (
              <div key={i} className="aracni-attack-line" style={{ color: LINE_COLOR[l.type] ?? "#888" }}>
                {l.text}
              </div>
            ))}

            {/* Currently typing line */}
            {typingLine && (
              <div className="aracni-attack-line aracni-attack-line--typing" style={{ color: LINE_COLOR[typingLine.type] ?? "#888" }}>
                {typingLine.text.slice(0, typingLine.pos)}
                <span className="aracni-cursor">▋</span>
              </div>
            )}

            {/* Loading dots while waiting for next output */}
            {running && !typingLine && queueRef.current.length === 0 && (
              <div className="aracni-attack-line aracni-attack-line--waiting">
                <span className="aracni-dots"><span /><span /><span /></span>
              </div>
            )}
          </>
        )}
      </div>

      {/* ── Controls ── */}
      <div className="aracni-panel-input">
        <div className="aracni-input-wrap">
          <input
            className="aracni-attack-net-input"
            value={network}
            onChange={e => setNetwork(e.target.value)}
            placeholder="red objetivo  (ej: 10.0.0.0/24)"
            disabled={running}
            onKeyDown={e => e.key === "Enter" && !running && run()}
          />
        </div>
        <div className="aracni-input-row">
          <span className="aracni-input-hint">
            {running ? "operación en curso…" : "Enter para iniciar"}
          </span>
          {!running ? (
            <button onClick={run}>
              ▶ iniciar
            </button>
          ) : (
            <button
              onClick={() => { stopRef.current = true; addLog("// señal de parada", "warn"); }}
              style={{ background: "linear-gradient(135deg,#4a1515,#3a1010)", borderColor: "rgba(204,0,26,0.3)" }}
            >
              ■ detener
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
