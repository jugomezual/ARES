// ================================================
// Funciones IA específicas para AutoPwn
// Prompts diseñados para el contexto de pentesting
// ================================================

const { ia_realizar_consulta } = require("./ia");


// ================================================
// ia_analizar_vulnerabilidades(ip, servicios, vulns, contexto, cacheHost)
//
// Para hosts sin combo ganador exacto (fast path ya ejecutado).
// La IA tiene LIBERTAD TOTAL para decidir qué CVEs usar:
// puede priorizar los del scanner, añadir los suyos propios,
// o descartar los que considere inviables.
//
// Retorna:
//   {
//     resumen: string,
//     prioridad: [{ cve, razon, prioridad, fuente, puerto, servicio }],
//     advertencias: [string]
//   }
//   o -1 si error
// ================================================
async function ia_analizar_vulnerabilidades(ip, servicios, vulns, contexto = null, cacheHost = null) {
  // Combinar servicios del parámetro con los del caché de BD
  const allPorts = cacheHost?.ports?.length ? cacheHost.ports : (servicios ?? []);
  const osInfo   = cacheHost?.osInfo ?? null;

  const serviciosStr = allPorts.length > 0
    ? allPorts.map(s => `  - Port ${s.port}/tcp: ${s.service || "unknown"} ${s.version || ""}`.trim()).join("\n")
    : "  (no service information)";

  // Combinar CVEs del scanner con los del caché
  const allVulnsRaw = [
    ...(vulns ?? []),
    ...((cacheHost?.vulns ?? []).filter(cv => !(vulns ?? []).some(v => v.cve === cv.cve))),
  ];

  // Limitar el número de CVEs que van al prompt. Algunos escáneres (o el
  // histórico acumulado en la BD tras muchas ejecuciones) pueden devolver
  // cientos de CVEs para un mismo host — eso infla el prompt a varios miles
  // de caracteres y hace que modelos más pequeños (7B) tarden muchísimo o
  // directamente den timeout. Nos quedamos con los MAX_CVES más graves.
  const MAX_CVES = 20;
  const SEVERITY_ORDER = { critical: 0, crit: 0, alta: 1, high: 1, medium: 2, medio: 2, low: 3, baja: 3 };
  const allVulns = [...allVulnsRaw]
    .sort((a, b) => (SEVERITY_ORDER[a.severity?.toLowerCase()] ?? 9) - (SEVERITY_ORDER[b.severity?.toLowerCase()] ?? 9))
    .slice(0, MAX_CVES);

  const vulnsStr = allVulns.length > 0
    ? allVulns.map(v => `  - ${v.cve} [${v.severity}] port ${v.port ?? "?"} (${v.service || "unknown"})`).join("\n") +
      (allVulnsRaw.length > MAX_CVES ? `\n  (+ ${allVulnsRaw.length - MAX_CVES} more, lower priority, omitted for brevity)` : "")
    : "  (none detected by scanner)";

  let contextoStr = "";
  const prevExitos = contexto ? (contexto.compromised ?? []).filter(c => c.ip === ip) : [];
  const maxIntentos = prevExitos.length > 0 ? 10 : 5;
  if (contexto) {
    const prevFallos = (contexto.onlyFailed ?? []).filter(c => c.ip === ip);
    const cvesExitosos = (contexto.workingCves ?? [])
      .map(c => `  - ${c.cve}: worked ${c.veces} time(s) on [${c.hosts}]`).join("\n");
    const patrones = (contexto.successPatterns ?? [])
      .map(p => `  - Port ${p.port}: ${p.exitos} success(es) out of ${p.total_intentos} attempts`).join("\n");

    contextoStr = `
=== NETWORK HISTORY ===
${prevExitos.length > 0
  ? `THIS IP was previously compromised with: ${prevExitos.map(e => `${e.cve} (${e.type})`).join(", ")}`
  : "This IP was not previously compromised."}
${prevFallos.length > 0
  ? `Previous failures on this IP: ${prevFallos.map(f => `port ${f.port} (${f.intentos_fallidos} attempts)`).join(", ")}`
  : ""}
CVEs that opened a shell on this network:
${cvesExitosos || "  (none yet)"}
Success rate by port:
${patrones || "  (no data)"}`;
  }

  const prompt = `You are an expert in offensive security with deep knowledge of Metasploit and real CVEs.

CONTEXT: the fast path with exact combos already ran without success on this host.
You now have FULL FREEDOM to decide which CVEs and exploits to use.

=== TARGET ===
IP: ${ip}
Detected OS: ${osInfo ?? "unknown"}
Ports and services:
${serviciosStr}

CVEs detected by automatic scanner:
${vulnsStr}
${contextoStr}

=== YOUR DECISION ===
Create the list of exploits to try. You can:
- Prioritize scanner CVEs that seem most viable
- Add CVEs from your own knowledge that apply to these services/versions (mark source as "ia")
- Discard scanner CVEs that you consider unviable
- The port must be one of the OPEN ports listed above

Return ONLY a JSON:
{
  "resumen": "1-2 sentence analysis of the target",
  "prioridad": [
    {
      "cve": "CVE-XXXX-XXXXX",
      "modulo_msf": "exploit/windows/smb/ms17_010_eternalblue",
      "payload": "windows/x64/meterpreter/bind_tcp",
      "puerto": 445,
      "opciones": {},
      "razon": "why this exploit has real chances here",
      "prioridad": 1,
      "fuente": "scanner"
    }
  ],
  "advertencias": ["warning if any"]
}

Rules:
- "modulo_msf" must be the exact Metasploit path (e.g. "exploit/windows/smb/ms17_010_eternalblue"). For wu-ftpd use "wu-ftpd 2.6.1-16 / 7350wurm".
- "payload" must be a valid Metasploit payload for that module. For self-contained modules (wu-ftpd, vsftpd) use null.
- "opciones" is an object with extra MSF options to set before running (e.g. {"SMBUser": "administrator", "SMBPass": "", "SMBDomain": "WORKGROUP"}). Use it when the module requires it or when you have information that improves the odds (known user, domain, etc.). Leave {} if there are no special options.
- Prefer bind_tcp payloads over reverse_tcp (the lab may block inbound connections).
- For CVE-2003-0352 (exploit/windows/dcerpc/ms03_026_dcom): always use "windows/shell/bind_tcp". Do NOT use meterpreter, the shellcode space of this 2003 exploit is too small for the meterpreter stager and the session never opens.
- As a general rule, for exploits older than 2010 (classic overflows with little shellcode space) prefer simple "shell" payloads over meterpreter, unless you know that specific module reliably supports meterpreter.
- For CVE-2017-0144 (ms17_010_eternalblue): the PRIORITY 1 attempt must always be WITHOUT SMBUser (opciones {}), that is what works in most cases (Windows 7/Server 2008 and also when the OS is unknown). Setting a wrong SMBUser can make Metasploit try an authenticated SMB session that fails (NT_STATUS_LOGON_FAILURE) and abort the exploit before reaching the vulnerable code, so NEVER put the credentialed attempt before the no-credentials attempt. Only IF the detected OS is explicitly Windows 10 / Server 2012+ (real data, not an assumption), add an ADDITIONAL lower-priority attempt with {"SMBUser": "Administrator", "SMBPass": ""} as reinforcement, never as a replacement for the no-credentials attempt.
- "fuente" must be "scanner" or "ia". Order by ascending prioridad (1 = first).
- MAXIMUM ${maxIntentos} entries. Each entry is ONE exact attempt, pick the most promising ones.${maxIntentos === 5 ? " This host was never compromised before: be selective, only the vectors with real chances." : ""}
Return ONLY the JSON, no additional text.`;

  return await ia_realizar_consulta(prompt, "analizar_vulnerabilidades");
}


// ================================================
// ia_recomendar_payload(modulePath, targetOs, targetArch)
//
// La IA recomienda el mejor payload para un módulo
// y objetivo concreto.
//
// Retorna:
//   {
//     payload: "windows/x64/meterpreter/reverse_tcp",
//     razon: string,
//     alternativas: ["payload2", "payload3"]
//   }
//   o -1 si error
// ================================================
async function ia_recomendar_payload(modulePath, targetOs, targetArch) {
  const prompt = `You are an expert penetration tester. Recommend the best Metasploit payload.

Exploit module: ${modulePath}
Target OS: ${targetOs || "unknown (likely Windows)"}
Target architecture: ${targetArch || "unknown (try x64 first)"}

Return ONLY a JSON object with this structure:
{
  "payload": "the best payload path (e.g. windows/x64/meterpreter/reverse_tcp)",
  "razon": "why this payload is recommended",
  "alternativas": ["second_best_payload", "third_best_payload"]
}

Consider:
- For EternalBlue (ms17_010_eternalblue): prefer bind_tcp over reverse_tcp
- For psexec: reverse_tcp is usually more reliable
- Use x64 payloads when architecture is unknown for modern Windows
Return ONLY the JSON, no other text.`;

  return await ia_realizar_consulta(prompt, "recomendar_payload");
}


// ================================================
// ia_analizar_fallo_exploit(modulePath, payload, errorLog)
//
// Dado un exploit fallido, la IA diagnostica el fallo
// y sugiere qué cambiar para el siguiente intento.
//
// Retorna:
//   {
//     diagnostico: string,
//     causa_probable: string,
//     sugerencias: [string],
//     siguiente_payload: string | null
//   }
//   o -1 si error
// ================================================
async function ia_analizar_fallo_exploit(modulePath, payload, errorLog) {
  // Truncate very long logs to avoid exceeding context limits
  const logTruncado = errorLog && errorLog.length > 2000
    ? errorLog.slice(-2000)
    : (errorLog || "(no log available)");

  const prompt = `You are an expert penetration tester. Analyze this failed exploit attempt.

Module: ${modulePath}
Payload: ${payload}
Error log (last lines):
${logTruncado}

Return ONLY a JSON object:
{
  "diagnostico": "what went wrong",
  "causa_probable": "most likely root cause",
  "sugerencias": ["specific suggestion 1", "suggestion 2"],
  "siguiente_payload": "next payload to try, or null if module itself is the problem"
}

Common failure patterns:
- "no session": payload/architecture mismatch or AV blocked
- "connection refused": target port wrong or service down
- "Read timeout": no response, possibly patched or wrong target OS
- "NT_STATUS_LOGON_FAILURE": need valid credentials
Return ONLY the JSON, no other text.`;

  return await ia_realizar_consulta(prompt, "analizar_fallo_exploit");
}


// ================================================
// ia_generar_informe_host(ip, resultados)
//
// Genera un informe ejecutivo de los resultados
// de la explotación de un host.
//
// resultados: { deepScan, findVulns, exploit }
//
// Retorna:
//   {
//     titulo: string,
//     resumen_ejecutivo: string,
//     hallazgos: [{ tipo, descripcion, criticidad }],
//     recomendaciones: [string],
//     comprometido: boolean
//   }
//   o -1 si error
// ================================================
async function ia_generar_informe_host(ip, resultados) {
  const resStr = JSON.stringify(resultados, null, 2).slice(0, 3000);

  const prompt = `You are a cybersecurity professional writing a pentest report section.

Target host: ${ip}
Test results:
${resStr}

Return ONLY a JSON object:
{
  "titulo": "Host Report: ${ip}",
  "resumen_ejecutivo": "2-3 sentence executive summary",
  "hallazgos": [
    {
      "tipo": "finding type (e.g. Remote Code Execution, Weak Credentials)",
      "descripcion": "what was found",
      "criticidad": "critical/high/medium/low"
    }
  ],
  "recomendaciones": ["patch recommendation 1", "recommendation 2"],
  "comprometido": true or false
}

Set comprometido to true only if a shell/meterpreter session was opened.
Return ONLY the JSON, no other text.`;

  return await ia_realizar_consulta(prompt, "generar_informe_host");
}


// ================================================
// ia_sugerir_siguiente_paso(ip, ports, vulns, historial)
//
// Modo guiado: la IA sugiere qué hacer a continuación
// basándose en el estado actual del ataque.
//
// historial: array de strings con acciones ya realizadas
//
// Retorna:
//   {
//     accion: "exploit" | "deep-scan" | "manual" | "skip",
//     razon: string,
//     detalle: string
//   }
//   o -1 si error
// ================================================
async function ia_sugerir_siguiente_paso(ip, ports, vulns, historial) {
  const portsStr  = (ports  || []).join(", ") || "unknown";
  const vulnsStr  = (vulns  || []).map(v => `${v.cve} [${v.severity}]`).join(", ") || "none found";
  const histStr   = (historial || []).length > 0
    ? historial.slice(-10).join("\n  ")
    : "none";

  const prompt = `You are an automated penetration testing assistant. Suggest the next action.

Target: ${ip}
Open ports: ${portsStr}
Known CVEs: ${vulnsStr}
Actions already performed:
  ${histStr}

Return ONLY a JSON object:
{
  "accion": one of: "exploit", "deep-scan", "manual", "skip",
  "razon": "why this action",
  "detalle": "specific details about what to do"
}

Action meanings:
- "exploit": run automated Metasploit exploit
- "deep-scan": run deeper nmap service scan first
- "manual": manual intervention needed (explain in detalle)
- "skip": no promising attack vector (explain why)

Return ONLY the JSON, no other text.`;

  return await ia_realizar_consulta(prompt, "sugerir_siguiente_paso");
}


// ================================================
// ia_planificar_ataque(hosts, contexto)
//
// FUNCIÓN CLAVE: antes de escanear en profundidad,
// la IA mira el historial completo de la BD y decide
// qué hosts atacar, en qué orden, y cuáles saltar.
//
// hosts:    [{ ip, ports: [22, 445, 80, ...] }]
// contexto: resultado de GET /ai-context
//
// Retorna:
//   {
//     plan: [
//       {
//         ip: "10.0.0.48",
//         accion: "skip" | "exploit_direct" | "scan_and_exploit",
//         prioridad: 1,           // 1 = atacar primero
//         razon: string,
//         cves_sugeridos: ["CVE-2017-0144"]   // CVEs a probar primero
//       }
//     ],
//     resumen: string
//   }
//   o -1 si error
// ================================================
async function ia_planificar_ataque(hosts, contexto) {
  const hostsStr = hosts.map(h =>
    `  - ${h.ip}  open ports: [${(h.ports || []).join(", ")}]`
  ).join("\n");

  const comprometidosStr = (contexto.compromised ?? []).length > 0
    ? (contexto.compromised ?? []).map(c =>
        `  - ${c.ip}: comprometido con ${c.cve ?? "exploit SMB"} (${c.type}) el ${c.last_success}`
      ).join("\n")
    : "  (ninguno todavía)";

  const cvesExitososStr = (contexto.workingCves ?? []).length > 0
    ? (contexto.workingCves ?? []).map(c =>
        `  - ${c.cve}: funcionó ${c.veces} vez/veces en hosts [${c.hosts}]`
      ).join("\n")
    : "  (ninguno todavía)";

  const patronesStr = (contexto.successPatterns ?? []).map(p =>
    `  - Port ${p.port}: ${p.exitos} éxito(s) de ${p.total_intentos} intentos totales`
  ).join("\n") || "  (sin datos)";

  const soloFallosStr = (contexto.onlyFailed ?? []).length > 0
    ? (contexto.onlyFailed ?? []).map(f =>
        `  - ${f.ip} port ${f.port}: ${f.intentos_fallidos} intentos, nunca éxito`
      ).join("\n")
    : "  (ninguno)";

  // Combos exactos ganadores — módulo+payload que abrió sesión real en cada IP
  const winningStr = (contexto.winningCombinations ?? []).length > 0
    ? (contexto.winningCombinations ?? []).map(w =>
        `  - ${w.ip}: module=${w.module}  payload=${w.payloads?.[0] ?? w.payload}  port=${w.port}  cve=${w.cve}  (last: ${w.last_success})`
      ).join("\n")
    : "  (ninguno todavía)";

  // IPs con combo exacto ganador — la IA DEBE asignarles exploit_direct
  const mustExploitIps = [...new Set((contexto.winningCombinations ?? []).map(w => w.ip))];
  const mustExploitStr = mustExploitIps.length > 0
    ? mustExploitIps.join(", ")
    : "(ninguna)";

  const prompt = `You are an expert penetration tester planning an automated attack.
You have historical data from previous attacks on this network. Use it to make SMART decisions.

=== DISCOVERED HOSTS ===
${hostsStr}

=== HISTORICAL DATA ===

Previously compromised hosts (these CVEs/methods already worked):
${comprometidosStr}

EXACT winning module+payload combinations (these opened real sessions):
${winningStr}

CVEs that successfully opened shells on this network:
${cvesExitososStr}

Port success rates across all attacks:
${patronesStr}

Hosts with only failures (never succeeded despite attempts):
${soloFallosStr}

=== YOUR TASK ===
For each discovered host, decide the best action based on THAT HOST's actual open ports and the historical data.

CRITICAL RULES — follow strictly IN THIS ORDER:

RULE 0 (ABSOLUTE PROHIBITION — overrides everything else):
The following IPs are network infrastructure and are STRICTLY FORBIDDEN as targets. NEVER include them in the plan with any action other than "skip":
FORBIDDEN HOSTS: 10.0.0.1, 10.0.0.2
If these IPs appear in the discovered hosts list, assign "skip" and do not suggest any CVEs for them.

RULE 0a (NO INVENTED HOSTS):
The "plan" array must contain EXACTLY ONE entry per IP listed in === DISCOVERED HOSTS === above — no more, no fewer. NEVER add an IP that is not in that list, even if it looks like a plausible neighbor (e.g. do not add .52, .55, .56 just because .48, .50, .53, .54 are present). Do not repeat an IP twice either.

RULE 0b (PROTOCOL RESTRICTION):
ARES only supports exploitation over the following protocols: SMB (ports 445, 139), RPC (port 135), FTP (port 21), HTTP/HTTPS (ports 80, 443, 8080, 8443).
Only suggest CVEs and attack vectors that target these protocols. IGNORE SSH, IMAP, MySQL, VNC, SMTP and any other service not listed above.
If a host only exposes unsupported protocols, assign "skip".

RULE 1 (HIGHEST PRIORITY after Rule 0):
Hosts with exact winning combinations MUST be assigned "exploit_direct". NEVER assign "skip" to these hosts.
Hosts that MUST get exploit_direct: ${mustExploitStr}

RULE 2: A CVE may only appear in "cves_sugeridos" for a host if the PORT required by that CVE is listed in that host's open ports.
   - SMB CVEs (CVE-2017-0143, CVE-2017-0144, CVE-2017-0145) require port 445 or 139.
   - SSH CVEs require port 22.

RULE 3: "skip" is only valid for hosts with NO promising ports AND NO history of compromise on this network.

RULE 4 — PRIORITY ORDER for non-fast-path hosts:
1. Hosts that were previously compromised (highest historical success count first) → assign lowest prioridad numbers.
2. Hosts with no compromise history → order by attack surface (number/severity of open ports and likely CVEs).
Never assign prioridad arbitrarily — it determines attack order.

Keep each "razon" field SHORT (under 15 words) — you have a limited response budget and every host in the discovered list must get an entry.

Return ONLY a JSON object:
{
  "resumen": "overall attack plan summary in 1-2 sentences",
  "plan": [
    {
      "ip": "10.0.x.x",
      "accion": "scan_and_exploit",
      "prioridad": 1,
      "razon": "Port 445 open — same port that succeeded on 10.0.0.48 with CVE-2017-0144",
      "cves_sugeridos": ["CVE-2017-0144", "CVE-2017-0143"]
    }
  ]
}

Valid actions:
- "scan_and_exploit": deep scan then exploit (standard flow)
- "exploit_direct": skip deep scan, go straight to exploit (host already characterized in history)
- "skip": no promising attack vector based on history and open ports

Order plan array by prioridad ascending (1 = attack first).
Write out EVERY entry in the plan array in full. NEVER abbreviate, truncate, or replace entries with a comment like "// ... repeat for remaining hosts" — JSON does not support comments and this breaks parsing. Every single host from DISCOVERED HOSTS must appear as a complete, fully-written object.
Return ONLY the JSON, no other text, no explanations before or after it.`;

  return await ia_realizar_consulta(prompt, "planificar_ataque");
}


module.exports = {
  ia_analizar_vulnerabilidades,
  ia_planificar_ataque,
  ia_recomendar_payload,
  ia_analizar_fallo_exploit,
  ia_generar_informe_host,
  ia_sugerir_siguiente_paso,
};
