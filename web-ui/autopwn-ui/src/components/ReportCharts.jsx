import { useEffect, useRef } from "react";
import { Chart, registerables } from "chart.js";

Chart.register(...registerables);

const DARK = {
  critical: "#e05555",
  high:     "#f07800",
  medium:   "#f0d000",
  low:      "#8888ff",
  pwned:    "#4ade80",
  failed:   "#cc4466",
  idle:     "#2a2a2a",
  text:     "#888",
  grid:     "#1e1e1e",
};

Chart.defaults.color       = DARK.text;
Chart.defaults.borderColor = DARK.grid;
Chart.defaults.font.family = "'JetBrains Mono', 'Fira Mono', monospace";
Chart.defaults.font.size   = 11;

// val(ctx) — extrae el número del parsed, sea escalar u objeto {x,y}
const val = ctx => (typeof ctx.parsed === "object" ? ctx.parsed.x ?? ctx.parsed.y : ctx.parsed) ?? 0;

function useChart(ref, type, data, options) {
  const chartRef = useRef(null);
  useEffect(() => {
    if (!ref.current) return;
    chartRef.current?.destroy();
    chartRef.current = new Chart(ref.current, { type, data, options });
    return () => chartRef.current?.destroy();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [JSON.stringify(data)]);
}

function fmtSec(ms) {
  if (!ms || ms < 0) return "0s";
  if (ms < 60000) return `${(ms / 1000).toFixed(0)}s`;
  return `${Math.floor(ms / 60000)}m ${Math.floor((ms % 60000) / 1000)}s`;
}

/* ── Gráfica 1: Estado de hosts (donut) ─────────────────────────── */
function HostStatusDonut({ summary }) {
  const canvasRef = useRef(null);
  const { hostsScanned, hostsWithVulns, hostsAttacked, hostsCompromised } = summary;
  const noVulns   = hostsScanned   - hostsWithVulns;
  const vulnNoAtk = hostsWithVulns - hostsAttacked;
  const atkNoSess = hostsAttacked  - hostsCompromised;

  useChart(canvasRef, "doughnut",
    {
      labels: ["Sin vulns", "Con vulns, no atacado", "Atacado sin sesión", "Comprometido"],
      datasets: [{
        data: [noVulns, vulnNoAtk, atkNoSess, hostsCompromised],
        backgroundColor: [DARK.idle, "#3a3060", DARK.failed + "cc", DARK.pwned],
        borderWidth: 1, borderColor: "#111",
      }],
    },
    {
      responsive: true,
      maintainAspectRatio: true,
      aspectRatio: 1.6,
      plugins: {
        legend: { position: "bottom", labels: { boxWidth: 11, padding: 8, font: { size: 10 } } },
        tooltip: { callbacks: { label: ctx => ` ${ctx.label}: ${val(ctx)} host(s)` } },
      },
      cutout: "62%",
    }
  );

  return (
    <div className="rc-card">
      <div className="rc-title">Estado de hosts</div>
      <canvas ref={canvasRef} />
    </div>
  );
}

/* ── Gráfica 2: Severidad de vulnerabilidades (donut) ───────────── */
function SeverityDonut({ summary }) {
  const canvasRef = useRef(null);
  const sev = summary.vulnsBySeverity ?? {};

  useChart(canvasRef, "doughnut",
    {
      labels: ["Crítica", "Alta", "Media", "Baja"],
      datasets: [{
        data: [sev.critical ?? 0, sev.high ?? 0, sev.medium ?? 0, sev.low ?? 0],
        backgroundColor: [DARK.critical, DARK.high, DARK.medium, DARK.low],
        borderWidth: 1, borderColor: "#111",
      }],
    },
    {
      responsive: true,
      maintainAspectRatio: true,
      aspectRatio: 1.6,
      plugins: {
        legend: { position: "bottom", labels: { boxWidth: 11, padding: 8, font: { size: 10 } } },
        tooltip: { callbacks: { label: ctx => ` ${ctx.label}: ${val(ctx)} CVE(s)` } },
      },
      cutout: "62%",
    }
  );

  return (
    <div className="rc-card">
      <div className="rc-title">Severidad de vulnerabilidades</div>
      <canvas ref={canvasRef} />
    </div>
  );
}

/* ── Gráfica 3: Intentos de exploit por host (barra horizontal) ─── */
function ExploitAttemptsBar({ hosts }) {
  const canvasRef = useRef(null);
  const attacked = hosts.filter(h => h.exploitAttempts > 0);

  useChart(canvasRef, "bar",
    {
      labels: attacked.map(h => h.ip),
      datasets: [{
        label: "Intentos de exploit",
        data: attacked.map(h => h.exploitAttempts),
        backgroundColor: attacked.map(h => h.sessionOpened ? DARK.pwned + "cc" : DARK.failed + "cc"),
        borderColor:     attacked.map(h => h.sessionOpened ? DARK.pwned : DARK.failed),
        borderWidth: 1, borderRadius: 4,
      }],
    },
    {
      indexAxis: "y",
      responsive: true,
      maintainAspectRatio: true,
      aspectRatio: Math.max(2.5, attacked.length * 0.6),
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: ctx => {
              const h = attacked[ctx.dataIndex];
              const n = val(ctx);
              const extra = h.sessionOpened ? ` ✓ sesión (${h.sessionType})` : " ✗ sin sesión";
              return ` ${n} intento${n !== 1 ? "s" : ""}${extra}`;
            },
          },
        },
      },
      scales: {
        x: { ticks: { stepSize: 1 }, grid: { color: DARK.grid } },
        y: { grid: { display: false }, ticks: { font: { family: "monospace", size: 11 } } },
      },
    }
  );

  if (!attacked.length) return null;
  return (
    <div className="rc-card rc-card--wide">
      <div className="rc-title">
        Intentos de exploit por host
        <span className="rc-legend">
          <span style={{ color: DARK.pwned }}>■</span> comprometido &nbsp;
          <span style={{ color: DARK.failed }}>■</span> sin sesión
        </span>
      </div>
      <canvas ref={canvasRef} />
    </div>
  );
}

/* ── Gráfica 4: Tiempo activo de ataque por host ────────────────── */
function AttackTimeBar({ hosts }) {
  const canvasRef = useRef(null);
  const attacked = hosts.filter(h => h.exploitAttempts > 0 && h.totalAttackMs);

  useChart(canvasRef, "bar",
    {
      labels: attacked.map(h => h.ip),
      datasets: [
        {
          label: "Tiempo total activo (s)",
          data: attacked.map(h => Math.round((h.totalAttackMs ?? 0) / 1000)),
          backgroundColor: attacked.map(h => h.sessionOpened ? DARK.pwned + "88" : DARK.failed + "88"),
          borderColor:     attacked.map(h => h.sessionOpened ? DARK.pwned : DARK.failed),
          borderWidth: 1, borderRadius: 4,
        },
        {
          label: "Hasta sesión (s)",
          data: attacked.map(h =>
            h.timeToSessionMs != null ? Math.round(h.timeToSessionMs / 1000) : 0
          ),
          backgroundColor: DARK.pwned + "33",
          borderColor: DARK.pwned,
          borderWidth: 1, borderRadius: 4,
        },
      ],
    },
    {
      indexAxis: "y",
      responsive: true,
      maintainAspectRatio: true,
      aspectRatio: Math.max(2.5, attacked.length * 0.6),
      plugins: {
        legend: { position: "bottom", labels: { boxWidth: 11, padding: 8, font: { size: 10 } } },
        tooltip: {
          callbacks: {
            label: ctx => {
              const secs = val(ctx);
              return ` ${ctx.dataset.label}: ${fmtSec(secs * 1000)}`;
            },
          },
        },
      },
      scales: {
        x: { grid: { color: DARK.grid }, ticks: { callback: v => `${v}s` } },
        y: { grid: { display: false }, ticks: { font: { family: "monospace", size: 11 } } },
      },
    }
  );

  if (!attacked.length) return null;
  return (
    <div className="rc-card rc-card--wide">
      <div className="rc-title">Tiempo de ataque por host</div>
      <canvas ref={canvasRef} />
    </div>
  );
}

/* ── Gráfica 5: Intentos por CVE ────────────────────────────────── */
function CveBar({ hosts }) {
  const canvasRef = useRef(null);

  const cveMap = {};
  for (const h of hosts)
    for (const c of h.cveBreakdown ?? []) {
      if (!cveMap[c.cve]) cveMap[c.cve] = { attempts: 0, successes: 0 };
      cveMap[c.cve].attempts += c.attempts;
      if (c.success) cveMap[c.cve].successes++;
    }
  const cves = Object.entries(cveMap).sort((a, b) => b[1].attempts - a[1].attempts);

  useChart(canvasRef, "bar",
    {
      labels: cves.map(([cve]) => cve),
      datasets: [
        {
          label: "Intentos",
          data: cves.map(([, v]) => v.attempts),
          backgroundColor: DARK.failed + "99",
          borderColor: DARK.failed,
          borderWidth: 1, borderRadius: 4,
        },
        {
          label: "Hosts comprometidos",
          data: cves.map(([, v]) => v.successes),
          backgroundColor: DARK.pwned + "99",
          borderColor: DARK.pwned,
          borderWidth: 1, borderRadius: 4,
        },
      ],
    },
    {
      responsive: true,
      maintainAspectRatio: true,
      aspectRatio: Math.max(2.5, cves.length * 0.55),
      plugins: {
        legend: { position: "bottom", labels: { boxWidth: 11, padding: 8, font: { size: 10 } } },
        tooltip: { callbacks: { label: ctx => ` ${ctx.dataset.label}: ${val(ctx)}` } },
      },
      scales: {
        x: { grid: { display: false }, ticks: { font: { family: "monospace", size: 10 }, maxRotation: 25 } },
        y: { ticks: { stepSize: 1 }, grid: { color: DARK.grid } },
      },
    }
  );

  if (!cves.length) return null;
  return (
    <div className="rc-card rc-card--wide">
      <div className="rc-title">Intentos por CVE</div>
      <canvas ref={canvasRef} />
    </div>
  );
}

/* ── Componente raíz ─────────────────────────────────────────────── */
export default function ReportCharts({ summary, hosts }) {
  if (!summary || !hosts) return null;
  const hasAttacks = hosts.some(h => h.exploitAttempts > 0);

  return (
    <div className="rc-grid">
      <HostStatusDonut summary={summary} />
      <SeverityDonut   summary={summary} />
      {hasAttacks && <ExploitAttemptsBar hosts={hosts} />}
      {hasAttacks && <AttackTimeBar      hosts={hosts} />}
      {hasAttacks && <CveBar            hosts={hosts} />}
    </div>
  );
}
