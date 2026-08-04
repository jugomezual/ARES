import { useState, useEffect } from "react";
import PageHeader from "./PageHeader";
import ReportCharts from "./ReportCharts";
import { generatePDF } from "../utils/pdfExport";

const API_BASE = "http://localhost:3000";
const SEVERITY_COLOR = { critical: "#e05555", high: "#f07800", medium: "#f0d000", low: "#8888ff" };

function Col({ title, icon, count, children }) {
  const [open, setOpen] = useState(true);
  return (
    <div className="rr-col">
      <button className="rr-col-head" onClick={() => setOpen((o) => !o)}>
        <i className={icon}></i>
        <span>{title}</span>
        {count != null && <span className="rr-badge">{count}</span>}
        <i className={`fas fa-chevron-${open ? "up" : "down"} rr-chevron`}></i>
      </button>
      {open && <div className="rr-col-body">{children}</div>}
    </div>
  );
}

function fmtDuration(ms) {
  if (ms == null || ms === 0) return "—";
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  const m = Math.floor(ms / 60000);
  const s = Math.floor((ms % 60000) / 1000);
  return `${m}m ${s}s`;
}


const SEV_COLOR = { critical: "#e05555", high: "#f07800", medium: "#f0d000", low: "#8888ff" };

function HostRow({ h }) {
  const [open, setOpen] = useState(false);
  const hasVulns   = h.vulns?.length > 0;
  const hasAttack  = h.exploitAttempts > 0;

  return (
    <>
      <tr
        className={`rr-host-row${h.sessionOpened ? " rr-host-row--pwned" : ""}${!hasAttack ? " rr-host-row--idle" : ""}`}
        onClick={() => hasVulns && setOpen(o => !o)}
        style={{ cursor: hasVulns ? "pointer" : "default" }}
      >
        <td className="rr-td-ip">
          {h.sessionOpened
            ? <i className="fas fa-skull-crossbones" style={{ color: "#e05555", marginRight: ".4rem" }}></i>
            : hasAttack
              ? <i className="fas fa-times-circle"   style={{ color: "#555",    marginRight: ".4rem" }}></i>
              : <i className="fas fa-minus-circle"   style={{ color: "#333",    marginRight: ".4rem" }}></i>
          }
          {h.ip}
        </td>
        <td className="rr-td-center">
          {h.vulnsFound > 0
            ? <span style={{ color: SEV_COLOR[h.vulns[0]?.severity] ?? "#888" }}>{h.vulnsFound}</span>
            : <span className="rr-dim">—</span>}
        </td>
        <td className="rr-td-center">
          {hasAttack ? h.exploitAttempts : <span className="rr-dim">—</span>}
        </td>
        <td className="rr-td-center">
          {hasAttack ? fmtDuration(h.totalAttackMs) : <span className="rr-dim">—</span>}
        </td>
        <td className="rr-td-session">
          {h.sessionOpened ? (
            <>
              <span className="rr-badge-session">{h.sessionType}</span>
              {h.sessionCve && <span className="rr-cve-tag">{h.sessionCve}</span>}
            </>
          ) : hasAttack ? (
            <span className="rr-dim">sin sesión</span>
          ) : (
            <span className="rr-dim">no atacado</span>
          )}
        </td>
        <td className="rr-td-center">
          {h.timeToSessionMs != null ? fmtDuration(h.timeToSessionMs) : <span className="rr-dim">—</span>}
        </td>
      </tr>

      {/* Fila expandible con módulo/payload y CVEs intentados */}
      {open && hasVulns && (
        <tr className="rr-host-detail-row">
          <td colSpan={6}>
            <div className="rr-host-detail">
              {h.sessionOpened && (
                <div className="rr-detail-section">
                  <span className="rr-detail-label">Módulo exitoso</span>
                  <code>{h.successModule}</code>
                  {h.successPayload && <><span className="rr-detail-sep">·</span><code>{h.successPayload}</code></>}
                </div>
              )}
              {h.cvesTried?.length > 0 && (
                <div className="rr-detail-section">
                  <span className="rr-detail-label">CVEs intentados</span>
                  {h.cvesTried.map(c => <span key={c} className="rr-cve-tag">{c}</span>)}
                </div>
              )}
              <div className="rr-detail-section">
                <span className="rr-detail-label">Vulnerabilidades encontradas</span>
                {h.vulns.map(v => (
                  <span key={v.cve} className="rr-cve-tag" style={{ color: SEV_COLOR[v.severity] ?? "#888" }}>
                    {v.cve}{v.port ? `:${v.port}` : ""}
                  </span>
                ))}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

function JobReport({ jobId, rep, onDownloadJson, onDownloadCsv }) {
  const [view, setView] = useState("table"); // "table" | "charts"

  if (!rep) return null;
  if (rep.loading) return <p className="rr-no-data" style={{ padding: "1rem" }}>Cargando informe...</p>;
  if (rep.error)   return <p className="rr-no-data" style={{ padding: "1rem", color: "#e05555" }}>{rep.error}</p>;
  if (!rep.data)   return null;

  const { meta, summary, hosts } = rep.data;

  return (
    <div className="report-card report-card--inline">
      {/* ── Cabecera ── */}
      <div className="report-header">
        <div className="report-agent">
          <i className={`fas ${meta?.type === "IA" ? "fa-robot" : "fa-user"}`}></i>
          <div>
            <div className="report-agent-name">{meta?.agent}</div>
            <div className="report-agent-sub">
              Job #{meta?.jobId} · {new Date(meta?.startedAt).toLocaleString()}
            </div>
          </div>
        </div>
        <div className="report-actions">
          {/* Toggle vista */}
          <div className="report-view-tabs">
            <button
              className={`report-view-tab${view === "table" ? " report-view-tab--active" : ""}`}
              onClick={() => setView("table")}
            >
              <i className="fas fa-table"></i> Tabla
            </button>
            <button
              className={`report-view-tab${view === "charts" ? " report-view-tab--active" : ""}`}
              onClick={() => setView("charts")}
            >
              <i className="fas fa-chart-bar"></i> Gráficas
            </button>
          </div>
          <button className="action-btn action-btn--deep-scan" onClick={() => onDownloadJson(jobId)}>
            <i className="fas fa-file-code"></i> JSON
          </button>
          <button className="action-btn action-btn--find-vulns" onClick={() => onDownloadCsv(jobId)}>
            <i className="fas fa-file-csv"></i> CSV
          </button>
          <button className="action-btn action-btn--exploit" onClick={() => generatePDF(rep.data)}>
            <i className="fas fa-file-pdf"></i> PDF
          </button>
        </div>
      </div>

      {/* ── Resumen global (siempre visible) ── */}
      {summary && (
        <div className="report-summary-bar">
          <span><strong>{summary.hostsScanned}</strong> escaneados</span>
          <span className="rr-sep">·</span>
          <span><strong>{summary.hostsWithVulns}</strong> con vulns</span>
          <span className="rr-sep">·</span>
          <span><strong>{summary.hostsAttacked}</strong> atacados</span>
          <span className="rr-sep">·</span>
          <span style={{ color: summary.hostsCompromised > 0 ? "#4ade80" : "#555" }}>
            <strong>{summary.hostsCompromised}</strong> comprometidos
          </span>
          <span className="rr-sep">·</span>
          <span><strong>{summary.totalExploitAttempts}</strong> intentos</span>
          <span className="rr-sep">·</span>
          <span><strong>{fmtDuration(summary.totalAttackMs)}</strong> tiempo activo</span>
        </div>
      )}

      {/* ── Vista tabla ── */}
      {view === "table" && hosts?.length > 0 && (
        <div className="report-hosts-wrap">
          <table className="report-hosts-table">
            <thead>
              <tr>
                <th>Host</th>
                <th className="rr-th-center">Vulns</th>
                <th className="rr-th-center">Intentos</th>
                <th className="rr-th-center">Tiempo activo</th>
                <th>Sesión</th>
                <th className="rr-th-center">Tiempo hasta sesión</th>
              </tr>
            </thead>
            <tbody>
              {hosts.map(h => <HostRow key={h.ip} h={h} />)}
            </tbody>
          </table>
          <p className="rr-table-hint">Haz clic en un host con vulns para ver detalle de módulos y CVEs</p>
        </div>
      )}

      {/* ── Vista gráficas ── siempre en DOM para que el PDF las capture ── */}
      <div style={view !== "charts" ? {
        position: "fixed", left: "-9999px", top: 0,
        width: "900px", visibility: "hidden", pointerEvents: "none"
      } : {}}>
        <ReportCharts summary={summary} hosts={hosts ?? []} />
      </div>
    </div>
  );
}

export default function Results({ hosts = [], hostScans = {}, hostVulns = {}, hostExploits = {}, jobId = null }) {
  const [jobs, setJobs]                   = useState([]);
  const [serverStartedAt, setServerStartedAt] = useState(null);
  const [expandedJobId, setExpandedJobId] = useState(null);
  const [reports, setReports]             = useState({});   // { [jobId]: { loading, error, data } }

  useEffect(() => {
    fetch(`${API_BASE}/jobs`)
      .then((r) => r.json())
      .then((data) => {
        setServerStartedAt(data.serverStartedAt ?? null);
        if (Array.isArray(data.jobs)) setJobs(data.jobs);
      })
      .catch(() => {});
  }, [jobId]);

  const toggleJob = (id) => {
    if (expandedJobId === id) { setExpandedJobId(null); return; }
    setExpandedJobId(id);
    if (reports[id]) return;
    setReports((prev) => ({ ...prev, [id]: { loading: true, error: null, data: null } }));
    fetch(`${API_BASE}/report/${id}`)
      .then((r) => r.json())
      .then((data) => setReports((prev) => ({ ...prev, [id]: { loading: false, error: null, data } })))
      .catch(() => setReports((prev) => ({ ...prev, [id]: { loading: false, error: "Error cargando informe", data: null } })));
  };

  const downloadJson = (id) => {
    const rep = reports[id]?.data;
    if (!rep) return;
    const blob = new Blob([JSON.stringify(rep, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `ares_report_job${id}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const downloadCsv = (id) => {
    window.open(`${API_BASE}/report/${id}/csv`, "_blank");
  };

  // Split jobs into current session vs historical
  const currentJobs    = serverStartedAt ? jobs.filter((j) => new Date(j.timestamp) >= new Date(serverStartedAt)) : jobs;
  const historicalJobs = serverStartedAt ? jobs.filter((j) => new Date(j.timestamp) <  new Date(serverStartedAt)) : [];

  const renderJobItem = (j) => (
    <div key={j.id} className="report-job-item-wrap">
      <button
        className={`report-job-item${expandedJobId === j.id ? " report-job-item--active" : ""}`}
        onClick={() => toggleJob(j.id)}
      >
        <i className={`fas ${j.type === "IA" ? "fa-robot" : "fa-user"} report-job-type-icon`}></i>
        <div className="report-job-info">
          <span className="report-job-agent">{j.agent}</span>
          <span className="report-job-meta">
            Job #{j.id} · {new Date(j.timestamp).toLocaleString()}
            {j.id === jobId && <span className="report-job-badge">activo</span>}
          </span>
        </div>
        <div className="report-job-stats">
          <span><i className="fas fa-desktop"></i> {j.hostsFound}</span>
          <span><i className="fas fa-terminal"></i> {j.sessionsOpened}</span>
        </div>
        <i className={`fas fa-chevron-${expandedJobId === j.id ? "up" : "down"} rr-chevron`}></i>
      </button>
      {expandedJobId === j.id && (
        <JobReport
          jobId={j.id}
          rep={reports[j.id]}
          onDownloadJson={downloadJson}
          onDownloadCsv={downloadCsv}
        />
      )}
    </div>
  );

  if (hosts.length === 0) {
    return (
      <>
        <PageHeader icon="fa-chart-bar" title="Results & Reports" subtitle="attack reports and findings" />
        <div className="rr-page rr-page--full">

          {/* Aviso compacto — sin resultados activos */}
          <div className="rr-no-results-notice">
            <i className="fas fa-folder-open"></i>
            <span>Sin resultados activos — ejecuta un <strong>Network Scan</strong> y acciones de <strong>Exploitation</strong> para verlos aquí.</span>
          </div>

          {/* Reports ocupa el resto */}
          <div className="rr-section-title">
            <i className="fas fa-file-alt"></i>
            Reports
          </div>
          <div className="rr-reports-wrap">
            <div className="rr-reports-card">
              {jobs.length === 0 && <p className="rr-no-data">No hay jobs registrados aún.</p>}
              {currentJobs.length > 0 && (
                <>
                  <div className="rr-jobs-group-label">Sesión actual</div>
                  <div className="report-job-list">{currentJobs.map(renderJobItem)}</div>
                </>
              )}
              {historicalJobs.length > 0 && (
                <>
                  <div className="rr-jobs-group-label rr-jobs-group-label--historical">Histórico</div>
                  <div className="report-job-list">{historicalJobs.map(renderJobItem)}</div>
                </>
              )}
            </div>
          </div>
        </div>
      </>
    );
  }

  return (
    <>
      <PageHeader icon="fa-chart-bar" title="Results & Reports" subtitle="attack reports and findings" />
      <div className="rr-page">

        {/* ══ RESULTS SECTION ══ */}
        <div className="rr-section-title">
          <i className="fas fa-list-alt"></i>
          Results
        </div>

        {hosts.map((host) => {
          const scan    = hostScans[host.ip];
          const vulns   = hostVulns[host.ip];
          const exploit = hostExploits[host.ip];
          const hasData = scan?.services || vulns?.vulns?.length > 0 || exploit?.text;

          return (
            <div key={host.ip} className="rr-host">
              <div className="rr-host-head">
                <i className="fas fa-server"></i>
                <span className="rr-ip">{host.ip}</span>
                <div className="rr-ports">
                  {host.ports.slice(0, 10).map((p) => (
                    <span key={p} className="port-badge">{p}</span>
                  ))}
                  {host.ports.length > 10 && (
                    <span className="port-badge port-badge--more">+{host.ports.length - 10}</span>
                  )}
                </div>
              </div>

              {!hasData && (
                <p className="rr-no-data">No actions performed yet on this host.</p>
              )}

              {hasData && (
                <div className="rr-cols">
                  {scan?.services && (
                    <Col title="Deep Scan" icon="fas fa-search" count={scan.services.length}>
                      {scan.services.length === 0 ? (
                        <p className="rr-note">No services detected.</p>
                      ) : (
                        <table className="services-table">
                          <thead>
                            <tr><th>Port</th><th>Proto</th><th>Service</th><th>Version</th></tr>
                          </thead>
                          <tbody>
                            {scan.services.map((s) => (
                              <tr key={`${s.port}/${s.proto}`}>
                                <td className="td-port">{s.port}</td>
                                <td>{s.proto}</td>
                                <td className="td-service">{s.service}</td>
                                <td className="td-version">{s.version || "—"}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      )}
                    </Col>
                  )}

                  {vulns?.vulns?.length > 0 && (
                    <Col title="Find Vulns" icon="fas fa-bug" count={vulns.vulns.length}>
                      <div className="vuln-list">
                        {vulns.vulns.map((v, i) => (
                          <div key={i} className="vuln-item">
                            <div className="vuln-item-header">
                              <span className="vuln-cve" style={{ color: SEVERITY_COLOR[v.severity] ?? "#888" }}>
                                {v.cve}
                              </span>
                              {v.port    && <span className="vuln-port">:{v.port}</span>}
                              {v.service && <span className="vuln-script">{v.service}</span>}
                              <span className="vuln-state" style={{ color: SEVERITY_COLOR[v.severity] ?? "#888" }}>
                                {v.severity}
                              </span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </Col>
                  )}

                  {exploit?.text && (
                    <Col title="Exploitation" icon="fas fa-skull-crossbones">
                      <pre className="terminal-output rr-exploit-pre">{exploit.text}</pre>
                    </Col>
                  )}
                </div>
              )}
            </div>
          );
        })}

        {/* ══ REPORTS SECTION ══ */}
        <div className="rr-section-title" style={{ marginTop: "2.5rem" }}>
          <i className="fas fa-file-alt"></i>
          Reports
        </div>

        <div className="rr-reports-wrap">
          <div className="rr-reports-card">
            {jobs.length === 0 && (
              <p className="rr-no-data">No hay jobs registrados aún.</p>
            )}
            {currentJobs.length > 0 && (
              <>
                <div className="rr-jobs-group-label">Sesión actual</div>
                <div className="report-job-list">{currentJobs.map(renderJobItem)}</div>
              </>
            )}
            {historicalJobs.length > 0 && (
              <>
                <div className="rr-jobs-group-label rr-jobs-group-label--historical">Histórico</div>
                <div className="report-job-list">{historicalJobs.map(renderJobItem)}</div>
              </>
            )}
          </div>
        </div>

      </div>
    </>
  );
}
