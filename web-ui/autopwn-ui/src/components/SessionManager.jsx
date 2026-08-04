import { useState, useEffect, useCallback } from "react";

const API_BASE = "http://localhost:3000";

// ── OS logos (inline SVG) ────────────────────────────────────────────────────
function WindowsLogo({ size = 48 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 88 88" fill="none" xmlns="http://www.w3.org/2000/svg">
      <rect x="4"  y="4"  width="36" height="36" rx="3" fill="#00a4ef" fillOpacity="0.85"/>
      <rect x="48" y="4"  width="36" height="36" rx="3" fill="#00a4ef" fillOpacity="0.55"/>
      <rect x="4"  y="48" width="36" height="36" rx="3" fill="#00a4ef" fillOpacity="0.55"/>
      <rect x="48" y="48" width="36" height="36" rx="3" fill="#00a4ef" fillOpacity="0.35"/>
    </svg>
  );
}

function LinuxLogo({ size = 48 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 88 88" fill="none" xmlns="http://www.w3.org/2000/svg">
      <rect x="6" y="6" width="76" height="76" rx="8" fill="#1a1a2e" stroke="#f0c040" strokeWidth="2.5"/>
      <polyline points="16,30 32,44 16,58" fill="none" stroke="#f0c040" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round"/>
      <line x1="38" y1="58" x2="72" y2="58" stroke="#f0c040" strokeWidth="4" strokeLinecap="round"/>
    </svg>
  );
}

function UnknownLogo({ size = 48 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 88 88" fill="none" xmlns="http://www.w3.org/2000/svg">
      <rect x="6" y="6" width="76" height="76" rx="8" fill="#1a1a2e" stroke="#cc1133" strokeWidth="2.5"/>
      <text x="44" y="56" textAnchor="middle" fill="#cc1133" fontSize="40" fontFamily="monospace" fontWeight="bold">?</text>
    </svg>
  );
}

function OsLogo({ os, size }) {
  const normalized = (os || "").toLowerCase();
  if (normalized.includes("win"))   return <WindowsLogo size={size} />;
  if (normalized.includes("linux")) return <LinuxLogo   size={size} />;
  return <UnknownLogo size={size} />;
}

// ── Sesión activa (exploit) ───────────────────────────────────────────────────
function SessionCard({ session, onConnect }) {
  const typeBadge = session.type === "meterpreter" ? "METERPRETER" : session.type === "raw" ? "RAW SHELL" : "SHELL";
  const typeColor  = session.type === "meterpreter" ? "#b090e0" : session.type === "raw" ? "#f0a030" : "#00ffc3";

  const infoClean = session.info
    .replace(/Shell Banner:\s*/i, "")
    .replace(/---+.*/g, "")
    .trim()
    .slice(0, 60);

  return (
    <div className="sm-card" style={session.stale ? { opacity: 0.5, filter: "grayscale(60%)" } : {}} onClick={() => onConnect(session)}>
      <div className="sm-card-logo">
        <OsLogo os={session.os} size={52} />
      </div>

      <div className="sm-card-body">
        <div className="sm-card-ip">{session.ip}</div>
        <div className="sm-card-badges">
          <span className="sm-badge sm-badge--id">#{session.id}</span>
          <span className="sm-badge" style={{ color: typeColor, borderColor: typeColor + "55" }}>
            {typeBadge}
          </span>
          <span className="sm-badge sm-badge--arch">{session.arch}/{session.os}</span>
          {session.stale && <span className="sm-badge" style={{ color: "#ff4444", borderColor: "#ff444455" }}>DEAD?</span>}
        </div>
        {infoClean && <div className="sm-card-info">{infoClean}</div>}
      </div>

      <button className="sm-card-connect" onClick={e => { e.stopPropagation(); onConnect(session); }}>
        <i className="fas fa-terminal" /> Connect
      </button>
    </div>
  );
}

// ── Sesión persistente ────────────────────────────────────────────────────────
function PersistentSessionCard({ session, showToast, onDelete }) {
  const [connecting,  setConnecting]  = useState(false);
  const [confirming,  setConfirming]  = useState(false);
  const [deleting,    setDeleting]    = useState(false);
  const isRdp = session.accessMethod === "rdp";

  const handleDelete = async () => {
    setDeleting(true);
    try {
      await fetch(`${API_BASE}/persistent-session`, {
        method:  "DELETE",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ ip: session.ip, user: session.user }),
      });
      showToast?.(`Sesión ${session.ip} eliminada`, "info");
      onDelete(session.ip, session.user);
    } catch {
      showToast?.("Error al eliminar", "error");
    } finally {
      setDeleting(false);
      setConfirming(false);
    }
  };

  const connect = async (e) => {
    e.stopPropagation();
    if (connecting) return;
    setConnecting(true);
    try {
      const res  = await fetch(`${API_BASE}/rdp-connect`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ ip: session.ip, user: session.user, password: session.password, rdpClient: session.rdpClient }),
      });
      const data = await res.json();
      if (data.ok) {
        showToast?.(`RDP abierto · ${session.ip}`, "success");
      } else {
        showToast?.(`Error al abrir RDP: ${data.error ?? "desconocido"}`, "error");
      }
    } catch {
      showToast?.("Backend no disponible", "error");
    } finally {
      setConnecting(false);
    }
  };

  const date = session.createdAt
    ? new Date(session.createdAt).toLocaleDateString("es-ES", { day: "2-digit", month: "2-digit", year: "2-digit", hour: "2-digit", minute: "2-digit" })
    : "—";

  return (
    <div className="sm-card sm-card--persist">
      <div className="sm-card-logo">
        <OsLogo os={session.os} size={52} />
      </div>

      <div className="sm-card-body">
        <div className="sm-card-ip">{session.ip}</div>
        <div className="sm-card-badges">
          <span className="sm-badge sm-badge--persist-method">
            <i className={`fas fa-${isRdp ? "desktop" : "terminal"}`} /> {session.accessMethod.toUpperCase()}
          </span>
          <span className="sm-badge sm-badge--arch">{session.os}</span>
        </div>
        <div className="sm-card-info">
          {session.user} / {session.password} &nbsp;·&nbsp; {date}
        </div>
      </div>

      <div className="sm-card-actions">
        {/* Botón conectar */}
        {isRdp ? (
          <button
            className="sm-card-connect sm-card-connect--rdp"
            onClick={connect}
            disabled={connecting || confirming}
            title={`rdesktop -u ${session.user} -0 ${session.ip}`}
          >
            {connecting
              ? <><i className="fas fa-spinner fa-spin" /> Abriendo...</>
              : <><i className="fas fa-desktop" /> Conectar RDP</>}
          </button>
        ) : (
          <button
            className="sm-card-connect"
            disabled={connecting || confirming}
            onClick={async (e) => {
              e.stopPropagation();
              if (connecting) return;
              setConnecting(true);
              try {
                const res = await fetch(`${API_BASE}/ssh-connect`, {
                  method: "POST",
                  headers: { "Content-Type": "application/json" },
                  body: JSON.stringify({ ip: session.ip, user: session.user, password: session.password }),
                });
                const data = await res.json();
                if (data.ok) showToast?.(`SSH abierto · ${session.ip}`, "success");
                else showToast?.(`Error SSH: ${data.error ?? "desconocido"}`, "error");
              } catch {
                showToast?.("Backend no disponible", "error");
              } finally {
                setConnecting(false);
              }
            }}
            title={`ssh ${session.user}@${session.ip}`}
          >
            {connecting
              ? <><i className="fas fa-spinner fa-spin" /> Abriendo...</>
              : <><i className="fas fa-terminal" /> Conectar SSH</>}
          </button>
        )}

        {/* Botón eliminar con confirm inline */}
        {!confirming ? (
          <button className="sm-card-delete" onClick={() => setConfirming(true)} title="Eliminar sesión persistente">
            <i className="fas fa-trash-alt" />
          </button>
        ) : (
          <div className="sm-card-confirm">
            <span>¿Eliminar?</span>
            <button className="sm-confirm-yes" onClick={handleDelete} disabled={deleting}>
              {deleting ? <i className="fas fa-spinner fa-spin" /> : "Sí"}
            </button>
            <button className="sm-confirm-no" onClick={() => setConfirming(false)}>No</button>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export default function SessionManager({ onConnect, showToast }) {
  const [sessions,    setSessions]    = useState([]);
  const [persistent,  setPersistent]  = useState([]);
  const [loading,     setLoading]     = useState(true);
  const [error,       setError]       = useState(null);
  const [lastSync,    setLastSync]    = useState(null);

  const fetchAll = useCallback(async () => {
    try {
      const [r1, r2] = await Promise.all([
        fetch(`${API_BASE}/sessions`),
        fetch(`${API_BASE}/persistent-sessions`),
      ]);
      const d1 = await r1.json();
      const d2 = await r2.json();
      if (d1.error) throw new Error(d1.error);
      setSessions(Array.isArray(d1.sessions) ? d1.sessions : []);
      setPersistent(Array.isArray(d2.sessions) ? d2.sessions : []);
      setError(null);
      setLastSync(new Date().toLocaleTimeString());
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
    const id = setInterval(fetchAll, 12000);
    return () => clearInterval(id);
  }, [fetchAll]);

  return (
    <div className="sm-page">

      {/* ── Header ── */}
      <div className="sm-header">
        <div className="sm-header-left">
          <span className="sm-header-icon"><i className="fas fa-satellite-dish" /></span>
          <div>
            <h1 className="sm-title">Session Manager</h1>
            <p className="sm-subtitle">active & persistent sessions</p>
          </div>
        </div>

        <div className="sm-header-right">
          {sessions.length > 0 && (
            <span className="sm-count-badge">{sessions.length} activa{sessions.length !== 1 ? "s" : ""}</span>
          )}
          {persistent.length > 0 && (
            <span className="sm-count-badge sm-count-badge--persist">{persistent.length} persistente{persistent.length !== 1 ? "s" : ""}</span>
          )}
          <button className="sm-refresh-btn" onClick={fetchAll} disabled={loading} title="Actualizar">
            <i className={`fas fa-sync-alt${loading ? " fa-spin" : ""}`} />
          </button>
          {lastSync && <span className="sm-sync-time">sync {lastSync}</span>}
        </div>
      </div>
      <div className="separator-title" />

      {/* ── Error ── */}
      {error && (
        <div className="sm-empty sm-empty--error">
          <i className="fas fa-exclamation-triangle sm-empty-icon" />
          <p>Error: {error}</p>
          <button className="sm-refresh-btn" onClick={fetchAll}>Reintentar</button>
        </div>
      )}

      {!error && (
        <div className="sm-content">

          {/* ── Sesiones activas ── */}
          <div className="sm-section-label">
            <i className="fas fa-bolt" /> Active sessions
          </div>

          {loading && sessions.length === 0 && (
            <div className="sm-empty">
              <i className="fas fa-spinner fa-spin sm-empty-icon" />
              <p>consultando Metasploit...</p>
            </div>
          )}

          {!loading && sessions.length === 0 && (
            <div className="sm-empty sm-empty--inline">
              <i className="fas fa-satellite sm-empty-icon" />
              <p>No hay sesiones activas.</p>
            </div>
          )}

          {sessions.length > 0 && (
            <div className="sm-grid">
              {sessions.map(s => (
                <SessionCard key={s.id} session={s} onConnect={(sess) => {
                  showToast?.(`session · ${sess.ip}`, "info");
                  onConnect(sess);
                }} />
              ))}
            </div>
          )}

          {/* ── Sesiones persistentes ── */}
          <div className="sm-section-label sm-section-label--persist">
            <i className="fas fa-user-shield" /> Sesiones persistentes
          </div>

          {!loading && persistent.length === 0 && (
            <div className="sm-empty sm-empty--inline">
              <i className="fas fa-lock-open sm-empty-icon" />
              <p>Ninguna persistencia creada aún.</p>
            </div>
          )}

          {persistent.length > 0 && (
            <div className="sm-grid">
              {persistent.map((s, i) => (
                <PersistentSessionCard
                  key={`${s.ip}-${i}`}
                  session={s}
                  showToast={showToast}
                  onDelete={(ip, user) => setPersistent(p => p.filter(x => !(x.ip === ip && x.user === user)))}
                />
              ))}
            </div>
          )}

        </div>
      )}
    </div>
  );
}
