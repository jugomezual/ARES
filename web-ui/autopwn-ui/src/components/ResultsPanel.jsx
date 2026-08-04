const ACTION_META = {
  "deep-scan":  { label: "Deep Scan",  icon: "fas fa-search",           color: "#00ffc3" },
  "find-vulns": { label: "Find Vulns", icon: "fas fa-bug",              color: "#f0a500" },
  exploit:      { label: "Exploit",    icon: "fas fa-skull-crossbones",  color: "#e05555" },
};

export default function ResultsPanel({ scanResults = {} }) {
  const ips = Object.keys(scanResults);

  return (
    <aside className="results-sidebar">
      <div className="results-sidebar-label">RESULTADOS</div>

      <div className="results-sidebar-scroll">
        {ips.length === 0 ? (
          <div className="results-sidebar-empty">
            <i className="fas fa-folder-open"></i>
            <p>Sin resultados aún.<br />Ejecuta acciones en<br /><strong>Exploitation</strong>.</p>
          </div>
        ) : (
          ips.map((ip) => {
            const actions = scanResults[ip];
            return (
              <div key={ip} className="rp-host-block">
                <div className="rp-host-header">
                  <i className="fas fa-server"></i>
                  {ip}
                </div>

                {Object.entries(actions).map(([actionKey, data]) => {
                  const meta = ACTION_META[actionKey] ?? { label: actionKey, icon: "fas fa-terminal", color: "#00ffc3" };

                  return (
                    <div key={actionKey} className="rp-result-card">
                      <div className="rp-result-title" style={{ color: meta.color }}>
                        <i className={meta.icon}></i>
                        {meta.label}
                      </div>

                      {/* Deep Scan: show service list */}
                      {actionKey === "deep-scan" && Array.isArray(data.services) && (
                        data.services.length > 0 ? (
                          <ul className="rp-services-list">
                            {data.services.map((s) => (
                              <li key={`${s.port}/${s.proto}`}>
                                <span className="rp-port">{s.port}/{s.proto}</span>
                                <span className="rp-service">{s.service}</span>
                                {s.version && <span className="rp-version">{s.version}</span>}
                              </li>
                            ))}
                          </ul>
                        ) : (
                          <p className="rp-no-data">Sin servicios detectados.</p>
                        )
                      )}

                      {/* Other actions: show text snippet */}
                      {typeof data.text === "string" && (
                        <pre className="rp-text-snippet">
                          {data.text.slice(0, 220)}{data.text.length > 220 ? "\n…" : ""}
                        </pre>
                      )}
                    </div>
                  );
                })}
              </div>
            );
          })
        )}
      </div>
    </aside>
  );
}
