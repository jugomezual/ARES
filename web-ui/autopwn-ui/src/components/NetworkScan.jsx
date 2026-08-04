  import { useState } from "react";
  import PageHeader from "./PageHeader";

  const API_BASE = "http://localhost:3000";

  export default function NetworkScan({ hosts = [], onScanComplete, onNavigate, showToast }) {
    const [scanning,   setScanning]   = useState(false);
    const [error,      setError]      = useState(null);
    const [hasScanned, setHasScanned] = useState(false);

    const handleScan = async () => {
      setScanning(true);
      setError(null);

      try {
        const res = await fetch(`${API_BASE}/scan-network`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ network: "10.0.0.0/24" }),
        });

        if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);

        const data = await res.json();

        // ── DEBUG ────────────────────────────────────────────────────────────
        console.log("[NetworkScan] Backend response:", data);
        // ─────────────────────────────────────────────────────────────────────

        // Primary format: { hosts: [{ip, ports}, ...] }
        // Fallback format: { result: "<json-string>" }  (server parse failed, double-encoded)
        let discoveredHosts = [];
        if (Array.isArray(data.hosts)) {
          discoveredHosts = data.hosts;
        } else if (typeof data.result === "string") {
          console.warn("[NetworkScan] data.hosts missing — attempting to parse data.result as JSON");
          try {
            const inner = JSON.parse(data.result);
            if (Array.isArray(inner?.hosts)) discoveredHosts = inner.hosts;
          } catch (e) {
            console.error("[NetworkScan] Could not parse data.result:", e.message);
          }
        }

        console.log("[NetworkScan] discoveredHosts count:", discoveredHosts.length);

        if (typeof onScanComplete === "function") {
          onScanComplete(discoveredHosts, data.jobId ?? null);
        } else {
          console.error("[NetworkScan] onScanComplete is not a function:", onScanComplete);
        }

        setHasScanned(true);
        showToast?.(`scan complete · ${discoveredHosts.length} host${discoveredHosts.length !== 1 ? "s" : ""} found`, discoveredHosts.length > 0 ? "info" : "warning");

        // Navigate to Exploitation automatically once hosts are ready
        if (discoveredHosts.length > 0 && typeof onNavigate === "function") {
          setTimeout(() => onNavigate("exploitation"), 900);
        }
      } catch (err) {
        console.error("[NetworkScan] Fetch error:", err);
        setError(`Error en escaneo: ${err.message}`);
        showToast?.("scan failed · check backend", "error");
      } finally {
        setScanning(false);
      }
    };

    const totalPorts = hosts.reduce((sum, h) => sum + h.ports.length, 0);

    return (
      <>
        <PageHeader icon="fa-magnifying-glass" title="Network Scan" subtitle="host discovery across the network" />
        <div className="dashboard-content">
          <div className="card" id="start-network-scan" style={{ flex: 1 }}>
            <h3>Start Network Scan</h3>
            <div className="sidebar-separator"></div>
            <p>Click the button below to scan your network for active hosts and open ports.</p>

            <button className="sm-card-connect" onClick={handleScan} disabled={scanning}
              style={{ width: "fit-content", opacity: scanning ? 0.5 : 1, cursor: scanning ? "not-allowed" : "pointer" }}>
              <i className={`fas ${scanning ? "fa-spinner fa-spin" : "fa-satellite-dish"}`} />
              {scanning ? "Scanning..." : "Start Scan"}
            </button>

            {scanning && (
              <div className="spinner">
                <svg viewBox="0 0 50 50" xmlns="http://www.w3.org/2000/svg">
                  <g fill="none" fillRule="evenodd" strokeWidth="4" transform="translate(2 2)"
                    stroke="#00ffc3">
                    <circle cx="22" cy="22" r="6" strokeOpacity=".5" />
                    <path d="M22 4c9.94 0 18 8.06 18 18" />
                  </g>
                </svg>
              </div>
            )}

            {error && <pre className="scan-results">{error}</pre>}

            {/* Results table — populated from App.jsx shared state */}
            {!scanning && hosts.length > 0 && (
              <>
                <div className="scan-summary">
                  <span>
                    <i className="fas fa-server" style={{ marginRight: "0.4rem" }}></i>
                    {hosts.length} host{hosts.length !== 1 ? "s" : ""} found
                  </span>
                  <span>
                    <i className="fas fa-door-open" style={{ marginRight: "0.4rem" }}></i>
                    {totalPorts} open port{totalPorts !== 1 ? "s" : ""}
                  </span>
                </div>

                <table className="hosts-table">
                  <thead>
                    <tr>
                      <th>IP Address</th>
                      <th>Open Ports</th>
                    </tr>
                  </thead>
                  <tbody>
                    {hosts.map((host) => (
                      <tr key={host.ip}>
                        <td className="host-ip">{host.ip}</td>
                        <td className="host-ports">
                          {host.ports.length > 0 ? (
                            host.ports.map((p) => (
                              <span key={p} className="port-badge">{p}</span>
                            ))
                          ) : (
                            <span className="no-ports">no open ports</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}

            {/* Empty states — distinguish "not scanned yet" vs "scan returned 0 hosts" */}
            {!scanning && !error && hosts.length === 0 && !hasScanned && (
              <p style={{ color: "#555", marginTop: "1.2rem", fontSize: "0.85rem" }}>
                No scan results yet. Hit &quot;Start Scan&quot; to discover hosts.
              </p>
            )}
            {!scanning && !error && hosts.length === 0 && hasScanned && (
              <p style={{ color: "#888", marginTop: "1.2rem", fontSize: "0.85rem" }}>
                Scan complete — no active hosts found in this network.
              </p>
            )}
          </div>

        </div>
      </>
    );
  }
