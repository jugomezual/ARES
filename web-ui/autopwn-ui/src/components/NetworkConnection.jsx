import { useState, useRef } from "react";
import PageHeader from "./PageHeader";

const API_BASE = "http://localhost:3000";

export default function NetworkConnection({ showToast }) {
  const [formData, setFormData] = useState({ type: "vpn", ip: "", port: "", user: "", password: "" });
  const [log, setLog]           = useState("");
  const [connecting, setConnecting] = useState(false);
  const timeoutsRef = useRef([]);

  const addLine = (line) => setLog((prev) => prev + line + "\n");

  const clearTimeouts = () => {
    timeoutsRef.current.forEach(clearTimeout);
    timeoutsRef.current = [];
  };

  const startFakeLog = (type, ip, port, user) => {
    setLog("");
    const steps = [
      `[INFO] Preparing ${type.toUpperCase()} connection...`,
      `[INFO] Target: ${ip}:${port}`,
      `[INFO] User: ${user}`,
      "[INFO] Establishing secure tunnel...",
      "[INFO] Negotiating encryption...",
      "[INFO] Awaiting server response...",
    ];
    steps.forEach((line, i) => {
      const id = setTimeout(() => addLine(line), i * 700);
      timeoutsRef.current.push(id);
    });
  };

  const handleChange = (e) => setFormData({ ...formData, [e.target.name]: e.target.value });

  const handleSubmit = async (e) => {
    e.preventDefault();
    const { type, ip, port, user, password } = formData;
    setConnecting(true);
    startFakeLog(type, ip, port, user);

    try {
      const res = await fetch(`${API_BASE}/connect`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type, ip, port, user, password }),
      });
      const result = await res.json();

      const finalMsg = res.ok
        ? `✅ ${result.message}`
        : `❌ Error: ${result.error || "No se pudo establecer la conexión"}`;

      setTimeout(() => {
        clearTimeouts();
        addLine(finalMsg);
        setConnecting(false);
        if (res.ok) showToast?.(`${formData.type.toUpperCase()} connected · ${formData.ip}`, "success");
        else showToast?.("connection failed", "error");
      }, 4500);
    } catch (err) {
      setTimeout(() => {
        clearTimeouts();
        addLine("❌ No se pudo contactar con el servidor. Verifica que está en ejecución.");
        setConnecting(false);
        showToast?.("server unreachable", "error");
      }, 4500);
    }
  };

  return (
    <>
      <PageHeader icon="fa-plug" title="Network Connection" subtitle="VPN and Netcat connections" />
      <div className="dashboard-content">
        <div className="card" style={{ flex: 1 }}>
          <h3>Establish a Connection</h3>
          <div className="sidebar-separator"></div>
          <p>Select a connection type and configure the parameters:</p>

          <form onSubmit={handleSubmit}>
            <label>Type:
              <select name="type" value={formData.type} onChange={handleChange}>
                <option value="vpn">VPN</option>
                <option value="ncat">Netcat</option>
              </select>
            </label>
            <label>Target IP:
              <input type="text" name="ip" placeholder="e.g., 192.168.1.10"
                value={formData.ip} onChange={handleChange} required />
            </label>
            <label>Port:
              <input type="number" name="port" placeholder="e.g., 443"
                value={formData.port} onChange={handleChange} required />
            </label>
            <label>User:
              <input type="text" name="user" placeholder="e.g., usuario"
                value={formData.user} onChange={handleChange} required />
            </label>
            <label>Password:
              <input type="password" name="password" placeholder="e.g., p@ssw0rd"
                value={formData.password} onChange={handleChange} required />
            </label>
            <button type="submit" disabled={connecting}>
              {connecting ? "Connecting..." : "Connect"}
            </button>
          </form>

          {log && <pre className="connection-log">{log}</pre>}
        </div>

      </div>
    </>
  );
}
