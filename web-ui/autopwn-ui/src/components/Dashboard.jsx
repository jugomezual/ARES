import { useEffect, useRef, useMemo } from "react";
import { Chart, registerables } from "chart.js";
import * as THREE from "three";
import PageHeader from "./PageHeader";

Chart.register(...registerables);

const SEV_COLOR = {
  critical: "#e05555",
  high:     "#f07800",
  medium:   "#f0d000",
  low:      "#8888ff",
};

// ── Stat card ────────────────────────────────────────────────────────────────
function StatCard({ label, value, color = "#00ffc3", pulse = false, icon, secondary, progress }) {
  return (
    <div className="stat-card" style={{ borderTopColor: color, color }}>
      <div className="stat-card-top">
        <div className="stat-label">{label}</div>
        {icon && <i className={`${icon} stat-icon`} style={{ color }} />}
      </div>
      <div className="stat-value" style={{
        color,
        textShadow: `0 0 18px ${color}44`,
        animation: pulse ? "da-pulse 1.2s ease-in-out infinite" : "none",
      }}>
        {value}
      </div>
      <div className="stat-secondary">{secondary ?? "\u00A0"}</div>
      <div className="stat-bar-track">
        <div className="stat-bar-fill" style={{
          width: `${Math.min((progress ?? 0) * 100, 100)}%`,
          background: color,
          opacity: 0.5,
        }} />
      </div>
    </div>
  );
}

// ── Dashboard ────────────────────────────────────────────────────────────────
export default function Dashboard({
  hosts        = [],
  hostScans    = {},
  hostVulns    = {},
  hostExploits = {},
}) {
  const hostsChartRef = useRef(null);
  const vulnChartRef  = useRef(null);
  const threeRef      = useRef(null);
  const hostsInstance = useRef(null);
  const vulnInstance  = useRef(null);
  const logsRef       = useRef(null);
  const logsInterval  = useRef(null);

  const hasData = hosts.length > 0;

  // ── Derived stats ──────────────────────────────────────────────────────────
  const totalPorts = useMemo(
    () => hosts.reduce((s, h) => s + (h.ports?.length ?? 0), 0),
    [hosts],
  );

  const allVulns = useMemo(
    () => Object.values(hostVulns).flatMap((v) => v?.vulns ?? []),
    [hostVulns],
  );

  const vulnsBySev = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0 };
    allVulns.forEach((v) => { c[v.severity] = (c[v.severity] ?? 0) + 1; });
    return c;
  }, [allVulns]);

  const hostsExploited = useMemo(
    () => Object.values(hostExploits).filter((e) => e?.success).length,
    [hostExploits],
  );

  // ── Charts ─────────────────────────────────────────────────────────────────
  useEffect(() => {
    // Bar chart — hosts by open port count (horizontal)
    if (hostsChartRef.current) {
      hostsInstance.current?.destroy();

      const portCounts = hasData ? hosts.map((h) => h.ports?.length ?? 0) : [0];
      const maxPorts   = Math.max(...portCounts, 1);
      const avgPorts   = hasData ? (portCounts.reduce((a, b) => a + b, 0) / portCounts.length) : 0;

      // Per-bar color: more ports = brighter red
      const barColors = portCounts.map((v) => {
        const intensity = v / maxPorts;
        const r = Math.round(140 + intensity * 64);
        const g = Math.round(20 + intensity * 10);
        const b = Math.round(40 + intensity * 20);
        return `rgba(${r},${g},${b},0.85)`;
      });
      const borderColors = portCounts.map((v) => {
        const intensity = v / maxPorts;
        const r = Math.round(160 + intensity * 70);
        return `rgba(${r},30,50,1)`;
      });

      // Average line plugin
      const avgLinePlugin = {
        id: "avgLine",
        afterDraw(chart) {
          if (!hasData || avgPorts === 0) return;
          const { ctx, scales: { x } } = chart;
          const xPos = x.getPixelForValue(avgPorts);
          const top    = chart.chartArea.top;
          const bottom = chart.chartArea.bottom;
          ctx.save();
          ctx.beginPath();
          ctx.moveTo(xPos, top);
          ctx.lineTo(xPos, bottom);
          ctx.strokeStyle = "rgba(255,200,80,0.5)";
          ctx.lineWidth   = 1;
          ctx.setLineDash([4, 4]);
          ctx.stroke();
          ctx.setLineDash([]);
          ctx.font = "10px 'Fira Code', monospace";
          ctx.fillStyle = "rgba(255,200,80,0.7)";
          ctx.textAlign = "center";
          ctx.fillText(`avg ${avgPorts.toFixed(1)}`, xPos, top - 4);
          ctx.restore();
        },
      };

      hostsInstance.current = new Chart(hostsChartRef.current, {
        type: "bar",
        plugins: [avgLinePlugin],
        data: {
          labels: hasData ? hosts.map((h) => h.ip) : ["No Data"],
          datasets: [{
            label: "Open Ports",
            data:            portCounts,
            backgroundColor: barColors,
            borderColor:     borderColors,
            borderWidth:     1,
            borderRadius:    4,
            borderSkipped:   false,
          }],
        },
        options: {
          indexAxis: "y",
          responsive: true,
          animation: { duration: 900, easing: "easeOutQuart" },
          layout: { padding: { top: 18, right: 24 } },
          scales: {
            x: {
              beginAtZero: true,
              ticks: {
                color: "#9a8fa8",
                font: { size: 9, family: "Fira Code" },
                stepSize: 1,
              },
              grid:   { color: "rgba(255,255,255,0.04)" },
              border: { color: "transparent" },
            },
            y: {
              ticks: {
                color: "#b0a8b8",
                font: { size: 9, family: "Fira Code" },
                padding: 6,
              },
              grid:   { color: "transparent" },
              border: { color: "rgba(255,255,255,0.06)" },
            },
          },
          plugins: {
            legend: { display: false },
            tooltip: {
              backgroundColor: "#0e0c10",
              borderColor:     "rgba(204,68,102,0.3)",
              borderWidth:     1,
              titleColor:      "#cc4466",
              bodyColor:       "#999",
              padding:         10,
              callbacks: {
                title: (items) => items[0].label,
                label: (item) => {
                  const host = hasData ? hosts[item.dataIndex] : null;
                  const ports = host?.ports?.slice(0, 8).join(", ") ?? "";
                  return [
                    ` ${item.raw} open port${item.raw !== 1 ? "s" : ""}`,
                    ports ? ` ${ports}${host.ports.length > 8 ? " …" : ""}` : "",
                  ].filter(Boolean);
                },
              },
            },
          },
        },
      });
    }

    // Doughnut chart — vulnerabilities by severity
    if (vulnChartRef.current) {
      vulnInstance.current?.destroy();
      const hasVulns = allVulns.length > 0;
      const total = hasVulns ? allVulns.length : 0;
      const centerTextPlugin = {
        id: "doughnutCenter",
        beforeDraw(chart) {
          const { ctx, chartArea } = chart;
          if (!chartArea) return;
          const cx = (chartArea.left + chartArea.right) / 2;
          const cy = (chartArea.top  + chartArea.bottom) / 2;
          ctx.save();
          ctx.font = `bold 2rem "Fira Code", monospace`;
          ctx.fillStyle = hasVulns ? "#e05555" : "#333";
          ctx.textAlign = "center";
          ctx.textBaseline = "middle";
          ctx.fillText(total, cx, cy - 10);
          ctx.font = `0.52rem "Fira Code", monospace`;
          ctx.fillStyle = "#555";
          ctx.fillText("VULNS", cx, cy + 14);
          ctx.restore();
        },
      };
      vulnInstance.current = new Chart(vulnChartRef.current, {
        type: "doughnut",
        plugins: [centerTextPlugin],
        data: {
          labels: ["Critical", "High", "Medium", "Low"],
          datasets: [{
            label: "Vulnerabilities",
            data: hasVulns
              ? [vulnsBySev.critical, vulnsBySev.high, vulnsBySev.medium, vulnsBySev.low]
              : [1, 1, 1, 1],
            backgroundColor: hasVulns
              ? ["#e05555cc", "#f07800cc", "#f0d000cc", "#8888ffcc"]
              : ["#1e1e1e", "#1e1e1e", "#1e1e1e", "#1e1e1e"],
            borderColor: hasVulns
              ? ["#e05555", "#f07800", "#f0d000", "#8888ff"]
              : ["#2a2a2a", "#2a2a2a", "#2a2a2a", "#2a2a2a"],
            borderWidth: 2,
            hoverOffset: 10,
            hoverBorderWidth: 3,
          }],
        },
        options: {
          responsive: true,
          cutout: "70%",
          animation: { duration: 900, easing: "easeOutQuart" },
          plugins: {
            legend: {
              position: "bottom",
              labels: {
                color: "#aaa",
                font: { size: 11, family: "Fira Code" },
                boxWidth: 10,
                padding: 16,
              },
            },
            tooltip: {
              backgroundColor: "#111",
              borderColor: "rgba(255,255,255,0.1)",
              borderWidth: 1,
              titleColor: "#fff",
              bodyColor: "#aaa",
              padding: 10,
              callbacks: {
                label: (ctx) => hasVulns ? ` ${ctx.label}: ${ctx.raw}` : ` ${ctx.label}: 0`,
              },
            },
          },
        },
      });
    }

    return () => {
      hostsInstance.current?.destroy();
      vulnInstance.current?.destroy();
    };
  }, [hosts, allVulns, vulnsBySev, hasData]);

  // ── Three.js network graph ─────────────────────────────────────────────────
  useEffect(() => {
    const container = threeRef.current;
    if (!container) return;

    const w = container.clientWidth  || 800;
    const h = container.clientHeight || 320;

    const scene  = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(55, w / h, 0.1, 1000);
    camera.position.set(0, 1.2, 8.5);
    camera.lookAt(0, 0, 0);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(w, h);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.innerHTML = "";
    container.appendChild(renderer.domElement);

    scene.add(new THREE.AmbientLight(0xffffff, 0.08));

    // ── helpers ────────────────────────────────────────────────────────────────
    const mkSphere = (r, hex, emInt = 0.85) => new THREE.Mesh(
      new THREE.SphereGeometry(r, 20, 20),
      new THREE.MeshPhongMaterial({ color: hex, emissive: hex, emissiveIntensity: emInt,
        shininess: 60, transparent: true, opacity: 0.92 }),
    );

    const mkEdge = (a, b, hex, op = 0.28) => new THREE.Line(
      new THREE.BufferGeometry().setFromPoints([a.clone(), b.clone()]),
      new THREE.LineBasicMaterial({ color: hex, transparent: true, opacity: op }),
    );

    const mkLabel = (text, hexStr) => {
      const cv = document.createElement("canvas");
      cv.width = 256; cv.height = 56;
      const cx = cv.getContext("2d");
      cx.font = "bold 20px 'Fira Code',monospace";
      cx.fillStyle = hexStr;
      cx.textAlign = "center";
      cx.textBaseline = "middle";
      cx.fillText(text, 128, 28);
      const sp = new THREE.Sprite(new THREE.SpriteMaterial({
        map: new THREE.CanvasTexture(cv), transparent: true, opacity: 0.82,
      }));
      sp.scale.set(2.8, 0.62, 1);
      return sp;
    };

    const group = new THREE.Group();
    scene.add(group);

    // ── background particles ───────────────────────────────────────────────────
    const ptGeo = new THREE.BufferGeometry();
    const ptPos = new Float32Array(300 * 3);
    for (let i = 0; i < 300; i++) {
      ptPos[i*3]   = (Math.random() - 0.5) * 30;
      ptPos[i*3+1] = (Math.random() - 0.5) * 18;
      ptPos[i*3+2] = (Math.random() - 0.5) * 14;
    }
    ptGeo.setAttribute("position", new THREE.BufferAttribute(ptPos, 3));
    scene.add(new THREE.Points(ptGeo,
      new THREE.PointsMaterial({ color: 0x334433, size: 0.06, transparent: true, opacity: 0.5 })
    ));

    // ── central ARES node ─────────────────────────────────────────────────────
    const CENTER = new THREE.Vector3(0, 0, 0);
    const aresNode = mkSphere(0.48, 0xcc1133, 1.0);
    group.add(aresNode);
    const aresHalo = mkSphere(0.62, 0xcc1133, 0.18);
    group.add(aresHalo);
    const aresLbl = mkLabel("ARES", "#ff4466");
    aresLbl.position.set(0, 0.9, 0);
    group.add(aresLbl);

    // ── host nodes ────────────────────────────────────────────────────────────
    const PHANTOM = !hasData;
    const nodeList = hasData ? hosts : Array.from({ length: 8 }, (_, i) => ({
      ip: `10.0.0.${i + 1}`, ports: Array(i % 4 + 1).fill(0), _phantom: true,
    }));

    const floaters = [];
    const pulses   = [];

    nodeList.forEach((host, i) => {
      const total  = nodeList.length;
      const angle  = (i / total) * Math.PI * 2;
      const orbit  = 4.8 + (i % 3) * 0.6;
      const yOff   = ((i % 3) - 1) * 1.1;
      const pos    = new THREE.Vector3(
        Math.cos(angle) * orbit,
        yOff,
        Math.sin(angle) * orbit * 0.55,
      );

      const exploit = !PHANTOM && hostExploits[host.ip];
      const vulns   = !PHANTOM ? (hostVulns[host.ip]?.vulns ?? []) : [];
      const hex     = exploit?.success ? 0xe05555 : vulns.length > 0 ? 0xf0d000 : 0x00ffc3;
      const hexStr  = exploit?.success ? "#e05555" : vulns.length > 0 ? "#f0d000" : "#00ffc3";
      const sz      = 0.13 + Math.min((host.ports?.length ?? 1) / 14, 1) * 0.18;

      const mesh = mkSphere(sz, hex, PHANTOM ? 0.5 : 0.9);
      mesh.position.copy(pos);
      group.add(mesh);
      floaters.push({ mesh, base: pos.clone(), phase: i * 0.85 });

      group.add(mkEdge(CENTER, pos, hex, PHANTOM ? 0.12 : 0.3));

      if (!PHANTOM) {
        const lbl = mkLabel(host.ip, hexStr);
        lbl.position.copy(pos).add(new THREE.Vector3(0, sz + 0.52, 0));
        group.add(lbl);
      }

      // pulse dot traveling from ARES → host
      const pdot = mkSphere(0.07, hex, 1.0);
      group.add(pdot);
      pulses.push({ mesh: pdot, from: CENTER.clone(), to: pos.clone(),
        t: (i / total), speed: 0.004 + (i % 3) * 0.002 });
    });

    // ── animation ─────────────────────────────────────────────────────────────
    let animId = 0, elapsed = 0;
    const tick = () => {
      animId = requestAnimationFrame(tick);
      elapsed += 0.016;

      group.rotation.y += 0.0018;

      // ARES pulse
      const s = 1 + Math.sin(elapsed * 2.8) * 0.07;
      aresNode.scale.setScalar(s);
      aresHalo.scale.setScalar(1 + Math.sin(elapsed * 2.8 + 1) * 0.15);
      aresHalo.material.opacity = 0.08 + Math.sin(elapsed * 2.8) * 0.06;

      // float hosts
      floaters.forEach(({ mesh, base, phase }) => {
        mesh.position.y = base.y + Math.sin(elapsed * 0.7 + phase) * 0.09;
      });

      // traveling pulses
      pulses.forEach((p) => {
        p.t += p.speed;
        if (p.t > 1) p.t = 0;
        p.mesh.position.lerpVectors(p.from, p.to, p.t);
        p.mesh.material.opacity = 0.4 + Math.sin(p.t * Math.PI) * 0.6;
      });

      renderer.render(scene, camera);
    };
    tick();

    const onResize = () => {
      const nw = container.clientWidth  || 800;
      const nh = container.clientHeight || 320;
      renderer.setSize(nw, nh);
      camera.aspect = nw / nh;
      camera.updateProjectionMatrix();
    };
    window.addEventListener("resize", onResize);

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener("resize", onResize);
      renderer.dispose();
    };
  }, [hosts, hostVulns, hostExploits, hasData]);

  // ── Live logs ──────────────────────────────────────────────────────────────
  useEffect(() => {
    if (!logsRef.current) return;
    const ts = () => new Date().toLocaleTimeString();
    const lines = [];
    if (hasData) {
      lines.push(`[${ts()}] Network scan complete — ${hosts.length} host(s) discovered`);
      hosts.forEach((h) => {
        lines.push(`[${ts()}] Host ${h.ip} — ${h.ports?.length ?? 0} port(s) open`);
      });
      Object.entries(hostVulns).forEach(([ip, v]) => {
        if (v?.vulns?.length) {
          lines.push(`[${ts()}] ${ip} — ${v.vulns.length} vuln(s) detected`);
          v.vulns.slice(0, 3).forEach((vu) => {
            lines.push(`[${ts()}]   [${vu.severity.toUpperCase()}] ${vu.cve} port ${vu.port}`);
          });
        }
      });
      Object.entries(hostExploits).forEach(([ip, e]) => {
        if (e?.success) lines.push(`[${ts()}] [PWNED] ${ip} — session ${e.sessionId} opened`);
      });
    } else {
      lines.push(`[${ts()}] AutoPwn ready — run a Network Scan to start`);
    }
    logsRef.current.textContent = lines.join("\n") + "\n";
    logsRef.current.scrollTop   = logsRef.current.scrollHeight;
  }, [hosts, hostVulns, hostExploits, hasData]);

  useEffect(() => {
    logsInterval.current = setInterval(() => {
      if (!logsRef.current) return;
      const ts     = new Date().toLocaleTimeString();
      const active = Object.values(hostExploits).filter((e) => e?.success).length;
      logsRef.current.textContent += `[${ts}] [SYS] Heartbeat — active sessions: ${active}\n`;
      logsRef.current.scrollTop    = logsRef.current.scrollHeight;
    }, 5000);
    return () => clearInterval(logsInterval.current);
  }, [hostExploits]);

  // ── Render ─────────────────────────────────────────────────────────────────
  return (
    <>
      <PageHeader icon="fa-gauge" title="Dashboard" subtitle="control panel & statistics">
        <div className="cube-container" style={{ marginLeft: "1rem" }}>
          <div className="cube">
            <div className="face front">PWN</div>
            <div className="face back">OWN</div>
            <div className="face right">1337</div>
            <div className="face left">H4X</div>
            <div className="face top">R00T</div>
            <div className="face bottom">EXP</div>
          </div>
        </div>
      </PageHeader>

      {/* ── Summary stat cards ── */}
      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(4, 1fr)",
        gap: "1rem",
        marginBottom: "1.5rem",
      }}>
        <StatCard
          label="Hosts Discovered"
          value={hosts.length}
          color="#00ffc3"
          icon="fas fa-network-wired"
          secondary={hosts.length > 0 ? `${Object.keys(hostScans).length} scanned · ${hosts.length - Object.keys(hostScans).length} pending` : "no hosts yet"}
          progress={hosts.length > 0 ? Object.keys(hostScans).length / hosts.length : 0}
        />
        <StatCard
          label="Total Open Ports"
          value={totalPorts}
          color="#4fc3f7"
          icon="fas fa-plug"
          secondary={hosts.length > 0 ? `avg ${(totalPorts / hosts.length).toFixed(1)} per host` : "no data"}
          progress={Math.min(totalPorts / 100, 1)}
        />
        <StatCard
          label="Vulnerabilities Found"
          value={allVulns.length}
          color={allVulns.length > 0 ? "#e05555" : "#444"}
          icon="fas fa-bug"
          secondary={allVulns.length > 0 ? `${vulnsBySev.critical} critical · ${vulnsBySev.high} high` : "no vulnerabilities"}
          progress={allVulns.length > 0 ? (vulnsBySev.critical + vulnsBySev.high) / allVulns.length : 0}
        />
        <StatCard
          label="Hosts Exploited"
          value={hostsExploited}
          color={hostsExploited > 0 ? "#e05555" : "#444"}
          pulse={hostsExploited > 0}
          icon="fas fa-skull-crossbones"
          secondary={hosts.length > 0 ? `${hostsExploited} of ${hosts.length} compromised` : "no targets"}
          progress={hosts.length > 0 ? hostsExploited / hosts.length : 0}
        />
      </div>

      {/* ── Host table ── */}
      <div className="card" style={{ marginBottom: "1.5rem" }}>
        <h3>Host Overview</h3>
        <div className="sidebar-separator" />

        {hasData ? (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.82rem" }}>
              <thead>
                <tr>
                  {["IP Address", "Open Ports", "Deep Scan", "Vulnerabilities", "Status"].map((th) => (
                    <th key={th} style={{
                      textAlign: "left",
                      padding: "0.5rem 0.75rem",
                      color: "#00ffc3",
                      borderBottom: "1px solid rgba(0,255,195,0.2)",
                      fontSize: "0.68rem",
                      textTransform: "uppercase",
                      letterSpacing: "1px",
                    }}>
                      {th}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {hosts.map((host) => {
                  const scan    = hostScans[host.ip];
                  const vulnRes = hostVulns[host.ip];
                  const exploit = hostExploits[host.ip];
                  const vulns   = vulnRes?.vulns ?? [];
                  const sev     = { critical: 0, high: 0, medium: 0, low: 0 };
                  vulns.forEach((v) => { sev[v.severity] = (sev[v.severity] ?? 0) + 1; });
                  const pwned   = exploit?.success === true;

                  return (
                    <tr key={host.ip} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                      <td style={{ padding: "0.65rem 0.75rem", color: "#00ffc3", fontFamily: "Fira Code, monospace" }}>
                        {host.ip}
                      </td>
                      <td style={{ padding: "0.65rem 0.75rem" }}>
                        <span style={{ color: "#4fc3f7", fontWeight: "bold" }}>
                          {host.ports?.length ?? 0}
                        </span>
                        {(host.ports?.length ?? 0) > 0 && (
                          <span style={{ color: "#555", fontSize: "0.72rem", marginLeft: "0.5rem" }}>
                            {host.ports.slice(0, 6).join(", ")}
                            {host.ports.length > 6 ? " …" : ""}
                          </span>
                        )}
                      </td>
                      <td style={{ padding: "0.65rem 0.75rem" }}>
                        {scan
                          ? <span style={{ color: "#00ffc3" }}>✓ {scan.services?.length ?? 0} services</span>
                          : <span style={{ color: "#444" }}>—</span>
                        }
                      </td>
                      <td style={{ padding: "0.65rem 0.75rem" }}>
                        {vulns.length === 0
                          ? <span style={{ color: "#444" }}>—</span>
                          : ["critical", "high", "medium", "low"].map((s) =>
                              sev[s] > 0 ? (
                                <span key={s} style={{
                                  display: "inline-block",
                                  padding: "0.12rem 0.38rem",
                                  borderRadius: 3,
                                  fontSize: "0.63rem",
                                  fontWeight: "bold",
                                  marginRight: "0.25rem",
                                  background: `${SEV_COLOR[s]}22`,
                                  color: SEV_COLOR[s],
                                  border: `1px solid ${SEV_COLOR[s]}55`,
                                }}>
                                  {sev[s]} {s}
                                </span>
                              ) : null
                            )
                        }
                      </td>
                      <td style={{ padding: "0.65rem 0.75rem" }}>
                        {pwned
                          ? <span style={{ color: "#e05555", fontWeight: "bold", animation: "da-pulse 1.2s ease-in-out infinite" }}>◉ PWNED</span>
                          : <span style={{ color: "#444", fontSize: "0.75rem" }}>not exploited</span>
                        }
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{ textAlign: "center", padding: "2.5rem 1rem" }}>
            <div style={{ fontSize: "2.5rem", marginBottom: "0.75rem", color: "rgba(0,255,195,0.12)" }}>⬡</div>
            <div style={{ fontSize: "0.88rem", color: "#555" }}>
              Run a Network Scan to populate the dashboard
            </div>
          </div>
        )}
      </div>

      {/* ── Charts ── */}
      <div className="section cards-row">
        <div className="card">
          <h3>Vulnerabilities by Severity</h3>
          <canvas ref={vulnChartRef} id="vulnChart" />
        </div>
        <div className="card">
          <h3>Hosts by Open Ports</h3>
          <canvas ref={hostsChartRef} id="hostsChart" />
        </div>
      </div>

      {/* ── Three.js ── */}
      <div className="card" style={{ height: "340px" }}>
        <h3>Network Topology — Live Map</h3>
        <div ref={threeRef} id="threejs-section" style={{ width: "100%", height: "295px" }} />
      </div>

      {/* ── Live Logs ── */}
      <div className="card">
        <h3>Live Logs</h3>
        <pre ref={logsRef} className="live-logs" />
      </div>
    </>
  );
}
