import { useState, useRef, useEffect } from "react";

const API_BASE = "http://localhost:3000";

export default function TargetAcquired({ ip, sessionId, exploitModule, exploitOptions, onTerminate, onBack }) {
  const [history, setHistory] = useState(() => {
    const lines = [
      `[+] Session ${sessionId} opened on ${ip}`,
    ];
    if (exploitModule) {
      lines.push(`[+] Exploit: ${exploitModule}`);
      lines.push("");
    }
    if (exploitOptions) {
      exploitOptions.split("\n").forEach((l) => lines.push(l));
      lines.push("");
    }
    lines.push(`[*] Type commands below. Session is live.`);
    lines.push("");
    return lines;
  });
  const [input,      setInput]      = useState("");
  const [running,   setRunning]   = useState(false);
  const [persisting, setPersisting] = useState(false);
  const outputRef = useRef(null);
  const inputRef  = useRef(null);

  useEffect(() => {
    if (outputRef.current)
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
  }, [history]);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const pushLine = (line) => setHistory((h) => [...h, line]);

  const handleTerminate = async () => {
    try {
      await fetch(`${API_BASE}/session-close`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ sessionId }),
      });
    } catch {
      // proceed even if backend unreachable
    }
    onTerminate();
  };

  const generatePersistence = async () => {
    if (persisting || running) return;
    setPersisting(true);
    pushLine("[*] Iniciando generación de persistencia...");
    pushLine("");
    try {
      const res = await fetch(`${API_BASE}/session-persist`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ sessionId }),
      });
      const data = await res.json();
      if (data.log) data.log.split("\n").forEach((l) => pushLine(l));
    } catch {
      pushLine("[-] Error al conectar con el backend — ¿sigue activa la sesión?");
    } finally {
      setPersisting(false);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  };

  const sendCommand = async (e) => {
    e.preventDefault();
    const cmd = input.trim();
    if (!cmd || running) return;

    setInput("");
    pushLine(`root@${ip}:~# ${cmd}`);
    setRunning(true);

    try {
      const res  = await fetch(`${API_BASE}/exploit-cmd`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ sessionId, command: cmd }),
      });
      const data = await res.json();
      const out  = (data.output ?? "").trim() || "[no output]";
      out.split("\n").forEach((l) => pushLine(l));
    } catch {
      pushLine("[-] Backend unreachable");
    } finally {
      setRunning(false);
      pushLine("");
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  };

  return (
    <div className="ta-page">

      {/* ── Header bar ── */}
      <div className="ta-header">
        <span className="ta-pulse"></span>
        <span className="ta-title">TARGET ACQUIRED</span>
        <span className="ta-ip">{ip}</span>
        <span className="ta-session-badge">SESSION #{sessionId}</span>
        <button
          className="ta-ssh-btn"
          onClick={generatePersistence}
          disabled={persisting || running}
          title="Crea usuario admin + acceso persistente (SSH en Linux, RDP en Windows)"
        >
          {persisting
            ? <><i className="fas fa-spinner fa-spin"></i> Generating...</>
            : <><i className="fas fa-user-shield"></i> Generate Persistence</>}
        </button>
        {onBack && (
          <button className="ta-back-btn" onClick={onBack} title="Volver al gestor de sesiones (la sesión sigue activa)">
            <i className="fas fa-chevron-left"></i> Back
          </button>
        )}
        <button className="ta-terminate" onClick={handleTerminate}>
          <i className="fas fa-times-circle"></i> Terminate
        </button>
      </div>

      {/* ── Terminal output ── */}
      <div className="ta-terminal" ref={outputRef}>
        <pre className="ta-output">{history.join("\n")}</pre>
        {running && <p className="ta-running">[*] executing...</p>}
      </div>

      {/* ── Command input ── */}
      <form className="ta-input-row" onSubmit={sendCommand}>
        <span className="ta-prompt">root@{ip}:~#</span>
        <input
          ref={inputRef}
          className="ta-cmd-input"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="enter command..."
          disabled={running}
          autoComplete="off"
          spellCheck="false"
        />
        <button className="ta-send-btn" type="submit" disabled={running || !input.trim()}>
          {running ? <i className="fas fa-spinner fa-spin"></i> : <i className="fas fa-paper-plane"></i>}
        </button>
      </form>
    </div>
  );
}
