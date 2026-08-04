import { useState, useRef, useEffect } from "react";
import AracniAttack from "./AracniAttack";
import "../styles/AIAssistant.css";

const API_BASE = "http://localhost:3000";

export default function AIAssistant({ open, onClose, onHoverEnter, onHoverLeave, jobId = null, onJobCreated }) {
  const [mode,     setMode]     = useState("chat");   // "chat" | "attack"
  const [input,    setInput]    = useState("");
  const [messages, setMessages] = useState([]);
  const [thinking, setThinking] = useState(false);

  const msgsRef = useRef(null);

  useEffect(() => {
    if (msgsRef.current)
      msgsRef.current.scrollTop = msgsRef.current.scrollHeight;
  }, [messages, thinking]);

  const handleSubmit = async () => {
    const question = input.trim();
    if (!question || thinking) return;
    setMessages(prev => [...prev, { role: "user", text: question }]);
    setInput("");
    setThinking(true);

    try {
      const res  = await fetch(`${API_BASE}/ai-chat`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ prompt: question, historial: messages }),
      });
      if (res.ok) {
        const data = await res.json();
        setMessages(prev => [...prev, { role: "assistant", text: data.respuesta ?? JSON.stringify(data) }]);
      } else {
        throw new Error("sin respuesta");
      }
    } catch {
      setMessages(prev => [...prev, {
        role: "assistant",
        text: `endpoint /ai-chat no disponible aún.\n\nPregunta recibida: "${question}"`,
      }]);
    } finally {
      setThinking(false);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === "Enter" && e.ctrlKey) handleSubmit();
  };

  return (
    <div
      className={`aracni-panel${open ? " aracni-panel--open" : ""}${mode === "attack" ? " aracni-panel--attack" : ""}`}
      onMouseEnter={onHoverEnter}
      onMouseLeave={onHoverLeave}
    >
      {/* ── Header ── */}
      <div className="aracni-panel-header">
        <span className="aracni-panel-logo">🕷️</span>
        <div className="aracni-panel-title-wrap">
          <span className="aracni-panel-title">Aracni</span>
          <span className="aracni-panel-sub">asistente de ataque</span>
        </div>

        {/* Mode toggle */}
        <div className="aracni-mode-tabs">
          <button
            className={`aracni-mode-tab${mode === "chat" ? " aracni-mode-tab--active" : ""}`}
            onClick={() => setMode("chat")}
            title="Modo chat"
          >
            💬
          </button>
          <button
            className={`aracni-mode-tab${mode === "attack" ? " aracni-mode-tab--active" : ""}`}
            onClick={() => setMode("attack")}
            title="Modo auto-attack"
          >
            ⚡
          </button>
        </div>

        <span className="aracni-panel-status">online</span>
        <button className="aracni-panel-close" onClick={onClose} title="Cerrar">✕</button>
      </div>

      {/* ── Chat mode — always mounted, hidden when inactive ── */}
      <div style={{ display: mode === "chat" ? "contents" : "none" }}>
        <div className="aracni-panel-messages" ref={msgsRef}>
          {messages.length === 0 && !thinking && (
            <div className="aracni-panel-empty">
              <span className="aracni-panel-empty-icon">🕷️</span>
              <p>Soy <strong>Aracni</strong>.<br />Pregúntame sobre vulnerabilidades,<br />payloads, CVEs o estrategias de ataque.</p>
            </div>
          )}
          {messages.map((m, i) => (
            <div key={i} className={`aracni-msg aracni-msg--${m.role}`}>
              <pre>{m.text}</pre>
            </div>
          ))}
          {thinking && (
            <div className="aracni-msg aracni-msg--assistant aracni-msg--thinking">
              <span className="aracni-dots"><span /><span /><span /></span>
            </div>
          )}
        </div>

        <div className="aracni-panel-input">
          <div className="aracni-input-wrap">
            <textarea
              placeholder="Pregunta a Aracni…"
              rows={3}
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              disabled={thinking}
            />
          </div>
          <div className="aracni-input-row">
            <span className="aracni-input-hint">Ctrl+Enter para enviar</span>
            <button onClick={handleSubmit} disabled={thinking || !input.trim()}>
              Enviar
            </button>
          </div>
        </div>
      </div>

      {/* ── Attack mode — always mounted, hidden when inactive ── */}
      <div style={{ display: mode === "attack" ? "contents" : "none" }}>
        <AracniAttack jobId={jobId} onJobCreated={onJobCreated} />
      </div>
    </div>
  );
}
