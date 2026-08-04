import { useEffect } from "react";
import "../styles/Toast.css";

const ICONS = {
  success: "fa-check",
  error:   "fa-xmark",
  info:    "fa-circle-info",
  warning: "fa-triangle-exclamation",
};

function ToastItem({ id, message, type, onRemove }) {
  useEffect(() => {
    const t = setTimeout(() => onRemove(id), 3500);
    return () => clearTimeout(t);
  }, [id, onRemove]);

  return (
    <div className={`toast toast--${type}`} onClick={() => onRemove(id)}>
      <i className={`fas ${ICONS[type]} toast-icon`} />
      <span>{message}</span>
    </div>
  );
}

export default function ToastContainer({ toasts, onRemove }) {
  if (!toasts.length) return null;
  return (
    <div className="toast-container">
      {toasts.map(t => (
        <ToastItem key={t.id} {...t} onRemove={onRemove} />
      ))}
    </div>
  );
}
