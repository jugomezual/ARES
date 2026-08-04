export default function AracniButton({ onClick, active, onMouseEnter }) {
  return (
    <button
      className={`aracni-btn${active ? " aracni-btn--active" : ""}`}
      onClick={onClick}
      onMouseEnter={onMouseEnter}
      title="Aracni Assistant"
    >
      <i className="fas fa-spider" />
    </button>
  );
}
