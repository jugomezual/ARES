export default function PageHeader({ icon, title, subtitle, children }) {
  return (
    <>
      <div className="sm-header" style={{ marginBottom: "1.5rem", paddingBottom: "0.5rem" }}>
        <div className="sm-header-left">
          {icon && (
            <span className="sm-header-icon">
              <i className={`fas ${icon}`} />
            </span>
          )}
          <div>
            <h1 className="sm-title">{title}</h1>
            {subtitle && <p className="sm-subtitle">{subtitle}</p>}
          </div>
          {children}
        </div>
      </div>
      <div className="separator-title" />
    </>
  );
}
