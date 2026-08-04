import PageHeader from "./PageHeader";

export default function ComingSoon({ title }) {
  return (
    <>
      <PageHeader title={title} />
      <div className="card" style={{ textAlign: "center", padding: "3rem" }}>
        <h3 style={{ color: "#e83050", fontSize: "1.5rem" }}>Coming Soon</h3>
        <div className="sidebar-separator"></div>
        <p>This section is under construction.</p>
      </div>
    </>
  );
}
