import jsPDF from "jspdf";

// ═══════════════════════════════════════════════════════════════════════════
// PALETA — Tema "command center" para herramientas de seguridad
// ═══════════════════════════════════════════════════════════════════════════
const C = {
  // Backgrounds
  bg:        [22,  25,  35],
  surface:   [28,  32,  44],
  card:      [35,  39,  54],
  cardAlt:   [42,  47,  63],
  // Borders
  border:    [52,  58,  72],
  borderL:   [72,  80,  98],
  // Brand
  accent:    [225, 70,  95],
  accentD:   [60,  20,  32],
  accentS:   [255, 110, 130],
  // Status
  pwned:     [74,  222, 128],
  pwnedD:    [18,  52,  30],
  pwnedS:    [120, 250, 170],
  failed:    [200, 70,  85],
  failedD:   [50,  20,  25],
  // Severity
  critical:  [232, 80,  80],
  high:      [245, 130, 30],
  medium:    [240, 200, 60],
  low:       [120, 150, 240],
  // Accents
  teal:      [56,  189, 148],
  blue:      [88,  166, 255],
  yellow:    [230, 180, 50],
  // Text
  white:     [255, 255, 255],
  text:      [225, 228, 235],
  textD:     [180, 184, 195],
  muted:     [108, 114, 128],
  dim:       [60,  64,  74],
};
const SEV = {
  critical: C.critical,
  high:     C.high,
  medium:   C.medium,
  low:      C.low,
};

// ═══════════════════════════════════════════════════════════════════════════
// FORMATTERS
// ═══════════════════════════════════════════════════════════════════════════
function fmtMs(ms) {
  if (!ms || ms <= 0) return "—";
  if (ms < 1000)  return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  const m = Math.floor(ms / 60000);
  const s = Math.floor((ms % 60000) / 1000);
  return `${m}m ${s}s`;
}
function fmtDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("es-ES", {
    dateStyle: "long",
    timeStyle: "short",
  });
}
function fmtDateShort(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString("es-ES");
}
function pct(n) { return n != null ? `${n}%` : "—"; }

// ═══════════════════════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════════════════════
export function generatePDF(reportData) {
  const { meta, summary, hosts } = reportData;
  const kpi = summary.kpi ?? {};
  const jt  = summary.jobTimingMs ?? {};
  const doc = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });

  const PW = doc.internal.pageSize.getWidth();
  const PH = doc.internal.pageSize.getHeight();
  const ML = 16, MR = 16;
  const CW = PW - ML - MR;

  let y = 0;

  // ── Drawing primitives ─────────────────────────────────────────────────────
  const fillRect = (x, yy, w, h, color) => {
    doc.setFillColor(...color);
    doc.rect(x, yy, w, h, "F");
  };
  const fillRound = (x, yy, w, h, r, color) => {
    doc.setFillColor(...color);
    doc.roundedRect(x, yy, w, h, r, r, "F");
  };
  const strokeRound = (x, yy, w, h, r, color, lw = 0.2) => {
    doc.setDrawColor(...color);
    doc.setLineWidth(lw);
    doc.roundedRect(x, yy, w, h, r, r, "S");
  };
  const line = (x1, y1, x2, y2, color, lw = 0.2) => {
    doc.setDrawColor(...color);
    doc.setLineWidth(lw);
    doc.line(x1, y1, x2, y2);
  };

  // ── Background ─────────────────────────────────────────────────────────────
  const bg = () => fillRect(0, 0, PW, PH, C.bg);

  const newPage = (withCard = false) => {
    doc.addPage();
    bg();
    if (withCard) {
      fillRound(ML - 4, 16, CW + 8, PH - 30, 3, C.surface);
      strokeRound(ML - 4, 16, CW + 8, PH - 30, 3, C.border, 0.3);
    }
    y = 22;
  };
  const checkY = (needed) => {
    if (y + needed > PH - 18) newPage();
  };

  // ── Text helpers ───────────────────────────────────────────────────────────
  const txt = (text, x, yy, opts = {}) => {
    doc.setFont(opts.font ?? "helvetica", opts.bold ? "bold" : (opts.italic ? "italic" : "normal"));
    doc.setFontSize(opts.size ?? 9);
    doc.setTextColor(...(opts.color ?? C.text));
    if (opts.charSpace != null) doc.setCharSpace(opts.charSpace);
    const lines = doc.splitTextToSize(String(text ?? "—"), opts.maxW ?? 9999);
    doc.text(lines, x, yy, { align: opts.align ?? "left" });
    if (opts.charSpace != null) doc.setCharSpace(0);
    return lines.length;
  };
  const mono = (text, x, yy, opts = {}) => txt(text, x, yy, { ...opts, font: "courier" });

  // ── Corner marks (technical look) ─────────────────────────────────────────
  const cornerMarks = (x, yy, w, h, len = 3, color = C.accent, lw = 0.4) => {
    doc.setDrawColor(...color);
    doc.setLineWidth(lw);
    doc.line(x, yy, x + len, yy);
    doc.line(x, yy, x, yy + len);
    doc.line(x + w - len, yy, x + w, yy);
    doc.line(x + w, yy, x + w, yy + len);
    doc.line(x, yy + h - len, x, yy + h);
    doc.line(x, yy + h, x + len, yy + h);
    doc.line(x + w - len, yy + h, x + w, yy + h);
    doc.line(x + w, yy + h - len, x + w, yy + h);
  };

  // ── Section header ─────────────────────────────────────────────────────────
  const section = (num, title, subtitle = null) => {
    const sh = subtitle ? 22 : 18;
    checkY(sh + 8);

    // Background panel
    fillRound(ML, y, CW, sh, 1.5, C.surface);
    // Left accent bar
    fillRect(ML, y, 3.5, sh, C.accent);
    // Section number badge
    fillRound(ML + 7, y + (sh / 2) - 5, 14, 10, 1.5, C.accentD);
    txt(num, ML + 14, y + (sh / 2) + 2, { font: "courier", bold: true, size: 10, color: C.accentS, align: "center" });
    // Vertical divider
    line(ML + 25, y + 4, ML + 25, y + sh - 4, C.borderL, 0.4);
    // Title + subtitle
    const tx = ML + 30;
    if (subtitle) {
      txt(title.toUpperCase(), tx, y + 9, { bold: true, size: 10.5, color: C.white, charSpace: 0.3 });
      txt(subtitle, tx, y + 16, { size: 6.5, color: C.textD });
    } else {
      txt(title.toUpperCase(), tx, y + sh / 2 + 2, { bold: true, size: 10.5, color: C.white, charSpace: 0.3 });
    }
    // Bottom accent line
    line(ML, y + sh, ML + CW, y + sh, C.accentD, 0.4);

    y += sh + 8;
  };

  // ── Progress bar (refined) ────────────────────────────────────────────────
  const progressBar = (label, value, maxVal, x, yy, w, color = C.accent, opts = {}) => {
    const ratio = maxVal > 0 ? Math.min(value / maxVal, 1) : 0;
    const valStr = opts.valueText ?? (maxVal === 100 ? `${value}%` : `${value}/${maxVal}`);
    txt(label, x, yy, { size: 6.2, color: C.textD, charSpace: 0.3 });
    txt(valStr, x + w, yy, { size: 8, color, bold: true, align: "right", font: "courier" });
    fillRound(x, yy + 3.5, w, 2.5, 1.25, C.border);
    if (ratio > 0) {
      fillRound(x, yy + 3.5, w * ratio, 2.5, 1.25, color);
    }
    return 9;
  };

  // ── Footer ────────────────────────────────────────────────────────────────
  const footer = (p, total) => {
    fillRect(0, PH - 11, PW, 11, C.surface);
    line(0, PH - 11, PW, PH - 11, C.accentD, 0.4);
    txt("CONFIDENCIAL", ML, PH - 4, { size: 5.5, color: C.dim, bold: true, charSpace: 0.5 });
    mono(`ARES-${meta.jobId}-${fmtDateShort(meta.startedAt).replace(/\//g, "")}`,
         PW / 2, PH - 4, { size: 5.5, color: C.muted, align: "center" });
    mono(`${String(p).padStart(2, "0")} / ${String(total).padStart(2, "0")}`,
         PW - MR, PH - 4, { size: 5.5, color: C.textD, align: "right", bold: true });
  };

  // ════════════════════════════════════════════════════════════════════════════
  // PORTADA
  // ════════════════════════════════════════════════════════════════════════════
  bg();

  // Top stripe
  fillRect(0, 0, PW, 1.5, C.accent);

  // Header metadata row
  txt("CLASSIFICATION", ML, 10, { size: 5.5, color: C.muted, charSpace: 0.5 });
  txt("CONFIDENCIAL", ML, 14, { size: 7, color: C.accent, bold: true, charSpace: 0.4 });

  txt("DOCUMENT ID", PW / 2, 10, { size: 5.5, color: C.muted, align: "center", charSpace: 0.5 });
  mono(`ARES-${String(meta.jobId).padStart(4, "0")}`, PW / 2, 14, { size: 7, color: C.text, align: "center", bold: true });

  txt("FECHA EMISIÓN", PW - MR, 10, { size: 5.5, color: C.muted, align: "right", charSpace: 0.5 });
  mono(fmtDateShort(meta.exportedAt), PW - MR, 14, { size: 7, color: C.text, align: "right", bold: true });

  // Subtle dot grid in upper area
  doc.setFillColor(...C.dim);
  for (let gy = 24; gy < 64; gy += 4) {
    for (let gx = ML; gx <= PW - MR; gx += 4) {
      doc.circle(gx, gy, 0.15, "F");
    }
  }

  // ─── HERO ───
  line(ML, 75, ML + 30, 75, C.accent, 0.6);
  txt("SECURITY ASSESSMENT REPORT", ML, 80, { size: 7, color: C.accent, bold: true, charSpace: 1.5 });

  txt("ARES", ML, 118, { bold: true, size: 90, color: C.white, charSpace: 4 });

  txt("Auto Red Team Exploit System", ML, 128, { size: 9, color: C.textD, italic: true });

  line(ML, 134, PW - MR, 134, C.border, 0.3);

  // ─── METADATA GRID ───
  const mY = 144;
  const colW = CW / 2;

  txt("AGENTE", ML, mY, { size: 5.5, color: C.muted, charSpace: 0.6 });
  line(ML, mY + 2, ML + 12, mY + 2, C.accent, 0.5);
  txt(meta.agent, ML, mY + 9, { size: 12, bold: true, color: C.white, maxW: colW - 6 });

  txt("MODO DE EJECUCIÓN", ML, mY + 22, { size: 5.5, color: C.muted, charSpace: 0.6 });
  line(ML, mY + 24, ML + 12, mY + 24, C.accent, 0.5);
  const modoLabel = meta.type === "IA"
    ? `Autónomo · IA${meta.model ? ` · ${meta.model}` : ""}`
    : "Manual · Operador humano";
  txt(modoLabel, ML, mY + 31, { size: 9, color: C.text, bold: true });

  const rX = ML + colW + 4;
  txt("INICIO DEL JOB", rX, mY, { size: 5.5, color: C.muted, charSpace: 0.6 });
  line(rX, mY + 2, rX + 12, mY + 2, C.accent, 0.5);
  mono(fmtDate(meta.startedAt), rX, mY + 9, { size: 8.5, color: C.text, bold: true });

  txt("ID DE TRABAJO", rX, mY + 22, { size: 5.5, color: C.muted, charSpace: 0.6 });
  line(rX, mY + 24, rX + 12, mY + 24, C.accent, 0.5);
  mono(`#${String(meta.jobId).padStart(6, "0")}`, rX, mY + 31, { size: 9, color: C.text, bold: true });

  // ─── 4 STATS ROW ───
  const sY = 198;
  const sH = 44;
  fillRound(ML, sY, CW, sH, 2, C.surface);
  cornerMarks(ML, sY, CW, sH, 3, C.accent, 0.5);

  const networkCidr = hosts.length > 0 ? hosts[0].ip.replace(/\.\d+$/, ".0/24") : "la red";
  const resisted = (summary.hostsAttacked ?? 0) - (summary.hostsCompromised ?? 0);
  const resistedTxt = resisted === 1
    ? `solo 1 host resistió el ataque`
    : resisted === 0
      ? `ningún host resistió el ataque`
      : `${resisted} hosts resistieron el ataque`;

  const stats = [
    { label: "HOSTS RECONOCIDOS EN LA RED",
      sub:   `${summary.hostsScanned} hosts detectados con IPs únicas en ${networkCidr}`,
      value: summary.hostsScanned,
      color: C.blue  },
    { label: "VULNERABILIDADES DETECTADAS",
      sub:   `${summary.totalVulnsFound} vulnerabilidades encontradas en total`,
      value: summary.totalVulnsFound,
      color: C.high  },
    { label: "HOSTS COMPROMETIDOS",
      sub:   `De ${summary.hostsAttacked ?? 0} atacados, ${resistedTxt}`,
      value: summary.hostsCompromised,
      color: summary.hostsCompromised > 0 ? C.pwned : C.muted },
    { label: "TASA DE ÉXITO",
      sub:   `${summary.hostsCompromised ?? 0} de ${summary.hostsAttacked ?? 0} objetivos comprometidos`,
      value: pct(kpi.compromiseRate),
      color: kpi.compromiseRate > 0 ? C.pwned : C.muted },
  ];
  const stW = CW / 4;
  stats.forEach((s, i) => {
    const sx = ML + i * stW;
    if (i > 0) line(sx, sY + 8, sx, sY + sH - 8, C.border, 0.25);
    fillRect(sx + 6, sY + 2, stW - 12, 1.8, s.color);
    txt(s.label, sx + stW / 2, sY + 12, { size: 5.2, color: C.textD, align: "center", maxW: stW - 6 });
    txt(String(s.value), sx + stW / 2, sY + 27, { bold: true, size: 18, color: s.color, align: "center" });
    txt(s.sub, sx + stW / 2, sY + 38, { size: 5, color: C.text, align: "center", italic: true, maxW: stW - 8 });
  });

  // Bottom strip
  fillRect(0, PH - 11, PW, 11, C.surface);
  line(0, PH - 11, PW, PH - 11, C.accentD, 0.3);
  txt("ARES — Auto Red Team Exploit System", ML, PH - 4, { size: 5.5, color: C.dim, charSpace: 0.3 });
  txt("CONFIDENTIAL", PW - MR, PH - 4, { size: 5.5, color: C.dim, align: "right", bold: true, charSpace: 0.5 });

  // ════════════════════════════════════════════════════════════════════════════
  // PÁGINA 2 — RESUMEN EJECUTIVO
  // ════════════════════════════════════════════════════════════════════════════
  newPage();
  section("01", "Resumen ejecutivo", "Visión global del trabajo de evaluación");

  // ─── Hero metric ───
  const heroPwn      = summary.hostsCompromised;
  const heroAttacked = summary.hostsAttacked ?? 0;
  const heroScanned  = summary.hostsScanned  ?? 0;
  const compromisedHosts = hosts.filter(h => h.sessionOpened);

  // OS label: use real nmap-detected info from DB; fallback to service banners, then module inference
  const osFromHost = (h) => {
    if (h.osInfo) return h.osInfo;

    // Inferir desde banners de servicios nmap (h.ports)
    const banners = (h.ports ?? []).map(p => p.version ?? "").join(" ");
    if (banners) {
      if (/ubuntu/i.test(banners))                        return "Linux (Ubuntu)";
      if (/debian/i.test(banners))                        return "Linux (Debian)";
      if (/red\s*hat|rhel|centos/i.test(banners))         return "Linux (Red Hat)";
      if (/fedora/i.test(banners))                        return "Linux (Fedora)";
      if (/freebsd/i.test(banners))                       return "FreeBSD";
      if (/openbsd/i.test(banners))                       return "OpenBSD";
      if (/microsoft windows xp/i.test(banners))          return "Windows XP";
      if (/microsoft windows server 2003/i.test(banners)) return "Windows Server 2003";
      if (/microsoft windows 7/i.test(banners))           return "Windows 7";
      if (/microsoft windows 10/i.test(banners))          return "Windows 10";
      if (/microsoft windows/i.test(banners))             return "Windows";
      if (/windows/i.test(banners))                       return "Windows";
      if (/linux/i.test(banners))                         return "Linux";
    }

    // Inferir desde servicios detectados
    const services = (h.ports ?? []).map(p => (p.service ?? "") + " " + (p.version ?? "")).join(" ");
    if (/microsoft iis|netbios-ssn.*microsoft|microsoft.*rpc/i.test(services)) return "Windows";
    if (/samba/i.test(services) && /ubuntu|debian/i.test(services))            return "Linux (Ubuntu)";
    if (/samba/i.test(services))                                                return "Linux";
    if (/openssh.*ubuntu/i.test(services))                                      return "Linux (Ubuntu)";
    if (/openssh.*debian/i.test(services))                                      return "Linux (Debian)";

    // Fallback: inferir desde módulo de exploit exitoso
    const mod = h.successModule ?? "";
    if (/wu.?ftpd|7350wurm/i.test(mod))    return "Linux (Red Hat)";
    if (/ms03_026_dcom/i.test(mod))        return "Windows Server 2003";
    if (/ms17_010_eternalblue/i.test(mod)) return "Windows 7 / Server 2008 R2";
    if (/ms17_010_psexec/i.test(mod))      return "Windows";
    if (/vsftpd/i.test(mod))               return "Linux (Ubuntu)";
    if (/ms08_067/i.test(mod))             return "Windows XP / Server 2003";
    if (/windows/i.test(mod))              return "Windows";
    if (/linux|unix|ftpd/i.test(mod))      return "Linux";
    return "Sistema desconocido";
  };

  const resistedCount = heroAttacked - heroPwn;
  const heroH = 22 + 12 + compromisedHosts.length * 8 + (compromisedHosts.length > 0 ? 12 : 0);
  // Thin teal bar — contrasts with red section headers
  fillRect(ML, y, 1.5, heroH, C.teal);

  const tx = ML + 7, tw = CW - 10;

  // "INTRODUCCIÓN" mini-header — starts after the teal bar
  txt("INTRODUCCIÓN", tx, y + 2, { size: 6.5, color: C.textD, bold: true, charSpace: 0.6 });
  line(tx, y + 4, ML + CW, y + 4, C.border, 0.3);

  let iy = y + 11;

  const prose = heroPwn > 0
    ? `El presente informe recoge los resultados del proceso de evaluación de seguridad llevado a cabo sobre la red ${networkCidr}, ` +
      `en la que se identificaron ${heroScanned} hosts activos. De estos, ${heroAttacked} ${heroAttacked === 1 ? "fue seleccionado" : "fueron seleccionados"} ` +
      `como objetivo de un proceso de explotación activa. El resultado fue la obtención de acceso completo sobre ${heroPwn} ` +
      `${heroPwn === 1 ? "sistema" : "sistemas"}` +
      (resistedCount === 0
        ? heroAttacked === 1
          ? `, siendo el único objetivo atacado comprometido con éxito.`
          : `, siendo todos los objetivos atacados comprometidos con éxito.`
        : resistedCount === 1
          ? `, mientras que 1 host resistió el ataque sin ser comprometido.`
          : `, mientras que ${resistedCount} hosts resistieron el ataque sin ser comprometidos.`)
    : `El presente informe recoge los resultados del proceso de evaluación sobre la red ${networkCidr}, ` +
      `donde se identificaron ${heroScanned} hosts activos. Se intentó ejecutar vectores de explotación sobre ${heroAttacked} ` +
      `${heroAttacked === 1 ? "objetivo" : "objetivos"}, sin lograrse en ningún caso la apertura de una sesión de acceso.`;

  // Set font BEFORE splitTextToSize so line breaks are calculated with the correct metrics
  doc.setFont("helvetica", "normal");
  doc.setFontSize(9);
  doc.setTextColor(...C.text);
  const proseLines = doc.splitTextToSize(prose, tw);
  const lineH = 5;

  // Manual justify: distribute extra space between words (skip last line)
  const justifyLine = (lineText, x, lineY, maxW) => {
    const words = lineText.trim().split(/\s+/);
    if (words.length <= 1) { doc.text(lineText, x, lineY); return; }
    const totalWordW = words.reduce((s, w) => s + doc.getTextWidth(w), 0);
    const gap = (maxW - totalWordW) / (words.length - 1);
    let cx = x;
    words.forEach(w => { doc.text(w, cx, lineY); cx += doc.getTextWidth(w) + gap; });
  };

  proseLines.forEach((ln, idx) => {
    const isLast = idx === proseLines.length - 1;
    if (isLast) doc.text(ln, tx, iy + idx * lineH);
    else        justifyLine(ln, tx, iy + idx * lineH, tw);
  });
  iy += proseLines.length * lineH + 5;

  // Thin separator before the host list
  line(tx, iy, tx + tw, iy, C.border, 0.3);
  iy += 5;

  if (compromisedHosts.length > 0) {
    txt("Sistemas con acceso obtenido:", tx, iy, { size: 7.5, bold: true, color: C.textD, charSpace: 0.2 });
    iy += 7;
    for (const h of compromisedHosts) {
      const os = osFromHost(h);
      fillRound(tx, iy - 2.8, 2, 2, 0.4, C.pwned);
      txt(`${h.ip}  —  ${os}`, tx + 5, iy, { size: 7.5, color: C.text });
      iy += 8;
    }
  }

  y += heroH + 6;

  // ─── Índice de rendimiento ───
  y += 4;
  checkY(90);
  txt("RENDIMIENTO", ML, y, { size: 6.5, color: C.textD, bold: true, charSpace: 0.6 });
  line(ML, y + 2, ML + CW, y + 2, C.border, 0.3);
  y += 6;

  // KPI bars with explanatory text below each
  const hostsComp = summary.hostsCompromised ?? 0;
  const hostsAtk  = summary.hostsAttacked    ?? 0;
  const totalAttempts = (kpi.moduleAccuracyRate ?? 0) > 0
    ? Math.round(hostsComp * 100 / kpi.moduleAccuracyRate)
    : (summary.totalExploitAttempts ?? 0);
  const firstHits = kpi.firstAttemptSuccesses ?? 0;

  const kpiBars = [
    { label: "TASA DE COMPROMISO  /  hosts comprometidos sobre hosts atacados",
      fraction: `${hostsComp} / ${hostsAtk}`,
      value: kpi.compromiseRate ?? 0, maxVal: 100, color: C.pwned,
      desc: "Porcentaje de hosts atacados que fueron comprometidos con éxito. Un valor alto indica alta efectividad en la fase de explotación." },
    { label: "PRECISIÓN DE MÓDULOS  /  sesiones obtenidas sobre intentos de exploit",
      fraction: totalAttempts > 0 ? `${hostsComp} / ${totalAttempts}` : null,
      value: kpi.moduleAccuracyRate ?? 0, maxVal: 100, color: C.teal,
      desc: "Ratio entre sesiones abiertas y el total de intentos de exploit ejecutados. Refleja la eficiencia en la selección y ejecución de módulos." },
    { label: "ACIERTOS AL PRIMER INTENTO  /  sesiones logradas en el primer try",
      fraction: `${firstHits} / ${Math.max(hostsComp, 1)}`,
      value: firstHits, maxVal: Math.max(hostsComp, 1), color: C.blue,
      valueText: `${firstHits}/${Math.max(hostsComp, 1)}`,
      desc: "Compromisos logrados en la primera tentativa de explotación, sin necesitar iteraciones adicionales de módulos o payloads." },
  ];

  const kpiX  = ML + 8;
  const barW  = CW - 22;
  const kpiPadTop    = 10;
  const kpiPadBottom = 1;

  // Pre-calcular altura real del contenido
  let kpiContentH = 0;
  doc.setFont("helvetica", "italic");
  doc.setFontSize(7.5);
  for (const b of kpiBars) {
    const dLines = doc.splitTextToSize(b.desc, barW);
    kpiContentH += 14 + dLines.length * 4.5 + 4;
  }
  const kpiCardH = kpiContentH + kpiPadTop + kpiPadBottom;

  fillRound(ML, y, CW, kpiCardH, 2, C.card);
  cornerMarks(ML, y, CW, kpiCardH, 2.5, C.borderL, 0.3);

  let ky = y + kpiPadTop;

  for (const b of kpiBars) {
    progressBar(b.label, b.value, b.maxVal, kpiX, ky, barW, b.color, b.valueText ? { valueText: b.valueText } : {});
    // Fracción justo debajo de la barra, alineada a la izquierda
    if (b.fraction) {
      mono(`${b.fraction}`, kpiX + barW / 2, ky + 9, { size: 6, color: b.color, align: "center" });
    }
    ky += 14;
    doc.setFont("helvetica", "italic");
    doc.setFontSize(7.5);
    doc.setTextColor(...C.text);
    const dLines = doc.splitTextToSize(b.desc, barW);
    doc.text(dLines, kpiX, ky);
    ky += dLines.length * 4.5 + 4;
  }

  y += kpiCardH + 6;

  checkY(32);
  const effMetrics = [
    { label: "INTENTOS / SESIÓN",      value: kpi.attemptsPerSession != null ? String(kpi.attemptsPerSession) : "—", sub: "menos = más eficiente",   color: C.accent },
    { label: "TIEMPO MEDIO / SESIÓN",  value: fmtMs(kpi.avgTimePerSessionMs),                                        sub: "velocidad de compromiso", color: C.yellow },
    { label: "T. HASTA 1ª SESIÓN",     value: fmtMs(jt.timeToFirstSessionMs),                                        sub: "desde inicio del job",    color: C.pwned  },
    { label: "DURACIÓN TOTAL DEL JOB", value: fmtMs(jt.totalJobDurationMs),                                          sub: "tiempo activo completo",  color: C.text   },
  ];
  const emW = (CW - 6) / 4;
  const emH = 26;
  effMetrics.forEach((m, i) => {
    const ex = ML + i * (emW + 2);
    fillRound(ex, y, emW, emH, 2, C.cardAlt);
    fillRect(ex, y + emH - 0.6, emW, 0.6, m.color);
    txt(m.label,        ex + emW / 2, y + 6,  { size: 5.5, color: C.textD, align: "center" });
    txt(String(m.value),ex + emW / 2, y + 15, { bold: true, size: 10, color: m.color, align: "center", font: "courier" });
    txt(m.sub,          ex + emW / 2, y + 21, { size: 5.5, color: C.text, align: "center" });
  });
  y += emH + 6;

  // ════════════════════════════════════════════════════════════════════════════
  // PÁGINAS 3+ — DETALLE POR HOST
  // ════════════════════════════════════════════════════════════════════════════

  // Helper global accesible en sección 02 y 04
  const inferCveFromModule = (module) => {
    const m = (module ?? "").toLowerCase();
    if (/ms17_010/.test(m))          return "CVE-2017-0144";
    if (/ms08_067/.test(m))          return "CVE-2008-4250";
    if (/ms03_026|dcom/.test(m))     return "CVE-2003-0352";
    if (/ms09_050/.test(m))          return "CVE-2009-3103";
    if (/ms10_061/.test(m))          return "CVE-2010-2729";
    if (/ms06_040/.test(m))          return "CVE-2006-3439";
    if (/vsftpd/.test(m))            return "CVE-2011-2523";
    if (/wu.?ftpd|7350wurm/.test(m)) return "CVE-2000-0573";
    if (/shellshock|bash_env/.test(m)) return "CVE-2014-6271";
    if (/usermap_script/.test(m))    return "CVE-2007-2447";
    if (/samba.*symlink/.test(m))    return "CVE-2010-0926";
    return null;
  };

  const attackedHosts = hosts.filter(h => h.exploitAttempts > 0);
  if (attackedHosts.length > 0) {
    newPage();
    section("02", "Detalle por host atacado",
      `${attackedHosts.length} ${attackedHosts.length === 1 ? "host evaluado" : "hosts evaluados"} en profundidad`);

    const getExploitDesc = (module, cve) => {
      const m = (module ?? "").toLowerCase();
      const c = (cve ?? "").toLowerCase();
      if (m.includes("ms17_010_psexec") || c.includes("2017-0145"))
        return "MS17-010 psexec aprovecha la vulnerabilidad EternalBlue para obtener acceso SYSTEM al kernel y entrega el payload ejecutando un servicio via SMB. Funciona en Windows sin el parche de marzo 2017, incluyendo sistemas con SMBv1 deshabilitado mediante acceso anonimo.";
      if (m.includes("ms17_010") || c.includes("2017-0144"))
        return "EternalBlue (MS17-010) explota un fallo critico en SMBv1 de Windows para ejecutar codigo remoto sin autenticacion. Afecta a sistemas sin el parche de seguridad de marzo 2017.";
      if (m.includes("ms08_067") || c.includes("2008-4250"))
        return "MS08-067 aprovecha un fallo en el servicio Server de Windows via una solicitud RPC maliciosa. Permite ejecucion remota de codigo como SYSTEM en Windows XP/2003.";
      if (m.includes("vsftpd"))
        return "Backdoor en vsftpd 2.3.4 que abre una shell en el puerto 6200 cuando el login incluye ':)'. Proporciona acceso root directo sin autenticacion.";
      if (m.includes("ms03_026") || m.includes("dcom"))
        return "MS03-026: desbordamiento de buffer en DCOM RPC que permite ejecucion remota como SYSTEM. Afecta a Windows 2000/XP/2003 sin parche.";
      if (m.includes("wu_ftpd") || (m.includes("ftpd") && !m.includes("vsftpd")))
        return "Desbordamiento de buffer en wu-ftpd que permite a un atacante remoto escalar privilegios y obtener una shell root en el sistema.";
      return "El exploit aprovecho una vulnerabilidad en el servicio objetivo para obtener ejecucion remota de codigo y establecer una sesion interactiva con el sistema comprometido.";
    };

    for (const [hIdx, h] of attackedHosts.entries()) {
      if (hIdx > 0) newPage();
      const ad         = h.agentDurations ?? {};
      const allVulns   = h.vulns ?? [];
      const topVulns   = allVulns.filter(v => v.severity === "critical" || v.severity === "high").slice(0, 16);
      const vulnAgentRan = allVulns.length > 0 || ad.findVulnsMs;
      const openPorts  = (h.ports ?? []).filter(p => p.port && p.service);
      const failedMods = (h.failedModules ?? []);

      // ── Calcular altura de cada sección de agente ──────────────────────────
      const agentHeaderH = 14;
      const reconRowH = 7;
      const vulnRowH  = 7;
      const reconH  = openPorts.length > 0
        ? agentHeaderH + 8 + openPorts.length * reconRowH + 3
        : agentHeaderH + 12;
      const vulnH   = topVulns.length  > 0
        ? agentHeaderH + 8 + topVulns.length  * vulnRowH  + 3
        : agentHeaderH + 12;
      const exploitRowH    = 7;
      const exploitFailedH = failedMods.length > 0 ? 7 + failedMods.length * exploitRowH + 3 : 0;
      const exploitSuccessH = h.sessionOpened ? 7 + 3 + 46 : 10;
      const exploitH = agentHeaderH + exploitFailedH + exploitSuccessH + 3;

      const persist       = h.sessionOpened ? (h.persistence ?? null) : null;
      const persistH      = h.sessionOpened
        ? (persist
            ? agentHeaderH + 7 + 7 + 4 * 6 + 3   // subsección + cabecera amber + 4 filas + padding
            : agentHeaderH + 12)                  // no ejecutado
        : 0;                                  // sin sesión → sección oculta

      const cx = ML, cw = CW;
      const statusColor = h.sessionOpened ? C.pwned : C.failed;
      const statusBg    = h.sessionOpened ? C.pwnedD : C.failedD;

      // ── HEADER BOX — cabe solo en su página ─────────────────────────────────
      const headerH = 40;
      checkY(headerH + 8);
      const hy = y;
      fillRect(cx, hy, cw, headerH, C.card);
      fillRect(cx, hy, 1.5, headerH, statusColor);

      txt("FLUJO DE ATAQUE", cx + 10, hy + 6,
        { size: 5.5, color: C.textD, charSpace: 0.8 });

      // Status pill — primero para conocer su ancho y reservar espacio al título
      const pillLabel = h.sessionOpened ? "SESSION OPENED" : "NO SESSION";
      doc.setFont("helvetica", "bold");
      doc.setFontSize(6);
      const plw = doc.getTextWidth(pillLabel) + 10;
      const pillX = cx + cw - plw - 8;
      const pillY = hy + 5;
      const pillH = 7;
      fillRound(pillX, pillY, plw, pillH, 1.5, statusBg);
      strokeRound(pillX, pillY, plw, pillH, 1.5, statusColor, 0.4);
      txt(pillLabel, pillX + plw / 2, pillY + pillH * 0.65,
        { size: 6, bold: true, color: statusColor, align: "center" });

      // Título en una sola línea — trunca el SO si no cabe
      const titleAvailW = pillX - (cx + 10) - 6;
      doc.setFont("helvetica", "bold");
      doc.setFontSize(12);
      const inferredOs = osFromHost(h);
      const rawTitle = (inferredOs && inferredOs !== "Sistema desconocido")
        ? `Host ${h.ip}  —  ${inferredOs}`
        : `Host ${h.ip}`;
      const tLines = doc.splitTextToSize(rawTitle, titleAvailW);
      const titleText = tLines.length > 1 ? `${tLines[0].trimEnd()}...` : tLines[0];
      txt(titleText, cx + 10, hy + 17, { bold: true, size: 12, color: C.white });

      // KPIs
      line(cx + 5, hy + 24, cx + cw - 5, hy + 24, C.border, 0.2);
      const colW4 = (cw - 12) / 4;
      const m4Y   = hy + 28;
      [
        { label: "VULNS DETECTADAS", value: h.vulnsFound,           color: h.vulnsFound > 0 ? C.high : C.text },
        { label: "INTENTOS EXPLOIT", value: h.exploitAttempts,      color: C.accent },
        { label: "TIEMPO TOTAL",     value: fmtMs(h.totalAttackMs), color: C.text },
        { label: "T. HASTA SESION",  value: h.sessionOpened ? fmtMs(h.timeToSessionMs) : "--",
          color: h.sessionOpened ? C.pwned : C.text },
      ].forEach((m, i) => {
        const mx = cx + 6 + i * colW4;
        if (i > 0) line(mx - 1, hy + 25, mx - 1, hy + 37, C.border, 0.15);
        txt(m.label,      mx + 2, m4Y,     { size: 5,  color: C.text, charSpace: 0.3 });
        txt(String(m.value), mx + 2, m4Y + 6,
          { bold: true, size: 9, color: m.color,
            font: typeof m.value === "string" && /[a-zA-Z]/.test(m.value) ? "courier" : "helvetica" });
      });
      line(cx + 5, hy + 38, cx + cw - 5, hy + 38, C.border, 0.15);

      // ── Helper: sección de agente ─────────────────────────────────────────
      // Cada sección tiene su propia caja y checkY — permite saltos de página entre agentes
      y = hy + headerH;
      let iy = y;

      // Dibuja icono vectorial dentro del badge (bx,by = esquina sup-izq del badge 7.5x7.5)
      const drawAgentIcon = (type, bx, by, color) => {
        const icx = bx + 3.75;
        doc.setDrawColor(...color);
        doc.setFillColor(...color);
        if (type === "recon") {
          // Lupa: círculo (lente) + asa diagonal
          doc.setLineWidth(0.6);
          doc.circle(bx + 3.0, by + 3.1, 2.0, "S");
          doc.setLineWidth(1.0);
          doc.line(bx + 4.5, by + 4.7, bx + 6.9, by + 7.1);
          doc.circle(bx + 6.9, by + 7.1, 0.45, "F");
        } else if (type === "vuln") {
          // Triángulo de aviso ⚠ + signo !
          doc.setLineWidth(0.5);
          doc.lines([[3.2, 6.3], [-6.4, 0]], icx, by + 0.7, [1, 1], "S", true);
          doc.rect(icx - 0.22, by + 2.6, 0.44, 2.2, "F");
          doc.circle(icx, by + 5.8, 0.38, "F");
        } else if (type === "exploit") {
          // Bomba: cuerpo + mecha en zigzag + chispa
          doc.setLineWidth(0.55);
          doc.circle(bx + 3.4, by + 4.7, 2.1, "S");
          doc.setLineWidth(0.55);
          doc.line(bx + 3.4, by + 2.6, bx + 4.4, by + 1.7);
          doc.line(bx + 4.4, by + 1.7, bx + 5.3, by + 1.0);
          doc.circle(bx + 5.7, by + 0.65, 0.6, "F");
        } else if (type === "persist") {
          // Llave: anillo + vástago + dientes
          doc.setLineWidth(0.55);
          doc.circle(bx + 2.8, by + 3.5, 1.9, "S");
          doc.setLineWidth(0.7);
          doc.line(bx + 4.7, by + 3.5, bx + 7.1, by + 3.5);
          doc.setLineWidth(0.5);
          doc.line(bx + 6.1, by + 3.5, bx + 6.1, by + 5.0);
          doc.line(bx + 5.1, by + 3.5, bx + 5.1, by + 4.4);
        }
      };

      const drawAgentSection = (iconType, title, color, duration) => {
        fillRect(cx + 1.5, iy, cw - 1.5, agentHeaderH, [
          Math.round(color[0] * 0.15 + C.card[0] * 0.85),
          Math.round(color[1] * 0.15 + C.card[1] * 0.85),
          Math.round(color[2] * 0.15 + C.card[2] * 0.85),
        ]);
        fillRect(cx + 1.5, iy, 3, agentHeaderH, color);
        // Badge con icono vectorial (centrado en los 14mm de altura)
        fillRound(cx + 6, iy + 3.25, 7.5, 7.5, 1.2, [
          Math.round(color[0] * 0.35 + C.card[0] * 0.65),
          Math.round(color[1] * 0.35 + C.card[1] * 0.65),
          Math.round(color[2] * 0.35 + C.card[2] * 0.65),
        ]);
        drawAgentIcon(iconType, cx + 6, iy + 3.25, color);
        txt(title, cx + 16, iy + 9, { size: 7, bold: true, color, charSpace: 0.3 });
        if (duration) {
          txt("Tiempo de duracion del agente:", cx + cw - 8, iy + 5.5,
            { size: 5, color: C.textD, align: "right", charSpace: 0.1 });
          mono(duration, cx + cw - 8, iy + 11,
            { size: 8.5, color: C.white, align: "right", bold: true });
        }
        iy += agentHeaderH;
      };

      // Placeholder cuando un agente no fue ejecutado en este host
      const drawNotExecuted = () => {
        fillRect(cx + 1.5, iy, cw - 1.5, 9, [
          Math.round(C.muted[0] * 0.06 + C.card[0] * 0.94),
          Math.round(C.muted[1] * 0.06 + C.card[1] * 0.94),
          Math.round(C.muted[2] * 0.06 + C.card[2] * 0.94),
        ]);
        fillRect(cx + 1.5, iy, 2, 9, C.border);
        txt(
          "Este agente no fue ejecutado en este host durante esta sesion de evaluacion.",
          cx + 8, iy + 5.5,
          { size: 6, color: C.muted, italic: true, maxW: cw - 14 }
        );
        iy += 12;
      };

      // Subsección dentro de un agente (banda tintada con etiqueta y barra lateral)
      const drawSubSection = (label, color) => {
        fillRect(cx + 1.5, iy, cw - 1.5, 7, [
          Math.round(color[0] * 0.12 + C.card[0] * 0.88),
          Math.round(color[1] * 0.12 + C.card[1] * 0.88),
          Math.round(color[2] * 0.12 + C.card[2] * 0.88),
        ]);
        txt(label, cx + 4, iy + 4.5, { size: 5.5, bold: true, color, charSpace: 0.4 });
        iy += 7;
      };

      // ── AGENTE 1: RECONOCIMIENTO DE RED ──────────────────────────────────────
      checkY(reconH + 4);
      fillRect(cx, y, cw, 4, C.cardAlt);
      fillRect(cx, y, 1.5, 4, statusColor);
      y += 4;
      fillRect(cx, y, cw, reconH, C.card);
      fillRect(cx, y, 1.5, reconH, statusColor);
      iy = y;
      drawAgentSection("recon", "AGENTE DE RECONOCIMIENTO DE RED", C.blue,
        ad.deepScanMs ? fmtMs(ad.deepScanMs) : null);
      if (openPorts.length > 0) {
        // Cabecera de tabla
        const cPort = cx + 6, cSvc = cx + 28, cVer = cx + 66;
        fillRect(cx + 1.5, iy, cw - 1.5, 6, [
          Math.round(C.blue[0] * 0.08 + C.card[0] * 0.92),
          Math.round(C.blue[1] * 0.08 + C.card[1] * 0.92),
          Math.round(C.blue[2] * 0.08 + C.card[2] * 0.92),
        ]);
        txt("PUERTO", cPort, iy + 4, { size: 5, bold: true, color: C.text, charSpace: 0.3 });
        txt("SERVICIO", cSvc, iy + 4, { size: 5, bold: true, color: C.text, charSpace: 0.3 });
        txt("VERSION / BANNER", cVer, iy + 4, { size: 5, bold: true, color: C.text, charSpace: 0.3 });
        iy += 8;  // 6 header + 2 padding para separar de la primera fila
        for (const p of openPorts) {
          mono(String(p.port), cPort, iy + 4.5, { size: 7, bold: true, color: C.blue });
          txt(p.service ?? "—", cSvc, iy + 4.5, { size: 7, color: C.white, maxW: 35 });
          txt(p.version ? p.version.slice(0, 55) : "—", cVer, iy + 4.5,
            { size: 6.5, color: C.text, maxW: cw - (cVer - cx) - 6 });
          line(cx + 1.5, iy + reconRowH, cx + cw - 1.5, iy + reconRowH, C.border, 0.15);
          iy += reconRowH;
        }
        iy += 3;
      } else {
        drawNotExecuted();
      }
      y = iy;

      // ── AGENTE 2: ANÁLISIS DE VULNERABILIDADES ───────────────────────────────
      checkY(vulnH + 4);
      fillRect(cx, y, cw, 4, C.cardAlt);
      fillRect(cx, y, 1.5, 4, statusColor);
      y += 4;
      fillRect(cx, y, cw, vulnH, C.card);
      fillRect(cx, y, 1.5, vulnH, statusColor);
      iy = y;
      drawAgentSection("vuln", "AGENTE DE ANALISIS DE VULNERABILIDADES", C.high,
        ad.findVulnsMs ? fmtMs(ad.findVulnsMs) : null);
      if (topVulns.length > 0) {
        // Subtítulo informativo
        fillRect(cx + 1.5, iy, cw - 1.5, 7, [
          Math.round(C.high[0] * 0.06 + C.card[0] * 0.94),
          Math.round(C.high[1] * 0.06 + C.card[1] * 0.94),
          Math.round(C.high[2] * 0.06 + C.card[2] * 0.94),
        ]);
        txt(
          "Solo se muestran vulnerabilidades CRITICAL y HIGH con vector de ataque real detectado por ARES.",
          cx + 8, iy + 4.5,
          { size: 5.5, color: C.textD, italic: true, maxW: cw - 14 }
        );
        iy += 8;  // 7 subtítulo + 1 padding
        for (const v of topVulns) {
          const sevColor = SEV[v.severity] ?? C.text;
          const sevLabel = v.severity === "critical" ? "CRIT" : "ALTA";
          fillRound(cx + 6, iy + 1.5, 10, 4, 0.8, sevColor);
          txt(sevLabel, cx + 11, iy + 4.5, { size: 5, bold: true, color: C.bg, align: "center" });
          mono(v.cve, cx + 19, iy + 4.5, { size: 7, bold: true, color: C.white });
          const ctx2 = v.service ? `${v.service}${v.port ? `:${v.port}` : ""}` : "";
          txt(ctx2, cx + cw - 8, iy + 4.5, { size: 6.5, color: C.text, align: "right" });
          line(cx + 1.5, iy + vulnRowH, cx + cw - 1.5, iy + vulnRowH, C.border, 0.15);
          iy += vulnRowH;
        }
        iy += 3;
      } else if (vulnAgentRan) {
        fillRect(cx + 1.5, iy, cw - 1.5, 9, [
          Math.round(C.teal[0] * 0.06 + C.card[0] * 0.94),
          Math.round(C.teal[1] * 0.06 + C.card[1] * 0.94),
          Math.round(C.teal[2] * 0.06 + C.card[2] * 0.94),
        ]);
        txt(
          "Este host no presenta vulnerabilidades con vector de ataque real clasificadas como Critical o High.",
          cx + 8, iy + 5.5,
          { size: 6, color: C.teal, italic: true, maxW: cw - 14 }
        );
        iy += 12;
      } else {
        drawNotExecuted();
      }
      y = iy;

      // ── AGENTE 3: EXPLOTACIÓN ────────────────────────────────────────────────
      {
        const exploitColor = h.sessionOpened ? C.pwned : C.failed;
        checkY(exploitH + 4);
        fillRect(cx, y, cw, 4, C.cardAlt);
        fillRect(cx, y, 1.5, 4, statusColor);
        y += 4;
        fillRect(cx, y, cw, exploitH, C.card);
        fillRect(cx, y, 1.5, exploitH, statusColor);
        iy = y;
        drawAgentSection("exploit", "AGENTE DE EXPLOTACION", exploitColor, fmtMs(ad.exploitMs));

        // ── Subsección 1: intentos fallidos ─────────────────────────────────
        if (failedMods.length > 0) {
          drawSubSection("INTENTOS FALLIDOS — VECTORES SIN SESION", C.failed);
          for (const fm of failedMods) {
            const short = fm.mod.replace(/^exploit\//, "").replace(/^(windows|linux|unix|multi)\//, "");
            fillRound(cx + 6, iy + 2.5, 3, 3, 1.5, C.failed);
            mono(short, cx + 12, iy + 4.5, { size: 7, bold: true, color: C.white, maxW: cw - 53 });
            mono(`x${fm.attempts}`, cx + cw - 8, iy + 4.5,
              { size: 7.5, bold: true, color: C.text, align: "right" });
            line(cx + 1.5, iy + exploitRowH, cx + cw - 1.5, iy + exploitRowH, C.border, 0.15);
            iy += exploitRowH;
          }
          iy += 3;
        }

        // ── Subsección 2: resultado ──────────────────────────────────────────
        if (h.sessionOpened) {
          drawSubSection("EXPLOIT EXITOSO — SESION OBTENIDA", C.pwned);
          iy += 3;  // margen entre subtítulo y card

          const cardX  = cx + 6;
          const cardW2 = cw - 16;
          const scH    = 46;
          fillRound(cardX, iy, cardW2, scH, 1.5, C.card);
          strokeRound(cardX, iy, cardW2, scH, 1.5, C.pwned, 0.4);

          // Cabecera de la card
          fillRound(cardX, iy, cardW2, 10, 1.5, [
            Math.round(C.pwned[0] * 0.12 + C.card[0] * 0.88),
            Math.round(C.pwned[1] * 0.12 + C.card[1] * 0.88),
            Math.round(C.pwned[2] * 0.12 + C.card[2] * 0.88),
          ]);
          fillRound(cardX + 4, iy + 3, 4, 4, 2, C.pwned);
          txt("ACCESO OBTENIDO", cardX + 11, iy + 6.5,
            { size: 7, bold: true, color: C.pwned, charSpace: 0.4 });
          // Pill tipo de sesión
          const stLabel = (h.sessionType ?? "shell").toUpperCase();
          doc.setFont("courier", "bold"); doc.setFontSize(6);
          const stW2 = doc.getTextWidth(stLabel) + 8;
          fillRound(cardX + cardW2 - stW2 - 4, iy + 2, stW2, 6.5, 1.5, C.pwned);
          mono(stLabel, cardX + cardW2 - stW2 - 4 + stW2 / 2, iy + 6.5,
            { size: 6, bold: true, color: C.bg, align: "center" });
          iy += 11;

          // Filas de detalle
          const lX   = cardX + 6;
          const vX   = cardX + 34;
          const vW   = cardW2 - 40;
          const drH  = 5;
          const rows = [
            ["Modulo usado:", h.successModule ?? "—"],
            ["CVE / Vuln:  ", h.sessionCve ?? inferCveFromModule(h.successModule) ?? "—"],
            ["Payload:     ", h.successPayload ?? "—"],
            ["Tipo sesion: ", (h.sessionType ?? "shell").toLowerCase()],
          ];
          for (const [label, val] of rows) {
            txt(label, lX, iy + drH, { size: 6, bold: true, color: C.textD });
            mono(val,   vX, iy + drH, { size: 6, color: C.white, maxW: vW });
            iy += drH;
          }
          iy += 2;

          // Separador + descripción
          line(cardX + 4, iy, cardX + cardW2 - 4, iy, C.pwned, 0.2);
          iy += 4;
          const desc = getExploitDesc(h.successModule, h.sessionCve ?? inferCveFromModule(h.successModule));
          txt(desc, lX, iy + 3.5, { size: 6, italic: true, color: C.text, maxW: cardW2 - 12 });
          iy += 9;

        } else {
          fillRect(cx + 1.5, iy, cw - 1.5, 7, [
            Math.round(C.failed[0] * 0.08 + C.card[0] * 0.92),
            Math.round(C.failed[1] * 0.08 + C.card[1] * 0.92),
            Math.round(C.failed[2] * 0.08 + C.card[2] * 0.92),
          ]);
          txt("Sin sesion activa — todos los vectores de ataque han sido bloqueados o fallaron.",
            cx + 4, iy + 4.5, { size: 6, italic: true, color: C.failed, maxW: cw - 10 });
          iy += 10;
        }
      }
      y = iy + 2;

      // ── AGENTE 4: PERSISTENCIA (solo si hubo sesión) ───────────────────────
      if (h.sessionOpened) {
        const persistColor = persist ? C.teal : C.muted;
        checkY(persistH + 4);
        fillRect(cx, y, cw, 4, C.cardAlt);
        fillRect(cx, y, 1.5, 4, statusColor);
        y += 4;
        fillRect(cx, y, cw, persistH, C.card);
        fillRect(cx, y, 1.5, persistH, statusColor);
        iy = y;
        drawAgentSection("persist", "AGENTE DE PERSISTENCIA", persistColor, null);

        if (persist) {
          // Subsección: acceso persistente establecido
          drawSubSection("ACCESO PERSISTENTE ESTABLECIDO", C.teal);

          let connCmd;
          if (persist.accessMethod === "ssh") {
            connCmd = `ssh ${persist.user}@${persist.ip}`;
          } else if (persist.rdpClient === "xfreerdp3") {
            connCmd = `xfreerdp3 /v:${persist.ip} /u:${persist.user} /p:${persist.password} /cert:ignore`;
          } else {
            connCmd = `rdesktop -u ${persist.user} -p ${persist.password} -0 ${persist.ip}`;
          }

          // Cabecera amber "CREDENCIALES — INFORMACION SENSIBLE"
          const amberH = 7;
          fillRect(cx + 1.5, iy, cw - 1.5, amberH, [160, 100, 0]);
          txt("CREDENCIALES — INFORMACION SENSIBLE", cx + (cw / 2), iy + 5,
            { size: 5.5, bold: true, color: C.white, align: "center" });
          iy += amberH;

          // Bloque con fondo tintado ámbar muy sutil
          const credBlockH = 4 * 6 + 6;
          fillRect(cx + 1.5, iy, cw - 1.5, credBlockH, [
            Math.round(C.yellow[0] * 0.07 + C.card[0] * 0.93),
            Math.round(C.yellow[1] * 0.07 + C.card[1] * 0.93),
            Math.round(C.yellow[2] * 0.07 + C.card[2] * 0.93),
          ]);
          iy += 3;

          const detailRows = [
            ["Usuario creado:", persist.user ?? "—"],
            ["Contraseña:   ", persist.password ?? "—"],
            ["Metodo acceso: ", (persist.accessMethod ?? "—").toUpperCase()],
            ["Comando:       ", connCmd],
          ];
          const lX  = cx + 6;
          const vX  = cx + 38;
          const drH = 6;
          for (const [label, val] of detailRows) {
            txt(label, lX, iy + drH, { size: 6, bold: true, color: C.textD });
            mono(val,   vX, iy + drH, { size: 6, color: C.white, maxW: cw - 44 });
            iy += drH;
          }
          iy += 3;
        } else {
          drawNotExecuted();
        }
      }

      y = iy + 8;
    }
  }


  // ════════════════════════════════════════════════════════════════════════════
  // SECCIÓN 04 — ANÁLISIS GRÁFICO (visualizaciones nativas jsPDF)
  // ════════════════════════════════════════════════════════════════════════════
  newPage();
  section("03", "Análisis gráfico", "Visualizaciones de la evaluación");

  // ─── TIMELINE DEL JOB ──────────────────────────────────────────────────────
  {
    const totalJobMs   = jt.totalJobDurationMs || 1;
    const jobStartTs   = meta.startedAt ? new Date(meta.startedAt).getTime() : null;

    // Posición absoluta desde el inicio del job.
    // Comprometido: timestamp exacto del evento session_opened (campo sessionTimestamp del backend).
    // Fallido: lastActivityAt (cuando se abandonó el ataque a ese host).
    const absMs = (h) => {
      if (!jobStartTs) return h.totalAttackMs ?? 0;
      if (h.sessionOpened && h.sessionTimestamp) {
        return Math.max(0, new Date(h.sessionTimestamp).getTime() - jobStartTs);
      }
      const ts = h.lastActivityAt ?? h.firstActivityAt;
      if (!ts) return h.totalAttackMs ?? 0;
      return Math.max(0, new Date(ts).getTime() - jobStartTs);
    };

    // Rango: máximo de posición absoluta entre hosts atacados + 8% padding
    const lastActivityMs = Math.max(
      1,
      ...hosts.filter(h => h.exploitAttempts > 0).map(absMs)
    );
    const rangeMs = lastActivityMs * 1.08;

    const tlW    = CW;
    const dotR   = 1.2;                  // bola pequeña sobre el eje
    const rowH   = 10;                   // altura entre filas de labels
    const aboveRows = 2, belowRows = 2;
    const spaceAbove = aboveRows * rowH + 6;
    const spaceBelow = belowRows * rowH + 14; // espacio bajo el eje (labels + ticks)
    const tlBarY = y + 12 + spaceAbove;   // eje centrado con espacio arriba y abajo
    const tlNoteY = tlBarY + spaceBelow + 4;

    txt("TIMELINE DEL JOB", ML, y, { size: 6.5, color: C.textD, bold: true, charSpace: 0.6 });
    line(ML, y + 2, ML + CW, y + 2, C.border, 0.3);

    // Eje principal
    fillRect(ML, tlBarY - 0.75, tlW, 1.5, C.borderL);

    // Ticks pegados al eje (justo debajo)
    [0, 0.25, 0.5, 0.75, 1].forEach(pct => {
      const tx = ML + tlW * pct;
      line(tx, tlBarY - 2.5, tx, tlBarY + 2.5, C.text, 0.4);
      mono(fmtMs(rangeMs * pct), tx, tlBarY + 7, { size: 8, color: C.white, align: "center" });
    });

    // Nota contextual (más grande)
    const noteText = totalJobMs > lastActivityMs * 1.15
      ? `· flujo de ataque: ${fmtMs(lastActivityMs)}  (job total incl. post-ataque: ${fmtMs(totalJobMs)})`
      : `· duración del flujo de ataque: ${fmtMs(lastActivityMs)}`;
    txt(noteText, ML + tlW, tlNoteY, { size: 8, color: C.text, align: "right" });

    // Hosts — spread mínimo para legibilidad
    const tlHosts = hosts
      .filter(h => h.exploitAttempts > 0)
      .map(h => ({ ...h, tlMs: absMs(h), rawX: ML + tlW * Math.min(absMs(h) / rangeMs, 1) }))
      .filter(h => h.tlMs > 0)
      .sort((a, b) => a.tlMs - b.tlMs);

    const minSep = 16;
    tlHosts.forEach((h, i) => { h.above = i % 2 === 0; });

    const spreadGroup = (items) => {
      const sorted = [...items].sort((a, b) => a.rawX - b.rawX);
      sorted.forEach((h, i) => {
        h.labelX = i === 0 ? h.rawX : Math.max(h.rawX, sorted[i-1].labelX + minSep);
        h.labelX = Math.min(ML + CW - 4, h.labelX);
      });
    };
    spreadGroup(tlHosts.filter(h =>  h.above));
    spreadGroup(tlHosts.filter(h => !h.above));

    let aboveIdx = 0, belowIdx = 0;
    tlHosts.forEach(h => {
      const color = h.sessionOpened ? C.pwned : C.failed;

      // Símbolo pequeño SOBRE el eje
      if (h.sessionOpened) {
        doc.setFillColor(...C.pwned);
        doc.circle(h.rawX, tlBarY, dotR * 1.4, "F");
      } else {
        // X pequeña sobre el eje
        doc.setDrawColor(...C.failed); doc.setLineWidth(0.7);
        doc.line(h.rawX - 1.8, tlBarY - 1.8, h.rawX + 1.8, tlBarY + 1.8);
        doc.line(h.rawX + 1.8, tlBarY - 1.8, h.rawX - 1.8, tlBarY + 1.8);
      }

      if (h.above) {
        const row    = aboveIdx % 2;
        const labelY = tlBarY - 8 - row * rowH;
        aboveIdx++;
        // Leader line diagonal desde el símbolo en el eje hasta la IP
        line(h.rawX, tlBarY - dotR * 1.8, h.labelX, labelY + 2, color, 0.25);
        mono(h.ip, h.labelX, labelY, { size: 9, color, align: "center" });
      } else {
        const row    = belowIdx % 2;
        const labelY = tlBarY + 17 + row * rowH;
        belowIdx++;
        // Leader line diagonal
        line(h.rawX, tlBarY + dotR * 1.8, h.labelX, labelY - 3, color, 0.25);
        mono(h.ip, h.labelX, labelY, { size: 9, color, align: "center" });
      }
    });

    // Leyenda
    const legY = tlNoteY + 8;
    doc.setFillColor(...C.pwned);
    doc.circle(ML + 3, legY - 1, 1.5, "F");
    txt("Sesión obtenida", ML + 7, legY, { size: 9, color: C.white });
    doc.setDrawColor(...C.failed);
    doc.setLineWidth(0.6);
    doc.line(ML + 62 - 2, legY - 2, ML + 62 + 2, legY + 2);
    doc.line(ML + 62 + 2, legY - 2, ML + 62 - 2, legY + 2);
    txt("Sin sesión", ML + 67, legY, { size: 9, color: C.white });

    y = legY + 10;

    // ── Párrafo interpretativo del timeline — mismo estilo que sección 01 ──
    {
      const pwn    = summary.hostsCompromised ?? 0;
      const atk    = summary.hostsAttacked   ?? 0;
      const fastMs = jt.timeToFirstSessionMs;
      const attackedHosts04 = hosts.filter(h => h.exploitAttempts > 0)
        .sort((a, b) => absMs(a) - absMs(b));

      const ptx = ML + 7, ptw = CW - 10;
      const lh  = 5;

      // Construir todos los textos para calcular la altura total del bloque
      // Construir el texto centrado en lo observable en el timeline
      const compromisedByTime = attackedHosts04.filter(h => h.sessionOpened)
        .sort((a, b) => absMs(a) - absMs(b));
      const failedHosts = attackedHosts04.filter(h => !h.sessionOpened);

      const firstPwn  = compromisedByTime[0];
      const lastPwn   = compromisedByTime[compromisedByTime.length - 1];
      const spreadMs  = firstPwn && lastPwn ? absMs(lastPwn) - absMs(firstPwn) : 0;

      // Métricas temporales adicionales
      const sessionTimes = compromisedByTime.map(h => absMs(h)).filter(t => t > 0);
      const avgSessionGapMs = sessionTimes.length > 1
        ? (sessionTimes[sessionTimes.length - 1] - sessionTimes[0]) / (sessionTimes.length - 1)
        : null;
      const fastestHost = compromisedByTime[0];
      const fastestMs   = fastestHost ? absMs(fastestHost) : null;
      const pctInFirst5 = sessionTimes.filter(t => t <= 5 * 60 * 1000).length;

      const proseText = pwn > 0
        ? `El timeline permite apreciar el ritmo temporal del ataque con precisión. ` +
          (fastMs ? `La ${pwn === 1 ? "única sesión fue abierta" : "primera sesión fue abierta"} a los ${fmtMs(fastMs)} del inicio${pwn === 1 ? "." : ","} ` : ``) +
          (pwn > 1
            ? spreadMs > 60000
              ? `con un intervalo de ${fmtMs(spreadMs)} entre el primer y el último compromiso, evidenciando diferencias en la resistencia entre sistemas. `
              : `con todas las sesiones obtenidas en un margen temporal muy estrecho` +
                (meta.type === "IA" ? `, lo que refleja la efectividad inmediata del fast path sobre sistemas ya caracterizados` : ``) +
                `. `
            : ``) +
          (pctInFirst5 > 0 && lastActivityMs > 5 * 60 * 1000
            ? `${pctInFirst5} de los ${pwn} compromisos se produjeron en los primeros 5 minutos del flujo, concentrando la mayor actividad exitosa en la fase inicial. `
            : ``) +
          (failedHosts.length > 0
            ? `Los ${failedHosts.length} sistemas sin sesión (${failedHosts.map(h => h.ip).join(", ")}) aparecen desplazados hacia la derecha del eje, reflejando el tiempo invertido en intentos sin éxito. Su posición tardía en el timeline indica que el agente de explotación dedicó la mayor parte del tiempo restante a explorar vectores sobre ellos.`
            : `La ausencia de hosts sin sesión en el eje derecho confirma que todos los objetivos atacados fueron comprometidos.`)
        : `El timeline refleja un flujo de ${fmtMs(lastActivityMs)} en el que los ${atk} sistemas seleccionados resistieron todos los vectores ejecutados. La distribución temporal de las X rojas permite identificar el orden y duración de cada intento fallido.`;

      const aiProse = meta.type === "IA" && pwn > 0
        ? `Lo que el timeline no muestra directamente, pero que subyace en cada marca verde, es la capacidad ` +
          `del agente para hilar fino antes de ejecutar. Aracni no tantea: llega al objetivo con el contexto ` +
          `completo: servicios detectados, versiones expuestas, vulnerabilidades identificadas y el historial ` +
          `acumulado de qué ha funcionado y qué no en evaluaciones anteriores sobre esas mismas IPs. ` +
          `Con todo ello, traza un plan de explotación preciso y ejecuta. La concentración de éxitos en la zona ` +
          `inicial del eje no es casualidad ni suerte: es la expresión visual de una toma de decisión informada ` +
          `que actúa con determinación donde otros sistemas probarían a ciegas.`
        : null;

      doc.setFont("helvetica", "normal"); doc.setFontSize(9);
      const proseLines = doc.splitTextToSize(proseText, ptw);
      const aiLines    = aiProse ? doc.splitTextToSize(aiProse, ptw) : [];
      const totalH = 11
        + proseLines.length * lh
        + (aiLines.length > 0 ? lh + aiLines.length * lh : 0)
        + 4;

      checkY(totalH + 6);
      fillRect(ML, y, 1.5, totalH, C.teal);
      txt("INTERPRETACIÓN DEL TIMELINE", ptx, y + 2,
        { size: 6.5, color: C.textD, bold: true, charSpace: 0.6 });
      line(ptx, y + 4, ML + CW, y + 4, C.border, 0.3);

      const justifyBlock = (lines, startY) => {
        doc.setFont("helvetica", "normal"); doc.setFontSize(9); doc.setTextColor(...C.text);
        lines.forEach((ln, idx) => {
          const lineY = startY + idx * lh;
          const isLast = idx === lines.length - 1;
          if (isLast) { doc.text(ln, ptx, lineY); return; }
          const words = ln.trim().split(/\s+/);
          if (words.length <= 1) { doc.text(ln, ptx, lineY); return; }
          const tw2 = words.reduce((s, w) => s + doc.getTextWidth(w), 0);
          const gap = (ptw - tw2) / (words.length - 1);
          let cx2 = ptx;
          words.forEach(w => { doc.text(w, cx2, lineY); cx2 += doc.getTextWidth(w) + gap; });
        });
      };

      justifyBlock(proseLines, y + 11);
      if (aiLines.length > 0) {
        // Línea en blanco entre párrafos (un lh de separación)
        justifyBlock(aiLines, y + 11 + proseLines.length * lh + lh);
      }
      y += totalH + 8;

      // ── Mini-cards de métricas temporales ──────────────────────────────────
      if (pwn > 0) {
        const tmCards = [
          {
            label: "PRIMERA SESIÓN",
            value: fastestMs ? fmtMs(fastestMs) : "—",
            sub:   fastestHost ? `en ${fastestHost.ip}` : "desde inicio del flujo",
            color: C.pwned,
          },
          {
            label: "INTERVALO MEDIO",
            value: avgSessionGapMs ? fmtMs(avgSessionGapMs) : "—",
            sub:   "entre sesiones consecutivas",
            color: C.teal,
          },
          {
            label: "COMPROMISOS < 5min",
            value: String(pctInFirst5),
            sub:   `de ${pwn} sesiones totales`,
            color: pctInFirst5 === pwn ? C.pwned : C.yellow,
          },
          {
            label: "HOSTS SIN SESIÓN",
            value: String(failedHosts.length),
            sub:   failedHosts.length > 0 ? failedHosts.map(h => h.ip).join(", ") : "ninguno resistió",
            color: failedHosts.length > 0 ? C.failed : C.pwned,
          },
        ];

        const tmW = (CW - 6) / 4;
        const tmH = 26;
        checkY(tmH + 6);

        tmCards.forEach((m, i) => {
          const ex = ML + i * (tmW + 2);
          fillRound(ex, y, tmW, tmH, 2, C.cardAlt);
          fillRect(ex, y + tmH - 0.6, tmW, 0.6, m.color);
          txt(m.label,        ex + tmW / 2, y + 7,  { size: 5, color: C.textD, align: "center" });
          mono(m.value,       ex + tmW / 2, y + 16, { bold: true, size: 10, color: m.color, align: "center" });
          txt(m.sub,          ex + tmW / 2, y + 22, { size: 5, color: C.text, align: "center", maxW: tmW - 4 });
        });

        y += tmH + 6;
      }

    }
  }

  // ─── MAPA DE VECTORES ────────────────────────────────────────────────────────
  {
    const shortMod = (m) => (m ?? "unknown").split("/").slice(-1)[0];

    const tlHosts = hosts.filter(h => h.exploitAttempts > 0);

    // Recoger todos los módulos con su frecuencia total
    const modFreq = {};
    for (const h of tlHosts) {
      if (h.successModule) {
        const k = shortMod(h.successModule);
        modFreq[k] = (modFreq[k] ?? 0) + 20;
      }
      for (const fm of h.failedModules ?? []) {
        const k = shortMod(fm.mod);
        modFreq[k] = (modFreq[k] ?? 0) + (fm.attempts ?? 1);
      }
    }

    const topMods = Object.entries(modFreq)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([m]) => m);

    if (tlHosts.length > 0 && topMods.length > 0) {
      // ── Párrafo introductorio ──────────────────────────────────────────────
      {
        const nMods = Math.min(topMods.length, 10);
        const nHosts = tlHosts.length;
        const prose =
          `La siguiente matriz cruza ${nHosts === 1 ? "el sistema atacado" : `los ${nHosts} sistemas atacados`} con ${nMods === 1 ? "el módulo" : `los ${nMods} módulos`} de explotación ` +
          `más relevantes del flujo. Cada celda indica si ese vector fue probado en ese sistema y con qué resultado: ` +
          `verde cuando se obtuvo sesión, rojo apagado cuando se intentó sin éxito, y vacío cuando ese módulo ` +
          `no llegó a ejecutarse contra ese objetivo. La lectura horizontal permite evaluar la cobertura de ` +
          `ataque sobre cada sistema, mientras que la vertical revela qué vectores demostraron ser más o menos ` +
          `efectivos a lo largo del flujo.`;

        const ptx = ML + 7, ptw = CW - 10, lh = 5;
        doc.setFont("helvetica", "normal"); doc.setFontSize(9);
        const pLines = doc.splitTextToSize(prose, ptw);
        const pH = 11 + pLines.length * lh + 4;
        checkY(pH + 6);
        fillRect(ML, y, 1.5, pH, C.blue);
        txt("MAPA DE VECTORES", ptx, y + 2, { size: 6.5, color: C.textD, bold: true, charSpace: 0.6 });
        line(ptx, y + 4, ML + CW, y + 4, C.border, 0.3);
        doc.setFont("helvetica", "normal"); doc.setFontSize(9); doc.setTextColor(...C.text);
        pLines.forEach((ln, idx) => {
          const lineY = y + 11 + idx * lh;
          const isLast = idx === pLines.length - 1;
          if (isLast) { doc.text(ln, ptx, lineY); return; }
          const words = ln.trim().split(/\s+/);
          if (words.length <= 1) { doc.text(ln, ptx, lineY); return; }
          const tw2 = words.reduce((s, w) => s + doc.getTextWidth(w), 0);
          const gap = (ptw - tw2) / (words.length - 1);
          let cx2 = ptx;
          words.forEach(w => { doc.text(w, cx2, lineY); cx2 += doc.getTextWidth(w) + gap; });
        });
        y += pH + 6;
      }

      const cellW  = 9;
      const cellH  = 9;
      const ipColW = 36;
      const rotH   = 32;
      const matW   = topMods.length * cellW;
      // Centrar la matriz en la página
      const totalMatW = ipColW + matW;
      const matOffX   = ML + (CW - totalMatW) / 2;
      const matX      = matOffX + ipColW;
      const matH      = tlHosts.length * cellH;

      checkY(rotH + matH + 24);

      txt("MAPA DE VECTORES", ML, y, { size: 6.5, color: C.textD, bold: true, charSpace: 0.6 });
      line(ML, y + 2, ML + CW, y + 2, C.border, 0.3);
      y += 8;

      // Cabeceras de columna rotadas 45° — más grandes y blancas
      doc.setFont("courier", "bold");
      doc.setFontSize(7);
      doc.setTextColor(...C.white);
      topMods.forEach((mod, i) => {
        const cx = matX + i * cellW + cellW / 2;
        doc.text(mod, cx, y + rotH - 2, { angle: 45 });
      });
      y += rotH;

      const failedBg = [
        Math.round(C.failed[0] * 0.3 + C.card[0] * 0.7),
        Math.round(C.failed[1] * 0.3 + C.card[1] * 0.7),
        Math.round(C.failed[2] * 0.3 + C.card[2] * 0.7),
      ];

      tlHosts.forEach((h, row) => {
        const ry = y + row * cellH;
        if (row % 2 === 0) fillRect(matOffX, ry, totalMatW, cellH, [
          Math.round(C.surface[0] * 0.5 + C.card[0] * 0.5),
          Math.round(C.surface[1] * 0.5 + C.card[1] * 0.5),
          Math.round(C.surface[2] * 0.5 + C.card[2] * 0.5),
        ]);

        // Label IP — grande y blanca
        mono(h.ip, matOffX, ry + cellH * 0.72, { size: 8, bold: true, color: C.white });

        topMods.forEach((mod, col) => {
          const cx     = matX + col * cellW;
          const isOk   = shortMod(h.successModule ?? "") === mod;
          const isFail = (h.failedModules ?? []).some(fm => shortMod(fm.mod) === mod);
          if (isOk)   fillRect(cx + 0.5, ry + 0.5, cellW - 1, cellH - 1, C.pwned);
          else if (isFail) fillRect(cx + 0.5, ry + 0.5, cellW - 1, cellH - 1, failedBg);
          doc.setDrawColor(...C.border); doc.setLineWidth(0.2);
          doc.rect(cx + 0.5, ry + 0.5, cellW - 1, cellH - 1, "S");
        });
      });

      y += matH + 8;

      // Leyenda centrada y más grande
      const legItems = [
        { color: C.pwned,  label: "Comprometido con este vector", stroke: false },
        { color: failedBg, label: "Intentado sin exito",          stroke: true  },
        { color: C.card,   label: "No probado",                   stroke: true  },
      ];
      const legItemW = CW / legItems.length;
      legItems.forEach((item, i) => {
        const lx = ML + i * legItemW;
        fillRect(lx, y, 5, 5, item.color);
        if (item.stroke) {
          doc.setDrawColor(...C.border); doc.setLineWidth(0.2);
          doc.rect(lx, y, 5, 5, "S");
        }
        txt(item.label, lx + 7, y + 4, { size: 7, color: C.white });
      });

      y += 14;

      // ── Párrafo de hallazgos ──────────────────────────────────────────────
      {
        const successfulMods = [...new Set(tlHosts.filter(h => h.sessionOpened).map(h => shortMod(h.successModule ?? "")))].filter(Boolean);
        const universalFails = topMods.filter(mod =>
          tlHosts.every(h => !h.sessionOpened || shortMod(h.successModule ?? "") !== mod) &&
          tlHosts.some(h => (h.failedModules ?? []).some(fm => shortMod(fm.mod) === mod))
        );
        const mostTriedFailed = tlHosts.filter(h => !h.sessionOpened)
          .sort((a, b) => (b.failedModules ?? []).reduce((s, m) => s + m.attempts, 0) - (a.failedModules ?? []).reduce((s, m) => s + m.attempts, 0));

        // Estadísticas reales de la matriz
        const totalCells    = tlHosts.length * topMods.length;
        const triedCells    = topMods.reduce((s, mod) =>
          s + tlHosts.filter(h => h.sessionOpened
            ? shortMod(h.successModule ?? "") === mod
            : (h.failedModules ?? []).some(fm => shortMod(fm.mod) === mod)).length, 0);
        const coveragePct   = totalCells > 0 ? Math.round(triedCells / totalCells * 100) : 0;
        const onlyOneHost   = tlHosts.length === 1;
        const onlyOneMod    = topMods.length === 1;

        let findings = "";

        // Intro según el resultado global
        if (successfulMods.length > 0) {
          findings += onlyOneMod
            ? `El único módulo presente en el mapa, ${successfulMods[0] ?? topMods[0]}, ` +
              (tlHosts.every(h => h.sessionOpened)
                ? `resultó efectivo en todos los sistemas atacados. `
                : `obtuvo sesión en ${successfulMods.length === 1 ? "uno" : "varios"} de los sistemas del flujo. `)
            : `De los ${topMods.length} vectores representados, ` +
              `${successfulMods.length === 1 ? `${successfulMods[0]} fue el único que abrió sesión` : `${successfulMods.join(", ")} lograron abrir sesión`}` +
              `, destacando ${successfulMods.length === 1 ? "su columna" : "sus columnas"} en verde dentro del mapa. `;
        } else {
          findings += `Ninguno de los ${topMods.length} módulos representados logró abrir sesión durante este flujo. `;
        }

        // Módulos fallidos en todos los hosts donde se probaron
        if (universalFails.length > 0 && !onlyOneMod) {
          findings += `${universalFails.slice(0, 3).join(", ")} ${universalFails.length === 1 ? "aparece" : "aparecen"} en rojo en cada host donde ${universalFails.length === 1 ? "fue probado" : "fueron probados"}, lo que indica que ese vector no encontró condiciones favorables en ningún sistema del entorno. `;
        }

        // Sistema más resistente (solo si hay hosts fallidos)
        if (mostTriedFailed.length > 0 && !onlyOneHost) {
          findings += `${mostTriedFailed[0].ip} fue el sistema que más intentos absorbió sin ceder acceso. `;
        } else if (mostTriedFailed.length > 0 && onlyOneHost) {
          const totalAttempts = (mostTriedFailed[0].failedModules ?? []).reduce((s, m) => s + m.attempts, 0);
          findings += `El sistema resistió ${totalAttempts} intento${totalAttempts !== 1 ? "s" : ""} en total. `;
        }

        // Cobertura
        if (!onlyOneMod && !onlyOneHost) {
          findings += `La cobertura del mapa alcanza el ${coveragePct}% de las combinaciones posibles host×módulo.`;
        } else if (onlyOneHost && !onlyOneMod) {
          findings += `Se probaron ${triedCells} de los ${topMods.length} módulos representados sobre este host.`;
        }

        const ptx = ML + 7, ptw = CW - 10, lh = 5;
        doc.setFont("helvetica", "normal"); doc.setFontSize(9);
        const fLines = doc.splitTextToSize(findings, ptw);
        const fH = 11 + fLines.length * lh + 4;
        checkY(fH + 6);
        fillRect(ML, y, 1.5, fH, C.blue);
        txt("HALLAZGOS DEL MAPA", ptx, y + 2, { size: 6.5, color: C.textD, bold: true, charSpace: 0.6 });
        line(ptx, y + 4, ML + CW, y + 4, C.border, 0.3);
        doc.setFont("helvetica", "normal"); doc.setFontSize(9); doc.setTextColor(...C.text);
        fLines.forEach((ln, idx) => {
          const lineY = y + 11 + idx * lh;
          const isLast = idx === fLines.length - 1;
          if (isLast) { doc.text(ln, ptx, lineY); return; }
          const words = ln.trim().split(/\s+/);
          if (words.length <= 1) { doc.text(ln, ptx, lineY); return; }
          const tw2 = words.reduce((s, w) => s + doc.getTextWidth(w), 0);
          const gap = (ptw - tw2) / (words.length - 1);
          let cx2 = ptx;
          words.forEach(w => { doc.text(w, cx2, lineY); cx2 += doc.getTextWidth(w) + gap; });
        });
        y += fH;
      }
    }
  }

  // ─── DURACIÓN POR AGENTE — DESGLOSE POR HOST ─────────────────────────────────
  {
    const durHosts = hosts.filter(h => h.exploitAttempts > 0 && (h.totalAttackMs ?? 0) > 0);

    if (durHosts.length > 0) {
      const ipColW  = 32;
      const durColW = 26;
      const barMaxW = CW - ipColW - durColW;
      const barH    = 6;
      const rowH    = 11;
      const barX    = ML + ipColW;
      const maxTotal = Math.max(...durHosts.map(h => h.totalAttackMs));

      const segs = [
        { key: "deepScanMs",  color: C.blue,   label: "Reconocimiento" },
        { key: "findVulnsMs", color: C.high,   label: "Analisis vulns" },
        { key: "exploitMs",   color: C.accent, label: "Explotacion" },
      ];

      // ── Párrafo introductorio ──────────────────────────────────────────────
      {
        const prose =
          `Las barras horizontales muestran cómo se distribuyó el tiempo de ataque entre los tres agentes ` +
          `principales para cada sistema: reconocimiento, análisis de vulnerabilidades y explotación. ` +
          `La longitud total de cada barra es proporcional al tiempo total invertido en ese host, ` +
          `lo que permite identificar de un vistazo qué sistemas consumieron más recursos y en qué ` +
          `fase se concentró el mayor esfuerzo del flujo.`;

        const ptx = ML + 7, ptw = CW - 10, lh = 5;
        doc.setFont("helvetica", "normal"); doc.setFontSize(9);
        const pLines = doc.splitTextToSize(prose, ptw);
        const pH = 11 + pLines.length * lh + 4;
        checkY(pH + 6);
        fillRect(ML, y, 1.5, pH, C.accent);
        txt("DURACION POR AGENTE — DESGLOSE POR HOST", ptx, y + 2,
          { size: 6.5, color: C.textD, bold: true, charSpace: 0.6 });
        line(ptx, y + 4, ML + CW, y + 4, C.border, 0.3);
        doc.setFont("helvetica", "normal"); doc.setFontSize(9); doc.setTextColor(...C.text);
        pLines.forEach((ln, idx) => {
          const lineY = y + 11 + idx * lh;
          const isLast = idx === pLines.length - 1;
          if (isLast) { doc.text(ln, ptx, lineY); return; }
          const words = ln.trim().split(/\s+/);
          if (words.length <= 1) { doc.text(ln, ptx, lineY); return; }
          const tw2 = words.reduce((s, w) => s + doc.getTextWidth(w), 0);
          const gap = (ptw - tw2) / (words.length - 1);
          let cx2 = ptx;
          words.forEach(w => { doc.text(w, cx2, lineY); cx2 += doc.getTextWidth(w) + gap; });
        });
        y += pH + 8;
      }

      checkY(durHosts.length * rowH + 20);

      durHosts.forEach((h, idx) => {
        const ad    = h.agentDurations ?? {};
        const total = h.totalAttackMs;
        const bw    = (total / maxTotal) * barMaxW;
        const ry    = y + idx * rowH;
        const barY  = ry + (rowH - barH) / 2;

        // Label IP — blanca y legible
        mono(h.ip, ML, barY + barH * 0.78, { size: 8, bold: true, color: C.white });

        fillRect(barX, barY, bw, barH, C.dim);

        const segMs = {
          deepScanMs:  ad.deepScanMs  ?? 0,
          findVulnsMs: ad.findVulnsMs ?? 0,
          exploitMs:   ad.exploitMs   ?? 0,
        };
        const segSum = Object.values(segMs).reduce((a, b) => a + b, 0);
        const denom  = Math.max(total, segSum, 1);

        let sx = barX;
        for (const seg of segs) {
          const ms = segMs[seg.key] ?? 0;
          if (ms <= 0) continue;
          const sw = Math.max((ms / denom) * bw, 0.5);
          const actualW = Math.min(sw, barX + bw - sx);
          fillRect(sx, barY, actualW, barH, seg.color);
          // Tiempo encima del segmento si hay espacio suficiente (> 8mm)
          if (actualW >= 8) {
            mono(fmtMs(ms), sx + actualW / 2, barY - 1.5,
              { size: 5, color: seg.color, align: "center" });
          }
          sx += sw;
        }

        // Suma de tiempos de agentes ejecutados en este host
        const sumAgentMs = (ad.deepScanMs ?? 0) + (ad.findVulnsMs ?? 0) + (ad.exploitMs ?? 0);
        mono(fmtMs(sumAgentMs || total), barX + barMaxW + 3, barY + barH * 0.78,
          { size: 8, bold: true, color: C.white });

        if (idx < durHosts.length - 1)
          line(ML, ry + rowH - 0.5, ML + CW, ry + rowH - 0.5, C.dim, 0.1);
      });

      y += durHosts.length * rowH + 8;

      // Nota estática explicativa
      {
        const noteText = `Nota: el tiempo hasta conseguir sesión en un host mostrado en el timeline puede diferir del tiempo acumulado de agentes reflejado en las barras. Esto se debe a que sobre un mismo host pueden haberse ejecutado distintos procesos de explotación a lo largo del flujo, y la duración registrada corresponde al último proceso de explotación completado, no a la suma total de todos los intentos realizados.`;
        const ptx2 = ML + 7, ptw2 = CW - 10, lh2 = 4.5;
        doc.setFont("helvetica", "italic"); doc.setFontSize(7.5);
        const nLines = doc.splitTextToSize(noteText, ptw2);
        const nH = nLines.length * lh2 + 4;
        checkY(nH + 4);
        doc.setTextColor(...C.muted);
        nLines.forEach((ln, i) => { doc.text(ln, ptx2, y + lh2 + i * lh2); });
        y += nH + 4;
      }

      // Leyenda — blanca y más grande
      const legW = CW / segs.length;
      segs.forEach((s, i) => {
        const lx = ML + i * legW;
        fillRect(lx, y, 5, 5, s.color);
        txt(s.label, lx + 7, y + 4, { size: 7, color: C.white });
      });

      y += 14;
    }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // FOOTERS
  // ════════════════════════════════════════════════════════════════════════════
  const totalPages = doc.internal.getNumberOfPages();
  for (let p = 2; p <= totalPages; p++) {
    doc.setPage(p);
    footer(p, totalPages);
  }

  doc.save(`ARES_Report_Job${meta.jobId}.pdf`);

  const pdfBase64 = doc.output("datauristring").split(",")[1];
  fetch(`http://localhost:3000/report/${meta.jobId}/save-pdf`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ data: pdfBase64 }),
  }).catch((err) => console.warn("[pdf] No se pudo guardar en servidor:", err));
}