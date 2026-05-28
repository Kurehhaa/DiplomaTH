import { useState } from "react";
import "./App.css";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

const PORT_SERVICES = {
  21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",
  110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",3306:"MySQL",
  3389:"RDP",5432:"PostgreSQL",5900:"VNC",6379:"Redis",
  8080:"HTTP-Alt",8443:"HTTPS-Alt",27017:"MongoDB",
};

const HIGH_RISK = new Set([21,22,23,445,3389,3306,5432,5900,6379,27017]);

function SeverityBadge({ severity }) {
  const s = (severity || "unknown").toLowerCase();
  return <span className={`severity-badge severity-${s}`}>{severity}</span>;
}

function RiskColor({ level }) {
  const map = { Critical:"#f87171", High:"#fb923c", Medium:"#facc15", Low:"#4ade80" };
  return map[level] || "#94a3b8";
}

export default function App() {
  const [targetInput,    setTargetInput]    = useState("");
  const [activeTarget,   setActiveTarget]   = useState("");
  const [scan,           setScan]           = useState(null);
  const [loading,        setLoading]        = useState(false);
  const [reportLoading,  setReportLoading]  = useState(false);
  const [aiReport,       setAiReport]       = useState("");
  const [activeTab,      setActiveTab]      = useState("recon");
  const [error,          setError]          = useState("");

  async function startScan(value = targetInput) {
    const t = value.trim();
    if (!t) return;
    setLoading(true); setAiReport(""); setError("");
    try {
      const res = await fetch(`${API_BASE}/api/scans/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: t }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setActiveTarget(t); setTargetInput(t);
      setScan(data); setActiveTab("recon");
    } catch (err) {
      setError("Scan failed: " + err.message);
    } finally {
      setLoading(false);
    }
  }

  async function generateAiReport() {
    if (!scan) return;
    setReportLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scan_result: scan }),
      });
      const data = await res.json();
      setAiReport(data.report || "Generation error");
    } catch { setAiReport("Could not connect to Groq."); }
    finally { setReportLoading(false); }
  }

  const openPorts   = scan?.network?.open_ports || [];
  const dangerPorts = openPorts.filter(p => HIGH_RISK.has(p));
  const cveList     = scan?.cve?.vulnerabilities || [];
  const cveSummary  = scan?.cve?.summary || {};
  const waf         = scan?.waf || {};
  const findings    = scan?.findings || [];

  const NAV = [
    { id:"recon",        label:"Recon Dashboard",    icon:"📊" },
    { id:"surface",      label:"Attack Surface",     icon:"🗺️" },
    { id:"findings",     label:"Findings & Risks",   icon:"🔍", badge: findings.filter(f=>["High","Critical"].includes(f.severity)).length },
    { id:"intelligence", label:"Threat Intelligence",icon:"🧠", badge: cveList.length },
    { id:"report",       label:"AI Security Report", icon:"📄" },
  ];

  return (
    <div className="workspace">

      {/* ─── SIDEBAR ─── */}
      <aside className="sidebar">
        <div className="brand">
          <div className="logo">TS</div>
          <div>
            <strong>ThreatScope</strong>
            <span>Proactive Intelligence</span>
          </div>
        </div>

        <nav>
          {NAV.map(({ id, label, icon, badge }) => (
            <button
              key={id}
              className={activeTab === id ? "active" : ""}
              onClick={() => setActiveTab(id)}
            >
              <span>{icon}</span>
              <span style={{ flex: 1 }}>{label}</span>
              {badge > 0 && (
                <span style={{
                  background: id === "findings" ? "rgba(249,115,22,0.25)" : "rgba(239,68,68,0.25)",
                  color:      id === "findings" ? "#fb923c" : "#f87171",
                  borderRadius: "99px", padding: "1px 8px",
                  fontSize: "11px", fontWeight: 800,
                }}>
                  {badge}
                </span>
              )}
            </button>
          ))}
        </nav>

        {/* WAF статус в сайдбаре */}
        {scan && (
          <div style={{ marginTop: "auto", padding: "16px 6px 0", borderTop: "1px solid rgba(255,255,255,0.08)" }}>
            <div style={{ fontSize: "11px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.07em", color: "#4a5568", marginBottom: "8px" }}>
              WAF Status
            </div>
            <span className={`waf-badge ${waf.detected ? "waf-detected" : "waf-not-detected"}`}>
              {waf.detected ? `${waf.icon || "🛡️"} ${waf.name}` : "⚠️ No WAF"}
            </span>
            {waf.detected && waf.confidence && (
              <div style={{ fontSize: "11px", color: "#4a5568", marginTop: "5px" }}>
                Confidence: {waf.confidence}
              </div>
            )}
          </div>
        )}
      </aside>

      {/* ─── MAIN ─── */}
      <main className="workspace-main">

        {/* Header */}
        <header className="workspace-header">
          <div>
            <div className="eyebrow">Active Target</div>
            <h2>{activeTarget || "No target selected"}</h2>
            {scan && (
              <p>
                Scanned {new Date(scan.scanned_at).toLocaleTimeString()} ·
                Risk: <strong style={{ color: RiskColor({ level: scan.risk_level }) }}>{scan.risk_level}</strong> ·
                ML Score: <strong>{scan.ml_risk?.risk_score}/10</strong>
              </p>
            )}
          </div>
          <div className="header-actions">
            <button className="secondary-btn" onClick={() => startScan(activeTarget)} disabled={!activeTarget || loading}>
              ↺ Rescan
            </button>
            <button className="secondary-btn" onClick={() => { setScan(null); setActiveTarget(""); setAiReport(""); setError(""); }}>
              + New Scan
            </button>
          </div>
        </header>

        <section className="workspace-content">

          {/* Scan form */}
          <div className="scan-form">
            <input
              value={targetInput}
              onChange={e => setTargetInput(e.target.value)}
              placeholder="example.com"
              onKeyDown={e => e.key === "Enter" && startScan()}
            />
            <button className="primary-btn" onClick={() => startScan()} disabled={loading}>
              {loading ? <span className="loading-pulse">Scanning…</span> : "Start Scan"}
            </button>
          </div>

          {error && (
            <div style={{ background:"rgba(239,68,68,0.1)", border:"1px solid rgba(239,68,68,0.3)", borderRadius:"var(--radius-md)", padding:"14px 18px", color:"#f87171", marginBottom:"20px", fontSize:"14px" }}>
              ⚠️ {error}
            </div>
          )}

          {/* ════════════ RECON DASHBOARD ════════════ */}
          {activeTab === "recon" && scan && (() => {
            const riskColor = RiskColor({ level: scan.risk_level });
            return (
              <>
                {/* Stat Cards */}
                <div className="stat-grid">
                  <div className="stat-card">
                    <div className="stat-label">IP Address</div>
                    <div className="stat-value" style={{ fontSize:"20px", fontFamily:"monospace" }}>
                      {scan.network?.ip_address || "—"}
                    </div>
                    <div className="stat-sub">{scan.domain}</div>
                  </div>

                  <div className="stat-card" style={{ "--accent-grad": "linear-gradient(90deg,#3b82f6,#06b6d4)" }}>
                    <div className="stat-label">Open Ports</div>
                    <div className="stat-value" style={{ color:"#60a5fa" }}>{openPorts.length}</div>
                    {dangerPorts.length > 0 && (
                      <div className="stat-sub" style={{ color:"#f87171" }}>⚠ {dangerPorts.length} high-risk</div>
                    )}
                  </div>

                  <div className="stat-card" style={{ "--accent-grad": `linear-gradient(90deg,${riskColor},${riskColor}88)` }}>
                    <div className="stat-label">Risk Level</div>
                    <div className="stat-value" style={{ color: riskColor }}>{scan.risk_level}</div>
                    <div className="stat-sub">{scan.ml_risk?.risk_score}/10 ML score</div>
                  </div>

                  <div className="stat-card" style={{ "--accent-grad": cveList.length ? "linear-gradient(90deg,#ef4444,#f97316)" : "linear-gradient(90deg,#22c55e,#06b6d4)" }}>
                    <div className="stat-label">CVE Found</div>
                    <div className="stat-value" style={{ color: cveList.length ? "#f87171" : "#4ade80" }}>
                      {cveList.length}
                    </div>
                    <div className="stat-sub">
                      {cveSummary.critical > 0 ? `${cveSummary.critical} critical` : cveList.length === 0 ? "No known CVEs" : `${cveSummary.high || 0} high`}
                    </div>
                  </div>
                </div>

                {/* SHAP + Ports */}
                <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:"20px" }}>

                  {/* SHAP */}
                  {scan.ml_risk?.features && Object.keys(scan.ml_risk.features).length > 0 && (
                    <div className="panel">
                      <h3>Why this risk score? <span style={{ fontSize:"13px", color:"#4a5568", fontWeight:500 }}>(SHAP)</span></h3>
                      <div style={{ display:"flex", flexDirection:"column", gap:"14px" }}>
                        {Object.entries(scan.ml_risk.features)
                          .sort((a,b) => Math.abs(b[1]) - Math.abs(a[1]))
                          .slice(0,7)
                          .map(([key, val]) => (
                            <div key={key} style={{ display:"flex", alignItems:"center", gap:"12px" }}>
                              <div style={{ width:"160px", fontSize:"12px", fontWeight:600, color:"#94a3b8", textTransform:"capitalize", flexShrink:0 }}>
                                {key.replace(/_/g," ")}
                              </div>
                              <div className="shap-bar-track">
                                <div
                                  className={val > 0 ? "shap-bar-fill-red" : "shap-bar-fill-green"}
                                  style={{ width:`${Math.min(Math.abs(val)*35,100)}%` }}
                                />
                              </div>
                              <div style={{ fontFamily:"monospace", fontSize:"12px", fontWeight:700, width:"48px", textAlign:"right", color: val > 0 ? "#f87171" : "#4ade80" }}>
                                {val > 0 ? "+" : ""}{val.toFixed(2)}
                              </div>
                            </div>
                          ))}
                      </div>
                      <p style={{ fontSize:"11px", color:"#4a5568", marginTop:"14px", marginBottom:0 }}>
                        Red = increases risk · Green = reduces risk
                      </p>
                    </div>
                  )}

                  {/* Ports */}
                  <div className="panel">
                    <h3>Open Ports</h3>
                    <div style={{ display:"flex", flexWrap:"wrap", gap:"8px" }}>
                      {openPorts.sort((a,b)=>a-b).map(p => (
                        <div key={p} className={`port-chip ${HIGH_RISK.has(p) ? "port-chip-danger" : ""}`}>
                          <div>{p}</div>
                          <div style={{ fontSize:"10px", fontWeight:600, color:"inherit", opacity:0.7 }}>
                            {PORT_SERVICES[p] || "?"}
                          </div>
                        </div>
                      ))}
                      {openPorts.length === 0 && <p style={{ color:"#4a5568", margin:0 }}>No open ports found</p>}
                    </div>

                    {/* Probability bars */}
                    {scan.ml_risk?.probabilities && (
                      <div style={{ marginTop:"20px", paddingTop:"20px", borderTop:"1px solid rgba(255,255,255,0.06)" }}>
                        <div style={{ fontSize:"12px", fontWeight:700, textTransform:"uppercase", letterSpacing:"0.07em", color:"#4a5568", marginBottom:"12px" }}>
                          Risk Distribution
                        </div>
                        {[
                          ["Critical", "#f87171"],
                          ["High",     "#fb923c"],
                          ["Medium",   "#facc15"],
                          ["Low",      "#4ade80"],
                        ].map(([label, color]) => {
                          const val = scan.ml_risk.probabilities[label] || 0;
                          return (
                            <div key={label} style={{ display:"flex", alignItems:"center", gap:"10px", marginBottom:"8px" }}>
                              <div style={{ width:"56px", fontSize:"12px", color:"#94a3b8" }}>{label}</div>
                              <div className="shap-bar-track">
                                <div style={{ height:"100%", borderRadius:"99px", background:color, width:`${val*100}%`, opacity:0.8 }} />
                              </div>
                              <div style={{ fontFamily:"monospace", fontSize:"12px", color:"#94a3b8", width:"36px", textAlign:"right" }}>
                                {(val*100).toFixed(0)}%
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>

                </div>
              </>
            );
          })()}

          {/* ════════════ ATTACK SURFACE ════════════ */}
          {activeTab === "surface" && scan && (
            <>
              {/* WAF Card */}
              <div className="panel" style={{ marginBottom:"20px" }}>
                <h3>WAF / Firewall Detection</h3>
                <div style={{ display:"flex", alignItems:"flex-start", gap:"20px", flexWrap:"wrap" }}>
                  <div>
                    <span className={`waf-badge ${waf.detected ? "waf-detected" : "waf-not-detected"}`} style={{ fontSize:"15px", padding:"10px 20px" }}>
                      {waf.detected
                        ? `${waf.icon || "🛡️"} ${waf.name}`
                        : "⚠️ No WAF Detected"}
                    </span>
                    {waf.detected && (
                      <div style={{ marginTop:"8px", display:"flex", gap:"8px", flexWrap:"wrap" }}>
                        <span style={{ fontSize:"12px", color:"#94a3b8" }}>Confidence:</span>
                        <span style={{ fontSize:"12px", fontWeight:700, color: waf.confidence==="high"?"#4ade80": waf.confidence==="medium"?"#facc15":"#94a3b8" }}>
                          {waf.confidence}
                        </span>
                        {waf.blocked_test && (
                          <span style={{ fontSize:"12px", color:"#4ade80" }}>· ✓ Blocked test payload</span>
                        )}
                      </div>
                    )}
                  </div>
                  <div style={{ flex:1, fontSize:"13.5px", color:"#94a3b8", lineHeight:"1.6" }}>
                    {waf.description || "No WAF was identified. The application may be directly exposed to automated attacks."}
                  </div>
                </div>
                {waf.signals?.length > 0 && (
                  <div style={{ marginTop:"14px", display:"flex", gap:"8px", flexWrap:"wrap" }}>
                    <span style={{ fontSize:"11px", fontWeight:700, color:"#4a5568", textTransform:"uppercase", letterSpacing:"0.06em" }}>Signals:</span>
                    {waf.signals.map((s,i) => (
                      <span key={i} style={{ fontSize:"12px", background:"rgba(34,197,94,0.1)", color:"#4ade80", border:"1px solid rgba(34,197,94,0.2)", borderRadius:"6px", padding:"2px 10px" }}>
                        {s}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* Network info */}
              <div className="panel" style={{ marginBottom:"20px" }}>
                <h3>Network & Web</h3>
                <div className="list">
                  {scan.network?.ip_address && <div className="list-item"><strong>IP Address</strong><span>{scan.network.ip_address}</span></div>}
                  {openPorts.length > 0 && <div className="list-item"><strong>Open Ports</strong><span>{openPorts.join(", ")}</span></div>}
                  {scan.web?.server && scan.web.server !== "Unknown" && <div className="list-item"><strong>Server</strong><span>{scan.web.server}</span></div>}
                  {scan.web?.x_powered_by && scan.web.x_powered_by !== "Unknown" && <div className="list-item"><strong>X-Powered-By</strong><span>{scan.web.x_powered_by}</span></div>}
                  {scan.web?.cms && <div className="list-item"><strong>CMS</strong><span>{scan.web.cms}</span></div>}
                  {scan.ssl?.enabled && (
                    <div className="list-item">
                      <strong>SSL Certificate</strong>
                      <span>
                        {scan.ssl.valid ? "✅ Valid" : "❌ Invalid"} · {scan.ssl.expires_in_days} days left · {scan.ssl.protocol} · Issuer: {scan.ssl.issuer}
                        {scan.ssl.self_signed ? " ⚠️ Self-Signed" : ""}
                      </span>
                    </div>
                  )}
                  {scan.subdomains?.length > 0 && <div className="list-item"><strong>Subdomains ({scan.subdomains.length})</strong><span style={{ wordBreak:"break-all" }}>{scan.subdomains.join(", ")}</span></div>}
                </div>
              </div>

              {/* Banner Grabbing */}
              {scan.banners && Object.keys(scan.banners).length > 0 && (
                <div className="panel" style={{ marginBottom:"20px" }}>
                  <h3>Banner Grabbing</h3>
                  <p style={{ color:"#94a3b8", fontSize:"13px", marginTop:0 }}>Direct service responses — exact versions for CVE lookup</p>
                  <div className="list">
                    {Object.entries(scan.banners).map(([port, banner]) => (
                      <div key={port} className="list-item">
                        <strong>{port} / {PORT_SERVICES[port] || "Unknown"}</strong>
                        <span style={{ fontFamily:"monospace", fontSize:"13px" }}>{banner}</span>
                      </div>
                    ))}
                  </div>
                  {scan.banner_versions && Object.keys(scan.banner_versions).length > 0 && (
                    <div style={{ marginTop:"14px", padding:"12px 16px", background:"rgba(99,102,241,0.08)", borderRadius:"var(--radius-sm)", border:"1px solid rgba(99,102,241,0.2)" }}>
                      <div style={{ fontSize:"12px", fontWeight:700, color:"#818cf8", marginBottom:"8px" }}>Extracted Versions</div>
                      <div style={{ display:"flex", gap:"8px", flexWrap:"wrap" }}>
                        {Object.entries(scan.banner_versions).map(([t,v]) => (
                          <span key={t} style={{ background:"rgba(99,102,241,0.12)", border:"1px solid rgba(99,102,241,0.25)", borderRadius:"6px", padding:"3px 12px", fontSize:"12px", fontFamily:"monospace", color:"#a5b4fc" }}>
                            {t} {v}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* DNS */}
              {scan.dns && (
                <div className="panel">
                  <h3>DNS Reconnaissance</h3>
                  <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:"12px", marginBottom:"20px" }}>
                    {[["A",scan.dns.A],["MX",scan.dns.MX],["NS",scan.dns.NS],["TXT",scan.dns.TXT]].map(([label,records]) =>
                      records?.length > 0 && (
                        <div key={label} style={{ background:"var(--bg-surface)", borderRadius:"var(--radius-sm)", padding:"14px 16px", border:"1px solid var(--border-soft)" }}>
                          <div style={{ fontSize:"11px", fontWeight:700, textTransform:"uppercase", letterSpacing:"0.06em", color:"#4a5568", marginBottom:"8px" }}>{label}</div>
                          {records.map((r,i) => <div key={i} style={{ fontFamily:"monospace", fontSize:"12px", color:"#94a3b8", marginBottom:"3px" }}>{r.length>60?r.slice(0,60)+"…":r}</div>)}
                        </div>
                      )
                    )}
                  </div>
                  <div style={{ fontSize:"13px", fontWeight:700, color:"#94a3b8", marginBottom:"10px" }}>Email Security</div>
                  <div style={{ display:"flex", gap:"10px", flexWrap:"wrap" }}>
                    {[["SPF",scan.dns.SPF?.length>0],["DMARC",scan.dns.DMARC?.length>0],["DKIM",scan.dns.DKIM_selectors?.length>0]].map(([name,ok]) => (
                      <div key={name} style={{
                        padding:"8px 18px", borderRadius:"var(--radius-sm)",
                        background: ok ? "rgba(34,197,94,0.1)" : "rgba(239,68,68,0.1)",
                        border: `1px solid ${ok ? "rgba(34,197,94,0.25)" : "rgba(239,68,68,0.25)"}`,
                        color: ok ? "#4ade80" : "#f87171",
                        fontWeight:700, fontSize:"13px",
                      }}>
                        {ok ? "✅" : "❌"} {name}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}

          {/* ════════════ FINDINGS ════════════ */}
          {activeTab === "findings" && scan && (
            <div className="panel">
              <h3>Findings & Risks <span style={{ fontSize:"14px", color:"#4a5568", fontWeight:500 }}>({findings.length} total)</span></h3>
              {findings.length > 0 ? findings.map((f,i) => (
                <div key={i} className="finding" style={{ borderLeftColor:
                  f.severity==="Critical"?"#ef4444":f.severity==="High"?"#f97316":f.severity==="Medium"?"#eab308":"#22c55e"
                }}>
                  <SeverityBadge severity={f.severity} />
                  <h4>{f.title}</h4>
                  <p>{f.description}</p>
                </div>
              )) : <p style={{ color:"#4a5568" }}>No findings detected.</p>}
            </div>
          )}

          {/* ════════════ THREAT INTELLIGENCE ════════════ */}
          {activeTab === "intelligence" && scan && (
            <>
              {scan.mitre?.ttps?.length > 0 && (
                <div className="panel" style={{ marginBottom:"20px" }}>
                  <h3>MITRE ATT&CK Techniques</h3>
                  <div className="list">
                    {scan.mitre.ttps.map((t,i) => (
                      <div key={i} className="list-item">
                        <strong style={{ color:"#818cf8" }}>{t.technique_id}</strong>
                        <span>{t.description}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {scan.proactive?.attack_paths?.length > 0 && (
                <div className="panel" style={{ marginBottom:"20px" }}>
                  <h3>Most Probable Attack Paths</h3>
                  {scan.proactive.attack_paths.map((p,i) => (
                    <div key={i} className="finding" style={{ borderLeftColor:"#6366f1" }}>
                      <div style={{ display:"flex", alignItems:"center", gap:"10px", marginBottom:"8px" }}>
                        <SeverityBadge severity={p.likelihood} />
                        <strong style={{ fontSize:"15px" }}>{p.name}</strong>
                      </div>
                      <p>{p.description}</p>
                      {p.ttp_chain?.length > 0 && <p style={{ fontSize:"12px", color:"#4a5568", marginTop:"6px" }}>TTP: {p.ttp_chain.join(" → ")}</p>}
                      {p.recommendation && (
                        <div style={{ marginTop:"10px", padding:"10px 14px", background:"rgba(34,197,94,0.08)", borderRadius:"var(--radius-sm)", border:"1px solid rgba(34,197,94,0.15)", fontSize:"13px", color:"#4ade80" }}>
                          💡 {p.recommendation}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {/* CVE Section */}
              <div className="panel">
                <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:"18px", flexWrap:"wrap", gap:"12px" }}>
                  <h3 style={{ margin:0 }}>CVE Vulnerabilities <span style={{ fontSize:"13px", color:"#4a5568", fontWeight:500 }}>(NVD)</span></h3>
                  {cveList.length > 0 && (
                    <div style={{ display:"flex", gap:"8px" }}>
                      {cveSummary.critical > 0 && <span style={{ background:"rgba(239,68,68,0.15)", color:"#f87171", border:"1px solid rgba(239,68,68,0.3)", borderRadius:"6px", padding:"4px 12px", fontSize:"12px", fontWeight:700 }}>{cveSummary.critical} Critical</span>}
                      {cveSummary.high    > 0 && <span style={{ background:"rgba(249,115,22,0.15)", color:"#fb923c", border:"1px solid rgba(249,115,22,0.3)", borderRadius:"6px", padding:"4px 12px", fontSize:"12px", fontWeight:700 }}>{cveSummary.high} High</span>}
                      <span style={{ background:"rgba(148,163,184,0.1)", color:"#94a3b8", border:"1px solid rgba(148,163,184,0.15)", borderRadius:"6px", padding:"4px 12px", fontSize:"12px" }}>Total: {cveSummary.total}</span>
                    </div>
                  )}
                </div>

                {cveList.length === 0 ? (
                  <div style={{ textAlign:"center", padding:"40px", color:"#4a5568" }}>
                    <div style={{ fontSize:"36px", marginBottom:"12px" }}>✅</div>
                    <p style={{ margin:0 }}>No known CVEs found for detected technologies.</p>
                  </div>
                ) : (
                  <div style={{ display:"flex", flexDirection:"column", gap:"12px" }}>
                    {cveList.map((cve,i) => {
                      const sev = (cve.severity||"UNKNOWN").toLowerCase();
                      return (
                        <div key={i} style={{ padding:"16px 18px", borderRadius:"var(--radius-md)", background:"var(--bg-surface)", border:"1px solid var(--border-soft)" }}>
                          <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", flexWrap:"wrap", gap:"10px", marginBottom:"8px" }}>
                            <div style={{ display:"flex", alignItems:"center", gap:"10px" }}>
                              <SeverityBadge severity={cve.severity} />
                              <span style={{ fontFamily:"monospace", fontWeight:700, color:"#a5b4fc", fontSize:"14px" }}>{cve.cve_id}</span>
                              {cve.raw_technology && (
                                <span style={{ background:"rgba(99,102,241,0.1)", color:"#818cf8", border:"1px solid rgba(99,102,241,0.2)", borderRadius:"6px", padding:"2px 10px", fontSize:"11px", fontWeight:700 }}>
                                  {cve.raw_technology}
                                </span>
                              )}
                            </div>
                            <div style={{ display:"flex", alignItems:"center", gap:"8px" }}>
                              {cve.cvss != null && (
                                <span style={{ background: cve.cvss>=9?"rgba(239,68,68,0.2)":cve.cvss>=7?"rgba(249,115,22,0.2)":"rgba(234,179,8,0.2)", color: cve.cvss>=9?"#f87171":cve.cvss>=7?"#fb923c":"#facc15", borderRadius:"6px", padding:"3px 10px", fontSize:"12px", fontWeight:700 }}>
                                  CVSS {cve.cvss.toFixed(1)}
                                </span>
                              )}
                              {cve.published && <span style={{ fontSize:"11px", color:"#4a5568" }}>{cve.published.slice(0,10)}</span>}
                            </div>
                          </div>
                          {cve.description && (
                            <p style={{ margin:"0 0 8px", fontSize:"13px", color:"#94a3b8", lineHeight:"1.6" }}>
                              {cve.description.length > 280 ? cve.description.slice(0,280)+"…" : cve.description}
                            </p>
                          )}
                          <a href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`} target="_blank" rel="noopener noreferrer"
                            style={{ fontSize:"12px", color:"#818cf8", textDecoration:"none" }}>
                            View on NVD ↗
                          </a>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </>
          )}

          {/* ════════════ AI REPORT ════════════ */}
          {activeTab === "report" && (
            <div className="panel">
              <h3>AI Security Report</h3>
              <p style={{ color:"#94a3b8", fontSize:"14px", marginTop:0 }}>
                Generate a professional penetration testing report based on scan results.
              </p>
              <button className="primary-btn" onClick={generateAiReport} disabled={!scan || reportLoading}>
                {reportLoading ? <span className="loading-pulse">Generating…</span> : "Generate AI Report"}
              </button>
              {aiReport && <div className="report-box"><pre>{aiReport}</pre></div>}
            </div>
          )}

          {/* Empty state */}
          {!scan && !loading && (
            <div className="empty-module">
              <div className="empty-icon">🎯</div>
              <h3 style={{ margin:0, color:"#94a3b8", fontWeight:600 }}>Enter a target to begin</h3>
              <p style={{ margin:0, color:"#4a5568", fontSize:"14px" }}>Proactive threat intelligence & ML risk assessment</p>
            </div>
          )}

          {loading && (
            <div className="empty-module">
              <div className="empty-icon loading-pulse">🔍</div>
              <h3 style={{ margin:0, color:"#94a3b8", fontWeight:600 }} className="loading-pulse">Scanning target…</h3>
              <p style={{ margin:0, color:"#4a5568", fontSize:"14px" }}>Port scan · Banner grabbing · DNS · WAF · CVE lookup</p>
            </div>
          )}

        </section>
      </main>
    </div>
  );
}
