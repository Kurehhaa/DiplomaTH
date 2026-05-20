import { useState } from "react";
import "./app.css";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

export default function App() {
  const [targetInput, setTargetInput] = useState("");
  const [activeTarget, setActiveTarget] = useState("");
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(false);
  const [reportLoading, setReportLoading] = useState(false);
  const [aiReport, setAiReport] = useState("");
  const [activeTab, setActiveTab] = useState("recon");

  async function startScan(value = targetInput) {
    const cleanTarget = value.trim();
    if (!cleanTarget) return;

    setLoading(true);
    setAiReport("");

    try {
      const res = await fetch(`${API_BASE}/api/scans/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: cleanTarget }),
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();

      setActiveTarget(cleanTarget);
      setTargetInput(cleanTarget);
      setScan(data);
      setActiveTab("recon");
    } catch (err) {
      alert("Ошибка сканирования: " + err.message);
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
      setAiReport(data.report || "Ошибка генерации");
    } catch (err) {
      setAiReport("Не удалось подключиться к Groq.");
    } finally {
      setReportLoading(false);
    }
  }

  const openPorts = scan?.network?.open_ports || [];
  const highRiskPorts = openPorts.filter(p => [21, 22, 445, 3389, 3306].includes(p));

  return (
    <div className="workspace">
      <aside className="sidebar">
        <div className="brand">
          <div className="logo">TS</div>
          <div>
            <strong>ThreatScope</strong>
            <span>Proactive Threat Intelligence</span>
          </div>
        </div>

        <nav>
          {[
            ["recon", "Recon Dashboard"],
            ["surface", "Attack Surface"],
            ["findings", "Findings & Risks"],
            ["intelligence", "Threat Intelligence"],
            ["report", "AI Security Report"],
          ].map(([id, label]) => (
            <button
              key={id}
              className={activeTab === id ? "active" : ""}
              onClick={() => setActiveTab(id)}
            >
              {label}
            </button>
          ))}
        </nav>
      </aside>

      <main className="workspace-main">
        <header className="workspace-header">
          <div>
            <span className="eyebrow">ACTIVE TARGET</span>
            <h2>{activeTarget || "No target selected"}</h2>
            {scan && (
              <p>Last scan • Risk: <strong>{scan.risk_level}</strong> • ML: <strong>{scan.ml_risk?.risk_score} ({scan.ml_risk?.risk_level})</strong></p>
            )}
          </div>

          <div className="header-actions">
            <button className="secondary-btn" onClick={() => startScan(activeTarget)} disabled={!activeTarget || loading}>Rescan</button>
            <button className="primary-btn" onClick={() => { setScan(null); setActiveTarget(""); setAiReport(""); }}>New Scan</button>
          </div>
        </header>

        <section className="workspace-content">
          <div className="scan-form" style={{ marginBottom: "32px" }}>
            <input
              value={targetInput}
              onChange={(e) => setTargetInput(e.target.value)}
              placeholder="example.com или полный URL"
              onKeyDown={(e) => e.key === "Enter" && startScan()}
            />
            <button className="primary-btn" onClick={() => startScan()} disabled={loading}>
              {loading ? "Scanning..." : "Start Scan"}
            </button>
          </div>

          {/* ==================== RECON DASHBOARD ==================== */}
          {activeTab === "recon" && scan && (
            <>
              <h2 className="text-3xl font-semibold mb-2">Executive Overview</h2>
              <p className="text-slate-600 mb-8">External reconnaissance & ML risk assessment</p>

              <div className="grid grid-cols-2 lg:grid-cols-4 gap-6 mb-10">
                <div className="bg-white rounded-3xl p-8 shadow-sm">
                  <div className="text-slate-500 text-sm">IP Address</div>
                  <div className="text-4xl font-semibold mt-4">{scan.network?.ip_address || "—"}</div>
                </div>

                <div className="bg-white rounded-3xl p-8 shadow-sm">
                  <div className="text-slate-500 text-sm">Open Ports</div>
                  <div className="text-4xl font-semibold mt-4 text-blue-600">{openPorts.length}</div>
                  {highRiskPorts.length > 0 && <div className="text-red-600 text-sm mt-1">High Risk: {highRiskPorts.length}</div>}
                </div>

                <div className="bg-white rounded-3xl p-8 shadow-sm">
                  <div className="text-slate-500 text-sm">Risk Level</div>
                  <div className={`text-4xl font-semibold mt-4 ${scan.risk_level === 'High' || scan.risk_level === 'Critical' ? 'text-red-600' : 'text-amber-600'}`}>
                    {scan.risk_level}
                  </div>
                </div>

                <div className="bg-white rounded-3xl p-8 shadow-sm">
                  <div className="text-slate-500 text-sm">ML Risk Score</div>
                  <div className="text-4xl font-semibold mt-4">{scan.ml_risk?.risk_score} <span className="text-lg font-normal">/ 10</span></div>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {scan.ml_risk?.features && (
                  <div className="panel">
                    <h3>Why this risk score? (SHAP)</h3>
                    <div className="mt-6 space-y-6">
                      {Object.entries(scan.ml_risk.features)
                        .sort((a, b) => Math.abs(b[1]) - Math.abs(a[1]))
                        .slice(0, 6)
                        .map(([key, val]) => (
                          <div key={key} className="flex items-center gap-4">
                            <div className="w-48 text-sm font-medium capitalize">{key.replace(/_/g, " ")}</div>
                            <div className="flex-1 h-2.5 bg-gray-100 rounded-full">
                              <div className={`h-full rounded-full ${val > 0 ? 'bg-emerald-500' : 'bg-red-500'}`} 
                                   style={{ width: `${Math.min(Math.abs(val) * 30, 100)}%` }} />
                            </div>
                            <div className={`font-mono font-bold w-16 ${val > 0 ? 'text-emerald-600' : 'text-red-600'}`}>
                              {val > 0 ? '+' : ''}{val.toFixed(2)}
                            </div>
                          </div>
                        ))}
                    </div>
                  </div>
                )}

                <div className="panel">
                  <h3>Detected Open Ports</h3>
                  <div className="flex flex-wrap gap-3 mt-6">
                    {openPorts.sort((a,b)=>a-b).map(p => (
                      <div key={p} className={`px-6 py-4 rounded-2xl font-mono text-xl font-semibold border ${[21,445,3389].includes(p) ? 'border-red-300 bg-red-50 text-red-700' : 'border-slate-200 bg-slate-50'}`}>
                        {p}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </>
          )}

          {/* Attack Surface */}
          {activeTab === "surface" && scan && (
            <div className="panel">
              <h3>Attack Surface</h3>
              <div className="list">
                {scan.network?.ip_address && <div className="list-item"><strong>IP Address</strong><span>{scan.network.ip_address}</span></div>}
                {openPorts.length > 0 && <div className="list-item"><strong>Open Ports</strong><span>{openPorts.join(", ")}</span></div>}
                {scan.web?.server && <div className="list-item"><strong>Server</strong><span>{scan.web.server}</span></div>}
              </div>
            </div>
          )}

          {/* Findings & Risks */}
          {activeTab === "findings" && scan && (
            <div className="panel">
              <h3>Findings & Risks</h3>
              {scan.findings?.length > 0 ? (
                scan.findings.map((f, i) => (
                  <div key={i} className="finding">
                    <span className={`severity-badge severity-${f.severity?.toLowerCase() || 'medium'}`}>{f.severity}</span>
                    <h4>{f.title}</h4>
                    <p>{f.description}</p>
                  </div>
                ))
              ) : <p>No findings yet.</p>}
            </div>
          )}

          {/* Threat Intelligence */}
          {activeTab === "intelligence" && scan && (
            <div className="panel">
              <h3>Threat Intelligence</h3>
              {scan.mitre?.ttps?.length > 0 && (
                <div style={{ marginBottom: "30px" }}>
                  <h4>MITRE ATT&CK Techniques</h4>
                  <div className="list">
                    {scan.mitre.ttps.map((t, i) => (
                      <div key={i} className="list-item">
                        <strong>{t.technique_id}</strong>
                        <span>{t.description}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {scan.proactive?.attack_paths?.length > 0 && (
                <div>
                  <h4>Most Probable Attack Paths</h4>
                  {scan.proactive.attack_paths.map((path, i) => (
                    <div key={i} className="list-item">
                      <strong>{path.name}</strong>
                      <p>{path.description}</p>
                      {path.recommendation && <p><strong>Recommendation:</strong> {path.recommendation}</p>}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* AI Security Report */}
          {activeTab === "report" && (
            <div className="panel">
              <h3>AI Security Report</h3>
              <button className="primary-btn" onClick={generateAiReport} disabled={!scan || reportLoading}>
                {reportLoading ? "Generating..." : "Generate AI Report"}
              </button>
              {aiReport && <div className="report-box mt-6"><pre>{aiReport}</pre></div>}
            </div>
          )}

          {!scan && <div className="empty-module"><span>Run a scan to begin analysis</span></div>}
        </section>
      </main>
    </div>
  );
}