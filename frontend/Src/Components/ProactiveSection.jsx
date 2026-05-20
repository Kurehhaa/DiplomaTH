// frontend/Src/Components/ProactiveSection.jsx
export default function ProactiveSection({ proactive }) {
  const ttp = proactive?.ttp_predictions || [];
  const paths = proactive?.attack_paths || [];

  return (
    <section className="rounded-[2rem] border border-slate-200 bg-white p-6 shadow-sm">
      <h2 className="text-2xl font-medium tracking-tight text-slate-900 mb-1">
        Proactive Intelligence
      </h2>
      <p className="text-slate-600 mb-6">
        Predicted attack techniques and most likely attack paths (powered by Groq)
      </p>

      {/* TTP Predictions */}
      {ttp.length > 0 && (
        <div className="mb-8">
          <h3 className="font-medium text-lg mb-3">Likely MITRE ATT&CK Techniques</h3>
          <div className="grid gap-3">
            {ttp.map((item, i) => (
              <div key={i} className="flex items-start gap-4 p-4 bg-slate-50 rounded-2xl">
                <div className="font-mono font-bold text-indigo-600 text-lg">
                  {item.technique_id || item}
                </div>
                <div>
                  <div className="font-medium">{item.description || "Common technique"}</div>
                  <div className="text-sm text-slate-500 mt-1">
                    Likelihood: <span className="font-medium text-emerald-600">{item.likelihood || "Medium"}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Attack Paths */}
      {paths.length > 0 && (
        <div>
          <h3 className="font-medium text-lg mb-3">Most Probable Attack Paths</h3>
          <div className="space-y-4">
            {paths.map((path, i) => (
              <div key={i} className="border border-slate-200 rounded-3xl p-5 bg-white">
                <div className="flex justify-between items-start">
                  <div>
                    <div className="font-semibold text-lg">{path.name}</div>
                    <div className="text-slate-600 mt-1">{path.description}</div>
                  </div>
                  <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                    path.likelihood === 'High' ? 'bg-red-100 text-red-700' :
                    path.likelihood === 'Medium' ? 'bg-orange-100 text-orange-700' :
                    'bg-emerald-100 text-emerald-700'
                  }`}>
                    {path.likelihood}
                  </span>
                </div>

                {path.ttp_chain && (
                  <div className="mt-4">
                    <div className="text-xs uppercase tracking-widest text-slate-400 mb-2">TTP Chain</div>
                    <div className="flex flex-wrap gap-2">
                      {path.ttp_chain.map((ttp, idx) => (
                        <span key={idx} className="font-mono text-xs bg-slate-100 px-3 py-1 rounded-full">
                          {ttp}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {path.recommendation && (
                  <div className="mt-4 pt-4 border-t text-sm text-slate-600">
                    <strong>Recommendation:</strong> {path.recommendation}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {ttp.length === 0 && paths.length === 0 && (
        <p className="text-slate-500 italic">No proactive intelligence available yet. Run a scan.</p>
      )}
    </section>
  );
}