export default function Sidebar({ activeTab, setActiveTab }) {
  const modules = [
    ['recon', 'Recon Dashboard', 'Unified domain reconnaissance view'],
    ['cve', 'CVE Intelligence', 'Technology-to-vulnerability analysis'],
    ['correlation', 'Threat Correlation', 'IOC and external threat signals'],
    ['priority', 'Attack Prioritization', 'Top risky assets and focus order'],
    ['report', 'AI Security Report', 'Summaries, findings, and next steps'],
  ]

  return (
    <aside className="hidden lg:flex lg:w-64 xl:w-72 flex-col justify-between bg-[radial-gradient(circle_at_top_left,_rgba(59,130,246,0.20),_transparent_28%),linear-gradient(180deg,#09142f_0%,#03102a_100%)] text-white border-r border-white/10">
      <div>
        <div className="px-5 py-6 border-b border-white/10">
          <div className="flex items-center gap-3">
            <div className="h-12 w-12 rounded-2xl bg-gradient-to-br from-blue-500 to-indigo-500 flex items-center justify-center text-xl shadow-lg shadow-blue-500/20">
              ◎
            </div>
            <div>
              <div className="text-2xl font-semibold tracking-tight">ThreatScope</div>
              <div className="text-slate-300 text-sm">Proactive Threat Intelligence</div>
            </div>
          </div>
        </div>

        <div className="px-5 pt-7 pb-4 text-xs uppercase tracking-[0.22em] text-slate-400">
          Platform Modules
        </div>

        <div className="px-4 space-y-3">
          {modules.map(([key, title, subtitle]) => (
            <button
              key={key}
              onClick={() => setActiveTab(key)}
              className={`w-full text-left rounded-3xl border px-4 py-4 transition-all ${
                activeTab === key
                  ? 'border-indigo-400/20 bg-white/10 shadow-lg shadow-indigo-900/30'
                  : 'border-transparent bg-transparent hover:bg-white/5'
              }`}
            >
              <div className="text-lg font-medium tracking-tight">{title}</div>
              <div className="text-slate-400 text-sm mt-1">{subtitle}</div>
            </button>
          ))}
        </div>
      </div>

      <div className="p-4">
        <div className="rounded-3xl border border-emerald-400/20 bg-emerald-500/10 px-4 py-4">
          <div className="text-lg font-medium tracking-tight">ML Engine Active</div>
          <div className="text-slate-400 text-sm mt-1">
            Ready for prioritization and risk prediction
          </div>
        </div>
      </div>
    </aside>
  )
}