const severityStyles = {
  Critical: 'bg-red-100 text-red-700 border-red-200',
  High: 'bg-orange-100 text-orange-700 border-orange-200',
  Medium: 'bg-yellow-100 text-yellow-700 border-yellow-200',
  Low: 'bg-emerald-100 text-emerald-700 border-emerald-200',
}

export default function OverviewSection({ scanResult }) {
  const severityClass =
    severityStyles[scanResult.summary?.severity] ||
    'bg-slate-100 text-slate-700 border-slate-200'

  return (
    <section className="mt-6">
      <div className="mb-3">
        <h2 className="text-2xl font-medium text-slate-900">Overview</h2>
        <p className="text-slate-600">Primary scan summary and exposure posture.</p>
      </div>

      <div className="grid gap-4 xl:grid-cols-4">
        <div className="rounded-[2rem] border border-slate-200 bg-white p-5 shadow-sm">
          <div className="text-sm uppercase tracking-[0.22em] text-slate-400">Target</div>
          <div className="mt-3 break-words text-xl font-medium text-slate-900">
            {scanResult.target}
          </div>
        </div>

        <div className="rounded-[2rem] border border-slate-200 bg-white p-5 shadow-sm">
          <div className="text-sm uppercase tracking-[0.22em] text-slate-400">Subdomains</div>
          <div className="mt-3 text-xl font-medium text-slate-900">
            {scanResult.summary?.subdomains}
          </div>
        </div>

        <div className="rounded-[2rem] border border-slate-200 bg-white p-5 shadow-sm">
          <div className="text-sm uppercase tracking-[0.22em] text-slate-400">Open Ports</div>
          <div className="mt-3 text-xl font-medium text-slate-900">
            {scanResult.summary?.open_ports}
          </div>
        </div>

        <div className="rounded-[2rem] border border-slate-200 bg-white p-5 shadow-sm">
          <div className="text-sm uppercase tracking-[0.22em] text-slate-400">Risk Score</div>
          <div className="mt-3 flex items-center gap-3">
            <div className="text-xl font-medium text-slate-900">
              {scanResult.summary?.risk_score}
            </div>
            <span className={`rounded-full border px-3 py-1 text-sm font-medium ${severityClass}`}>
              {scanResult.summary?.severity}
            </span>
          </div>
        </div>
      </div>
    </section>
  )
}