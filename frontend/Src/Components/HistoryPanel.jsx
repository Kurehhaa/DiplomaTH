const severityStyles = {
  Critical: 'bg-red-100 text-red-700 border-red-200',
  High: 'bg-orange-100 text-orange-700 border-orange-200',
  Medium: 'bg-yellow-100 text-yellow-700 border-yellow-200',
  Low: 'bg-emerald-100 text-emerald-700 border-emerald-200',
}

export default function HistoryPanel({ history }) {
  const getSeverityClass = (severity) =>
    severityStyles[severity] || 'bg-slate-100 text-slate-700 border-slate-200'

  return (
    <section className="rounded-[2rem] border border-slate-200 bg-white p-6 shadow-sm">
      <h2 className="text-2xl font-medium tracking-tight text-slate-900">
        Recent Results
      </h2>
      <p className="mt-2 text-slate-600">
        Recent scans performed in the current backend session.
      </p>

      <div className="mt-5 space-y-3">
        {history?.length ? (
          history.map((item, index) => (
            <div
              key={`${item.target}-${item.scanned_at}-${index}`}
              className="rounded-2xl border border-slate-200 bg-slate-50 p-4"
            >
              <div className="flex items-center justify-between gap-3 flex-wrap">
                <div>
                  <div className="text-lg font-medium text-slate-900 break-words">
                    {item.target}
                  </div>
                  <div className="text-sm text-slate-500">{item.scanned_at}</div>
                </div>

                <div className="flex items-center gap-3">
                  <span className="rounded-full bg-slate-900 px-3 py-1 text-sm text-white">
                    {item.risk_score}
                  </span>
                  <span
                    className={`rounded-full border px-3 py-1 text-sm font-medium ${getSeverityClass(
                      item.severity
                    )}`}
                  >
                    {item.severity}
                  </span>
                </div>
              </div>
            </div>
          ))
        ) : (
          <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 p-4 text-slate-500">
            No scan history yet.
          </div>
        )}
      </div>
    </section>
  )
}