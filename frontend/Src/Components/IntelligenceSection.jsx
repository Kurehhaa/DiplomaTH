const severityStyles = {
  Critical: 'bg-red-100 text-red-700 border-red-200',
  High: 'bg-orange-100 text-orange-700 border-orange-200',
  Medium: 'bg-yellow-100 text-yellow-700 border-yellow-200',
  Low: 'bg-emerald-100 text-emerald-700 border-emerald-200',
}

export default function IntelligenceSection({ findings }) {
  const getSeverityClass = (severity) =>
    severityStyles[severity] || 'bg-slate-100 text-slate-700 border-slate-200'

  return (
    <section className="rounded-[2rem] border border-slate-200 bg-white p-6 shadow-sm">
      <h2 className="text-2xl font-medium tracking-tight text-slate-900">Intelligence</h2>
      <p className="mt-2 text-slate-600">
        Prioritized findings and proactive interpretation for pentest focus.
      </p>

      <div className="mt-5 space-y-4">
        {findings?.length ? (
          findings.map((finding) => (
            <div
              key={finding.title}
              className="rounded-3xl border border-slate-200 p-5 bg-slate-50"
            >
              <div className="flex items-center justify-between gap-3 flex-wrap">
                <div className="text-xl font-medium text-slate-900">{finding.title}</div>
                <div className="flex items-center gap-3">
                  <span
                    className={`rounded-full border px-3 py-1 text-sm font-medium ${getSeverityClass(
                      finding.severity
                    )}`}
                  >
                    {finding.severity}
                  </span>
                  <span className="rounded-full bg-slate-900 px-3 py-1 text-sm font-medium text-white">
                    Risk {finding.score}
                  </span>
                </div>
              </div>
              <p className="mt-3 text-base leading-7 text-slate-600">
                {finding.description}
              </p>
            </div>
          ))
        ) : (
          <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 p-4 text-slate-500">
            No intelligence findings available.
          </div>
        )}
      </div>
    </section>
  )
}