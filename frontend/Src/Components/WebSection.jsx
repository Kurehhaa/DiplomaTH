export default function WebSection({ web, summary }) {
  return (
    <section className="rounded-[2rem] border border-slate-200 bg-white p-6 shadow-sm">
      <h2 className="text-2xl font-medium tracking-tight text-slate-900">Web</h2>
      <p className="mt-2 text-slate-600">
        Web-facing metadata and detected technologies.
      </p>

      <div className="mt-5 grid gap-4 md:grid-cols-2">
        <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
          <div className="text-sm text-slate-500">Reachable URL</div>
          <div className="mt-1 break-words text-slate-900">
            {web?.reachable_url || 'Unavailable'}
          </div>
        </div>

        <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
          <div className="text-sm text-slate-500">HTTP Status</div>
          <div className="mt-1 text-slate-900">
            {web?.status_code || 'Unavailable'}
          </div>
        </div>

        <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
          <div className="text-sm text-slate-500">Server</div>
          <div className="mt-1 break-words text-slate-900">
            {web?.server || 'Unknown'}
          </div>
        </div>

        <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
          <div className="text-sm text-slate-500">Content Type</div>
          <div className="mt-1 break-words text-slate-900">
            {web?.content_type || 'Unknown'}
          </div>
        </div>
      </div>

      <div className="mt-5 rounded-2xl border border-slate-200 bg-slate-50 p-4">
        <div className="text-sm text-slate-500">Detected Technologies</div>
        <div className="mt-3 flex flex-wrap gap-2">
          {summary?.detected_technologies?.length ? (
            summary.detected_technologies.map((tech) => (
              <span
                key={tech}
                className="rounded-full bg-indigo-50 px-4 py-2 text-sm font-medium text-indigo-700"
              >
                {tech}
              </span>
            ))
          ) : (
            <span className="text-slate-500">No technologies detected.</span>
          )}
        </div>
      </div>
    </section>
  )
}