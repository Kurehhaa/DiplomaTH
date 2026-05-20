export default function RecommendationsSection({ recommendations }) {
  return (
    <section className="rounded-[2rem] border border-slate-200 bg-white p-6 shadow-sm">
      <h2 className="text-2xl font-medium tracking-tight text-slate-900">
        Recommendations
      </h2>
      <p className="mt-2 text-slate-600">
        Suggested next steps for validation and pentest prioritization.
      </p>

      <div className="mt-5 space-y-3">
        {recommendations?.length ? (
          recommendations.map((item, index) => (
            <div
              key={`${item}-${index}`}
              className="rounded-2xl border border-slate-200 bg-slate-50 p-4 text-slate-700"
            >
              {item}
            </div>
          ))
        ) : (
          <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 p-4 text-slate-500">
            No recommendations available.
          </div>
        )}
      </div>
    </section>
  )
}