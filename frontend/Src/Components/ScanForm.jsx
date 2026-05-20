export default function ScanForm({
  target,
  setTarget,
  loading,
  isValidTarget,
  onStartScan,
}) {
  return (
    <section className="mt-8 rounded-[2rem] border border-slate-200 bg-white/80 shadow-[0_24px_80px_-28px_rgba(15,23,42,0.25)] backdrop-blur px-5 py-6 md:px-8 md:py-8">
      <div className="text-xl md:text-2xl font-medium tracking-tight text-slate-800 mb-4">
        Target Domain
      </div>

      <div className="flex flex-col gap-4 xl:flex-row">
        <input
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="example.com"
          className="h-14 md:h-16 flex-1 rounded-3xl border border-slate-300 bg-slate-50 px-6 text-base md:text-xl text-slate-800 outline-none transition focus:border-indigo-400 focus:ring-4 focus:ring-indigo-100"
        />

        <button
          onClick={onStartScan}
          disabled={!isValidTarget || loading}
          className="h-14 md:h-16 rounded-3xl bg-gradient-to-r from-blue-400 to-violet-400 px-8 md:px-10 text-base md:text-xl font-medium text-white shadow-lg shadow-indigo-200 transition hover:scale-[1.01] active:scale-[0.99] disabled:opacity-60 disabled:cursor-not-allowed"
        >
          {loading ? 'Scanning...' : 'Start Scan'}
        </button>
      </div>

      <div className="mt-4 flex flex-wrap gap-3 text-sm text-slate-500">
        <span className="rounded-full bg-slate-100 px-4 py-2">Subdomain discovery</span>
        <span className="rounded-full bg-slate-100 px-4 py-2">Port exposure mapping</span>
        <span className="rounded-full bg-slate-100 px-4 py-2">Tech stack fingerprinting</span>
        <span className="rounded-full bg-slate-100 px-4 py-2">CVE likelihood scoring</span>
      </div>
    </section>
  )
}