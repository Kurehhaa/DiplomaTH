export default function NetworkSection({ network, assets }) {
  const networkAssets = assets?.filter(
    (asset) => asset.type === 'IP Address' || asset.type === 'Port'
  )

  return (
    <section className="rounded-[2rem] border border-slate-200 bg-white p-6 shadow-sm">
      <h2 className="text-2xl font-medium tracking-tight text-slate-900">Network</h2>
      <p className="mt-2 text-slate-600">
        Network-level indicators discovered during reconnaissance.
      </p>

      <div className="mt-5 space-y-4">
        <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
          <div className="text-sm text-slate-500">Resolved IP</div>
          <div className="mt-1 text-lg font-medium text-slate-900">
            {network?.ip_address || 'Unavailable'}
          </div>
        </div>

        <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
          <div className="text-sm text-slate-500">Open Ports</div>
          <div className="mt-2 flex flex-wrap gap-2">
            {network?.open_ports?.length ? (
              network.open_ports.map((port) => (
                <span
                  key={port}
                  className="rounded-full bg-indigo-50 px-3 py-1.5 text-sm font-medium text-indigo-700"
                >
                  {port}
                </span>
              ))
            ) : (
              <span className="text-slate-500">No open ports detected.</span>
            )}
          </div>
        </div>

        <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
          <div className="text-sm text-slate-500">Network Assets</div>
          <div className="mt-3 space-y-2">
            {networkAssets?.length ? (
              networkAssets.map((asset, index) => (
                <div key={`${asset.type}-${asset.value}-${index}`} className="text-slate-800">
                  <span className="font-medium">{asset.type}:</span> {asset.value}
                </div>
              ))
            ) : (
              <div className="text-slate-500">No network assets available.</div>
            )}
          </div>
        </div>
      </div>
    </section>
  )
}