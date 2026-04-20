import { useState } from 'react'

export default function ChainExplorer({ chain }) {
  const [selected, setSelected] = useState(null)

  if (chain.length === 0) {
    return (
      <div>
        <h2 className="text-lg font-semibold text-gray-200 mb-4">Chain Explorer</h2>
        <div className="text-gray-600 text-sm text-center py-16 bg-gray-900 rounded-lg border border-gray-800">
          No chain data — start the network first
        </div>
      </div>
    )
  }

  const reversed = [...chain].reverse()

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* Block list */}
      <div className="lg:col-span-1">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-lg font-semibold text-gray-200">Blocks</h2>
          <span className="text-xs font-mono text-gray-500">{chain.length} total</span>
        </div>
        <div className="space-y-2 max-h-[70vh] overflow-y-auto pr-1">
          {reversed.map(block => (
            <button
              key={block.index}
              onClick={() => setSelected(block)}
              className={`w-full text-left p-3 rounded-lg border transition-colors ${
                selected?.index === block.index
                  ? 'border-cyan-600 bg-cyan-950/30'
                  : 'border-gray-800 bg-gray-900 hover:border-gray-700'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="font-mono text-sm font-bold text-cyan-400">
                  #{block.index === 0 ? 'GENESIS' : block.index}
                </span>
                <span className="text-xs text-gray-500">{block.transactions.length} txns</span>
              </div>
              <div className="mt-1 text-xs font-mono text-gray-600 truncate">{block.hash}</div>
              <div className="mt-1 text-xs text-gray-500">
                {new Date(block.timestamp * 1000).toLocaleTimeString()}
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Block detail */}
      <div className="lg:col-span-2">
        <h2 className="text-lg font-semibold text-gray-200 mb-3">Block Detail</h2>
        {!selected ? (
          <div className="text-gray-600 text-sm text-center py-16 bg-gray-900 rounded-lg border border-gray-800">
            Select a block to inspect
          </div>
        ) : (
          <div className="bg-gray-900 rounded-lg border border-gray-800 p-5 space-y-4">
            <div className="grid grid-cols-2 gap-3 text-sm">
              <KV label="Index" value={selected.index} mono />
              <KV label="Transactions" value={selected.transactions.length} />
              <KV label="Hash" value={selected.hash.slice(0, 20) + '...'} mono />
              <KV label="Prev Hash" value={selected.previous_hash.slice(0, 20) + '...'} mono />
              <KV label="Timestamp" value={new Date(selected.timestamp * 1000).toLocaleString()} />
              <KV label="Nonce" value={selected.nonce} mono />
            </div>

            {selected.transactions.length > 0 && (
              <div>
                <div className="text-xs font-mono text-gray-500 uppercase tracking-widest mb-2">Transactions</div>
                <div className="space-y-2">
                  {selected.transactions.map((tx, i) => (
                    <div key={i} className="bg-gray-800 rounded p-3 text-xs font-mono space-y-1">
                      <div className="text-gray-400">id: <span className="text-gray-200">{tx.tx_id?.slice(0, 20)}...</span></div>
                      <div className="text-gray-400">sender: <span className="text-gray-200">{tx.sender?.slice(0, 16)}...</span></div>
                      <div className="text-gray-400">receiver: <span className="text-gray-200">{tx.receiver?.slice(0, 16)}...</span></div>
                      <div className="text-gray-400">amount: <span className="text-cyan-400">{tx.amount} {tx.currency}</span></div>
                      <div className="text-gray-400">corridor: <span className="text-gray-200">{tx.sender_country}→{tx.receiver_country}</span></div>
                      {tx.compliance_result && (
                        <div className="text-gray-400">compliance: <span className={tx.compliance_result.approved ? 'text-emerald-400' : 'text-red-400'}>
                          {tx.compliance_result.approved ? 'approved' : 'rejected'} · risk={tx.compliance_result.risk_level}
                        </span></div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {selected.index === 0 && (
              <div className="text-xs text-gray-600 italic">Genesis block — chain anchor</div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

function KV({ label, value, mono }) {
  return (
    <div>
      <div className="text-xs text-gray-500 uppercase tracking-wider mb-0.5">{label}</div>
      <div className={`text-sm text-gray-200 truncate ${mono ? 'font-mono' : ''}`}>{value}</div>
    </div>
  )
}