export default function ValidatorStatus({ nodes }) {
  const entries = Object.values(nodes)

  return (
    <div>
      <h2 className="text-lg font-semibold mb-4 text-gray-200">Validator Network</h2>
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        {entries.length === 0
          ? Array.from({ length: 5 }, (_, i) => (
              <NodeCard key={i} node={{ node_id: i + 1, port: 5001 + i, alive: false }} />
            ))
          : entries.map(node => <NodeCard key={node.node_id} node={node} />)
        }
      </div>
      <div className="mt-6 p-4 bg-gray-900 rounded-lg border border-gray-800">
        <div className="text-xs font-mono text-gray-500 mb-2">PBFT PARAMETERS</div>
        <div className="grid grid-cols-3 gap-4 text-sm">
          <div><span className="text-gray-500">n (total) </span><span className="text-cyan-400 font-mono">5</span></div>
          <div><span className="text-gray-500">f (faults) </span><span className="text-cyan-400 font-mono">1</span></div>
          <div><span className="text-gray-500">quorum (2f+1) </span><span className="text-cyan-400 font-mono">3</span></div>
        </div>
      </div>
    </div>
  )
}

function NodeCard({ node }) {
  const isAlive = node.alive
  const isPrimary = node.node_id === 1

  return (
    <div className={`p-4 rounded-lg border ${isAlive ? 'border-emerald-800 bg-gray-900' : 'border-gray-800 bg-gray-950 opacity-60'}`}>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full ${isAlive ? 'bg-emerald-400' : 'bg-red-500'}`} />
          <span className="font-mono text-sm font-bold">Node {node.node_id}</span>
        </div>
        {isPrimary && <span className="text-xs bg-violet-900 text-violet-300 px-2 py-0.5 rounded">PRIMARY</span>}
      </div>
      <div className="space-y-1 text-xs font-mono text-gray-400">
        <div>port: <span className="text-gray-300">{node.port}</span></div>
        <div>blocks: <span className="text-cyan-400">{node.chain_length ?? '—'}</span></div>
        <div>mempool: <span className="text-yellow-400">{node.mempool_size ?? '—'}</span></div>
        <div>valid: <span className={node.chain_valid ? 'text-emerald-400' : 'text-red-400'}>{isAlive ? String(node.chain_valid) : '—'}</span></div>
      </div>
      {node.address && (
        <div className="mt-2 text-xs font-mono text-gray-600 truncate" title={node.address}>
          {node.address.slice(0, 12)}...
        </div>
      )}
    </div>
  )
}