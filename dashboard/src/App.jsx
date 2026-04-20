import { useState, useEffect, useCallback } from 'react'
import axios from 'axios'
import ValidatorStatus from './components/ValidatorStatus'
import TransactionFeed from './components/TransactionFeed'
import ComplianceLog from './components/ComplianceLog'
import ChainExplorer from './components/ChainExplorer'

const NODES = [
  { id: 1, port: 5001 },
  { id: 2, port: 5002 },
  { id: 3, port: 5003 },
  { id: 4, port: 5004 },
  { id: 5, port: 5005 },
]

const POLL_MS = 3000
const CODESPACE_NAME = import.meta.env.VITE_CODESPACE_NAME || ''

function nodeUrl(port) {
  if (CODESPACE_NAME) {
    return `https://${CODESPACE_NAME}-${port}.app.github.dev`
  }
  return `http://localhost:${port}`
}

export default function App() {
  const [nodeStatuses, setNodeStatuses] = useState({})
  const [chain, setChain] = useState([])
  const [complianceLogs, setComplianceLogs] = useState([])
  const [activeTab, setActiveTab] = useState('validators')

  const fetchStatuses = useCallback(async () => {
    const results = {}
    await Promise.all(
      NODES.map(async (n) => {
        try {
          const r = await axios.get(`${nodeUrl(n.port)}/status`, { timeout: 2000 })
          results[n.id] = { ...r.data, alive: true }
        } catch {
          results[n.id] = { node_id: n.id, port: n.port, alive: false }
        }
      })
    )
    setNodeStatuses(results)
  }, [])

  const fetchChain = useCallback(async () => {
    for (const n of NODES) {
      try {
        const r = await axios.get(`${nodeUrl(n.port)}/chain`, { timeout: 2000 })
        setChain(r.data.chain || [])
        return
      } catch { continue }
    }
  }, [])

  const submitTransaction = async (txData) => {
    const log = { ...txData, timestamp: Date.now(), status: 'pending' }
    for (const n of NODES) {
      try {
        const r = await axios.post(`${nodeUrl(n.port)}/transaction`, txData, { timeout: 5000 })
        const result = r.data
        log.status = result.accepted ? 'approved' : 'rejected'
        log.reason = result.reason || null
        log.compliance = result.compliance
        setComplianceLogs(prev => [log, ...prev].slice(0, 50))
        return result
      } catch { continue }
    }
    log.status = 'error'
    log.reason = 'All nodes unreachable'
    setComplianceLogs(prev => [log, ...prev].slice(0, 50))
  }

  useEffect(() => {
    fetchStatuses()
    fetchChain()
    const interval = setInterval(() => {
      fetchStatuses()
      fetchChain()
    }, POLL_MS)
    return () => clearInterval(interval)
  }, [fetchStatuses, fetchChain])

  const aliveCount = Object.values(nodeStatuses).filter(n => n.alive).length

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      <div className="border-b border-gray-800 bg-gray-900 px-6 py-4">
        <div className="flex items-center justify-between max-w-7xl mx-auto">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-400 to-violet-600 flex items-center justify-center text-sm">⛓</div>
            <div>
              <div className="font-bold text-lg tracking-tight bg-gradient-to-r from-cyan-400 to-violet-400 bg-clip-text text-transparent">
                SecureChain
              </div>
              <div className="text-xs text-gray-500 font-mono">Compliance-Native Permissioned Blockchain</div>
            </div>
          </div>
          <div className="flex items-center gap-4 text-sm">
            <div className="flex items-center gap-2">
              <div className={`w-2 h-2 rounded-full ${aliveCount >= 3 ? 'bg-emerald-400' : 'bg-red-400'}`} />
              <span className="text-gray-400">{aliveCount}/5 nodes</span>
            </div>
            <div className="text-gray-400 font-mono">blocks: <span className="text-cyan-400">{chain.length}</span></div>
          </div>
        </div>
      </div>

      <div className="border-b border-gray-800 bg-gray-900 px-6">
        <div className="max-w-7xl mx-auto flex gap-1">
          {[
            { id: 'validators', label: 'Validator Status' },
            { id: 'transactions', label: 'Submit Transaction' },
            { id: 'compliance', label: 'Compliance Log' },
            { id: 'chain', label: 'Chain Explorer' },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
                activeTab === tab.id
                  ? 'border-cyan-400 text-cyan-400'
                  : 'border-transparent text-gray-500 hover:text-gray-300'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      <div className="max-w-7xl mx-auto p-6">
        {activeTab === 'validators' && <ValidatorStatus nodes={nodeStatuses} />}
        {activeTab === 'transactions' && <TransactionFeed onSubmit={submitTransaction} />}
        {activeTab === 'compliance' && <ComplianceLog logs={complianceLogs} />}
        {activeTab === 'chain' && <ChainExplorer chain={chain} />}
      </div>
    </div>
  )
}