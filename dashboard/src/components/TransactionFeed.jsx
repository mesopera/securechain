import { useState } from 'react'

const CORRIDORS = ['US-IN', 'US-GB', 'US-MX', 'GB-IN', 'AE-IN', 'US-NG', 'US-IR', 'US-KP', 'IN-US']

export default function TransactionFeed({ onSubmit }) {
  const [form, setForm] = useState({
    sender: '', receiver: '', amount: '', currency: 'USD',
    sender_country: 'US', receiver_country: 'IN',
    nonce: Date.now(), timestamp: Date.now() / 1000,
    signature: null, zkp_proof: null, compliance_result: null,
  })
  const [loading, setLoading] = useState(false)
  const [lastResult, setLastResult] = useState(null)

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }))

  const randomAddr = () => Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('')

  const fillRandom = () => {
    const [sc, rc] = (CORRIDORS[Math.floor(Math.random() * CORRIDORS.length)]).split('-')
    setForm(f => ({
      ...f,
      sender: randomAddr(),
      receiver: randomAddr(),
      amount: (Math.random() * 5000 + 100).toFixed(2),
      sender_country: sc,
      receiver_country: rc,
      nonce: Date.now(),
      timestamp: Date.now() / 1000,
    }))
  }

  const handleSubmit = async () => {
    if (!form.sender || !form.receiver || !form.amount) return
    setLoading(true)
    const tx = {
      tx_id: Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join(''),
      ...form,
      amount: parseFloat(form.amount),
    }
    const result = await onSubmit(tx)
    setLastResult(result)
    setLoading(false)
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Form */}
      <div className="bg-gray-900 rounded-lg border border-gray-800 p-5">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-gray-200">Submit Transaction</h2>
          <button onClick={fillRandom} className="text-xs px-3 py-1.5 bg-gray-800 hover:bg-gray-700 rounded text-gray-400 transition-colors">
            Random
          </button>
        </div>

        <div className="space-y-3">
          <Field label="Sender Address">
            <input value={form.sender} onChange={e => set('sender', e.target.value)}
              className="input font-mono text-xs" placeholder="64-char hex address" />
          </Field>
          <Field label="Receiver Address">
            <input value={form.receiver} onChange={e => set('receiver', e.target.value)}
              className="input font-mono text-xs" placeholder="64-char hex address" />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Amount">
              <input type="number" value={form.amount} onChange={e => set('amount', e.target.value)}
                className="input" placeholder="0.00" />
            </Field>
            <Field label="Currency">
              <select value={form.currency} onChange={e => set('currency', e.target.value)} className="input">
                {['USD', 'EUR', 'GBP', 'AED', 'INR'].map(c => <option key={c}>{c}</option>)}
              </select>
            </Field>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Sender Country">
              <input value={form.sender_country} onChange={e => set('sender_country', e.target.value.toUpperCase())}
                className="input font-mono" maxLength={2} placeholder="US" />
            </Field>
            <Field label="Receiver Country">
              <input value={form.receiver_country} onChange={e => set('receiver_country', e.target.value.toUpperCase())}
                className="input font-mono" maxLength={2} placeholder="IN" />
            </Field>
          </div>
        </div>

        <button
          onClick={handleSubmit}
          disabled={loading}
          className="mt-4 w-full py-2.5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg font-medium transition-colors text-sm"
        >
          {loading ? 'Processing...' : 'Submit Transaction'}
        </button>
      </div>

      {/* Result */}
      <div className="bg-gray-900 rounded-lg border border-gray-800 p-5">
        <h2 className="text-lg font-semibold text-gray-200 mb-4">Last Result</h2>
        {!lastResult ? (
          <div className="text-gray-600 text-sm text-center py-12">Submit a transaction to see compliance result</div>
        ) : (
          <div className="space-y-3">
            <div className={`flex items-center gap-2 text-lg font-bold ${lastResult.accepted ? 'text-emerald-400' : 'text-red-400'}`}>
              <span>{lastResult.accepted ? '✅' : '❌'}</span>
              <span>{lastResult.accepted ? 'APPROVED' : 'REJECTED'}</span>
            </div>
            {lastResult.reason && (
              <div className="text-sm text-red-300 bg-red-900/20 border border-red-800 rounded p-3">
                {lastResult.reason}
              </div>
            )}
            {lastResult.compliance && (
              <div className="space-y-2">
                <div className="text-xs font-mono text-gray-500 uppercase tracking-widest">Compliance Checks</div>
                {Object.entries(lastResult.compliance.checks || {}).map(([name, check]) => {
                  if (!check) return (
                    <div key={name} className="flex items-center gap-2 text-sm text-gray-600">
                      <span className="w-16 font-mono text-xs">{name.toUpperCase()}</span>
                      <span>— (not reached)</span>
                    </div>
                  )
                  return (
                    <div key={name} className="flex items-center gap-2 text-sm">
                      <span className="w-16 font-mono text-xs text-gray-400">{name.toUpperCase()}</span>
                      <span className={check.passed ? 'text-emerald-400' : 'text-red-400'}>
                        {check.passed ? '✓ passed' : '✗ failed'}
                      </span>
                      {name === 'fraud_score' && check.score !== undefined && (
                        <span className="text-gray-500 text-xs">score: {check.score}/100</span>
                      )}
                    </div>
                  )
                })}
                <div className="text-xs text-gray-500 mt-1">
                  risk: <span className={
                    lastResult.compliance.risk_level === 'HIGH' ? 'text-red-400' :
                    lastResult.compliance.risk_level === 'MEDIUM' ? 'text-yellow-400' : 'text-emerald-400'
                  }>{lastResult.compliance.risk_level}</span>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      <style>{`
        .input { width: 100%; background: #111827; border: 1px solid #1f2937; border-radius: 6px; padding: 8px 10px; color: #e2e8f0; font-size: 13px; outline: none; }
        .input:focus { border-color: #22d3ee; }
      `}</style>
    </div>
  )
}

function Field({ label, children }) {
  return (
    <div>
      <label className="block text-xs text-gray-500 font-mono mb-1 uppercase tracking-wider">{label}</label>
      {children}
    </div>
  )
}