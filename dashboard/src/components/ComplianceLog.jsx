export default function ComplianceLog({ logs }) {
  if (logs.length === 0) {
    return (
      <div>
        <h2 className="text-lg font-semibold text-gray-200 mb-4">Compliance Log</h2>
        <div className="text-gray-600 text-sm text-center py-16 bg-gray-900 rounded-lg border border-gray-800">
          No transactions submitted yet
        </div>
      </div>
    )
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold text-gray-200">Compliance Log</h2>
        <span className="text-xs text-gray-500 font-mono">{logs.length} events</span>
      </div>
      <div className="space-y-2">
        {logs.map((log, i) => <LogRow key={i} log={log} />)}
      </div>
    </div>
  )
}

function LogRow({ log }) {
  const approved = log.status === 'approved'
  const time = new Date(log.timestamp).toLocaleTimeString()

  const failedCheck = log.compliance?.checks
    ? Object.entries(log.compliance.checks).find(([, v]) => v && !v.passed)?.[0]
    : null

  return (
    <div className={`p-3 rounded-lg border text-sm ${
      approved ? 'bg-emerald-950/30 border-emerald-900' :
      log.status === 'pending' ? 'bg-gray-900 border-gray-800' :
      'bg-red-950/30 border-red-900'
    }`}>
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-base">{approved ? '✅' : log.status === 'pending' ? '⏳' : '❌'}</span>
          <span className="font-mono text-xs text-gray-400 truncate">
            {(log.sender || '').slice(0, 10)}... → {(log.receiver || '').slice(0, 10)}...
          </span>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          <span className="text-gray-300 font-mono text-xs">{log.amount} {log.currency}</span>
          <span className="text-gray-500 text-xs">{log.sender_country}→{log.receiver_country}</span>
          <span className="text-gray-600 text-xs">{time}</span>
        </div>
      </div>

      {!approved && log.reason && (
        <div className="mt-1.5 text-xs text-red-400 pl-7">
          {failedCheck && <span className="text-gray-500 mr-1">[{failedCheck.toUpperCase()}]</span>}
          {log.reason.slice(0, 120)}
        </div>
      )}

      {log.compliance?.checks?.fraud_score && (
        <div className="mt-1 pl-7 text-xs text-gray-500">
          fraud score: <span className={
            log.compliance.checks.fraud_score.score >= 70 ? 'text-red-400' :
            log.compliance.checks.fraud_score.score >= 40 ? 'text-yellow-400' : 'text-emerald-400'
          }>{log.compliance.checks.fraud_score.score}/100</span>
        </div>
      )}
    </div>
  )
}