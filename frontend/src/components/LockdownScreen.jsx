import { useState } from 'react'

export default function LockdownScreen({ session, onUnlock, unlocking }) {
  const [error, setError] = useState('')

  async function handleUnlock() {
    setError('')
    try {
      await onUnlock(session.session_id)
    } catch (err) {
      setError(err.message || 'Unlock failed')
    }
  }

  return (
    <div className="lockdown-overlay">
      <div className="glass lockdown-box">
        <div className="lock-icon">🔒</div>
        <h1>LOCKDOWN ENGAGED</h1>
        <p>
          Session <span className="mono-id">{session.session_id?.slice(0, 8)}</span> was automatically frozen
          after behavioral analysis crossed the security threshold. All protected actions are blocked.
        </p>
        <div className="lockdown-reasons">
          {(session.reason || []).map((r, i) => <span className="tag" key={i}>{r}</span>)}
        </div>
        {error && <div className="error-msg">⚠ {error}</div>}
        <button className="btn btn-danger btn-block" onClick={handleUnlock} disabled={unlocking}>
          {unlocking ? 'AUTHENTICATING…' : 'ADMIN UNLOCK'}
        </button>
        <div className="hint">Unlocking requires the signed-in admin/owner session — this cannot be bypassed automatically.</div>
      </div>
    </div>
  )
}
