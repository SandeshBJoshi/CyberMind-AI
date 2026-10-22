import { useEffect, useMemo, useState } from 'react'
import { getSessions, unlockSession, clearStepUp } from '../api'
import { shortDevice } from '../lib/ua'
import ShadowQueue from './ShadowQueue'

const FILTERS = [['all', 'ALL'], ['safe', 'ACTIVE'], ['sus', 'SUSPICIOUS'], ['shadow', 'SHADOW'], ['lock', 'LOCKDOWN']]

function cls(status) {
  const s = String(status || '').toLowerCase()
  if (s === 'locked' || s === 'lockdown') return 'lock'
  if (s === 'suspicious') return 'sus'
  if (s === 'shadow') return 'shadow'
  return 'safe'
}
const label = (status) => (cls(status) === 'lock' ? 'LOCKDOWN' : String(status || 'active').toUpperCase())

export default function SessionsPanel({ refreshKey, onUnlocked, focusId = null, onFocused }) {
  const [sessions, setSessions] = useState([])
  const [busyId, setBusyId] = useState(null)
  const [bulkBusy, setBulkBusy] = useState(false)
  const [error, setError] = useState('')
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState('all')
  const [view, setView] = useState('table')
  const [selId, setSelId] = useState(null)
  const [copied, setCopied] = useState(false)
  const [tab, setTab] = useState('sessions') // sessions | shadow

  async function load() {
    try {
      const res = await getSessions()
      setSessions(res)
      setError('')
    } catch (err) {
      setError(err.message)
    }
  }

  useEffect(() => { load() }, [refreshKey])
  // a body clicked in the 3D Trust Field opens that session here
  useEffect(() => {
    if (!focusId) return
    setTab('sessions'); setFilter('all'); setSelId(focusId)
    onFocused && onFocused()
  }, [focusId])
  useEffect(() => {
    const interval = setInterval(load, 3000)
    return () => clearInterval(interval)
  }, [])

  async function handleUnlock(sessionId) {
    setBusyId(sessionId)
    try {
      await unlockSession(sessionId)
      await load()
      onUnlocked && onUnlocked(sessionId)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusyId(null)
    }
  }

  const locked = useMemo(() => sessions.filter((s) => cls(s.status) === 'lock'), [sessions])
  async function handleClear(sessionId) {
    setBusyId(sessionId)
    try { await clearStepUp(sessionId); await load() } catch (err) { setError(err.message) } finally { setBusyId(null) }
  }

  async function unlockAll() {
    setBulkBusy(true)
    for (const s of locked) {
      try { await unlockSession(s.session_id); onUnlocked && onUnlocked(s.session_id) } catch (err) { setError(err.message) }
    }
    await load()
    setBulkBusy(false)
  }

  const counts = useMemo(() => {
    const c = { safe: 0, sus: 0, lock: 0, shadow: 0 }
    sessions.forEach((s) => { c[cls(s.status)]++ })
    return c
  }, [sessions])

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase()
    return sessions
      .filter((s) => (filter === 'all' || cls(s.status) === filter))
      .filter((s) => !q || [s.user_label, s.session_id, s.last_ip, s.last_device, s.status].join(' ').toLowerCase().includes(q))
      .sort((a, b) => ({ lock: 0, shadow: 1, sus: 2, safe: 3 }[cls(a.status)] - { lock: 0, shadow: 1, sus: 2, safe: 3 }[cls(b.status)]))
  }, [sessions, query, filter])

  const sel = sessions.find((s) => s.session_id === selId)
  function copy(text) {
    navigator.clipboard?.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1200) }).catch(() => {})
  }

  return (
    <div className="cm-page pro">
      <header className="cm-page-head">
        <div>
          <div className="cm-eyebrow mono"><span className="cm-dot" /> CONTAINMENT</div>
          <h1>Sessions</h1>
          <p>Monitored sessions and their lockdown state. Only an authenticated admin can unlock.</p>
        </div>
        {locked.length > 0 && (
          <button className="pro-btn danger" onClick={unlockAll} disabled={bulkBusy}>
            🔓 {bulkBusy ? 'Unlocking…' : `Unlock all (${locked.length})`}
          </button>
        )}
      </header>

      <div className="cm-seg" role="tablist" aria-label="Sessions view" style={{ marginBottom: 14 }}>
        <button className={tab === 'sessions' ? 'on' : ''} onClick={() => setTab('sessions')}>SESSIONS</button>
        <button className={tab === 'shadow' ? 'on' : ''} onClick={() => setTab('shadow')}>SHADOW QUEUE{counts.shadow ? ` (${counts.shadow})` : ''}</button>
      </div>

      {tab === 'shadow' ? <ShadowQueue onChanged={load} /> : (<>
      <div className="pro-kpis">
        <div className="cm-card pro-kpi"><span className="mono">MONITORED</span><b>{sessions.length}</b><em>sessions tracked</em></div>
        <div className="cm-card pro-kpi safe"><span className="mono">ACTIVE</span><b>{counts.safe}</b><em>within normal range</em></div>
        <div className="cm-card pro-kpi sus"><span className="mono">SUSPICIOUS</span><b>{counts.sus}</b><em>under closer watch</em></div>
        <div className="cm-card pro-kpi"><span className="mono">IN SHADOW</span><b>{counts.shadow}</b><em>contained, awaiting review</em></div>
        <div className="cm-card pro-kpi lock"><span className="mono">LOCKDOWN</span><b>{counts.lock}</b><em>frozen — admin unlock</em></div>
      </div>

      {error && <div className="cm-error">⚠ {error}</div>}

      <div className="cm-card pro-panel">
        <div className="pro-toolbar">
          <label className="pro-search">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></svg>
            <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search user, session, IP, device…" aria-label="Search sessions" />
            {query && <button onClick={() => setQuery('')} aria-label="Clear search">✕</button>}
          </label>
          <div className="cm-seg" role="tablist" aria-label="Filter by status">
            {FILTERS.map(([v, l]) => (
              <button key={v} className={`${filter === v ? 'on' : ''} ${v !== 'all' ? v : ''}`} onClick={() => setFilter(v)}>{l}</button>
            ))}
          </div>
          <div className="cm-seg pro-view" aria-label="View mode">
            <button className={view === 'table' ? 'on' : ''} onClick={() => setView('table')} title="Table">☰</button>
            <button className={view === 'grid' ? 'on' : ''} onClick={() => setView('grid')} title="Cards">▦</button>
          </div>
        </div>

        <div className="cm-card-head" style={{ margin: '4px 2px 10px' }}><div className="cm-card-title"><i />Monitored Sessions</div><span className="cm-count mono">{rows.length}</span></div>

        {sessions.length === 0 && <div className="cm-empty"><span>◈</span>No sessions yet — start the demo traffic from the Dashboard tab.</div>}

        {view === 'table' && rows.length > 0 && (
          <div className="pro-table-wrap">
            <table className="pro-table">
              <thead><tr><th>Session</th><th>Status</th><th>IP address</th><th>Device</th><th /></tr></thead>
              <tbody>
                {rows.map((s) => {
                  const c = cls(s.status)
                  return (
                    <tr key={s.session_id} className={`${c}${selId === s.session_id ? ' open' : ''}`} onClick={() => setSelId(s.session_id)}>
                      <td>
                        <div className="pro-who">
                          <span className={`pro-avatar ${c}`}>{(s.user_label || '?').slice(0, 1).toUpperCase()}</span>
                          <div><strong>{s.user_label}</strong><div className="mono-id">{s.session_id.slice(0, 8)}</div></div>
                        </div>
                      </td>
                      <td><span className={`cm-badge ${c}`}>{label(s.status)}</span></td>
                      <td className="mono pro-ip">{s.last_ip || '—'}</td>
                      <td title={s.last_device || ''}>{shortDevice(s.last_device)}</td>
                      <td className="pro-act" onClick={(e) => e.stopPropagation()}>
                        {c === 'lock'
                          ? <button className="pro-btn danger sm" disabled={busyId === s.session_id} onClick={() => handleUnlock(s.session_id)}>{busyId === s.session_id ? 'Unlocking…' : 'Unlock'}</button>
                          : c === 'sus'
                            ? <button className="pro-btn warn sm" disabled={busyId === s.session_id} onClick={() => handleClear(s.session_id)} title="Extra verification succeeded">Verified</button>
                            : <span className="pro-chev">▸</span>}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}

        {view === 'grid' && rows.length > 0 && (
          <div className="cm-session-grid">
            {rows.map((s) => {
              const c = cls(s.status)
              return (
                <article className={`cm-session ${c}`} key={s.session_id} onClick={() => setSelId(s.session_id)} style={{ cursor: 'pointer' }}>
                  <div className="cm-session-top">
                    <div className="cm-avatar">{(s.user_label || '?').slice(0, 1).toUpperCase()}</div>
                    <div className="cm-session-id"><strong>{s.user_label}</strong><span className="mono-id">{s.session_id.slice(0, 8)}</span></div>
                    <span className={`cm-badge ${c}`}>{label(s.status)}</span>
                  </div>
                  <div className="cm-session-meta mono">
                    <div><span>IP</span>{s.last_ip || '—'}</div>
                    <div><span>DEVICE</span>{shortDevice(s.last_device)}</div>
                  </div>
                  {c === 'lock' && (
                    <button className="cm-btn warn" disabled={busyId === s.session_id} onClick={(e) => { e.stopPropagation(); handleUnlock(s.session_id) }}>
                      <span>🔓</span> {busyId === s.session_id ? 'Unlocking…' : 'Unlock'}
                    </button>
                  )}
                </article>
              )
            })}
          </div>
        )}

        {sessions.length > 0 && rows.length === 0 && <div className="cm-empty"><span>◈</span>No sessions match your filters.</div>}
      </div>

      {/* detail drawer */}
      {sel && (
        <aside className={`pro-drawer ${cls(sel.status)}`} role="dialog" aria-label="Session details">
          <button className="pro-drawer-x" onClick={() => setSelId(null)} aria-label="Close">✕</button>
          <div className="pro-drawer-head">
            <span className={`pro-avatar lg ${cls(sel.status)}`}>{(sel.user_label || '?').slice(0, 1).toUpperCase()}</span>
            <div><h3>{sel.user_label}</h3><span className={`cm-badge ${cls(sel.status)}`}>{label(sel.status)}</span></div>
          </div>
          <dl className="pro-dl">
            <div><dt className="mono">SESSION ID</dt><dd><code>{sel.session_id}</code><button onClick={() => copy(sel.session_id)}>{copied ? 'Copied' : 'Copy'}</button></dd></div>
            <div><dt className="mono">LAST IP</dt><dd><code>{sel.last_ip || '—'}</code></dd></div>
            <div><dt className="mono">DEVICE</dt><dd>{shortDevice(sel.last_device)}</dd></div>
            <div><dt className="mono">USER-AGENT</dt><dd><code>{sel.last_device || '—'}</code></dd></div>
          </dl>
          {cls(sel.status) === 'lock'
            ? <button className="pro-btn danger block" disabled={busyId === sel.session_id} onClick={() => handleUnlock(sel.session_id)}>🔓 {busyId === sel.session_id ? 'Unlocking…' : 'Admin unlock session'}</button>
            : cls(sel.status) === 'sus'
              ? <button className="pro-btn warn block" disabled={busyId === sel.session_id} onClick={() => handleClear(sel.session_id)}>✓ Mark step-up as verified</button>
              : <div className="cm-note">This session is {cls(sel.status) === 'sus' ? 'under closer monitoring' : 'within its normal behavioral range'}. Lockdown is triggered automatically by the rule engine or ML detector.</div>}
        </aside>
      )}
      </>)}
    </div>
  )
}
