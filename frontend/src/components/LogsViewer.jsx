import { Fragment, useEffect, useMemo, useRef, useState } from 'react'
import { getLogs, downloadLogs } from '../api'
import CampaignsPanel from './CampaignsPanel'
import PoisonTraces from './PoisonTraces'
import { shortDevice, relTime } from '../lib/ua'

const FILTERS = [['', 'ALL'], ['SAFE', 'SAFE'], ['SUSPICIOUS', 'SUSPICIOUS'], ['SHADOW', 'SHADOW'], ['LOCKDOWN', 'LOCKDOWN']]
const PAGE = 100

function cls(status) {
  return status === 'LOCKDOWN' ? 'lock' : status === 'SUSPICIOUS' ? 'sus' : status === 'SHADOW' ? 'shadow' : 'safe'
}

function toCsv(rows) {
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`
  const head = ['timestamp', 'session_id', 'event_type', 'ip_address', 'device_info', 'rule_flags', 'ml_anomaly', 'status', 'action_taken']
  const lines = rows.map((r) => [r.timestamp, r.session_id, r.event_type, r.ip_address, r.device_info, (r.rule_flags || []).join('|'), r.ml_anomaly, r.status, r.action_taken].map(esc).join(','))
  return [head.join(','), ...lines].join('\n')
}

export default function LogsViewer({ refreshKey }) {
  const [data, setData] = useState({ total: 0, items: [] })
  const [statusFilter, setStatusFilter] = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  const [query, setQuery] = useState('')
  const [mlOnly, setMlOnly] = useState(false)
  const [live, setLive] = useState(true)
  const [limit, setLimit] = useState(PAGE)
  const [open, setOpen] = useState(() => new Set())
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [now, setNow] = useState(Date.now())
  const [tab, setTab] = useState('events') // events | campaigns | poison
  const first = useRef(true)

  async function load(silent = false) {
    if (!silent) setLoading(true)
    setError('')
    try {
      const params = { limit }
      if (statusFilter) params.status_filter = statusFilter
      const res = await getLogs(params)
      setData(res)
    } catch (err) {
      setError(err.message || 'Failed to load logs')
    } finally {
      setLoading(false)
      first.current = false
    }
  }

  useEffect(() => { load() }, [statusFilter, refreshKey, limit])
  useEffect(() => {
    const tick = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(tick)
  }, [])
  useEffect(() => {
    if (!live) return
    const id = setInterval(() => load(true), 4000)
    return () => clearInterval(id)
  }, [live, statusFilter, limit])

  const types = useMemo(() => [...new Set(data.items.map((i) => i.event_type).filter(Boolean))].sort(), [data.items])

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase()
    return data.items.filter((i) => {
      if (typeFilter && i.event_type !== typeFilter) return false
      if (mlOnly && !i.ml_anomaly) return false
      if (!q) return true
      const hay = [i.session_id, i.ip_address, i.event_type, i.action_taken, i.device_info, i.status, ...(i.rule_flags || [])].join(' ').toLowerCase()
      return hay.includes(q)
    })
  }, [data.items, query, typeFilter, mlOnly])

  const counts = useMemo(() => {
    const c = { SAFE: 0, SUSPICIOUS: 0, LOCKDOWN: 0, ml: 0 }
    data.items.forEach((i) => { c[i.status] = (c[i.status] || 0) + 1; if (i.ml_anomaly) c.ml++ })
    return c
  }, [data.items])
  const loaded = data.items.length || 1

  function toggle(id) {
    setOpen((prev) => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n })
  }
  function exportCsv() {
    const blob = new Blob([toCsv(rows)], { type: 'text/csv' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `cybermind-security-logs-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.csv`
    a.click()
    URL.revokeObjectURL(a.href)
  }

  return (
    <div className="cm-page pro">
      <header className="cm-page-head">
        <div>
          <div className="cm-eyebrow mono"><span className="cm-dot" /> AUDIT TRAIL</div>
          <h1>Detections</h1>
          <p>Every decision the engine made — rule flags, ML verdicts and the action taken.</p>
        </div>
        <div className="cm-seg" role="tablist" aria-label="Log view">
          <button className={tab === 'events' ? 'on' : ''} onClick={() => setTab('events')}>EVENTS</button>
          <button className={tab === 'campaigns' ? 'on' : ''} onClick={() => setTab('campaigns')}>CAMPAIGNS &amp; DECOYS</button>
          <button className={tab === 'poison' ? 'on' : ''} onClick={() => setTab('poison')}>POISON TRACES</button>
        </div>
        <button className={`pro-live mono${live ? ' on' : ''}`} onClick={() => setLive((v) => !v)} title="Auto-refresh every 4 seconds">
          <i /> {live ? 'LIVE TAIL' : 'PAUSED'}
        </button>
      </header>

      {tab === 'campaigns' ? <CampaignsPanel /> : tab === 'poison' ? <PoisonTraces /> : (<>
      {/* KPI strip */}
      <div className="pro-kpis">
        <div className="cm-card pro-kpi"><span className="mono">TOTAL EVENTS</span><b>{data.total.toLocaleString()}</b><em>{data.items.length} loaded</em></div>
        <div className="cm-card pro-kpi safe"><span className="mono">SAFE</span><b>{counts.SAFE}</b><em>{Math.round((counts.SAFE / loaded) * 100)}% of loaded</em></div>
        <div className="cm-card pro-kpi sus"><span className="mono">SUSPICIOUS</span><b>{counts.SUSPICIOUS}</b><em>{Math.round((counts.SUSPICIOUS / loaded) * 100)}% of loaded</em></div>
        <div className="cm-card pro-kpi lock"><span className="mono">LOCKDOWNS</span><b>{counts.LOCKDOWN}</b><em>{counts.ml} ML anomalies</em></div>
      </div>

      <div className="cm-card pro-panel">
        {/* severity distribution */}
        <div className="pro-dist" aria-label="Severity distribution of loaded events">
          <i className="s" style={{ flexGrow: counts.SAFE || 0.001 }} />
          <i className="a" style={{ flexGrow: counts.SUSPICIOUS || 0.001 }} />
          <i className="r" style={{ flexGrow: counts.LOCKDOWN || 0.001 }} />
        </div>

        {/* toolbar */}
        <div className="pro-toolbar">
          <label className="pro-search">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></svg>
            <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search session, IP, event, flag, action…" aria-label="Search logs" />
            {query && <button onClick={() => setQuery('')} aria-label="Clear search">✕</button>}
          </label>
          <div className="cm-seg" role="tablist" aria-label="Filter by status">
            {FILTERS.map(([v, label]) => (
              <button key={label} className={`${statusFilter === v ? 'on' : ''} ${v ? cls(v) : ''}`} onClick={() => setStatusFilter(v)}>{label}</button>
            ))}
          </div>
          <select className="pro-select" value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)} aria-label="Filter by event type">
            <option value="">All event types</option>
            {types.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
          <label className={`pro-toggle${mlOnly ? ' on' : ''}`}><input type="checkbox" checked={mlOnly} onChange={(e) => setMlOnly(e.target.checked)} /><span /> ML anomalies only</label>
          <button className="pro-btn" onClick={exportCsv} disabled={!rows.length}>↓ CSV</button>
          <button className="pro-btn" onClick={() => downloadLogs('jsonl')} title="Machine-readable export for a SIEM (Splunk, Sentinel, Wazuh)">↓ SIEM (.jsonl)</button>
        </div>

        {/* table */}
        <div className="pro-table-wrap">
          <table className="pro-table">
            <thead>
              <tr><th>Time</th><th>Session</th><th>Event</th><th>Source</th><th>Flags</th><th>Verdict</th><th>Action</th><th /></tr>
            </thead>
            <tbody>
              {rows.map((item) => {
                const c = cls(item.status), isOpen = open.has(item.id)
                const ts = new Date(item.timestamp)
                return (
                  <Fragment key={item.id}>
                    <tr className={`${c}${isOpen ? ' open' : ''}`} onClick={() => toggle(item.id)}>
                      <td>
                        <div className="pro-time mono">{ts.toLocaleTimeString()}</div>
                        <div className="pro-sub">{relTime(item.timestamp, now)}</div>
                      </td>
                      <td className="mono-id">{item.session_id?.slice(0, 8)}</td>
                      <td><span className="pro-type mono">{item.event_type}</span></td>
                      <td>
                        <div className="mono pro-ip">{item.ip_address || '—'}</div>
                        <div className="pro-sub" title={item.device_info || ''}>{shortDevice(item.device_info)}</div>
                      </td>
                      <td>
                        {(item.rule_flags || []).map((f, i) => <span className="tag" key={i}>{f}</span>)}
                        {item.ml_anomaly && <span className="tag tag-ml">ml_anomaly</span>}
                        {!(item.rule_flags || []).length && !item.ml_anomaly && <span className="pro-sub">—</span>}
                      </td>
                      <td><span className={`cm-badge ${c}`}>{item.status}</span>{item.tier && item.tier !== 'allow' ? <div className="pro-sub mono">{item.tier === 'step_up' ? 'step-up' : 'block'}</div> : null}</td>
                      <td className="mono-id">{item.action_taken}</td>
                      <td className="pro-chev">{isOpen ? '▾' : '▸'}</td>
                    </tr>
                    {isOpen && (
                      <tr className={`pro-exp ${c}`}>
                        <td colSpan={8}>
                          <div className="pro-detail">
                            <div><span className="mono">SESSION</span><code>{item.session_id}</code></div>
                            <div><span className="mono">TIMESTAMP</span><code>{ts.toISOString()}</code></div>
                            <div><span className="mono">USER-AGENT</span><code>{item.device_info || '—'}</code></div>
                            <div><span className="mono">ACTION TAKEN</span><code>{item.action_taken || '—'}</code></div>
                          </div>
                          {(item.reasons || []).length > 0 && (
                            <ul className="pro-reasons">
                              {item.reasons.map((r, i) => <li key={i}><b>+{r.points}</b><span>{r.text}</span></li>)}
                            </ul>
                          )}
                          <details className="pro-raw"><summary className="mono">RAW EVENT</summary><pre>{JSON.stringify(item, null, 2)}</pre></details>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
          {error && <div className="cm-error">⚠ {error}</div>}
          {loading && first.current && <div className="cm-empty small">Loading…</div>}
          {!loading && rows.length === 0 && !error && (
            <div className="cm-empty"><span>◈</span>{data.items.length ? 'No events match your filters.' : 'No events logged yet.'}</div>
          )}
        </div>

        <div className="pro-foot mono">
          <span>Showing {rows.length} of {data.items.length} loaded · {data.total.toLocaleString()} total</span>
          {data.items.length < data.total && (
            <button className="pro-btn" onClick={() => setLimit((l) => l + PAGE)}>Load {Math.min(PAGE, data.total - data.items.length)} more</button>
          )}
        </div>
      </div>
      </>)}
    </div>
  )
}
