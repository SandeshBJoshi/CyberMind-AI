import { useEffect, useState } from 'react'
import { getShadowQueue, getShadowDetail, releaseShadow, confirmShadow } from '../api'
import { relTime } from '../lib/ua'

const mmss = (s) => (s == null ? '' : s <= 0 ? 'overdue' : `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')} left`)
const STATE = { pending: ['sus', 'IN SHADOW'], released: ['safe', 'RELEASED · FALSE POSITIVE'], confirmed: ['lock', 'CONFIRMED ATTACKER'], expired: ['sus', 'EXPIRED → STEP-UP'] }

export default function ShadowQueue({ onChanged }) {
  const [data, setData] = useState({ enabled: true, review_minutes: 30, items: [], counts: { pending: 0, released: 0, confirmed: 0, expired: 0 } })
  const [open, setOpen] = useState(null)
  const [detail, setDetail] = useState(null)
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')
  const [now, setNow] = useState(Date.now())

  async function load() {
    try { setData(await getShadowQueue()); setError('') } catch (e) { setError(e.message) }
  }
  useEffect(() => {
    load()
    const a = setInterval(load, 3000), b = setInterval(() => setNow(Date.now()), 1000)
    return () => { clearInterval(a); clearInterval(b) }
  }, [])
  useEffect(() => {
    if (!open) { setDetail(null); return }
    getShadowDetail(open).then(setDetail).catch(e => setError(e.message))
  }, [open, data])

  async function act(kind, sid) {
    setBusy(sid + kind)
    try { await (kind === 'release' ? releaseShadow(sid) : confirmShadow(sid)); await load(); onChanged && onChanged() } catch (e) { setError(e.message) } finally { setBusy('') }
  }
  const pending = data.items.filter(i => i.status === 'pending')
  const history = data.items.filter(i => i.status !== 'pending')

  return (
    <div className="pro" style={{ display: 'grid', gap: 18 }}>
      {error && <div className="cm-error">⚠ {error}</div>}
      {!data.enabled && <div className="cm-error">Shadow mode is switched off on the server (SHADOW_MODE=false): uncertain sessions get step-up instead.</div>}

      <div className="pro-kpis">
        <div className="cm-card pro-kpi sus"><span className="mono">IN SHADOW NOW</span><b>{data.counts.pending}</b><em>awaiting your decision</em></div>
        <div className="cm-card pro-kpi safe"><span className="mono">FALSE POSITIVES</span><b>{data.counts.released}</b><em>real customers released</em></div>
        <div className="cm-card pro-kpi lock"><span className="mono">CONFIRMED ATTACKERS</span><b>{data.counts.confirmed}</b><em>frozen after review</em></div>
        <div className="cm-card pro-kpi"><span className="mono">EXPIRED</span><b>{data.counts.expired}</b><em>no review in {data.review_minutes} min → step-up</em></div>
      </div>

      <section className="cm-card pro-panel">
        <div className="cm-card-head"><div className="cm-card-title"><i />Shadow review queue</div><span className="cm-count mono">{pending.length} waiting</span></div>
        <p className="cm-muted" style={{ marginBottom: 14, maxWidth: '80ch', lineHeight: 1.55 }}>
          A <b>shadow</b> session looks completely normal to whoever is in it: balances look right and transfers appear to succeed, but nothing real moves and every action is recorded below.
          Decide within {data.review_minutes} minutes: <b>release</b> if this is the real customer (they are told which transfers did not run), or <b>confirm</b> an attacker to freeze it.
        </p>
        {pending.length === 0 ? (
          <div className="cm-empty"><span>◐</span>Nothing in shadow. A session enters shadow only when its identity changed (new device and network, or a big departure from the user's own normal) and the evidence is not conclusive.</div>
        ) : (
          <div className="sh-cases">
            {pending.map((c) => (
              <article key={c.session_id} className="sh-case">
                <header>
                  <div><b>{c.user_label}</b><small className="mono">{c.session_id.slice(0, 8)} · {c.ip || 'unknown IP'}</small></div>
                  <span className={`cm-badge sus ${c.seconds_left <= 120 ? 'urgent' : ''}`}>{mmss(c.seconds_left)}</span>
                </header>
                <ul className="sh-reasons">{c.reasons.filter(r => r.points > 0 || r.code === 'shadow_contained').slice(0, 5).map((r, i) => <li key={i}><b className="mono">{r.points > 0 ? `+${r.points}` : '·'}</b>{r.text}</li>)}</ul>
                <p className="sh-intent">
                  <b className="mono">WHAT THEY TRIED</b> {c.transfers ? <>{c.transfers} transfer{c.transfers === 1 ? '' : 's'} totalling <b>${c.total_amount.toLocaleString()}</b> to {c.recipients.join(', ')}</> : 'nothing yet'} · {c.actions} actions logged
                </p>
                <div className="sh-btns">
                  <button className="pro-btn" disabled={!!busy} onClick={() => act('release', c.session_id)}>{busy === c.session_id + 'release' ? 'Releasing…' : '✓ Real customer: release'}</button>
                  <button className="pro-btn danger" disabled={!!busy} onClick={() => act('confirm', c.session_id)}>{busy === c.session_id + 'confirm' ? 'Freezing…' : '⛔ Attacker: freeze'}</button>
                  <button className="pro-btn sm" onClick={() => setOpen(open === c.session_id ? null : c.session_id)}>{open === c.session_id ? 'Hide log' : 'Intent log'}</button>
                </div>
                {open === c.session_id && detail && detail.session_id === c.session_id && (
                  <ol className="sh-log">{detail.intent_log.map((a, i) => (
                    <li key={i}><span className="mono">{new Date(a.t + (String(a.t).endsWith('Z') ? '' : 'Z')).toLocaleTimeString()}</span><b>{a.action.replace('_', ' ')}</b>
                      <em>{a.detail && a.detail.recipient ? `${a.detail.recipient} · $${a.detail.amount}${a.detail.memo ? ' · ' + a.detail.memo : ''}` : ''}</em></li>))}</ol>
                )}
              </article>
            ))}
          </div>
        )}
      </section>

      {history.length > 0 && (
        <section className="cm-card pro-panel">
          <div className="cm-card-head"><div className="cm-card-title"><i />Resolved cases</div></div>
          <div className="pro-table-wrap">
            <table className="pro-table">
              <thead><tr><th>Customer</th><th>Outcome</th><th>Tried</th><th>Resolved</th><th>By</th></tr></thead>
              <tbody>{history.map((c) => {
                const [cls, text] = STATE[c.status] || ['sus', c.status.toUpperCase()]
                return <tr key={c.session_id} className={cls} style={{ cursor: 'default' }}>
                  <td><b>{c.user_label}</b><div className="pro-sub mono">{c.session_id.slice(0, 8)}</div></td>
                  <td><span className={`cm-badge ${cls}`}>{text}</span></td>
                  <td>{c.transfers ? `${c.transfers} transfer(s), $${c.total_amount.toLocaleString()}` : '—'}</td>
                  <td>{relTime(c.resolved_at, now)}</td><td>{c.resolved_by || '—'}</td></tr>
              })}</tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  )
}
