import { useEffect, useState } from 'react'
import { getPoisonList, getPoisonDetail, retirePoison } from '../api'
import { relTime } from '../lib/ua'

const STATUS = { planted: 'sus', used: 'lock', retired: 'safe' }
const KIND = { analysed: '✉', planted: '☠', used: '⚡', campaign_blocked: '⛔', retired: '○' }
const dur = (s) => (s == null ? '—' : s < 90 ? `${s}s` : s < 5400 ? `${Math.round(s / 60)} min` : s < 172800 ? `${(s / 3600).toFixed(1)} h` : `${Math.round(s / 86400)} days`)

export default function PoisonTraces() {
  const [data, setData] = useState({ enabled: true, items: [], counts: { planted: 0, used: 0, retired: 0 } })
  const [open, setOpen] = useState(null)
  const [detail, setDetail] = useState(null)
  const [error, setError] = useState('')
  const [now, setNow] = useState(Date.now())

  async function load() {
    try { setData(await getPoisonList()); setError('') } catch (e) { setError(e.message) }
  }
  useEffect(() => {
    load()
    const a = setInterval(load, 4000), b = setInterval(() => setNow(Date.now()), 1000)
    return () => { clearInterval(a); clearInterval(b) }
  }, [])
  useEffect(() => {
    if (open == null) { setDetail(null); return }
    getPoisonDetail(open).then(setDetail).catch(e => setError(e.message))
  }, [open, data])

  async function retire(id) {
    try { await retirePoison(id); await load() } catch (e) { setError(e.message) }
  }

  return (
    <div className="pro" style={{ display: 'grid', gap: 18 }}>
      {error && <div className="cm-error">⚠ {error}</div>}
      {!data.enabled && <div className="cm-error">Poison tracing is switched off on the server (POISON_TRACING=false). Existing credentials are ignored at login.</div>}

      <section className="cm-card pro-panel">
        <div className="cm-card-head">
          <div className="cm-card-title"><i />Poison traces: from phishing email to the login</div>
          <span className="cm-count mono">{data.counts.planted} planted · {data.counts.used} used</span>
        </div>
        <p className="cm-muted" style={{ marginBottom: 12, maxWidth: '78ch', lineHeight: 1.55 }}>
          After analysing a phishing email you can plant a unique <b>fake credential</b> tied to it (Email Analysis → <b>Plant credential</b>). CYBERMIND never submits it anywhere:
          you enter it manually, on a page you control. If it is ever tried at our login, the attacker's whole campaign is blocked and you see how long the attack took from email to use.
        </p>
        {data.items.length === 0 ? (
          <div className="cm-empty"><span>☠</span>No credentials planted yet. Analyse a suspicious email and press <b>Plant credential</b>.</div>
        ) : (
          <div className="pro-table-wrap">
            <table className="pro-table">
              <thead><tr><th>Credential</th><th>Status</th><th>From email</th><th>Planted</th><th>Phishing → use</th><th>Campaign</th><th /></tr></thead>
              <tbody>
                {data.items.map((p) => (
                  <tr key={p.id} className={STATUS[p.status]} onClick={() => setOpen(open === p.id ? null : p.id)} style={{ cursor: 'pointer' }}>
                    <td><div className="mono pro-time">{p.username}</div><div className="pro-sub">#{p.id}</div></td>
                    <td><span className={`cm-badge ${STATUS[p.status]}`}>{p.status.toUpperCase()}</span></td>
                    <td style={{ maxWidth: 260 }}><div style={{ whiteSpace: 'normal' }}>{p.subject || '—'}</div><div className="pro-sub">{p.verdict}</div></td>
                    <td>{relTime(p.created_at, now)}</td>
                    <td>{p.uses ? <><b>{dur(p.seconds_to_first_use)}</b><div className="pro-sub">{p.uses} use{p.uses === 1 ? '' : 's'} · {p.last_ip}</div></> : <span className="cm-muted">not used yet</span>}</td>
                    <td>{p.campaign_id ? <><span className="mono">#{p.campaign_id}</span><div className="pro-sub">{p.campaign_status}</div></> : '—'}</td>
                    <td className="pro-act">{p.status !== 'retired' && <button className="pro-btn sm" onClick={(e) => { e.stopPropagation(); retire(p.id) }}>Retire</button>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {detail && (
        <section className="cm-card pro-panel">
          <div className="cm-card-head"><div className="cm-card-title"><i />Timeline · {detail.username}</div><button className="pro-btn sm" onClick={() => setOpen(null)}>Close</button></div>
          <ol className="pt-timeline">
            {detail.timeline.map((e, i) => (
              <li key={i} className={e.kind}><span className="pt-ico">{KIND[e.kind] || '•'}</span><div><b>{e.text}</b><small className="mono">{new Date(e.t + (String(e.t).endsWith('Z') ? '' : 'Z')).toLocaleString()}</small></div></li>
            ))}
          </ol>
          <p className="cm-muted em-fine">Honest limit: this only traces attackers who actually try the planted credential. A careful attacker may validate stolen credentials elsewhere first.</p>
        </section>
      )}
    </div>
  )
}
