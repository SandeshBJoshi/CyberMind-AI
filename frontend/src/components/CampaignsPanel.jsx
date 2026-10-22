import { useEffect, useState } from 'react'
import { getCampaigns, getDecoys, getRecentAttempts, getNetworkStatus, releaseCampaign, addDecoy, deleteDecoy } from '../api'
import { relTime } from '../lib/ua'

const STATUS = { blocked: 'lock', watching: 'sus', released: 'safe' }

export default function CampaignsPanel() {
  const [campaigns, setCampaigns] = useState([])
  const [decoys, setDecoys] = useState([])
  const [attempts, setAttempts] = useState([])
  const [net, setNet] = useState(null)
  const [name, setName] = useState('')
  const [error, setError] = useState('')
  const [now, setNow] = useState(Date.now())

  async function load() {
    try {
      const [c, d, a] = await Promise.all([getCampaigns(), getDecoys(), getRecentAttempts()])
      setCampaigns(c.items); setDecoys(d); setAttempts(a); setError('')
      getNetworkStatus().then(setNet).catch(() => {})
    } catch (e) { setError(e.message) }
  }
  useEffect(() => {
    load()
    const a = setInterval(load, 4000), b = setInterval(() => setNow(Date.now()), 1000)
    return () => { clearInterval(a); clearInterval(b) }
  }, [])

  async function add(e) {
    e.preventDefault()
    if (!name.trim()) return
    try { await addDecoy(name.trim(), 'added from the console'); setName(''); await load() } catch (err) { setError(err.message) }
  }

  return (
    <div className="pro" style={{ display: 'grid', gap: 18 }}>
      {error && <div className="cm-error">⚠ {error}</div>}

      <section className="cm-card pro-panel">
        <div className="cm-card-head">
          <div className="cm-card-title"><i />CyberMind Network</div>
          <span className="cm-count mono">{net && net.enabled ? `${net.indicators.length} received · ${net.shared} shared` : 'OFF'}</span>
        </div>
        <p className="cm-muted" style={{ maxWidth: '80ch', lineHeight: 1.55 }}>
          {net && net.enabled
            ? <>Connected to a hub as <b>{net.member_id}</b>. Only a keyed hash of a blocked client fingerprint is shared, and a hint is accepted only when several installs agree.
                A received hint adds a few <b>watch-level</b> points with a visible reason; it can never block anyone by itself.
                {net.last_error ? <> Last problem: <code>{net.last_error}</code> (logins are not affected).</> : net.last_sync ? <> Last sync {net.last_sync} UTC.</> : null}</>
            : <>Not connected. Set <code>NETWORK_ENABLED=true</code> and the hub settings to let independent installs warn each other (see <code>hub/README.md</code>). Nothing is shared while it is off.</>}
        </p>
        {net && net.indicators.length > 0 && (
          <ul className="sh-reasons">{net.indicators.map((i, k) => <li key={k}><b className="mono">{i.members}×</b>{i.indicator} · {(i.reasons || []).join(', ') || 'no detail'}</li>)}</ul>
        )}
      </section>

      <section className="cm-card pro-panel">
        <div className="cm-card-head">
          <div className="cm-card-title"><i />Attack campaigns</div>
          <span className="cm-count mono">{campaigns.filter((c) => c.status === 'blocked').length} blocked</span>
        </div>
        <p className="cm-muted" style={{ marginBottom: 12 }}>
          Login attempts are grouped by <b>client fingerprint</b> (browser software and header order), not by IP address, so an attacker rotating through thousands of IPs still shows up as one campaign.
        </p>
        {campaigns.length === 0 ? (
          <div className="cm-empty"><span>◈</span>No campaigns detected. Run the Attack Lab, or send login attempts to <code>/api/auth-events/login-attempt</code>.</div>
        ) : (
          <div className="pro-table-wrap">
            <table className="pro-table">
              <thead><tr><th>Campaign</th><th>Status</th><th>Scale</th><th>Signals</th><th>Why it was flagged</th><th /></tr></thead>
              <tbody>
                {campaigns.map((c) => (
                  <tr key={c.id} className={STATUS[c.status] || 'safe'} style={{ cursor: 'default' }}>
                    <td><div className="mono pro-time">#{c.id}</div><div className="pro-sub">{relTime(c.last_seen, now)}</div></td>
                    <td><span className={`cm-badge ${STATUS[c.status] || 'safe'}`}>{c.status.toUpperCase()}</span></td>
                    <td><b>{c.attempts}</b> attempts<div className="pro-sub">{c.distinct_ips} IPs · {c.distinct_usernames} usernames</div></td>
                    <td className="mono" style={{ fontSize: 11.5 }}>{Math.round(c.failure_ratio * 100)}% failed<div className="pro-sub">{Math.round(c.breached_share * 100)}% breached pw · {c.decoy_hits} decoy</div></td>
                    <td style={{ maxWidth: 360 }}>{(c.reasons || []).slice(0, 4).map((r, i) => <div key={i} className="pro-sub" style={{ whiteSpace: 'normal', maxWidth: 'none' }}>+{r.points} {r.text}</div>)}</td>
                    <td className="pro-act">{c.status === 'blocked' && <button className="pro-btn sm" onClick={() => releaseCampaign(c.id).then(load)}>Release</button>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="cm-card pro-panel">
        <div className="cm-card-head"><div className="cm-card-title"><i />Decoy accounts</div><span className="cm-count mono">{decoys.length}</span></div>
        <p className="cm-muted" style={{ marginBottom: 12 }}>
          Fake accounts no real person uses. <b>Any attempt on one is an attacker</b>, so it produces an instant, near-zero-false-alarm alert and blocks that client.
        </p>
        <form className="pro-toolbar" onSubmit={add}>
          <label className="pro-search">
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Add a decoy username, e.g. backup.admin" aria-label="Decoy username" />
          </label>
          <button className="pro-btn" type="submit">＋ Add decoy</button>
        </form>
        <div className="decoys">
          {decoys.map((d) => (
            <div key={d.username} className={`decoy${d.hits ? ' hit' : ''}`}>
              <div><b className="mono">{d.username}</b><span>{d.hits ? `${d.hits} attempt${d.hits > 1 ? 's' : ''}, last ${relTime(d.last_hit, now)}` : 'untouched'}</span></div>
              <button onClick={() => deleteDecoy(d.username).then(load)} aria-label={`Remove ${d.username}`}>✕</button>
            </div>
          ))}
        </div>
      </section>

      <section className="cm-card pro-panel">
        <div className="cm-card-head"><div className="cm-card-title"><i />Recent login attempts</div><span className="cm-count mono">{attempts.length}</span></div>
        <div className="pro-table-wrap">
          <table className="pro-table">
            <thead><tr><th>Time</th><th>Username</th><th>Result</th><th>IP</th><th>Fingerprint</th><th>Flags</th><th>Decision</th></tr></thead>
            <tbody>
              {attempts.map((a, i) => (
                <tr key={i} className={a.decision === 'deny' ? 'lock' : a.decision === 'step_up' ? 'sus' : 'safe'} style={{ cursor: 'default' }}>
                  <td className="mono pro-time">{new Date(a.timestamp).toLocaleTimeString()}</td>
                  <td>{a.username || '—'}</td>
                  <td><span className={`cm-badge ${a.success ? 'safe' : 'sus'}`}>{a.success ? 'OK' : 'FAILED'}</span></td>
                  <td className="mono pro-ip">{a.ip_address || '—'}</td>
                  <td className="mono" style={{ fontSize: 11 }}>{a.signature}</td>
                  <td>{a.breached && <span className="tag">breached pw</span>}{a.decoy && <span className="tag tag-ml">decoy</span>}{a.campaign_id && <span className="tag">#{a.campaign_id}</span>}</td>
                  <td><span className={`cm-badge ${a.decision === 'deny' ? 'lock' : a.decision === 'step_up' ? 'sus' : 'safe'}`}>{a.decision.toUpperCase()}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
          {attempts.length === 0 && <div className="cm-empty small">No login attempts recorded yet.</div>}
        </div>
      </section>
    </div>
  )
}
