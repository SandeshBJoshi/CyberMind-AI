import { useEffect, useRef, useState } from 'react'
import { getAdaptiveResults, runAdaptive } from '../api'

export default function AdaptiveLab() {
  const [st, setSt] = useState({ running: false, progress: 0, report: null, error: null })
  const [error, setError] = useState('')
  const timer = useRef(null)

  async function poll() {
    try { setSt(await getAdaptiveResults()); setError('') } catch (e) { setError(e.message) }
  }
  useEffect(() => { poll(); return () => clearInterval(timer.current) }, [])
  useEffect(() => {
    clearInterval(timer.current)
    if (st.running) timer.current = setInterval(poll, 2000)
    return () => clearInterval(timer.current)
  }, [st.running])

  async function start() {
    try { const r = await runAdaptive(); if (!r.started) setError(r.reason); else { setSt({ running: true, progress: 0, report: null, error: null }); setError('') } } catch (e) { setError(e.message) }
  }
  const r = st.report, ev = r && r.best_evader

  return (
    <section className="cm-card pro-panel">
      <div className="cm-card-head"><div className="cm-card-title"><i className="red" />Adaptive stress test</div>
        <span className="cm-count mono">{st.running ? `${Math.round(st.progress * 100)}%` : r ? `${r.variations_tried} variations` : 'not run'}</span></div>
      <p className="cm-muted" style={{ maxWidth: '82ch', lineHeight: 1.55, marginBottom: 12 }}>
        The fixed scenarios ask <i>"do we catch these attacks?"</i>. This asks <i>"how much must an attacker change before one slips past?"</i>
        A simple genetic search tunes six attacker settings (tries, IPs, speed, browser fingerprint, breached passwords) against the real login guard, in a throw-away database.
        Lab only: nothing touches live data.
      </p>
      <button className="pro-btn" disabled={st.running} onClick={start}>{st.running ? 'Searching…' : r ? 'Run again' : 'Run stress test (about a minute)'}</button>
      {(error || st.error) && <div className="cm-error" style={{ marginTop: 10 }}>⚠ {error || st.error}</div>}
      {r && (
        <div style={{ marginTop: 16, display: 'grid', gap: 14 }}>
          <div className="pro-kpis">
            <div className={`cm-card pro-kpi ${r.slipped_count ? 'lock' : 'safe'}`}><span className="mono">VERDICT</span><b>{r.slipped_count ? 'EVADED' : 'HELD'}</b><em>{r.slipped_count} of {r.variations_tried} variations slipped through</em></div>
            <div className="cm-card pro-kpi"><span className="mono">FIRST SLIP AT</span><b>{r.first_slip_at_variation ? `#${r.first_slip_at_variation}` : '—'}</b><em>variations tried before one got through</em></div>
            <div className="cm-card pro-kpi sus"><span className="mono">COST TO THE ATTACKER</span><b>{ev && ev.cost_multiplier ? `${ev.cost_multiplier}×` : '—'}</b><em>attempts per stolen account vs undefended</em></div>
            <div className="cm-card pro-kpi"><span className="mono">NORMAL USERS DENIED</span><b>{r.false_alarms_on_normal_users}</b><em>across all variations</em></div>
          </div>
          {ev ? (
            <div className="cm-note"><b>Best evader:</b> {ev.description}. It took about <b>{ev.defended_harvest}</b> accounts (≈{ev.undefended_harvest} with no defence)
              and needed about <b>{ev.attempts_per_account}</b> attempts per account (undefended: {ev.attempts_per_account_undefended}).
              {ev.eventually_blocked ? ' The campaign was eventually blocked, but only after most attempts were made.' : ' It was never blocked.'}</div>
          ) : <div className="cm-note"><b>No variation got more than half its attempts through.</b> That is evidence, not proof: the search is small.</div>}
          {r.weakest_rule && (
            <div className="cm-note"><b>Weakest spot:</b> <code>{r.weakest_rule.rule}</code> stopped {Math.round(r.weakest_rule.fires_in_caught_attacks * 100)}% of the attacks that were caught, and the best evader stayed under it.
              Tightening this rule (or adding a signal that covers slow, spread-out attacks) is where to look first.</div>
          )}
          <div className="pro-table-wrap"><table className="pro-table">
            <thead><tr><th>Top attacker settings found</th><th>Got through</th><th>Peak score</th><th>Rules that fired</th></tr></thead>
            <tbody>{r.top.map((t, i) => (
              <tr key={i} className={t.slipped ? 'lock' : 'safe'} style={{ cursor: 'default' }}>
                <td style={{ whiteSpace: 'normal' }}>{t.description}</td>
                <td className="mono">{Math.round(t.allowed_share * 100)}%</td>
                <td className="mono">{t.peak_score} <span className="pro-sub">/ block at {r.thresholds.block}</span></td>
                <td className="pro-sub" style={{ whiteSpace: 'normal' }}>{Object.keys(t.rules).filter(k => t.rules[k] > 0).join(', ') || 'none'}</td>
              </tr>))}</tbody></table></div>
          <div className="cm-note"><b>Limits.</b> {r.limits.join(' ')}</div>
        </div>
      )}
    </section>
  )
}
