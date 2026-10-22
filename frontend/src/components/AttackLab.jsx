import { useEffect, useMemo, useRef, useState } from 'react'
import { getLabScenarios, getLabResults, runLab } from '../api'
import AdaptiveLab from './AdaptiveLab'

const VERDICT = {
  caught: { cls: 'safe', label: 'CAUGHT' },
  'caught late': { cls: 'sus', label: 'CAUGHT LATE' },
  missed: { cls: 'lock', label: 'MISSED' },
  clean: { cls: 'safe', label: 'CLEAN' },
  'false alarms': { cls: 'lock', label: 'FALSE ALARMS' },
  contained: { cls: 'safe', label: 'CONTAINED (SHADOW)' },
  'false positive': { cls: 'sus', label: 'FALSE POSITIVE (SHADOW)' },
}
const pct = (v) => `${Math.round((v || 0) * 100)}%`

export default function AttackLab() {
  const [scenarios, setScenarios] = useState([])
  const [picked, setPicked] = useState(new Set())
  const [scale, setScale] = useState(0.5)
  const [state, setState] = useState({ running: false, progress: 0, current: null, results: [], error: null })
  const [error, setError] = useState('')
  const timer = useRef(null)

  useEffect(() => {
    getLabScenarios().then((list) => { setScenarios(list); setPicked(new Set(list.map((s) => s.id))) }).catch((e) => setError(e.message))
    getLabResults().then(setState).catch(() => {})
    return () => clearInterval(timer.current)
  }, [])

  useEffect(() => {
    clearInterval(timer.current)
    if (state.running) timer.current = setInterval(() => getLabResults().then(setState).catch(() => {}), 1200)
    return () => clearInterval(timer.current)
  }, [state.running])

  async function start() {
    setError('')
    try {
      const res = await runLab([...picked], scale)
      if (!res.started) { setError(res.reason || 'Could not start'); return }
      setState({ running: true, progress: 0, current: null, results: [], error: null })
    } catch (e) { setError(e.message) }
  }
  const toggle = (id) => setPicked((p) => { const n = new Set(p); n.has(id) ? n.delete(id) : n.add(id); return n })

  const summary = useMemo(() => {
    const atk = state.results.filter((r) => r.scenario !== 'normal_only' && r.scenario !== 'session_owner_new_device')
    const caught = atk.filter((r) => r.verdict === 'caught' || r.verdict === 'caught late' || r.verdict === 'contained').length
    const compromised = atk.reduce((a, r) => a + (r.compromised_accounts || 0), 0)
    const undefended = atk.reduce((a, r) => a + (r.compromised_if_undefended || 0), 0)
    const denied = state.results.reduce((a, r) => a + (r.normal_denied || 0), 0)
    const normal = state.results.reduce((a, r) => a + (r.normal_attempts || 0), 0)
    const stepped = state.results.reduce((a, r) => a + (r.normal_step_up || 0), 0)
    const shadowFp = state.results.reduce((a, r) => a + (r.false_positive_sessions || 0), 0)
    return { atk: atk.length, caught, shadowFp, compromised, undefended: Math.round(undefended), denied, normal, stepped }
  }, [state.results])

  const byId = Object.fromEntries(scenarios.map((s) => [s.id, s]))

  return (
    <div className="lab">
      <section className="cm-card lab-intro">
        <div className="cm-card-head"><div className="cm-card-title"><i className="red" />Realistic Attack Lab</div></div>
        <p className="cm-muted">
          Replays scripted attacks, mixed with hundreds of normal users, through the <b>real detection code</b> on a throw-away in-memory database
          (your live data is never touched). It reports what a defender actually cares about: was the attack caught, how many accounts fell first,
          and how many innocent people were blocked. Two scenarios are <b>expected to be missed</b>; they show the limits of this design.
        </p>
        <div className="lab-controls">
          <div className="cm-seg" role="group" aria-label="Run size">
            <button className={scale <= 0.5 ? 'on' : ''} onClick={() => setScale(0.5)}>QUICK</button>
            <button className={scale > 0.5 ? 'on' : ''} onClick={() => setScale(1.0)}>FULL SIZE</button>
          </div>
          <button className="atk-fire lab-run" onClick={start} disabled={state.running || picked.size === 0}>
            {state.running ? `RUNNING ${state.current ? '· ' + (byId[state.current]?.title || state.current) : '…'}` : '▶ RUN THE LAB'}
          </button>
        </div>
        {state.running && <div className="atk-burst-bar lab-bar"><i style={{ width: `${Math.round(state.progress * 100)}%` }} /></div>}
        {(error || state.error) && <div className="cm-error">⚠ {error || state.error}</div>}
      </section>

      <section className="cm-card">
        <div className="cm-card-head"><div className="cm-card-title"><i />Scenarios</div><span className="cm-count mono">{picked.size} selected</span></div>
        <div className="lab-scn">
          {scenarios.map((s) => (
            <label key={s.id} className={`lab-sc${picked.has(s.id) ? ' on' : ''}`}>
              <input type="checkbox" checked={picked.has(s.id)} onChange={() => toggle(s.id)} />
              <div><b>{s.title}</b><span>{s.about}</span><em className="mono">EXPECTED: {s.expected}</em></div>
            </label>
          ))}
        </div>
      </section>

      {state.results.length > 0 && (
        <>
          <div className="pro-kpis">
            <div className="cm-card pro-kpi safe"><span className="mono">ATTACKS CAUGHT</span><b>{summary.caught} / {summary.atk}</b><em>including late catches</em></div>
            <div className="cm-card pro-kpi sus"><span className="mono">ACCOUNTS COMPROMISED</span><b>{summary.compromised}</b><em>vs about {summary.undefended} with no defence</em></div>
            <div className="cm-card pro-kpi lock"><span className="mono">NORMAL USERS DENIED</span><b>{summary.denied}</b><em>of {summary.normal.toLocaleString()} normal attempts</em></div>
            {state.results.some((r) => r.scenario === 'session_owner_new_device') && (
              <div className="cm-card pro-kpi sus"><span className="mono">SHADOW FALSE POSITIVES</span><b>{summary.shadowFp}</b><em>real owners contained until released</em></div>
            )}
            <div className="cm-card pro-kpi"><span className="mono">EXTRA-PROOF PROMPTS</span><b>{summary.stepped}</b><em>friction for real users</em></div>
          </div>

          <section className="cm-card pro-panel">
            <div className="cm-card-head"><div className="cm-card-title"><i />Results</div></div>
            <div className="pro-table-wrap">
              <table className="pro-table lab-table">
                <thead><tr><th>Scenario</th><th>Verdict</th><th>Attack attempts</th><th>Caught at attempt</th><th>Stopped after</th><th>Compromised</th><th>Normal denied</th><th>Extra proof</th></tr></thead>
                <tbody>
                  {state.results.map((r) => {
                    const v = VERDICT[r.verdict] || { cls: 'sus', label: r.verdict.toUpperCase() }
                    return (
                      <tr key={r.scenario} className={v.cls} style={{ cursor: 'default' }}>
                        <td><strong>{r.title}</strong><div className="pro-sub" style={{ maxWidth: 360, whiteSpace: 'normal' }}>expected: {r.expected}</div></td>
                        <td><span className={`cm-badge ${v.cls}`}>{v.label}</span></td>
                        <td className="mono">{r.attacker_attempts || '—'}</td>
                        <td className="mono">{r.first_response_at_attempt ? `#${r.first_response_at_attempt}` : '—'}{r.first_response_after_sec != null ? <div className="pro-sub">{r.first_response_after_sec}s in</div> : null}</td>
                        <td className="mono">{r.attacker_attempts ? pct(r.blocked_after_response) : '—'}</td>
                        <td className="mono">{r.attacker_attempts ? `${r.compromised_accounts} of ~${r.compromised_if_undefended}` : '—'}</td>
                        <td className="mono">{r.normal_denied} / {r.normal_attempts}</td>
                        <td className="mono">{r.normal_step_up || 0}{r.friction_rate ? <div className="pro-sub">{pct(r.friction_rate)} of normal</div> : null}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
            <div className="cm-note">
              <b>How to read this.</b> "Caught at attempt" is how many attack attempts got through before the defence reacted. "Stopped after" is the share of the
              remaining attempts that were blocked. "Compromised" counts stolen credentials that worked (2% would succeed if nothing stopped them).
              A scenario that blends into normal traffic or copies the owner perfectly <b>can</b> be missed; reporting that honestly is the point.
              These are <b>simulated</b> attackers: real-world validation needs real traffic.
            </div>
          </section>
        </>
      )}
      <AdaptiveLab />
    </div>
  )
}
